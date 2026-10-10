//! `log.watch`: retained log and event records, and the periodic telemetry
//! snapshots that ride on the same record.
//!
//! One record type ([`LogRecord`], defined in `API.md`) serves plain log lines,
//! structured events (`kind` set) and snapshots (`kind` is a telemetry method
//! name and `fields` is exactly that method's response). The retained history
//! is whatever implements [`LogSource`]: [`LogRing`] on the firmware, and an
//! adapter over `mesh::local_trace::LogBuffer` on Linux and Android. The
//! handler is an ordinary registered stream handler: register it with
//! `register_stream(methods::LOG_WATCH_RECORDS, LogWatchHandler::new(..))`.

use alloc::{
    boxed::Box,
    collections::VecDeque,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::{
    cbor::{Decoder, Encoder},
    stream::{BodySource, OpenFuture, Outcome, Request, Response, StreamHandler},
    tagged, telemetry,
};

pub const LEVEL_ERROR: u8 = 1;
pub const LEVEL_WARN: u8 = 2;
pub const LEVEL_INFO: u8 = 3;
pub const LEVEL_DEBUG: u8 = 4;
pub const LEVEL_TRACE: u8 = 5;

/// Encode a structured event into caller-owned storage without allocating.
/// The field map uses the same numeric-key CBOR contract as retained records.
pub fn encode_event_into(
    out: &mut [u8],
    seq: u64,
    time_ms: u64,
    level: u8,
    source: &str,
    kind: &str,
    fields: &[(u64, crate::cbor::FieldValue<'_>)],
) -> Option<usize> {
    let mut e = Encoder::new(out);
    e.map(7)?;
    e.uint(1)?;
    e.uint(seq)?;
    e.uint(2)?;
    e.uint(time_ms)?;
    e.uint(3)?;
    e.uint(u64::from(level))?;
    e.uint(4)?;
    e.text_value(source.as_bytes())?;
    e.uint(5)?;
    e.text_value(kind.as_bytes())?;
    e.uint(6)?;
    e.text_value(b"")?;
    e.uint(7)?;
    crate::cbor::encode_fields_into(&mut e, fields)?;
    Some(e.len())
}

#[cfg(test)]
#[test]
fn stack_event_matches_retained_record_and_rejects_short_storage() {
    use crate::cbor::FieldValue::{Bool, Signed, Unsigned};
    let fields = [(1, Unsigned(36)), (2, Bool(true)), (3, Signed(-67))];
    let mut out = [0; 512];
    let used = encode_event_into(
        &mut out,
        7,
        123,
        LEVEL_INFO,
        "wifi",
        "wifi.sta_disconnected",
        &fields,
    )
    .unwrap();
    let (record, consumed) = LogRecord::decode(&out[..used]).unwrap();
    assert_eq!(consumed, used);
    assert_eq!(record.seq, 7);
    assert_eq!(record.time_ms, 123);
    assert_eq!(record.kind.as_deref(), Some("wifi.sta_disconnected"));
    assert_eq!(record.encode(), out[..used]);
    let mut expected = [0; 32];
    let n = crate::cbor::encode_fields(&mut expected, &fields).unwrap();
    assert_eq!(record.fields.as_deref(), Some(&expected[..n]));
    assert!(encode_event_into(&mut [0; 8], 7, 123, LEVEL_INFO, "wifi", "event", &fields).is_none());
    assert!(
        encode_event_into(
            &mut out,
            7,
            123,
            LEVEL_INFO,
            "wifi",
            "event",
            &[(2, Bool(true)), (1, Bool(false))]
        )
        .is_none()
    );
}

#[cfg(test)]
#[test]
fn sta_candidate_event_fits_small_callback_storage() {
    use crate::cbor::FieldValue::Unsigned;
    // The richest current STA event has fourteen numeric fields. Exercise
    // maximum integer widths rather than only today's small counter values.
    let fields = core::array::from_fn::<_, 14, _>(|i| (i as u64 + 1, Unsigned(u64::MAX)));
    let mut out = [0; 256];
    let used = encode_event_into(
        &mut out,
        u64::MAX,
        u64::MAX,
        LEVEL_INFO,
        "wifi",
        "wifi.sta_candidate",
        &fields,
    )
    .unwrap();
    let (record, consumed) = LogRecord::decode(&out[..used]).unwrap();
    assert_eq!(consumed, used);
    assert_eq!(record.encode(), out[..used]);
}

#[cfg(test)]
#[test]
fn heap_event_fits_callback_storage_at_maximum_counter_widths() {
    use crate::cbor::FieldValue::Unsigned;
    let fields = [
        (1, Unsigned(u32::MAX.into())),
        (2, Unsigned(u32::MAX.into())),
        (3, Unsigned(u32::MAX.into())),
    ];
    let mut out = [0; 256];
    let used = encode_event_into(
        &mut out,
        u64::MAX,
        u64::MAX,
        LEVEL_INFO,
        "wifi",
        "quic.memory",
        &fields,
    )
    .unwrap();
    let (record, consumed) = LogRecord::decode(&out[..used]).unwrap();
    assert_eq!(consumed, used);
    assert_eq!(record.encode(), out[..used]);
}

/// A retained record's text is cut to this many bytes.
pub const MAX_TEXT_BYTES: usize = 240;
/// A poll with no `limit` returns at most this many records.
pub const DEFAULT_POLL_LIMIT: usize = 32;
/// A stream without a request `timeout` runs this long.
pub const DEFAULT_STREAM_MS: u64 = 60_000;
/// No stream runs longer than this, whatever the request asks.
pub const MAX_STREAM_MS: u64 = 3_600_000;
const DEFAULT_INTERVAL_MS: u64 = 1_000;
const MIN_INTERVAL_MS: u64 = 100;
const MAX_SNAPSHOTS: usize = 8;
/// Records encoded per body read.
const RECORDS_PER_READ: usize = 8;

const COMPONENT_LOG: u64 = 208;
const METHOD_WATCH: u64 = 2;

/// One log line, event or snapshot. `fields` is an encoded CBOR map.
///
/// This is the no-std type the firmware ring also uses, so it is written by
/// hand; on hosts `platform_api::LogRecord` is the generated twin, and a test
/// checks that the two codecs produce the same bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogRecord {
    pub seq: u64,
    pub time_ms: u64,
    pub level: u8,
    pub source: String,
    pub kind: Option<String>,
    pub text: String,
    pub fields: Option<Vec<u8>>,
}

impl LogRecord {
    /// Encode as the `LogRecord` map of `API.md`.
    pub fn encode(&self) -> Vec<u8> {
        let size = 64
            + self.source.len()
            + self.text.len()
            + self.kind.as_ref().map_or(0, String::len)
            + self.fields.as_ref().map_or(0, Vec::len);
        let mut out = vec![0u8; size];
        let used = self.encode_into(&mut out).unwrap_or(0);
        out.truncate(used);
        out
    }

    /// Encode one self-delimiting record into caller-owned storage.
    ///
    /// Streaming callers use this to avoid allocating a temporary `Vec` for
    /// each record. `None` means `out` was too small and remains retryable.
    pub fn encode_into(&self, out: &mut [u8]) -> Option<usize> {
        let mut e = Encoder::new(out);
        e.map(5 + u64::from(self.kind.is_some()) + u64::from(self.fields.is_some()))?;
        e.uint(1)?;
        e.uint(self.seq)?;
        e.uint(2)?;
        e.uint(self.time_ms)?;
        e.uint(3)?;
        e.uint(u64::from(self.level))?;
        e.uint(4)?;
        e.text_value(self.source.as_bytes())?;
        if let Some(kind) = &self.kind {
            e.uint(5)?;
            e.text_value(kind.as_bytes())?;
        }
        e.uint(6)?;
        e.text_value(self.text.as_bytes())?;
        if let Some(fields) = &self.fields {
            e.uint(7)?;
            e.encoded_value(fields)?;
        }
        Some(e.len())
    }

    /// Decode one record from the front of `bytes`; returns it and its length.
    pub fn decode(bytes: &[u8]) -> Option<(Self, usize)> {
        let mut d = Decoder::new(bytes);
        let (major, count) = d.head()?;
        if major != 5 {
            return None;
        }
        let mut record = Self {
            seq: 0,
            time_ms: 0,
            level: 0,
            source: String::new(),
            kind: None,
            text: String::new(),
            fields: None,
        };
        for _ in 0..count {
            match d.uint()? {
                1 => record.seq = d.uint()?,
                2 => record.time_ms = d.uint()?,
                3 => record.level = u8::try_from(d.uint()?).ok()?,
                4 => record.source = String::from_utf8(d.text_ref()?.to_vec()).ok()?,
                5 => record.kind = Some(String::from_utf8(d.text_ref()?.to_vec()).ok()?),
                6 => record.text = String::from_utf8(d.text_ref()?.to_vec()).ok()?,
                7 => {
                    let start = d.position();
                    d.skip()?;
                    record.fields = Some(bytes[start..d.position()].to_vec());
                }
                _ => d.skip()?,
            }
        }
        Some((record, d.position()))
    }

    /// Borrow this record's fields without allocating. This is useful for
    /// predicates and filtering; `fields` remains the original encoded CBOR
    /// value.
    pub fn view(&self) -> LogRecordView<'_> {
        LogRecordView {
            seq: self.seq,
            time_ms: self.time_ms,
            level: self.level,
            source: &self.source,
            kind: self.kind.as_deref(),
            text: &self.text,
            fields: self.fields.as_deref(),
        }
    }
}

/// Borrowed form of one self-delimiting `LogRecord` CBOR map.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogRecordView<'a> {
    pub seq: u64,
    pub time_ms: u64,
    pub level: u8,
    pub source: &'a str,
    pub kind: Option<&'a str>,
    pub text: &'a str,
    pub fields: Option<&'a [u8]>,
}

impl<'a> LogRecordView<'a> {
    /// Decode a borrowed view and the encoded length of its first CBOR item.
    pub fn decode(bytes: &'a [u8]) -> Option<(Self, usize)> {
        let mut d = Decoder::new(bytes);
        let (major, count) = d.head()?;
        if major != 5 {
            return None;
        }
        let mut view = Self {
            seq: 0,
            time_ms: 0,
            level: 0,
            source: "",
            kind: None,
            text: "",
            fields: None,
        };
        for _ in 0..count {
            match d.uint()? {
                1 => view.seq = d.uint()?,
                2 => view.time_ms = d.uint()?,
                3 => view.level = u8::try_from(d.uint()?).ok()?,
                4 => view.source = core::str::from_utf8(d.text_ref()?).ok()?,
                5 => view.kind = Some(core::str::from_utf8(d.text_ref()?).ok()?),
                6 => view.text = core::str::from_utf8(d.text_ref()?).ok()?,
                7 => {
                    let start = d.position();
                    d.skip()?;
                    view.fields = Some(&bytes[start..d.position()]);
                }
                _ => d.skip()?,
            }
        }
        Some((view, d.position()))
    }
}

/// Split an ESP-IDF log line (`E (1234) tag: text`) into level, source and
/// text. A line in any other shape is an info record from source `log`.
pub fn parse_esp_idf_line(line: &str) -> (u8, &str, &str) {
    let level = match line.as_bytes() {
        [b'E', b' ', ..] => LEVEL_ERROR,
        [b'W', b' ', ..] => LEVEL_WARN,
        [b'I', b' ', ..] => LEVEL_INFO,
        [b'D', b' ', ..] => LEVEL_DEBUG,
        [b'V', b' ', ..] => LEVEL_TRACE,
        _ => return (LEVEL_INFO, "log", line),
    };
    // `(1234) tag: text`
    let Some((_, rest)) = line[2..].strip_prefix('(').and_then(|r| r.split_once(") ")) else {
        return (level, "log", &line[2..]);
    };
    match rest.split_once(": ") {
        Some((tag, text)) if !tag.is_empty() && !tag.contains(' ') => (level, tag, text),
        _ => (level, "log", rest),
    }
}

/// The retained history `log.watch` reads.
pub trait LogSource: Send + Sync {
    /// Milliseconds since the node started; the clock of `time_ms`.
    fn now_ms(&self) -> u64;

    /// Call `visit` for each retained record with `seq > since`, oldest first,
    /// until it returns false. Returns how many records after `since` have
    /// already left the history.
    fn read(&self, since: u64, visit: &mut dyn FnMut(&LogRecord) -> bool) -> u64;

    /// Visit each retained record with its encoded CBOR bytes. Sources that
    /// already retain CBOR can override this to avoid decode/re-encode work;
    /// existing sources inherit the compatible encoding implementation.
    fn read_encoded(&self, since: u64, visit: &mut dyn FnMut(&LogRecord, &[u8]) -> bool) -> u64 {
        self.read(since, &mut |record| {
            let encoded = record.encode();
            visit(record, &encoded)
        })
    }

    /// Visit borrowed CBOR records without constructing owned field strings.
    /// Sources retaining encoded records should override this to walk those
    /// bytes directly. The compatibility implementation is allocation-free
    /// for matching, but may encode a temporary record for the visitor.
    fn read_encoded_views(
        &self,
        since: u64,
        visit: &mut dyn FnMut(LogRecordView<'_>, &[u8]) -> bool,
    ) -> u64 {
        self.read(since, &mut |record| {
            let encoded = record.encode();
            visit(record.view(), &encoded)
        })
    }

    /// Visit contiguous runs of matching encoded records. `through` is the
    /// sequence immediately before this run, including any records skipped by
    /// the predicate. Sources backed by packet history can override this to
    /// offer one borrowed range per packet instead of one write per record.
    /// Return `false` from `visit` to stop after the current run.
    fn read_encoded_runs(
        &self,
        since: u64,
        matches: &mut dyn FnMut(LogRecordView<'_>) -> bool,
        visit: &mut dyn FnMut(
            u64,
            &[u8],
            Option<quic_lite::OwnedPacket<quic_lite::ErasedPacketBuffer>>,
        ) -> bool,
    ) {
        let mut through = since;
        let mut stopped = false;
        self.read_encoded_views(since, &mut |record, encoded| {
            if matches(record) && !visit(through, encoded, None) {
                stopped = true;
                return false;
            }
            through = record.seq;
            true
        });
        if !stopped {
            // An empty run communicates trailing filtered records (or an
            // entirely filtered history) without asking the writer to emit
            // bytes.
            let _ = visit(through, &[], None);
        }
    }

    /// Release complete retained packets through a cursor after their bytes
    /// have been admitted to the reliable response stream. The default source
    /// keeps its own ring policy; pool-backed sources may return those leases
    /// to the shared node pool here.
    fn advance_stream_cursor(&self, _through_seq: u64) {}
}

impl LogSource for &'static LogRing {
    fn now_ms(&self) -> u64 {
        (**self).now_ms()
    }

    fn read(&self, since: u64, visit: &mut dyn FnMut(&LogRecord) -> bool) -> u64 {
        (**self).read(since, visit)
    }
}

struct RingState {
    records: VecDeque<LogRecord>,
    capacity: usize,
    next_seq: u64,
}

/// A fixed-capacity history: the oldest record is replaced when it is full.
/// Safe to share; the critical section is a short copy.
pub struct LogRing {
    locked: AtomicBool,
    state: UnsafeCell<RingState>,
    clock: fn() -> u64,
}

// SAFETY: `state` is only touched while `locked` is held.
unsafe impl Sync for LogRing {}
unsafe impl Send for LogRing {}

impl LogRing {
    /// A ring holding `capacity` records, timestamping with `clock`.
    pub const fn new(capacity: usize, clock: fn() -> u64) -> Self {
        Self {
            locked: AtomicBool::new(false),
            state: UnsafeCell::new(RingState {
                records: VecDeque::new(),
                capacity,
                next_seq: 1,
            }),
            clock,
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut RingState) -> R) -> R {
        while self.locked.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
        // SAFETY: the lock above serializes access.
        let result = f(unsafe { &mut *self.state.get() });
        self.locked.store(false, Ordering::Release);
        result
    }

    /// Retain one record and return its sequence number. `text` is cut to
    /// [`MAX_TEXT_BYTES`] at a character boundary.
    pub fn push(
        &self,
        level: u8,
        source: &str,
        kind: Option<&str>,
        text: &str,
        fields: Option<&[u8]>,
    ) -> u64 {
        let mut end = text.len().min(MAX_TEXT_BYTES);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let time_ms = (self.clock)();
        let record = LogRecord {
            seq: 0,
            time_ms,
            level,
            source: source.to_string(),
            kind: kind.map(str::to_string),
            text: text[..end].to_string(),
            fields: fields.map(<[u8]>::to_vec),
        };
        self.with(|state| {
            let seq = state.next_seq;
            state.next_seq += 1;
            if state.capacity == 0 {
                return seq;
            }
            while state.records.len() >= state.capacity {
                state.records.pop_front();
            }
            state.records.push_back(LogRecord { seq, ..record });
            seq
        })
    }
}

impl LogSource for LogRing {
    fn now_ms(&self) -> u64 {
        (self.clock)()
    }

    fn read(&self, since: u64, visit: &mut dyn FnMut(&LogRecord) -> bool) -> u64 {
        // Copy under the lock, visit outside it.
        let (records, dropped) = self.with(|state| {
            let oldest = state.records.front().map_or(state.next_seq, |r| r.seq);
            let dropped = oldest.saturating_sub(since.saturating_add(1));
            let records: Vec<LogRecord> = state
                .records
                .iter()
                .filter(|record| record.seq > since)
                .cloned()
                .collect();
            (records, dropped)
        });
        for record in &records {
            if !visit(record) {
                break;
            }
        }
        dropped
    }
}

/// The retained history of a host process: `mesh::local_trace::LogBuffer`,
/// which holds what the process's `tracing` layer retained (warnings, errors,
/// and events whose `event_type` is watched or marked `trace_prechecked`).
/// `target` becomes the dotted `source`, `event_type` becomes `kind`, and the
/// other fields become the record's text-keyed `fields` map.
#[cfg(feature = "std")]
pub struct MeshLogSource(pub mesh::local_trace::LogBuffer);

#[cfg(feature = "std")]
impl MeshLogSource {
    fn record(entry: &mesh::local_trace::LogEntry) -> LogRecord {
        let level = match entry.level.as_str() {
            "error" => LEVEL_ERROR,
            "warn" => LEVEL_WARN,
            "info" => LEVEL_INFO,
            "debug" => LEVEL_DEBUG,
            _ => LEVEL_TRACE,
        };
        let mut kind = None;
        let mut fields = None;
        if let Some(serde_json::Value::Object(map)) = &entry.fields {
            kind = map
                .get("event_type")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            let rest: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .filter(|(key, _)| !matches!(key.as_str(), "event_type" | "trace_prechecked"))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            if !rest.is_empty() {
                // An event too large for the encoding buffer is sent without
                // its fields rather than cut.
                let mut buffer = vec![0u8; 4096];
                fields =
                    crate::cbor::encode_json_value(&serde_json::Value::Object(rest), &mut buffer)
                        .map(|used| buffer[..used].to_vec());
            }
        }
        LogRecord {
            seq: entry.seq,
            time_ms: entry.uptime_ms,
            level,
            source: entry.target.replace("::", "."),
            kind,
            text: entry.message.clone(),
            fields,
        }
    }
}

#[cfg(feature = "std")]
impl LogSource for MeshLogSource {
    fn now_ms(&self) -> u64 {
        self.0.uptime_ms()
    }

    fn read(&self, since: u64, visit: &mut dyn FnMut(&LogRecord) -> bool) -> u64 {
        let (entries, dropped) = self.0.read_since(since);
        for entry in &entries {
            if !visit(&Self::record(entry)) {
                break;
            }
        }
        dropped
    }
}

/// A decoded `log.watch` request (`API.md` tags 1 to 8).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchRequest {
    pub since_seq: u64,
    pub limit: u32,
    pub level: u8,
    pub source: Option<String>,
    pub kind: Option<String>,
    pub stream: bool,
    pub snapshots: Vec<String>,
    pub interval_ms: u32,
}

impl WatchRequest {
    /// Decode the request's `fields` map; `None` when it is malformed.
    pub fn decode(fields: Option<&[u8]>) -> Option<Self> {
        let mut request = Self {
            since_seq: 0,
            limit: 0,
            level: LEVEL_TRACE,
            source: None,
            kind: None,
            stream: false,
            snapshots: Vec::new(),
            interval_ms: DEFAULT_INTERVAL_MS as u32,
        };
        let Some(fields) = fields else {
            return Some(request);
        };
        let mut d = Decoder::new(fields);
        let (major, count) = d.head()?;
        if major != 5 {
            return None;
        }
        for _ in 0..count {
            match d.uint()? {
                1 => request.since_seq = d.uint()?,
                2 => request.limit = u32::try_from(d.uint()?).ok()?,
                3 => request.level = u8::try_from(d.uint()?).ok()?,
                4 => request.source = Some(String::from_utf8(d.text_ref()?.to_vec()).ok()?),
                5 => request.kind = Some(String::from_utf8(d.text_ref()?.to_vec()).ok()?),
                6 => request.stream = d.bool()?,
                7 => {
                    let (major, items) = d.head()?;
                    if major != 4 || items as usize > MAX_SNAPSHOTS {
                        return None;
                    }
                    for _ in 0..items {
                        request
                            .snapshots
                            .push(String::from_utf8(d.text_ref()?.to_vec()).ok()?);
                    }
                }
                8 => request.interval_ms = u32::try_from(d.uint()?).ok()?,
                _ => d.skip()?,
            }
        }
        Some(request)
    }

    /// Whether `record` passes the level, source and kind filters.
    pub fn matches(&self, record: &LogRecord) -> bool {
        self.matches_view(record.view())
    }

    /// Whether a borrowed record passes the level, source and kind filters.
    pub fn matches_view(&self, record: LogRecordView<'_>) -> bool {
        if record.level > self.level {
            return false;
        }
        if let Some(source) = &self.source {
            let below = record
                .source
                .strip_prefix(source.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'));
            if !below {
                return false;
            }
        }
        if let Some(kind) = &self.kind {
            if !record
                .kind
                .as_deref()
                .is_some_and(|value| value.starts_with(kind.as_str()))
            {
                return false;
            }
        }
        true
    }

    fn interval_ms(&self) -> u64 {
        u64::from(self.interval_ms).max(MIN_INTERVAL_MS)
    }
}

/// The telemetry method a snapshot name (`telemetry.quic`) refers to.
pub fn snapshot_method(name: &str) -> Option<u64> {
    let method = match name.strip_prefix("telemetry.")? {
        "nan_status" => telemetry::NAN_STATUS_METHOD,
        "now" => telemetry::NOW_METRICS_METHOD,
        "nan" => telemetry::NAN_METRICS_METHOD,
        "udp6" => telemetry::UDP6_METRICS_METHOD,
        "wifi_link" => telemetry::WIFI_LINK_METRICS_METHOD,
        "battery" => telemetry::BATTERY_METHOD,
        "quic" => telemetry::QUIC_METRICS_METHOD,
        "quic_associations" => telemetry::QUIC_ASSOCIATIONS_METHOD,
        "bearers" => telemetry::BEARERS_METHOD,
        "memory" => telemetry::MEMORY_METHOD,
        "power" => telemetry::POWER_METHOD,
        "runtime" => telemetry::RUNTIME_METHOD,
        _ => return None,
    };
    Some(method)
}

/// Runs a request through the node's registry and returns the response, as
/// `Registry::dispatch_now` does. Handlers that need an async runtime cannot
/// be snapshotted this way and are skipped.
pub type Dispatch = Arc<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync>;

/// The `result` of a response record, which has no method and so does not
/// decode as a request. An error response has none.
pub fn response_result(response: &[u8]) -> Option<&[u8]> {
    let mut d = Decoder::new(response);
    let (major, count) = d.head()?;
    if major != 5 {
        return None;
    }
    let mut result = None;
    for _ in 0..count {
        match d.uint()? {
            6 => {
                let start = d.position();
                d.skip()?;
                result = Some(&response[start..d.position()]);
            }
            _ => d.skip()?,
        }
    }
    result
}

/// The `log.watch` stream handler.
pub struct LogWatchHandler {
    source: Arc<dyn LogSource>,
    dispatch: Option<Dispatch>,
    /// Streaming watchers are replaceable: one new generation supersedes the
    /// prior response body without keeping multiple log consumers alive.
    stream_generation: Arc<AtomicU32>,
}

impl LogWatchHandler {
    /// `dispatch` runs the snapshot requests; `None` serves records only.
    pub fn new(source: Arc<dyn LogSource>, dispatch: Option<Dispatch>) -> Self {
        Self {
            source,
            dispatch,
            stream_generation: Arc::new(AtomicU32::new(0)),
        }
    }

    fn header(id: u64, records: &[Vec<u8>], cursor: u64, dropped: u64) -> Option<Vec<u8>> {
        let size = 64 + records.iter().map(Vec::len).sum::<usize>();
        let mut result = vec![0u8; size];
        let used = (|| {
            let mut e = Encoder::new(&mut result);
            e.map(3)?;
            e.uint(1)?;
            e.array(records.len() as u64)?;
            for record in records {
                e.encoded_value(record)?;
            }
            e.uint(2)?;
            e.uint(cursor)?;
            e.uint(3)?;
            e.uint(dropped)?;
            Some(e.len())
        })()?;
        let mut out = vec![0u8; used + 32];
        let written = tagged::encode_numeric_response(
            COMPONENT_LOG,
            METHOD_WATCH,
            id,
            &result[..used],
            &mut out,
        )?;
        out.truncate(written);
        Some(out)
    }
}

impl StreamHandler for LogWatchHandler {
    fn open<'a>(&'a self, request: Request<'a>) -> OpenFuture<'a> {
        let outcome = (|| {
            let id = request.record.id?;
            let Some(watch) = WatchRequest::decode(request.record.fields) else {
                return Some(Outcome::Respond(Response::header(
                    crate::stream::error_header(Some(id), b"invalid log.watch request"),
                )));
            };
            let mut cursor = watch.since_seq;
            if watch.stream {
                let generation = self
                    .stream_generation
                    .fetch_add(1, Ordering::AcqRel)
                    .wrapping_add(1);
                let header = Self::header(id, &[], cursor, 0)?;
                let now = self.source.now_ms();
                let run = request
                    .context
                    .timeout_ms
                    .unwrap_or(DEFAULT_STREAM_MS)
                    .min(MAX_STREAM_MS);
                let mut snapshots = Vec::new();
                for name in &watch.snapshots {
                    // An unknown or unregistered snapshot is reported once in
                    // the stream and skipped.
                    snapshots.push((name.clone(), snapshot_method(name)));
                }
                let body = WatchBody {
                    next_snapshot_ms: now.saturating_add(watch.interval_ms()),
                    source: self.source.clone(),
                    dispatch: self.dispatch.clone(),
                    cursor,
                    deadline_ms: now.saturating_add(run),
                    snapshots,
                    reported: false,
                    pending: Vec::new(),
                    offset: 0,
                    partial_record_offset: 0,
                    watch,
                    next_id: 1,
                    generation: self.stream_generation.clone(),
                    generation_id: generation,
                };
                return Some(Outcome::Respond(Response::with_body(header, body)));
            }
            let limit = match watch.limit {
                0 => DEFAULT_POLL_LIMIT,
                value => value as usize,
            };
            let mut records = Vec::new();
            let dropped = self
                .source
                .read_encoded(watch.since_seq, &mut |record, encoded| {
                    cursor = cursor.max(record.seq);
                    if watch.matches(record) {
                        records.push(encoded.to_vec());
                        // The cursor stops at the last record returned so the
                        // next poll continues from it.
                        if records.len() >= limit {
                            return false;
                        }
                    }
                    true
                });
            Some(Outcome::Respond(Response::header(Self::header(
                id, &records, cursor, dropped,
            )?)))
        })();
        Box::pin(core::future::ready(outcome))
    }
}

/// The streaming body: new records and due snapshots, as concatenated
/// `LogRecord` items, until the deadline.
struct WatchBody {
    source: Arc<dyn LogSource>,
    dispatch: Option<Dispatch>,
    watch: WatchRequest,
    cursor: u64,
    deadline_ms: u64,
    snapshots: Vec<(String, Option<u64>)>,
    next_snapshot_ms: u64,
    /// The notice about skipped snapshots was sent.
    reported: bool,
    pending: Vec<u8>,
    offset: usize,
    partial_record_offset: usize,
    next_id: u64,
    generation: Arc<AtomicU32>,
    generation_id: u32,
}

impl WatchBody {
    fn snapshot(&mut self, name: &str, method: u64, now: u64) -> Option<LogRecord> {
        let dispatch = self.dispatch.as_ref()?;
        let mut request = [0u8; 32];
        let id = self.next_id;
        self.next_id += 1;
        let used = telemetry::encode_request(method, id, &mut request)?;
        let response = dispatch(&request[..used])?;
        let result = response_result(&response)?;
        Some(LogRecord {
            // Snapshots are not retained, so they have no sequence number.
            seq: 0,
            time_ms: now,
            level: LEVEL_INFO,
            source: "telemetry".to_string(),
            kind: Some(name.to_string()),
            text: String::new(),
            fields: Some(result.to_vec()),
        })
    }

    fn read_logs(&mut self, out: &mut [u8]) -> usize {
        let mut cursor = self.cursor;
        let mut written = 0usize;
        let mut taken = 0usize;
        self.source
            .read_encoded_views(self.cursor, &mut |record, encoded_record| {
                if self.watch.matches_view(record) {
                    if encoded_record.len() > out.len().saturating_sub(written) {
                        if written == 0 {
                            // A record may exceed the caller's current transport
                            // chunk. Retain only that one record so byte-stream
                            // reads can split it without losing the sequence.
                            self.pending.extend_from_slice(encoded_record);
                            cursor = cursor.max(record.seq);
                        }
                        // If prior records were written, leave this record at the
                        // cursor boundary for the next read.
                        return false;
                    }
                    out[written..written + encoded_record.len()].copy_from_slice(encoded_record);
                    written += encoded_record.len();
                    taken += 1;
                }
                cursor = cursor.max(record.seq);
                taken < RECORDS_PER_READ && written < out.len()
            });
        self.cursor = cursor;
        written
    }

    fn fill_snapshots(&mut self, now: u64) {
        if now >= self.next_snapshot_ms && !self.snapshots.is_empty() {
            self.next_snapshot_ms = now.saturating_add(self.watch.interval_ms());
            let mut skipped = Vec::new();
            for (name, method) in self.snapshots.clone() {
                let record = method.and_then(|method| self.snapshot(&name, method, now));
                match record {
                    Some(record) => self.pending.extend_from_slice(&record.encode()),
                    None => skipped.push(name),
                }
            }
            if !skipped.is_empty() && !self.reported {
                self.reported = true;
                let notice = LogRecord {
                    seq: 0,
                    time_ms: now,
                    level: LEVEL_WARN,
                    source: "log.watch".to_string(),
                    kind: None,
                    text: alloc::format!("snapshot skipped: {}", skipped.join(", ")),
                    fields: None,
                };
                self.pending.extend_from_slice(&notice.encode());
            }
        }
    }
}

impl BodySource for WatchBody {
    fn read(&mut self, out: &mut [u8]) -> (usize, bool) {
        if self.generation.load(Ordering::Acquire) != self.generation_id {
            return (0, true);
        }
        if self.offset < self.pending.len() {
            let count = (self.pending.len() - self.offset).min(out.len());
            out[..count].copy_from_slice(&self.pending[self.offset..self.offset + count]);
            self.offset += count;
            if self.offset == self.pending.len() {
                self.pending.clear();
                self.offset = 0;
            }
            return (count, false);
        }
        let now = self.source.now_ms();
        if now >= self.deadline_ms {
            return (0, true);
        }
        let count = self.read_logs(out);
        if count != 0 {
            return (count, false);
        }
        if !self.pending.is_empty() {
            let count = (self.pending.len() - self.offset).min(out.len());
            out[..count].copy_from_slice(&self.pending[self.offset..self.offset + count]);
            self.offset += count;
            if self.offset == self.pending.len() {
                self.pending.clear();
                self.offset = 0;
            }
            return (count, false);
        }
        if now >= self.next_snapshot_ms && !self.snapshots.is_empty() {
            self.pending.clear();
            self.offset = 0;
            self.fill_snapshots(now);
        }
        let count = self.pending.len().min(out.len());
        out[..count].copy_from_slice(&self.pending[self.offset..self.offset + count]);
        self.offset += count;
        (count, false)
    }

    fn write_chunk(
        &mut self,
        writer: &mut dyn crate::stream::BodyChunkWriter,
    ) -> Option<crate::stream::BodyChunkProgress> {
        use crate::stream::{
            BodyChunkProgress as Progress, BodyChunkWriteError as WriteError,
            OwnedBodyChunkProgress as OwnedProgress,
        };

        if self.generation.load(Ordering::Acquire) != self.generation_id {
            return Some(Progress::Done);
        }
        if !self.pending.is_empty() || self.offset != 0 {
            return None;
        }
        let now = self.source.now_ms();
        if now >= self.deadline_ms {
            return Some(Progress::Done);
        }
        // Snapshot responses are sparse and already use the ordinary CBOR
        // response path. Retained log records stay on the borrowed path.
        if now >= self.next_snapshot_ms && !self.snapshots.is_empty() {
            return None;
        }

        let mut cursor = self.cursor;
        let mut partial = self.partial_record_offset;
        let mut progress = None;
        self.source.read_encoded_runs(
            self.cursor,
            &mut |record| self.watch.matches_view(record),
            &mut |through, encoded, owned_packet| {
                cursor = cursor.max(through);
                if encoded.is_empty() {
                    return true;
                }
                if partial > encoded.len() {
                    partial = 0;
                }
                let remaining = &encoded[partial..];
                let offered = if partial == 0 {
                    match owned_packet {
                        Some(packet) => match writer.write_owned(packet) {
                            OwnedProgress::Accepted(count) => Ok(count),
                            OwnedProgress::Unsupported => writer.write(remaining),
                            OwnedProgress::Retryable => Err(WriteError::Retryable),
                            OwnedProgress::Failed => Err(WriteError::Failed),
                        },
                        None => writer.write(remaining),
                    }
                } else {
                    drop(owned_packet);
                    writer.write(remaining)
                };
                match offered {
                    Ok(0) => {
                        progress = Some(Progress::Waiting);
                        false
                    }
                    Ok(count) if count <= remaining.len() => {
                        let accepted_end = partial + count;
                        let mut record_offset = 0;
                        let mut last_complete_seq = cursor;
                        let mut next_partial = 0;
                        while record_offset < encoded.len() {
                            let Some((record, used)) =
                                LogRecordView::decode(&encoded[record_offset..])
                            else {
                                progress = Some(Progress::Failed);
                                return false;
                            };
                            let record_end = record_offset + used;
                            if record_end <= accepted_end {
                                last_complete_seq = last_complete_seq.max(record.seq);
                            } else {
                                if record_offset < accepted_end {
                                    next_partial = accepted_end - record_offset;
                                }
                                break;
                            }
                            record_offset = record_end;
                        }
                        cursor = last_complete_seq;
                        partial = next_partial;
                        progress = Some(Progress::Accepted(count));
                        count == remaining.len() && partial == 0
                    }
                    Ok(_) | Err(WriteError::Failed) => {
                        progress = Some(Progress::Failed);
                        false
                    }
                    Err(WriteError::Retryable) => {
                        progress = Some(Progress::Retryable);
                        false
                    }
                }
            },
        );
        self.cursor = cursor;
        self.partial_record_offset = partial;
        self.source.advance_stream_cursor(cursor);
        Some(progress.unwrap_or(Progress::Waiting))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::CallContext;
    use core::sync::atomic::AtomicU64;

    /// A clock per test: the tests run in parallel.
    macro_rules! clock {
        ($now:ident, $clock:ident) => {
            static $now: AtomicU64 = AtomicU64::new(0);
            fn $clock() -> u64 {
                $now.load(Ordering::Relaxed)
            }
        };
    }

    #[test]
    fn esp_idf_lines_split_into_level_source_and_text() {
        assert_eq!(
            parse_esp_idf_line("E (1234) wifi: scan failed: busy"),
            (LEVEL_ERROR, "wifi", "scan failed: busy")
        );
        assert_eq!(
            parse_esp_idf_line("W (9) nan: slow"),
            (LEVEL_WARN, "nan", "slow")
        );
        // No tag, or a tag with a space, keeps the whole message.
        assert_eq!(
            parse_esp_idf_line("I (5) just words here"),
            (LEVEL_INFO, "log", "just words here")
        );
        assert_eq!(
            parse_esp_idf_line("I (5) two words: text"),
            (LEVEL_INFO, "log", "two words: text")
        );
        // Not an ESP-IDF line at all.
        assert_eq!(
            parse_esp_idf_line("DMESH main: uart-start failed"),
            (LEVEL_INFO, "log", "DMESH main: uart-start failed")
        );
        assert_eq!(parse_esp_idf_line("E"), (LEVEL_INFO, "log", "E"));
    }

    #[cfg(feature = "std")]
    #[test]
    fn a_host_log_buffer_is_a_log_source() {
        let buffer = mesh::local_trace::LogBuffer::new(8);
        let entry =
            |level: &str, target: &str, message: &str, fields: Option<serde_json::Value>| {
                mesh::local_trace::LogEntry {
                    timestamp: String::new(),
                    level: level.into(),
                    target: target.into(),
                    message: message.into(),
                    fields,
                    seq: 0,
                    uptime_ms: 0,
                }
            };
        buffer.push(entry("warn", "lmesh_wifi::radio", "slow", None));
        buffer.push(entry(
            "info",
            "dmesh.event",
            "event",
            Some(serde_json::json!({
                "event_type": "wifi.rawnan.discovery",
                "trace_prechecked": true,
                "source": "wlan0",
            })),
        ));
        let source = MeshLogSource(buffer);
        let mut seen = Vec::new();
        assert_eq!(
            source.read(0, &mut |record| {
                seen.push(record.clone());
                true
            }),
            0
        );
        assert_eq!(seen[0].seq, 1);
        assert_eq!(
            (
                seen[0].level,
                seen[0].source.as_str(),
                seen[0].kind.as_deref()
            ),
            (LEVEL_WARN, "lmesh_wifi.radio", None)
        );
        assert_eq!(seen[1].kind.as_deref(), Some("wifi.rawnan.discovery"));
        // The event's other fields are a text-keyed map; the envelope fields are not.
        let mut d = Decoder::new(seen[1].fields.as_deref().unwrap());
        assert_eq!(d.head(), Some((5, 1)));
        let mut name = [0u8; 16];
        let used = d.text(&mut name).unwrap();
        assert_eq!(&name[..used], b"source");
        // Reading from a cursor returns only newer records.
        let mut newer = 0;
        source.read(1, &mut |_| {
            newer += 1;
            true
        });
        assert_eq!(newer, 1);
    }

    /// The no-std record and its generated twin (`platform_api::LogRecord`, the
    /// row type of `log.watch`) must be one wire format.
    #[cfg(feature = "std")]
    #[test]
    fn the_hand_written_record_and_the_generated_row_encode_identically() {
        for (kind, fields) in [
            (None, None),
            (Some("nan.event".to_owned()), Some(vec![0xa1, 0x01, 0x01])),
        ] {
            let record = LogRecord {
                seq: 7,
                time_ms: 1234,
                level: LEVEL_WARN,
                source: "nan".to_owned(),
                kind: kind.clone(),
                text: "hello".to_owned(),
                fields: fields.clone(),
            };
            let generated = crate::platform_api::LogRecord {
                seq: 7,
                time_ms: 1234,
                level: LEVEL_WARN,
                source: "nan".to_owned(),
                kind,
                text: "hello".to_owned(),
                fields: fields
                    .as_deref()
                    .map(|fields| mesh::cbor::decode_value_bytes(fields).unwrap()),
            };
            assert_eq!(record.encode(), generated.encode_cbor());
            let back = crate::platform_api::LogRecord::decode_cbor(&record.encode()).unwrap();
            assert_eq!(back, generated);
        }
    }

    #[test]
    fn a_record_round_trips_through_its_map() {
        let record = LogRecord {
            seq: 9,
            time_ms: 1234,
            level: LEVEL_WARN,
            source: "bearer.ble".into(),
            kind: Some("bearer.state".into()),
            text: "link up".into(),
            fields: Some(vec![0xa1, 0x01, 0x05]),
        };
        let wire = record.encode();
        assert_eq!(LogRecord::decode(&wire), Some((record.clone(), wire.len())));
        let (view, viewed) = LogRecordView::decode(&wire).unwrap();
        assert_eq!(viewed, wire.len());
        assert_eq!(view, record.view());
        let mut direct = vec![0u8; wire.len()];
        assert_eq!(record.encode_into(&mut direct), Some(wire.len()));
        assert_eq!(direct, wire);
        assert_eq!(record.encode_into(&mut direct[..1]), None);
        let plain = LogRecord {
            kind: None,
            fields: None,
            ..LogRecord::decode(&wire).unwrap().0
        };
        let wire = plain.encode();
        assert_eq!(LogRecord::decode(&wire).unwrap().0, plain);
    }

    #[test]
    fn the_ring_keeps_the_newest_records_and_counts_what_was_lost() {
        clock!(NOW, clock);
        static RING: LogRing = LogRing::new(3, clock);
        for index in 0..5 {
            NOW.store(100 + index, Ordering::Relaxed);
            RING.push(LEVEL_INFO, "t", None, &alloc::format!("line {index}"), None);
        }
        let mut seen = Vec::new();
        let dropped = RING.read(0, &mut |record| {
            seen.push((record.seq, record.text.clone(), record.time_ms));
            true
        });
        // Records 1 and 2 were replaced.
        assert_eq!(dropped, 2);
        assert_eq!(
            seen,
            vec![
                (3, "line 2".to_string(), 102),
                (4, "line 3".to_string(), 103),
                (5, "line 4".to_string(), 104),
            ]
        );
        // Reading on from the cursor loses nothing.
        assert_eq!(RING.read(5, &mut |_| true), 0);
        let mut encoded_seen = Vec::new();
        RING.read_encoded(2, &mut |record, encoded| {
            assert_eq!(
                LogRecord::decode(encoded).map(|pair| pair.0),
                Some(record.clone())
            );
            encoded_seen.push(encoded.to_vec());
            true
        });
        assert_eq!(encoded_seen.len(), 3);
        // Long text is cut at a character boundary.
        let long = "é".repeat(200);
        RING.push(LEVEL_INFO, "t", None, &long, None);
        RING.read(5, &mut |record| {
            assert!(record.text.len() <= MAX_TEXT_BYTES);
            assert!(record.text.chars().all(|c| c == 'é'));
            true
        });
    }

    fn request(fields: &[u8]) -> Vec<u8> {
        // {1: 208, 2: 2, 3: 7, 5: <fields>}
        let mut out = vec![0u8; 64 + fields.len()];
        let mut e = Encoder::new(&mut out);
        e.map(4).unwrap();
        for (key, value) in [(1, COMPONENT_LOG), (2, METHOD_WATCH), (3, 7)] {
            e.uint(key).unwrap();
            e.uint(value).unwrap();
        }
        e.uint(5).unwrap();
        e.encoded_value(fields).unwrap();
        let used = e.len();
        out.truncate(used);
        out
    }

    fn fields(build: impl FnOnce(&mut Encoder<'_>)) -> Vec<u8> {
        let mut out = vec![0u8; 256];
        let mut e = Encoder::new(&mut out);
        build(&mut e);
        let used = e.len();
        out.truncate(used);
        out
    }

    fn stream_body(handler: &LogWatchHandler, fields: &[u8]) -> Box<dyn BodySource> {
        let wire = request(fields);
        let record = tagged::decode(&wire).unwrap();
        let mut future = handler.open(Request {
            record,
            header: &wire,
            context: CallContext::local(),
        });
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        let core::task::Poll::Ready(Some(Outcome::Respond(response))) =
            future.as_mut().poll(&mut cx)
        else {
            panic!("expected a streaming response");
        };
        drop(future);
        response.body.expect("stream response body")
    }

    fn poll(handler: &LogWatchHandler, fields: &[u8]) -> (Vec<LogRecord>, u64, u64) {
        let wire = request(fields);
        let record = tagged::decode(&wire).unwrap();
        let mut future = handler.open(Request {
            record,
            header: &wire,
            context: CallContext::local(),
        });
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        let Some(Outcome::Respond(response)) = (match future.as_mut().poll(&mut cx) {
            core::task::Poll::Ready(outcome) => outcome,
            core::task::Poll::Pending => panic!("log.watch must answer immediately"),
        }) else {
            panic!("expected a response");
        };
        let result = response_result(&response.header).expect("result");
        let mut d = Decoder::new(result);
        assert_eq!(d.head(), Some((5, 3)));
        assert_eq!(d.uint(), Some(1));
        let (_, count) = d.head().unwrap();
        let mut records = Vec::new();
        for _ in 0..count {
            let start = d.position();
            d.skip().unwrap();
            records.push(LogRecord::decode(&result[start..d.position()]).unwrap().0);
        }
        assert_eq!(d.uint(), Some(2));
        let cursor = d.uint().unwrap();
        assert_eq!(d.uint(), Some(3));
        (records, cursor, d.uint().unwrap())
    }

    #[test]
    fn a_poll_filters_pages_and_reports_a_cursor() {
        clock!(NOW, clock);
        static RING: LogRing = LogRing::new(16, clock);
        NOW.store(5, Ordering::Relaxed);
        RING.push(LEVEL_ERROR, "quic", None, "e", None);
        RING.push(LEVEL_DEBUG, "quic", None, "d", None);
        RING.push(LEVEL_INFO, "bearer.ble", Some("bearer.state"), "up", None);
        RING.push(LEVEL_INFO, "bearerx", None, "other", None);
        RING.push(LEVEL_INFO, "nan", Some("nan.followup"), "f", None);
        let handler = LogWatchHandler::new(Arc::new(&RING as &'static LogRing), None);

        // Level: errors and warnings only.
        let (records, cursor, dropped) = poll(
            &handler,
            &fields(|e| {
                e.map(1).unwrap();
                e.uint(3).unwrap();
                e.uint(2).unwrap();
            }),
        );
        assert_eq!(records.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1]);
        assert_eq!((cursor, dropped), (5, 0));

        // Source matches a dotted prefix, not a string prefix.
        let (records, ..) = poll(
            &handler,
            &fields(|e| {
                e.map(1).unwrap();
                e.uint(4).unwrap();
                e.text_value(b"bearer").unwrap();
            }),
        );
        assert_eq!(records.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![3]);

        // Kind is a prefix; paging stops the cursor at the last record returned.
        let (records, cursor, _) = poll(
            &handler,
            &fields(|e| {
                e.map(2).unwrap();
                e.uint(2).unwrap();
                e.uint(1).unwrap();
                e.uint(5).unwrap();
                e.text_value(b"nan").unwrap();
            }),
        );
        assert_eq!(records.len(), 1);
        assert_eq!(cursor, 5);
        let (records, cursor, _) = poll(
            &handler,
            &fields(|e| {
                e.map(1).unwrap();
                e.uint(2).unwrap();
                e.uint(2).unwrap();
            }),
        );
        assert_eq!((records.len(), cursor), (2, 2));
        // Continuing from the cursor returns the rest.
        let (records, cursor, _) = poll(
            &handler,
            &fields(|e| {
                e.map(1).unwrap();
                e.uint(1).unwrap();
                e.uint(2).unwrap();
            }),
        );
        assert_eq!((records.len(), cursor), (3, 5));
        // A malformed request is an error, not a panic.
        assert!(WatchRequest::decode(Some(&[0x01])).is_none());
    }

    #[test]
    fn a_stream_sends_new_records_and_snapshots_the_method_response() {
        clock!(NOW, clock);
        static RING: LogRing = LogRing::new(16, clock);
        NOW.store(1_000, Ordering::Relaxed);
        RING.push(LEVEL_INFO, "t", None, "before", None);
        // `telemetry.udp6` answers with a metric map; the snapshot carries it.
        let registry = Arc::new(crate::registry::Registry::new());
        assert!(registry.register(
            crate::registry::methods::TELEMETRY_UDP6_METRICS,
            crate::registry::SyncFn(|record| {
                let mut result = [0u8; 32];
                let used = telemetry::encode_metrics(
                    &[telemetry::Metric {
                        id: telemetry::udp6_metric::RX_FRAMES,
                        value: 42,
                    }],
                    &mut result,
                )?;
                let mut out = [0u8; 64];
                let written = tagged::encode_numeric_response(
                    telemetry::TELEMETRY_COMPONENT,
                    telemetry::UDP6_METRICS_METHOD,
                    record.id?,
                    &result[..used],
                    &mut out,
                )?;
                Some(out[..written].to_vec())
            }),
        ));
        let dispatch: Dispatch = {
            let registry = registry.clone();
            Arc::new(move |request| registry.dispatch_now(request, CallContext::local()))
        };
        let handler = LogWatchHandler::new(Arc::new(&RING as &'static LogRing), Some(dispatch));
        let wire = request(&fields(|e| {
            e.map(3).unwrap();
            e.uint(6).unwrap();
            e.bool(true).unwrap();
            e.uint(7).unwrap();
            e.array(2).unwrap();
            e.text_value(b"telemetry.udp6").unwrap();
            e.text_value(b"telemetry.memory").unwrap();
            e.uint(8).unwrap();
            e.uint(200).unwrap();
        }));
        let record = tagged::decode(&wire).unwrap();
        let mut future = handler.open(Request {
            record,
            header: &wire,
            context: CallContext {
                timeout_ms: Some(2_000),
                ..CallContext::local()
            },
        });
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        let core::task::Poll::Ready(Some(Outcome::Respond(response))) =
            future.as_mut().poll(&mut cx)
        else {
            panic!("expected a streaming response");
        };
        let mut body = response.body.expect("a streamed body");
        let read_all = |body: &mut Box<dyn BodySource>| {
            let mut bytes = Vec::new();
            let mut chunk = [0u8; 7]; // small reads: items span calls
            loop {
                let (count, done) = body.read(&mut chunk);
                bytes.extend_from_slice(&chunk[..count]);
                if done || count == 0 {
                    return (bytes, done);
                }
            }
        };
        // The record already retained comes first.
        let (bytes, done) = read_all(&mut body);
        assert!(!done);
        let (first, _) = LogRecord::decode(&bytes).unwrap();
        assert_eq!((first.seq, first.text.as_str()), (1, "before"));

        // A record added later is sent; the snapshot is not due yet.
        NOW.store(1_050, Ordering::Relaxed);
        RING.push(LEVEL_WARN, "t", None, "later", None);
        let (bytes, _) = read_all(&mut body);
        let (second, used) = LogRecord::decode(&bytes).unwrap();
        assert_eq!(second.text, "later");
        assert_eq!(used, bytes.len());

        // Once the interval passes, the snapshot is the method's own response
        // (`telemetry.memory` is not registered, so it is reported once).
        NOW.store(1_250, Ordering::Relaxed);
        let (bytes, _) = read_all(&mut body);
        let mut offset = 0;
        let mut kinds = Vec::new();
        let mut udp6 = None;
        while offset < bytes.len() {
            let (record, used) = LogRecord::decode(&bytes[offset..]).unwrap();
            offset += used;
            if record.kind.as_deref() == Some("telemetry.udp6") {
                udp6 = record.fields.clone();
            }
            kinds.push((record.kind, record.text));
        }
        let metrics = udp6.expect("udp6 snapshot");
        let mut d = Decoder::new(&metrics);
        assert_eq!(d.head(), Some((5, 1)));
        assert_eq!((d.uint(), d.uint()), (Some(1), Some(42)));
        assert!(
            kinds
                .iter()
                .any(|(_, text)| text == "snapshot skipped: telemetry.memory")
        );

        // The stream ends at the request's timeout.
        NOW.store(3_100, Ordering::Relaxed);
        let (_, done) = read_all(&mut body);
        assert!(done);
    }

    #[test]
    fn a_stream_writer_accepts_borrowed_records_with_partial_retry() {
        use crate::stream::{BodyChunkProgress, BodyChunkWriteError, BodyChunkWriter};

        clock!(NOW, clock);
        static RING: LogRing = LogRing::new(8, clock);
        NOW.store(1_000, Ordering::Relaxed);
        RING.push(LEVEL_INFO, "wifi", None, "pool-backed", None);
        let handler = LogWatchHandler::new(Arc::new(&RING as &'static LogRing), None);
        let mut body = stream_body(
            &handler,
            &fields(|e| {
                e.map(1).unwrap();
                e.uint(6).unwrap();
                e.bool(true).unwrap();
            }),
        );

        struct Sink {
            bytes: Vec<u8>,
            max_accept: usize,
            retry_once: bool,
        }
        impl BodyChunkWriter for Sink {
            fn write(&mut self, bytes: &[u8]) -> Result<usize, BodyChunkWriteError> {
                if self.retry_once {
                    self.retry_once = false;
                    return Err(BodyChunkWriteError::Retryable);
                }
                let count = bytes.len().min(self.max_accept);
                self.bytes.extend_from_slice(&bytes[..count]);
                Ok(count)
            }
        }

        let mut sink = Sink {
            bytes: Vec::new(),
            max_accept: 5,
            retry_once: true,
        };
        assert_eq!(
            body.write_chunk(&mut sink),
            Some(BodyChunkProgress::Retryable)
        );
        for _ in 0..32 {
            match body.write_chunk(&mut sink) {
                Some(BodyChunkProgress::Accepted(_)) => {}
                Some(BodyChunkProgress::Waiting) => break,
                other => panic!("unexpected direct body progress: {other:?}"),
            }
        }
        let (record, used) = LogRecord::decode(&sink.bytes).expect("complete streamed record");
        assert_eq!(used, sink.bytes.len());
        assert_eq!((record.seq, record.text.as_str()), (1, "pool-backed"));
    }

    #[test]
    fn a_stream_writer_sends_a_contiguous_run_in_one_write() {
        use crate::stream::{BodyChunkProgress, BodyChunkWriteError, BodyChunkWriter};

        struct BatchedSource;
        impl LogSource for BatchedSource {
            fn now_ms(&self) -> u64 {
                1_000
            }

            fn read(&self, since: u64, visit: &mut dyn FnMut(&LogRecord) -> bool) -> u64 {
                for record in [
                    LogRecord {
                        seq: 1,
                        time_ms: 1_000,
                        level: LEVEL_INFO,
                        source: "t".into(),
                        kind: None,
                        text: "one".into(),
                        fields: None,
                    },
                    LogRecord {
                        seq: 2,
                        time_ms: 1_000,
                        level: LEVEL_INFO,
                        source: "t".into(),
                        kind: None,
                        text: "two".into(),
                        fields: None,
                    },
                ] {
                    if record.seq > since && !visit(&record) {
                        break;
                    }
                }
                0
            }

            fn read_encoded_runs(
                &self,
                since: u64,
                matches: &mut dyn FnMut(LogRecordView<'_>) -> bool,
                visit: &mut dyn FnMut(
                    u64,
                    &[u8],
                    Option<quic_lite::OwnedPacket<quic_lite::ErasedPacketBuffer>>,
                ) -> bool,
            ) {
                let records = [
                    LogRecord {
                        seq: 1,
                        time_ms: 1_000,
                        level: LEVEL_INFO,
                        source: "t".into(),
                        kind: None,
                        text: "one".into(),
                        fields: None,
                    },
                    LogRecord {
                        seq: 2,
                        time_ms: 1_000,
                        level: LEVEL_INFO,
                        source: "t".into(),
                        kind: None,
                        text: "two".into(),
                        fields: None,
                    },
                ];
                let mut run = Vec::new();
                let mut through = since;
                let mut run_through = since;
                for record in records {
                    if record.seq <= since {
                        continue;
                    }
                    let encoded = record.encode();
                    if matches(record.view()) {
                        if run.is_empty() {
                            run_through = through;
                        }
                        run.extend_from_slice(&encoded);
                    } else {
                        if !run.is_empty() && !visit(run_through, &run, None) {
                            return;
                        }
                        run.clear();
                        through = record.seq;
                    }
                    if matches(record.view()) {
                        through = record.seq;
                    }
                }
                if !run.is_empty() && !visit(run_through, &run, None) {
                    return;
                }
                let _ = visit(through, &[], None);
            }
        }

        struct Sink {
            bytes: Vec<u8>,
            calls: usize,
        }
        impl BodyChunkWriter for Sink {
            fn write(&mut self, bytes: &[u8]) -> Result<usize, BodyChunkWriteError> {
                self.calls += 1;
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
        }

        let handler = LogWatchHandler::new(Arc::new(BatchedSource), None);
        let mut body = stream_body(
            &handler,
            &fields(|e| {
                e.map(1).unwrap();
                e.uint(6).unwrap();
                e.bool(true).unwrap();
            }),
        );
        let mut sink = Sink {
            bytes: Vec::new(),
            calls: 0,
        };
        assert!(matches!(
            body.write_chunk(&mut sink),
            Some(BodyChunkProgress::Accepted(_))
        ));
        assert_eq!(sink.calls, 1, "contiguous records should share one write");
        let (first, used) = LogRecord::decode(&sink.bytes).unwrap();
        let (second, used_second) = LogRecord::decode(&sink.bytes[used..]).unwrap();
        assert_eq!((first.seq, second.seq), (1, 2));
        assert_eq!(used + used_second, sink.bytes.len());
    }

    #[test]
    fn a_new_streaming_watcher_finishes_the_previous_one() {
        clock!(NOW, clock);
        static RING: LogRing = LogRing::new(8, clock);
        NOW.store(1_000, Ordering::Relaxed);
        let handler = LogWatchHandler::new(Arc::new(&RING as &'static LogRing), None);
        let request_fields = fields(|e| {
            e.map(1).unwrap();
            e.uint(6).unwrap();
            e.bool(true).unwrap();
        });

        let mut previous = stream_body(&handler, &request_fields);
        let mut scratch = [0u8; 64];
        assert_eq!(previous.read(&mut scratch), (0, false));

        let mut replacement = stream_body(&handler, &request_fields);
        assert_eq!(previous.read(&mut scratch), (0, true));
        assert_eq!(replacement.read(&mut scratch), (0, false));
    }
}
