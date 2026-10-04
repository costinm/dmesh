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
use core::sync::atomic::{AtomicBool, Ordering};

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
    out: &mut [u8], seq: u64, time_ms: u64, level: u8,
    source: &str, kind: &str, fields: &[(u64, crate::cbor::FieldValue<'_>)],
) -> Option<usize> {
    let mut e = Encoder::new(out);
    e.map(7)?;
    e.uint(1)?; e.uint(seq)?;
    e.uint(2)?; e.uint(time_ms)?;
    e.uint(3)?; e.uint(u64::from(level))?;
    e.uint(4)?; e.text_value(source.as_bytes())?;
    e.uint(5)?; e.text_value(kind.as_bytes())?;
    e.uint(6)?; e.text_value(b"")?;
    e.uint(7)?; crate::cbor::encode_fields_into(&mut e, fields)?;
    Some(e.len())
}

#[cfg(test)]
#[test]
fn stack_event_matches_retained_record_and_rejects_short_storage() {
    use crate::cbor::FieldValue::{Unsigned, Bool, Signed};
    let fields = [(1, Unsigned(36)), (2, Bool(true)), (3, Signed(-67))];
    let mut out = [0; 512];
    let used = encode_event_into(&mut out, 7, 123, LEVEL_INFO, "wifi", "wifi.sta_disconnected", &fields).unwrap();
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
    assert!(encode_event_into(&mut out, 7, 123, LEVEL_INFO, "wifi", "event", &[(2, Bool(true)), (1, Bool(false))]).is_none());
}

#[cfg(test)]
#[test]
fn sta_candidate_event_fits_small_callback_storage() {
    use crate::cbor::FieldValue::Unsigned;
    // The richest current STA event has fourteen numeric fields. Exercise
    // maximum integer widths rather than only today's small counter values.
    let fields = core::array::from_fn::<_, 14, _>(|i| (i as u64 + 1, Unsigned(u64::MAX)));
    let mut out = [0; 256];
    let used = encode_event_into(&mut out, u64::MAX, u64::MAX, LEVEL_INFO,
        "wifi", "wifi.sta_candidate", &fields).unwrap();
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
        let used = (|| {
            let mut e = Encoder::new(&mut out);
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
        })()
        .unwrap_or(0);
        out.truncate(used);
        out
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
                fields = crate::cbor::encode_json_value(&serde_json::Value::Object(rest), &mut buffer)
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
}

impl LogWatchHandler {
    /// `dispatch` runs the snapshot requests; `None` serves records only.
    pub fn new(source: Arc<dyn LogSource>, dispatch: Option<Dispatch>) -> Self {
        Self { source, dispatch }
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
        let written =
            tagged::encode_numeric_response(COMPONENT_LOG, METHOD_WATCH, id, &result[..used], &mut out)?;
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
                    watch,
                    next_id: 1,
                };
                return Some(Outcome::Respond(Response::with_body(header, body)));
            }
            let limit = match watch.limit {
                0 => DEFAULT_POLL_LIMIT,
                value => value as usize,
            };
            let mut records = Vec::new();
            let dropped = self.source.read(watch.since_seq, &mut |record| {
                cursor = cursor.max(record.seq);
                if watch.matches(record) {
                    records.push(record.encode());
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
    next_id: u64,
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

    fn fill(&mut self, now: u64) {
        let watch = self.watch.clone();
        let mut cursor = self.cursor;
        let mut encoded = Vec::new();
        let mut taken = 0;
        self.source.read(self.cursor, &mut |record| {
            cursor = cursor.max(record.seq);
            if watch.matches(record) {
                encoded.extend_from_slice(&record.encode());
                taken += 1;
            }
            taken < RECORDS_PER_READ
        });
        self.cursor = cursor;
        self.pending.extend_from_slice(&encoded);
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
        if self.offset >= self.pending.len() {
            self.pending.clear();
            self.offset = 0;
            let now = self.source.now_ms();
            if now >= self.deadline_ms {
                return (0, true);
            }
            self.fill(now);
        }
        let count = (self.pending.len() - self.offset).min(out.len());
        out[..count].copy_from_slice(&self.pending[self.offset..self.offset + count]);
        self.offset += count;
        (count, false)
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
        assert_eq!(parse_esp_idf_line("W (9) nan: slow"), (LEVEL_WARN, "nan", "slow"));
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
        let entry = |level: &str, target: &str, message: &str, fields: Option<serde_json::Value>| {
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
            (seen[0].level, seen[0].source.as_str(), seen[0].kind.as_deref()),
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
        for (kind, fields) in [(None, None), (Some("nan.event".to_owned()), Some(vec![0xa1, 0x01, 0x01]))] {
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
                fields,
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
        assert_eq!(LogRecord::decode(&wire), Some((record, wire.len())));
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
        let (records, cursor, dropped) = poll(&handler, &fields(|e| {
            e.map(1).unwrap();
            e.uint(3).unwrap();
            e.uint(2).unwrap();
        }));
        assert_eq!(records.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1]);
        assert_eq!((cursor, dropped), (5, 0));

        // Source matches a dotted prefix, not a string prefix.
        let (records, ..) = poll(&handler, &fields(|e| {
            e.map(1).unwrap();
            e.uint(4).unwrap();
            e.text_value(b"bearer").unwrap();
        }));
        assert_eq!(records.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![3]);

        // Kind is a prefix; paging stops the cursor at the last record returned.
        let (records, cursor, _) = poll(&handler, &fields(|e| {
            e.map(2).unwrap();
            e.uint(2).unwrap();
            e.uint(1).unwrap();
            e.uint(5).unwrap();
            e.text_value(b"nan").unwrap();
        }));
        assert_eq!(records.len(), 1);
        assert_eq!(cursor, 5);
        let (records, cursor, _) = poll(&handler, &fields(|e| {
            e.map(1).unwrap();
            e.uint(2).unwrap();
            e.uint(2).unwrap();
        }));
        assert_eq!((records.len(), cursor), (2, 2));
        // Continuing from the cursor returns the rest.
        let (records, cursor, _) = poll(&handler, &fields(|e| {
            e.map(1).unwrap();
            e.uint(1).unwrap();
            e.uint(2).unwrap();
        }));
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
        let core::task::Poll::Ready(Some(Outcome::Respond(response))) = future.as_mut().poll(&mut cx)
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
        assert!(kinds
            .iter()
            .any(|(_, text)| text == "snapshot skipped: telemetry.memory"));

        // The stream ends at the request's timeout.
        NOW.store(3_100, Ordering::Relaxed);
        let (_, done) = read_all(&mut body);
        assert!(done);
    }
}
