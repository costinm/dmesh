//! Local trace provides configurable telemetry with an in-memory buffer.
//!
//! Events - trace, log, metrics, general purpose - are generated using rust tracing API.
//! Events are held in a circular buffer - and can be accessed by other components
//! in process.
//!
//! The events are also distributed via a Unix domain socket to one or more
//! consumers. A consumer conencts and subscribes to specific events, using pubsub pattern.
//!
//! This module provides:
//! - Dynamic trace level configuration.
//! - In-memory circular buffer for recent events
//! - event distribution using UDS.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::io::Write as _;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::broadcast;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry, reload};

/// Global handle for dynamically reloading the tracing filter, required to integrate.
///
/// Any binary using this module should set this handle after initializing
/// the tracing subscriber with a reload layer.
pub static TRACING_RELOAD_HANDLE: OnceLock<reload::Handle<EnvFilter, Registry>> = OnceLock::new();

/// Global reference to the process's primary `LogBuffer`.
pub static GLOBAL_LOG_BUFFER: OnceLock<LogBuffer> = OnceLock::new();

/// Current, reloadable producer filter.  Keeping the spelling lets HTTP/UDS
/// clients report the actual default instead of a placeholder.
static CURRENT_TRACE_LEVEL: OnceLock<RwLock<String>> = OnceLock::new();

/// Event telemetry is intentionally separate from severity. Producers attach
/// a generic `event_type` field and the core keeps bounded counters for every
/// type, but retains or streams an event only after its exact type is watched.
static EVENT_TRACE_CONTROL: OnceLock<RwLock<EventTraceControl>> = OnceLock::new();
const MAX_EVENT_TYPES: usize = 256;

#[derive(Default)]
struct EventTraceControl {
    counts: HashMap<String, u64>,
    selected: std::collections::HashSet<String>,
}

/// A bounded event-name counter exposed to observability UIs and future
/// metrics collectors. `selected` means the type is currently dispatched.
#[derive(Debug, Clone, Serialize)]
pub struct TraceEventStats {
    pub name: String,
    pub count: u64,
    pub selected: bool,
}

fn event_trace_control() -> &'static RwLock<EventTraceControl> {
    EVENT_TRACE_CONTROL.get_or_init(|| RwLock::new(EventTraceControl::default()))
}

fn watch_event_name(name: &str) -> bool {
    let mut control = event_trace_control().write();
    let selected = control.selected.contains(name);
    // Counters are bounded metrics, not trace records. Even packet-rate raw
    // sources are counted here, but below they reach neither history nor SSE
    // unless an operator watches the exact type.
    if let Some(count) = control.counts.get_mut(name) {
        *count = count.saturating_add(1);
    } else if control.counts.len() < MAX_EVENT_TYPES {
        control.counts.insert(name.to_string(), 1);
    } else {
        *control.counts.entry("event.other".to_string()).or_default() += 1;
    }
    selected
}

/// Count one named structured event and report whether tracing is enabled for
/// it. Producers on packet-rate paths must call this before constructing a
/// `tracing` event, so an unwatched event has no formatting, history, or
/// subscriber cost beyond this bounded counter update.
pub fn is_event_enabled(name: &str) -> bool {
    watch_event_name(name)
}

/// Return known event names and their lifetime process counters, most frequent
/// first. Counts stay bounded by the number of distinct names, not event rate.
pub fn trace_event_stats() -> Vec<TraceEventStats> {
    let control = event_trace_control().read();
    let mut stats: Vec<_> = control
        .counts
        .iter()
        .map(|(name, count)| TraceEventStats {
            name: name.clone(),
            count: *count,
            selected: control.selected.contains(name),
        })
        .chain(
            control
                .selected
                .iter()
                .filter(|name| !control.counts.contains_key(*name))
                .map(|name| TraceEventStats {
                    name: name.clone(),
                    count: 0,
                    selected: true,
                }),
        )
        .collect();
    stats.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.name.cmp(&right.name))
    });
    stats
}

/// Enable or disable dispatch for one exact generic event or fallback log type.
pub fn set_trace_event_info(name: &str, enabled: bool) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 192
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(
            "event name must be a bounded ASCII type such as wifi.raw.monitor or log.warn"
                .to_string(),
        );
    }
    let mut control = event_trace_control().write();
    if enabled {
        control.selected.insert(name.to_string());
    } else {
        control.selected.remove(name);
    }
    Ok(())
}

/// Retrieve the process-global `LogBuffer` if initialized.
pub fn global_buffer() -> Option<LogBuffer> {
    GLOBAL_LOG_BUFFER.get().cloned()
}

/// Maximum number of log entries to keep in the circular buffer (default)
const DEFAULT_BUFFER_SIZE: usize = 1000;

/// A single log entry in the buffer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Timestamp in RFC3339 format
    pub timestamp: String,
    /// Log level (trace, debug, info, warn, error)
    pub level: String,
    /// Target module/crate
    pub target: String,
    /// Log message
    pub message: String,
    /// Optional fields (key-value pairs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<serde_json::Value>,
}

impl LogEntry {
    pub fn to_text_record(&self) -> crate::message::TextRecord {
        let mut record = crate::message::TextRecord::new("trace")
            .field("ts", &self.timestamp)
            .field("level", &self.level)
            .field("target", &self.target)
            .field("message", &self.message);
        if let Some(fields) = self.fields.as_ref().and_then(serde_json::Value::as_object) {
            for (key, value) in fields {
                record
                    .fields
                    .insert(key.clone(), crate::message::text_value_from_json(value));
            }
        }
        record
    }

    pub fn to_text_line(&self) -> String {
        self.to_text_record().format()
    }
}

/// Request body for setting trace level, using EnvFilter patterns, i.e. comma separated
/// list of "(topic=level,)*default"
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TraceLevelRequest {
    /// The new trace level filter directive (e.g., "info", "debug", "trace", "ssh_mesh=debug,info")
    pub level: String,
}

/// Response for getting/setting trace level
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TraceLevelResponse {
    /// The current trace level filter directive
    pub level: String,
    /// Optional message indicating the result of the operation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Circular buffer for storing recent log entries
#[derive(Clone)]
pub struct LogBuffer {
    inner: Arc<RwLock<LogBufferInner>>,
}

struct LogBufferInner {
    buffer: VecDeque<LogEntry>,
    max_size: usize,
    tx: broadcast::Sender<LogEntry>,
}

impl LogBuffer {
    /// Create a new log buffer with the specified maximum size
    pub fn new(max_size: usize) -> Self {
        let (tx, _) = broadcast::channel(100);
        Self {
            inner: Arc::new(RwLock::new(LogBufferInner {
                buffer: VecDeque::with_capacity(max_size),
                max_size,
                tx,
            })),
        }
    }

    /// Add a log entry to the buffer
    pub fn push(&self, entry: LogEntry) {
        let mut inner = self.inner.write();

        // Add to circular buffer
        if inner.buffer.len() >= inner.max_size {
            inner.buffer.pop_front();
        }
        inner.buffer.push_back(entry.clone());

        // Broadcast to clients (ignore if no receivers)
        let _ = inner.tx.send(entry);
    }

    /// Get all current log entries
    pub fn get_all(&self) -> Vec<LogEntry> {
        let inner = self.inner.read();
        inner.buffer.iter().cloned().collect()
    }

    /// Subscribe to new log entries
    pub fn subscribe(&self) -> broadcast::Receiver<LogEntry> {
        let inner = self.inner.read();
        inner.tx.subscribe()
    }

    /// Broadcast a live-only event without retaining it in the circular
    /// history. This is used for high-rate radio packets whose consumers must
    /// explicitly subscribe while the monitor is active.
    pub fn push_unbuffered(&self, entry: LogEntry) {
        let inner = self.inner.read();
        let _ = inner.tx.send(entry);
    }

    /// Get the current buffer size
    pub fn len(&self) -> usize {
        let inner = self.inner.read();
        inner.buffer.len()
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Custom tracing layer that captures log events and stores them in the buffer
pub struct LogBufferLayer {
    buffer: LogBuffer,
}

impl Default for LogBufferLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl LogBufferLayer {
    pub fn new() -> Self {
        let buffer = create_log_buffer();

        Self { buffer }
    }

    /// Return a handle to the in-memory log buffer used by this layer.
    pub fn buffer(&self) -> LogBuffer {
        self.buffer.clone()
    }
}

impl<S> Layer<S> for LogBufferLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();

        // Create a visitor to extract the message and fields
        let mut visitor = LogVisitor::default();
        event.record(&mut visitor);

        let event_type = visitor
            .fields
            .get("event_type")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let prechecked = visitor
            .fields
            .get("trace_prechecked")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let entry = LogEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            level: metadata.level().to_string().to_lowercase(),
            target: metadata.target().to_string(),
            message: visitor.message,
            fields: if visitor.fields.is_empty() {
                None
            } else {
                // TODO: maybe delay json conversion until it is needed.
                Some(serde_json::to_value(&visitor.fields).unwrap_or(serde_json::Value::Null))
            },
        };

        // Event type, not severity, is the subscription key. Conventional
        // logs lack `event_type`, so warnings/errors use a small fallback type
        // while retaining their original target and level for context.
        let event_name = if let Some(event_type) = event_type.as_deref() {
            event_type
        } else {
            match metadata.level() {
                &tracing::Level::WARN => "log.warn",
                &tracing::Level::ERROR => "log.error",
                _ => return,
            }
        };
        if !prechecked && !watch_event_name(event_name) {
            return;
        }

        self.buffer.push(entry);
    }
}

/// Visitor to extract message and fields from tracing events
#[derive(Default)]
struct LogVisitor {
    message: String,
    fields: std::collections::HashMap<String, serde_json::Value>,
}

impl tracing::field::Visit for LogVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value);
            // Remove quotes if present
            if self.message.starts_with('"') && self.message.ends_with('"') {
                self.message = self.message[1..self.message.len() - 1].to_string();
            }
        } else {
            self.fields.insert(
                field.name().to_string(),
                serde_json::Value::String(format!("{:?}", value)),
            );
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.fields.insert(
                field.name().to_string(),
                serde_json::Value::String(value.to_string()),
            );
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), serde_json::Value::Bool(value));
    }
}

/// Get the current trace level (returns a placeholder since EnvFilter
/// doesn't easily expose its current state as a string).
pub fn get_trace_level() -> TraceLevelResponse {
    TraceLevelResponse {
        level: CURRENT_TRACE_LEVEL
            .get_or_init(|| RwLock::new(default_trace_filter()))
            .read()
            .clone(),
        message: Some("Event-name info capture is controlled separately".to_string()),
    }
}

/// Set the trace level dynamically using the global reload handle.
///
/// Returns `Ok(response)` on success, `Err(response)` with error details on failure.
pub fn set_trace_level(req: &TraceLevelRequest) -> Result<TraceLevelResponse, TraceLevelResponse> {
    let requested = req.level.trim();
    // Event routing is independent of severity. Keep info admitted so a
    // producer's generic `event_type` field can be counted, then let
    // LogBufferLayer decide whether that type is watched.
    let level = if requested.is_empty() {
        default_trace_filter()
    } else {
        format!("{requested},info")
    };
    // Parse the new filter
    let new_filter = match level.parse::<EnvFilter>() {
        Ok(filter) => filter,
        Err(e) => {
            return Err(TraceLevelResponse {
                level,
                message: Some(format!("Invalid filter format: {}", e)),
            });
        }
    };

    // Get the reload handle and update the filter
    match TRACING_RELOAD_HANDLE.get() {
        Some(handle) => match handle.reload(new_filter) {
            Ok(()) => {
                *CURRENT_TRACE_LEVEL
                    .get_or_init(|| RwLock::new(default_trace_filter()))
                    .write() = level.clone();
                tracing::info!("Tracing level updated to: {}", level);
                Ok(TraceLevelResponse {
                    level,
                    message: Some("Trace level updated successfully".to_string()),
                })
            }
            Err(e) => {
                tracing::error!("Failed to reload tracing filter: {:?}", e);
                Err(TraceLevelResponse {
                    level,
                    message: Some(format!("Failed to reload filter: {:?}", e)),
                })
            }
        },
        None => {
            tracing::error!("Tracing reload handle not initialized");
            Err(TraceLevelResponse {
                level,
                message: Some("Tracing reload handle not initialized".to_string()),
            })
        }
    }
}

/// JSON-based tracing configuration
///
/// This provides a structured alternative to RUST_LOG environment variable.
///
/// Example:
/// ```json
/// {
///   "global_level": "info",
///   "modules": {
///     "ssh_mesh::handlers": "debug",
///     "russh": "trace"
///   },
///   "targets": ["ssh_mesh", "russh"],
///   "min_level": "debug"
/// }
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TraceConfig {
    /// Global default trace level
    #[serde(default = "default_global_level")]
    pub global_level: String,

    /// Per-module trace levels
    #[serde(default)]
    pub modules: HashMap<String, String>,

    /// List of target prefixes to include (if empty, include all)
    #[serde(default)]
    pub targets: Vec<String>,

    /// Minimum level to capture (acts as a floor)
    #[serde(default)]
    pub min_level: Option<String>,

    /// Maximum level to capture (acts as a ceiling)
    #[serde(default)]
    pub max_level: Option<String>,

    /// Field filters - only include events with these fields
    #[serde(default)]
    pub fields: HashMap<String, String>,

    /// Control-only mode: when true, the producer applies `global_level`/
    /// `modules` (raising its trace level) and replies with a single JSON ack
    /// line, then closes the connection without streaming. Used by collectors
    /// to change a producer's level out-of-band.
    #[serde(default)]
    pub control: Option<bool>,
}

fn default_global_level() -> String {
    "warn".to_string()
}

fn default_trace_filter() -> String {
    "info".to_string()
}

impl TraceConfig {
    /// Convert to EnvFilter compatible string
    pub fn to_filter_string(&self) -> String {
        let mut parts = Vec::new();

        // Add module-specific levels
        for (module, level) in &self.modules {
            parts.push(format!("{}={}", module, level));
        }

        // Add global level
        parts.push(self.global_level.clone());

        parts.join(",")
    }

    /// Check if a log entry matches this configuration
    pub fn matches(&self, entry: &LogEntry) -> bool {
        // Check target filter
        if !self.targets.is_empty() {
            let matches_target = self.targets.iter().any(|t| entry.target.starts_with(t));
            if !matches_target {
                return false;
            }
        }

        // Check level bounds
        if let Some(ref min_level) = self.min_level {
            if !level_gte(&entry.level, min_level) {
                return false;
            }
        }

        if let Some(ref max_level) = self.max_level {
            if !level_lte(&entry.level, max_level) {
                return false;
            }
        }

        // Check field filters
        if !self.fields.is_empty() {
            if let Some(ref entry_fields) = entry.fields {
                for (key, value) in &self.fields {
                    if let Some(field_value) = entry_fields.get(key) {
                        let field_str = field_value.as_str().unwrap_or("");
                        if field_str != value {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
            } else {
                return false;
            }
        }

        true
    }
}

/// Compare log levels (greater than or equal)
fn level_gte(level: &str, threshold: &str) -> bool {
    let levels = ["trace", "debug", "info", "warn", "error"];
    let level_idx = levels.iter().position(|&l| l == level).unwrap_or(2);
    let threshold_idx = levels.iter().position(|&l| l == threshold).unwrap_or(2);
    level_idx >= threshold_idx
}

/// Compare log levels (less than or equal)
fn level_lte(level: &str, threshold: &str) -> bool {
    let levels = ["trace", "debug", "info", "warn", "error"];
    let level_idx = levels.iter().position(|&l| l == level).unwrap_or(2);
    let threshold_idx = levels.iter().position(|&l| l == threshold).unwrap_or(2);
    level_idx <= threshold_idx
}

/// Start listening on a Unix Domain Socket for trace connections.
///
/// Each connection:
/// 1. Optionally raises the producer's trace level if the config carries
///    `global_level`/`modules` (see [`set_trace_level`]).
/// 2. Sends all buffered entries that match the config.
/// 3. Streams new entries that match the config.
///
/// The parent directory is created if missing and the socket is given mode
/// `0o660` so that local collectors can connect.
///
/// Example usage:
/// ```bash
/// echo '{"global_level":"debug","modules":{"ssh_mesh":"trace"}}' | nc -U /run/mesh/mesh-init/mesh.sock
/// ```
pub async fn start_uds_listener(
    socket_path: impl AsRef<Path>,
    buffer: LogBuffer,
) -> std::io::Result<()> {
    let socket_path = socket_path.as_ref();

    // Ensure the parent directory exists (e.g. /run/mesh/mesh-init).
    if let Some(parent) = socket_path.parent()
        && !parent.as_os_str().is_empty()
    {
        let _ = std::fs::create_dir_all(parent);
    }

    // Remove existing socket if it exists
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;

    // Restrict to same-user/same-group, matching mesh-tun's trace socket.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(socket_path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o660);
            let _ = std::fs::set_permissions(socket_path, perms);
        }
    }

    tracing::info!("UDS trace listener started at: {:?}", socket_path);

    start_uds_listener_from_listener(listener, buffer).await
}

/// Start streaming traces from an already-bound UnixListener
pub async fn start_uds_listener_from_listener(
    listener: UnixListener,
    buffer: LogBuffer,
) -> std::io::Result<()> {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let buffer = buffer.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_uds_connection(stream, buffer).await {
                        tracing::warn!("UDS trace connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                tracing::error!("UDS accept error: {}", e);
            }
        }
    }
}

/// Handle a single UDS connection
async fn handle_uds_connection(
    stream: tokio::net::UnixStream,
    buffer: LogBuffer,
) -> std::io::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    // Read first line as JSON config
    let mut config_line = String::new();
    reader.read_line(&mut config_line).await?;

    let config: TraceConfig = match serde_json::from_str(config_line.trim()) {
        Ok(cfg) => {
            tracing::info!("UDS trace connection with config: {:?}", cfg);
            cfg
        }
        Err(e) => {
            let error_msg = format!("{{\"error\":\"Invalid config JSON: {}\"}}\n", e);
            writer.write_all(error_msg.as_bytes()).await?;
            return Ok(());
        }
    };

    // If the collector requests a level, apply it to this process so the
    // buffer/subscription actually receives those events. The level persists
    // via the global reload handle after the connection closes. The
    // `config.matches()` filter below still governs *what is sent* on this
    // connection, independent of the producer's level.
    let mut applied_level: Option<String> = None;
    let filter_str = config.to_filter_string();
    if !filter_str.is_empty() && !config.global_level.is_empty() {
        let req = TraceLevelRequest {
            level: filter_str.clone(),
        };
        match set_trace_level(&req) {
            Ok(resp) => {
                tracing::info!("UDS collector raised trace level: {}", resp.level);
                applied_level = Some(resp.level);
            }
            Err(resp) => {
                tracing::warn!(
                    "UDS collector requested level '{}' but it was rejected: {:?}",
                    filter_str,
                    resp.message
                );
            }
        }
    }

    // Control-only mode: ack and close without streaming. Used by collectors
    // that only want to change the level (or probe liveness).
    if config.control.unwrap_or(false) {
        let ack = serde_json::json!({
            "ok": true,
            "level": applied_level,
        })
        .to_string();
        let _ = writer.write_all(format!("{}\n", ack).as_bytes()).await;
        return Ok(());
    }

    // Send all existing buffered entries that match the config
    let existing_logs = buffer.get_all();
    tracing::debug!(
        "Sending {} buffered entries to UDS client",
        existing_logs.len()
    );

    for entry in existing_logs {
        if config.matches(&entry) {
            if let Ok(json) = serde_json::to_string(&entry) {
                let line = format!("{}\n", json);
                if writer.write_all(line.as_bytes()).await.is_err() {
                    return Ok(());
                }
            }
        }
    }

    // Subscribe to new entries
    let mut rx = buffer.subscribe();

    // Stream new entries that match the config
    loop {
        match rx.recv().await {
            Ok(entry) => {
                if config.matches(&entry) {
                    if let Ok(json) = serde_json::to_string(&entry) {
                        let line = format!("{}\n", json);
                        if writer.write_all(line.as_bytes()).await.is_err() {
                            tracing::debug!("UDS trace client disconnected");
                            break;
                        }
                    }
                }
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                tracing::warn!("UDS trace client lagged, skipped {} entries", skipped);
                continue;
            }
            Err(broadcast::error::RecvError::Closed) => {
                tracing::info!("UDS trace broadcast channel closed");
                break;
            }
        }
    }

    Ok(())
}

/// Create a log buffer with default size
pub fn create_log_buffer() -> LogBuffer {
    LogBuffer::new(DEFAULT_BUFFER_SIZE)
}

/// Create a log buffer with custom size
pub fn create_log_buffer_with_size(size: usize) -> LogBuffer {
    LogBuffer::new(size)
}

/// Resolve the shared directory where trace sockets live.
///
/// Honors the `TRACE_SOCKET_DIR` env var; otherwise defaults to the mesh
/// app runtime directory.
pub fn default_trace_socket_dir() -> Option<std::path::PathBuf> {
    if let Some(dir) = std::env::var_os("TRACE_SOCKET_DIR")
        && !dir.is_empty()
    {
        return Some(std::path::PathBuf::from(dir));
    }
    Some(crate::paths::AppPaths::for_app("mesh").run_dir("mesh"))
}

/// Resolve the default trace socket path for an app: `<dir>/<app>.sock`,
/// where `<dir>` comes from [`default_trace_socket_dir`].
///
/// Returns `None` when no shared directory is configured; callers should
/// treat that as "no trace socket; skip the bind".
pub fn default_trace_socket_path(app_name: &str) -> Option<std::path::PathBuf> {
    Some(default_trace_socket_dir()?.join(format!("{}.sock", app_name)))
}

/// Initialize tracing with a reloadable `EnvFilter` and an in-memory
/// `LogBuffer`. Replaces the per-app `init_telemetry` boilerplate; apps call
/// this and then (optionally) [`serve`] to expose the buffer over UDS.
///
/// `app` is the producer's short name (e.g. `"ssh-mesh"`, `"mesh-tun"`).
/// It is used as the directory-based log file's basename unless mesh-init
/// supplies the supervised service identity in `MESH_SERVICE_NAME`.
///
/// The initial filter admits info so generic `event_type` records can be
/// counted. `LogBufferLayer` still retains and streams only watched types; the
/// output sinks below keep ordinary info records out of operational logs. Set
/// `MESH_TRACE_LEVEL` to add diagnostic directives when needed.
///
/// A non-blocking JSON `fmt`
/// layer is also installed that writes every event (subject to the same
/// `EnvFilter`) to a file. `MESH_LOG_FILE` is an exact file path; otherwise,
/// logs go to `<service>.log` in `MESH_LOG_DIR`, or in `./logs` beneath the
/// process working directory when that variable is unset. Regular files
/// rotate by size: when the active file reaches `MESH_LOG_FILE_MAX_BYTES`
/// it is renamed to `<file>.1`, existing backups are shifted, and the
/// oldest backups are removed so rotated files stay within
/// `MESH_LOG_MAX_TOTAL_BYTES`. Special files such as `/dev/stderr` never
/// rotate. Parent directories are created if missing. The returned
/// `WorkerGuard` must be kept alive for the lifetime of the process
/// (dropping it stops the background writer thread and flushes pending
/// events); bind it to a named variable in `main` to be safe.
///
/// This calls `tracing_subscriber`'s global `.init()`, so it can only be
/// called once per process.
pub fn init(
    app: &str,
) -> (
    LogBuffer,
    Option<tracing_appender::non_blocking::WorkerGuard>,
) {
    let filter_text = std::env::var("MESH_TRACE_LEVEL").unwrap_or_else(|_| default_trace_filter());
    let filter = filter_text
        .parse::<EnvFilter>()
        .unwrap_or_else(|_| EnvFilter::new(default_trace_filter()));
    let (filter, reload_handle) = reload::Layer::new(filter);
    let buffer_layer = LogBufferLayer::new();
    let log_buffer = buffer_layer.buffer();

    let stderr_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(false)
        .with_span_list(false);

    let guard = match build_file_writer(app) {
        Some((non_blocking, guard)) => {
            // Radio packet events are intentionally retained in the bounded
            // in-memory/socket trace stream, but must not be copied into the
            // operational file.  With a file sink configured, do not also
            // inherit the supervisor's stderr: that path is commonly a
            // shared /tmp/log.json and defeats per-app rotation.
            Registry::default()
                .with(filter)
                .with(buffer_layer)
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_current_span(false)
                        .with_span_list(false)
                        .with_writer(non_blocking)
                        .with_filter(filter_fn(|metadata| {
                            matches!(
                                metadata.level(),
                                &tracing::Level::WARN | &tracing::Level::ERROR
                            )
                        })),
                )
                .init();
            Some(guard)
        }
        None => {
            Registry::default()
                .with(filter)
                .with(buffer_layer)
                // Info is admitted only so LogBufferLayer can count generic
                // event types. Never mirror it to stderr during on-demand
                // tracing.
                .with(stderr_layer.with_filter(filter_fn(|metadata| {
                    matches!(
                        metadata.level(),
                        &tracing::Level::WARN | &tracing::Level::ERROR
                    )
                })))
                .init();
            None
        }
    };

    let _ = TRACING_RELOAD_HANDLE.set(reload_handle);
    let _ = CURRENT_TRACE_LEVEL.set(RwLock::new(filter_text));
    let _ = GLOBAL_LOG_BUFFER.set(log_buffer.clone());
    (log_buffer, guard)
}

/// Build the optional non-blocking JSON file writer.
///
/// Returns `Some((writer, guard))` when the log path can be created.
fn build_file_writer(
    app: &str,
) -> Option<(
    tracing_appender::non_blocking::NonBlocking,
    tracing_appender::non_blocking::WorkerGuard,
)> {
    let log_path = if let Some(path) = std::env::var_os("MESH_LOG_FILE").filter(|s| !s.is_empty()) {
        std::path::PathBuf::from(path)
    } else {
        let dir = std::env::var_os("MESH_LOG_DIR")
            .filter(|s| !s.is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::env::current_dir()
                    .unwrap_or_else(|_| std::path::PathBuf::from("."))
                    .join("logs")
            });
        let service = std::env::var("MESH_SERVICE_NAME").unwrap_or_else(|_| app.to_string());
        dir.join(format!("{service}.log"))
    };

    let parent: std::path::PathBuf = log_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf();
    if let Err(e) = std::fs::create_dir_all(&parent) {
        tracing::warn!(
            path = ?parent,
            error = %e,
            "log directory could not be created; file logging disabled"
        );
        return None;
    }

    let limits = LogRotationLimits::from_env();
    let file_name = log_path.file_name()?.to_string_lossy().to_string();
    prune_log_files(&parent, &file_name, limits.max_total_bytes);
    // Regular files rotate by size so a single noisy event (or one day of
    // steady traffic) cannot grow without bound. Special files such as
    // /dev/stderr keep working through `never`.
    let writer: Box<dyn std::io::Write + Send> = if is_special_log_path(&log_path) {
        Box::new(tracing_appender::rolling::never(
            &parent,
            file_name.as_str(),
        ))
    } else {
        match SizeRotatingWriter::open(log_path, limits) {
            Ok(writer) => Box::new(writer),
            Err(e) => {
                tracing::warn!(
                    path = ?parent.join(file_name.as_str()),
                    error = %e,
                    "log file could not be opened; file logging disabled"
                );
                return None;
            }
        }
    };
    Some(tracing_appender::non_blocking(writer))
}

/// Size limits for log file rotation, read from the environment.
struct LogRotationLimits {
    max_file_bytes: u64,
    max_total_bytes: u64,
}

impl LogRotationLimits {
    fn from_env() -> Self {
        Self {
            max_file_bytes: parse_size_env("MESH_LOG_FILE_MAX_BYTES", 8 * 1024 * 1024),
            max_total_bytes: parse_size_env("MESH_LOG_MAX_TOTAL_BYTES", 64 * 1024 * 1024),
        }
    }
}

/// Parse a byte-count environment variable with optional k/m/g suffixes.
/// Invalid or missing values fall back to `default`.
fn parse_size_env(key: &str, default: u64) -> u64 {
    let Ok(raw) = std::env::var(key) else {
        return default;
    };
    let raw = raw.trim().to_ascii_lowercase();
    let (num, multiplier): (&str, u64) = if raw.ends_with("kib") {
        (raw.strip_suffix("kib").unwrap(), 1024)
    } else if raw.ends_with("mib") {
        (raw.strip_suffix("mib").unwrap(), 1024 * 1024)
    } else if raw.ends_with("gib") {
        (raw.strip_suffix("gib").unwrap(), 1024 * 1024 * 1024)
    } else if raw.ends_with('k') {
        (raw.strip_suffix('k').unwrap(), 1024)
    } else if raw.ends_with('m') {
        (raw.strip_suffix('m').unwrap(), 1024 * 1024)
    } else if raw.ends_with('g') {
        (raw.strip_suffix('g').unwrap(), 1024 * 1024 * 1024)
    } else {
        (raw.as_str(), 1)
    };
    num.trim()
        .parse::<u64>()
        .map(|value| value.saturating_mul(multiplier))
        .unwrap_or(default)
}

/// True for paths that must be opened exactly as-is without rotation,
/// such as `/dev/stderr`, `/dev/null`, or `/dev/console`.
fn is_special_log_path(path: &std::path::Path) -> bool {
    if path.parent() == Some(std::path::Path::new("/dev")) {
        return true;
    }
    match path.metadata() {
        Ok(metadata) => !metadata.file_type().is_file(),
        Err(_) => false,
    }
}

/// File writer that rotates by size.
///
/// The active file stays under `limits.max_file_bytes`. When it is
/// reached, the active file is renamed to `<file>.1` and existing backups
/// are shifted (`.1` to `.2`, and so on). The oldest backups are removed
/// first so the combined size of the active file and all backups fits in
/// `limits.max_total_bytes` at each rotation. Rotation runs on the
/// non-blocking writer's background thread, so logging never stalls the
/// caller.
struct SizeRotatingWriter {
    path: std::path::PathBuf,
    limits: LogRotationLimits,
    file: Option<std::fs::File>,
    size: u64,
}

impl SizeRotatingWriter {
    fn open(path: std::path::PathBuf, limits: LogRotationLimits) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let size = file.metadata()?.len();
        let mut writer = Self {
            path,
            limits,
            file: Some(file),
            size,
        };
        if writer.limits.max_file_bytes > 0 && writer.size >= writer.limits.max_file_bytes {
            // Already at or over the cap from a previous run; start fresh.
            writer.rotate()?;
        }
        Ok(writer)
    }

    fn backup_path(&self, index: usize) -> std::path::PathBuf {
        let name = self.path.file_name().unwrap_or_default().to_string_lossy();
        self.path.with_file_name(format!("{name}.{index}"))
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush()?;
        }
        let mut oldest = 0usize;
        let mut total = 0u64;
        for index in 1.. {
            let backup = self.backup_path(index);
            match backup.metadata() {
                Ok(metadata) => {
                    total += metadata.len();
                    oldest = index;
                }
                Err(_) => break,
            }
        }
        // The active file becomes the newest backup, so bound the combined
        // size of all log files at each rotation.
        while oldest > 0 && total + self.size > self.limits.max_total_bytes {
            let path = self.backup_path(oldest);
            let size = path.metadata().map(|metadata| metadata.len()).unwrap_or(0);
            if std::fs::remove_file(&path).is_ok() {
                total = total.saturating_sub(size);
            }
            oldest -= 1;
        }
        for index in (1..=oldest).rev() {
            let _ = std::fs::rename(self.backup_path(index), self.backup_path(index + 1));
        }
        if self.path.exists() {
            std::fs::rename(&self.path, self.backup_path(1))?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.file = Some(file);
        self.size = 0;
        Ok(())
    }
}

impl std::io::Write for SizeRotatingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let Some(file) = self.file.as_mut() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "log file is closed",
            ));
        };
        file.write_all(buf)?;
        self.size += buf.len() as u64;
        if self.limits.max_file_bytes > 0 && self.size >= self.limits.max_file_bytes {
            self.rotate()?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.file.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

/// Keep historical per-app logs bounded. The active file is retained;
/// oldest rotated files are removed first. Failure is deliberately best
/// effort because logging must never prevent the service from starting.
fn prune_log_files(dir: &std::path::Path, basename: &str, max_bytes: u64) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_string_lossy();
            if name == basename || !name.starts_with(&format!("{basename}.")) {
                return None;
            }
            let metadata = entry.metadata().ok()?;
            Some((path, metadata.len(), metadata.modified().ok()))
        })
        .collect::<Vec<_>>();
    let mut total = files.iter().map(|(_, size, _)| *size).sum::<u64>();
    if total <= max_bytes {
        return;
    }
    files.sort_by_key(|(_, _, modified)| *modified);
    for (path, size, _) in files {
        if total <= max_bytes {
            break;
        }
        if std::fs::remove_file(path).is_ok() {
            total = total.saturating_sub(size);
        }
    }
}

/// Bind the app's UDS trace socket and serve it in a background task.
///
/// The socket path comes from `default_trace_socket_path`, which is governed
/// solely by `TRACE_SOCKET_DIR` (the shared directory) and `HOME`. If
/// `TRACE_SOCKET_DIR` is unset, no socket is bound and the function is a
/// no-op — the producer keeps its in-memory buffer for in-process use but
/// does not advertise itself to collectors. This makes the trace surface
/// opt-in: set `TRACE_SOCKET_DIR` to enable it.
///
/// Apps typically invoke this with:
///
/// ```ignore
/// mesh::local_trace::serve("ssh-mesh", mesh::local_trace::init());
/// ```
pub fn serve(app_name: &str, buffer: LogBuffer) {
    let Some(socket) = default_trace_socket_path(app_name) else {
        tracing::debug!(
            app = %app_name,
            "TRACE_SOCKET_DIR not set; not binding UDS trace listener"
        );
        return;
    };

    let app_name = app_name.to_string();
    tracing::info!(app = %app_name, path = ?socket, "Binding UDS trace listener");

    tokio::spawn(async move {
        if let Err(e) = start_uds_listener(&socket, buffer).await {
            tracing::error!(app = %app_name, error = %e, "UDS trace listener stopped");
        }
    });
}

/// Stream log entries from `buffer` to `writer`.
///
/// Sends existing buffered entries matching optional filter criteria,
/// then subscribes and streams new entries until client disconnects or channel closes.
pub async fn stream_logs<W>(
    buffer: &LogBuffer,
    format: &crate::jsonl::ProtocolFormat,
    writer: &mut W,
    source_name: &str,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWriteExt + Unpin,
{
    let existing = buffer.get_all();
    for entry in existing {
        let line = format_log_entry(&entry, source_name, format);
        writer.write_all(line.as_bytes()).await?;
        writer.write_all(b"\n").await?;
    }
    let mut rx = buffer.subscribe();
    loop {
        match rx.recv().await {
            Ok(entry) => {
                let line = format_log_entry(&entry, source_name, format);
                if writer.write_all(line.as_bytes()).await.is_err()
                    || writer.write_all(b"\n").await.is_err()
                {
                    break;
                }
                let _ = writer.flush().await;
            }
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
    Ok(())
}

/// Stream buffered and future trace entries matching an explicit subscription
/// configuration. This is the pub/sub primitive used by component control
/// sockets; unlike a one-shot history request it remains connected until the
/// subscriber closes the socket.
pub async fn stream_logs_filtered<W>(
    buffer: &LogBuffer,
    format: &crate::jsonl::ProtocolFormat,
    writer: &mut W,
    source_name: &str,
    config: &TraceConfig,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWriteExt + Unpin,
{
    for entry in buffer.get_all() {
        if config.matches(&entry) {
            let line = format_log_entry(&entry, source_name, format);
            writer.write_all(line.as_bytes()).await?;
            writer.write_all(b"\n").await?;
        }
    }
    let mut rx = buffer.subscribe();
    loop {
        match rx.recv().await {
            Ok(entry) if config.matches(&entry) => {
                let line = format_log_entry(&entry, source_name, format);
                if writer.write_all(line.as_bytes()).await.is_err()
                    || writer.write_all(b"\n").await.is_err()
                {
                    break;
                }
                writer.flush().await?;
            }
            Ok(_) => {}
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
    Ok(())
}

fn format_log_entry(
    entry: &LogEntry,
    source_name: &str,
    format: &crate::jsonl::ProtocolFormat,
) -> String {
    let mut val = serde_json::to_value(entry).unwrap_or_default();
    if let serde_json::Value::Object(ref mut map) = val {
        map.insert(
            "source".to_string(),
            serde_json::Value::String(source_name.to_string()),
        );
        if let Some(serde_json::Value::Object(fields)) = map.get_mut("fields") {
            fields.remove("event_type");
        }
    }
    match format {
        crate::jsonl::ProtocolFormat::JsonRpc { .. } => serde_json::json!({
            "jsonrpc": "2.0",
            "method": "trace_entry",
            "params": val
        })
        .to_string(),
        _ => val.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_watch_is_exact_and_counted() {
        const EVENT: &str = "test.on_demand";
        set_trace_event_info(EVENT, false).unwrap();
        assert!(!watch_event_name(EVENT));
        set_trace_event_info(EVENT, true).unwrap();
        assert!(watch_event_name(EVENT));
        let stat = trace_event_stats()
            .into_iter()
            .find(|stat| stat.name == EVENT)
            .expect("event stat");
        assert!(stat.selected);
        assert!(stat.count >= 2);
        set_trace_event_info(EVENT, false).unwrap();
    }

    #[test]
    fn unwatched_raw_event_is_counted_without_trace_dispatch() {
        const EVENT: &str = "wifi.raw.test_counter_only";
        set_trace_event_info(EVENT, false).unwrap();
        assert!(!watch_event_name(EVENT));
        let stat = trace_event_stats()
            .into_iter()
            .find(|stat| stat.name == EVENT)
            .expect("raw event stat");
        assert_eq!(stat.count, 1);
        assert!(!stat.selected);
    }

    /// `init` installs a global subscriber; only one test in this module can
    /// call it. Verifies that `MESH_LOG_DIR=<dir> init("smoke-test")` writes a
    /// JSON line per emitted event to `<dir>/smoke-test.log`. Dropping the
    /// returned `WorkerGuard` flushes and shuts down the background writer.
    #[test]
    fn mesh_log_dir_writes_json_log_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        // SAFETY: this test owns `MESH_LOG_DIR` and `MESH_TRACE_LEVEL` for its
        // duration; the global subscriber is one-shot so concurrent
        // `init` calls would panic regardless.
        unsafe {
            std::env::set_var("MESH_LOG_DIR", dir.path());
            std::env::set_var("MESH_TRACE_LEVEL", "info");
        }

        set_trace_event_info("log.warn", true).unwrap();
        let (buffer, guard) = init("smoke-test");
        tracing::warn!(answer = 42, "smoke-test event");
        assert_eq!(buffer.get_all().len(), 1, "buffer should capture the event");

        // Drop the guard to flush and shut down the background writer.
        drop(guard);

        let contents = std::fs::read_dir(dir.path())
            .expect("read log directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("smoke-test.log")
            })
            .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
            .collect::<String>();
        assert!(!contents.is_empty(), "log file is empty: {:?}", contents);
        assert!(
            contents.contains("smoke-test event"),
            "log file: {}",
            contents
        );
        assert!(
            contents.contains("\"answer\":42") || contents.contains("\"answer\": 42"),
            "log file missing structured field: {}",
            contents
        );
        set_trace_event_info("log.warn", false).unwrap();
        assert!(
            contents.contains("\"level\":\"WARN\""),
            "log file missing level: {}",
            contents
        );
    }

    #[test]
    fn size_rotating_writer_rotates_and_binds_total_size() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rotate.log");
        let limits = LogRotationLimits {
            max_file_bytes: 64,
            max_total_bytes: 128,
        };
        let mut writer = SizeRotatingWriter::open(path.clone(), limits).expect("open");
        let chunk = vec![b'x'; 64];
        writer.write_all(&chunk).expect("write");
        // The first write reached the cap: the active file is fresh and the
        // previous content moved to `.1`.
        assert_eq!(file_len(&path), 0);
        assert_eq!(file_len(&dir.path().join("rotate.log.1")), 64);
        writer.write_all(&chunk).expect("write");
        assert_eq!(file_len(&dir.path().join("rotate.log.2")), 64);
        writer.write_all(&chunk).expect("write");
        // The third rotation must drop the oldest backup: 128 of backups plus
        // 64 of active exceeds the 128 cap.
        assert!(!dir.path().join("rotate.log.3").exists());
        let total: u64 = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_file())
            .map(|entry| file_len(&entry.path()))
            .sum();
        assert!(total <= 128, "total {total} exceeds the cap");
        drop(writer);
    }

    #[test]
    fn size_rotating_writer_rotates_over_sized_existing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rotate.log");
        std::fs::write(&path, vec![b'z'; 128]).expect("seed");
        let limits = LogRotationLimits {
            max_file_bytes: 64,
            max_total_bytes: 128,
        };
        let writer = SizeRotatingWriter::open(path.clone(), limits).expect("open");
        assert_eq!(file_len(&path), 0);
        assert_eq!(file_len(&dir.path().join("rotate.log.1")), 128);
        drop(writer);
    }

    #[test]
    fn parse_size_env_handles_suffixes_and_falls_back() {
        // SAFETY: this test owns `MESH_LOG_TEST_SIZE` for its duration and no
        // other thread reads it.
        unsafe {
            std::env::set_var("MESH_LOG_TEST_SIZE", "10k");
            assert_eq!(parse_size_env("MESH_LOG_TEST_SIZE", 1), 10 * 1024);
            std::env::set_var("MESH_LOG_TEST_SIZE", "2mib");
            assert_eq!(parse_size_env("MESH_LOG_TEST_SIZE", 1), 2 * 1024 * 1024);
            std::env::set_var("MESH_LOG_TEST_SIZE", "not-a-size");
            assert_eq!(parse_size_env("MESH_LOG_TEST_SIZE", 7), 7);
            std::env::remove_var("MESH_LOG_TEST_SIZE");
        }
        assert_eq!(parse_size_env("MESH_LOG_TEST_SIZE_UNSET", 9), 9);
    }

    fn file_len(path: &std::path::Path) -> u64 {
        std::fs::metadata(path)
            .map(|metadata| metadata.len())
            .unwrap_or(0)
    }

    #[test]
    fn log_entry_formats_as_text_record() {
        let entry = LogEntry {
            timestamp: "2026-07-10T00:00:00Z".to_string(),
            level: "info".to_string(),
            target: "mesh_test".to_string(),
            message: "hello trace".to_string(),
            fields: Some(serde_json::json!({"answer": 42, "ok": true})),
        };

        let line = entry.to_text_line();
        assert!(line.starts_with("trace "));
        assert!(line.contains("level=info"));
        assert!(line.contains(r#"message="hello trace""#));
        assert!(line.contains("answer=42"));
        assert!(line.contains("ok=true"));
    }
}
