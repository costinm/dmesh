use std::collections::VecDeque;
use std::ffi::CStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};

use anyhow::Result;
use quic_lite::framed_stream::{FramedStream, FramedStreamEnqueue, FramedStreamStats};

use crate::commands::protocol::quote_text_value;
use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::settings::{SharedSettings, parse_bool};

const DEFAULT_DEPTH: usize = 10;
const DEFAULT_RESPONSE_MAX_BYTES: usize = 2048;
const MIN_RESPONSE_MAX_BYTES: usize = 256;
const MAX_RESPONSE_MAX_BYTES: usize = 8192;
const MAX_DEPTH: usize = 64;
const MAX_COMPANION_DEPTH: usize = 64;
const PREVIEW_BYTES: usize = 96;
const LORA_WAKE_EVENT_INTERVAL_MS: u32 = 1_000;
/// Producer-side log buffering is intentionally small.  It is a lossy
/// diagnostic stream, never a work queue for a FreeRTOS task.
// Keep enough boot history to include the asynchronously started STA/UDP
// bearers, while remaining a small fixed lossy diagnostic queue. Producers
// never wait for this storage or for a transport consumer.
// `FramedStream::new()` constructs the fixed record array at its call site.
// Classic ESP32's early Main task cannot safely materialize an 8 KiB log
// queue on its stack before the rest of the runtime is established. Keep the
// same nonblocking/drop contract with a small classic profile; larger boards
// retain the diagnostic history needed for STA/UDP bring-up.
#[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
const LOG_STREAM_RECORDS: usize = 2;
#[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
const LOG_STREAM_RECORD_BYTES: usize = 256;
#[cfg(any(target_arch = "riscv32", target_feature = "esp32s3ops"))]
const LOG_STREAM_RECORDS: usize = 16;
#[cfg(any(target_arch = "riscv32", target_feature = "esp32s3ops"))]
const LOG_STREAM_RECORD_BYTES: usize = 512;

static LAST_LORA_WAKE_EVENT_MS: AtomicU32 = AtomicU32::new(0);

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    registry.register(TelemetryCommand::new("status", settings.clone()));
    registry.register(TelemetryCommand::new("xstatus", settings.clone()));
    registry.register(TelemetryCommand::new("stats", settings.clone()));
    registry.register(TelemetryCommand::new("logs", settings.clone()));
    registry.register(TelemetryCommand::new("messages", settings.clone()));
    registry.register(TelemetryCommand::new("local_messages", settings));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Rx,
    Tx,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Rx => "rx",
            Self::Tx => "tx",
        }
    }
}

#[derive(Clone)]
struct MessageRecord {
    seq: u64,
    ts_ms: i64,
    transport: &'static str,
    direction: Direction,
    len: usize,
    detail: String,
    data: String,
}

#[derive(Clone)]
struct CompanionRecord {
    seq: u64,
    ts_ms: i64,
    transport: &'static str,
    len: usize,
    hash: u32,
    data: Vec<u8>,
}

#[derive(Default)]
struct TelemetryState {
    seq: u64,
    companion_seq: u64,
    messages: VecDeque<MessageRecord>,
    local_messages: VecDeque<MessageRecord>,
    companion_messages: VecDeque<CompanionRecord>,
    logs: VecDeque<String>,
}

struct AtomicCounter {
    rx_packets: AtomicU32,
    rx_bytes: AtomicU32,
    tx_packets: AtomicU32,
    tx_bytes: AtomicU32,
}

impl AtomicCounter {
    const fn new() -> Self {
        Self {
            rx_packets: AtomicU32::new(0),
            rx_bytes: AtomicU32::new(0),
            tx_packets: AtomicU32::new(0),
            tx_bytes: AtomicU32::new(0),
        }
    }

    fn record(&self, direction: Direction, len: usize) {
        match direction {
            Direction::Rx => {
                self.rx_packets.fetch_add(1, Ordering::Relaxed);
                self.rx_bytes.fetch_add(len as u32, Ordering::Relaxed);
            }
            Direction::Tx => {
                self.tx_packets.fetch_add(1, Ordering::Relaxed);
                self.tx_bytes.fetch_add(len as u32, Ordering::Relaxed);
            }
        }
    }

    fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
        }
    }

    fn reset(&self) {
        self.rx_packets.store(0, Ordering::Relaxed);
        self.rx_bytes.store(0, Ordering::Relaxed);
        self.tx_packets.store(0, Ordering::Relaxed);
        self.tx_bytes.store(0, Ordering::Relaxed);
    }
}

struct CounterSnapshot {
    rx_packets: u32,
    rx_bytes: u32,
    tx_packets: u32,
    tx_bytes: u32,
}

static LORA_COUNTER: AtomicCounter = AtomicCounter::new();
static BLE_COUNTER: AtomicCounter = AtomicCounter::new();
static WIFI_COUNTER: AtomicCounter = AtomicCounter::new();
static MAIN_LOOP_COUNTER: AtomicU32 = AtomicU32::new(0);
static MAIN_UART_READ_COUNTER: AtomicU32 = AtomicU32::new(0);
static MAIN_UART_BYTE_COUNTER: AtomicU32 = AtomicU32::new(0);
static MAIN_UART_TIMEOUT_COUNTER: AtomicU32 = AtomicU32::new(0);
static UART_INGRESS_BYTES: AtomicU32 = AtomicU32::new(0);
static UART_INGRESS_TEXT: AtomicU32 = AtomicU32::new(0);
static UART_INGRESS_FRAMED: AtomicU32 = AtomicU32::new(0);
static UART_INGRESS_DROPPED: AtomicU32 = AtomicU32::new(0);
static UART_INGRESS_OVERSIZE: AtomicU32 = AtomicU32::new(0);
static MAIN_RAW_POLL_COUNTER: AtomicU32 = AtomicU32::new(0);
static MAIN_RAW_COMMAND_COUNTER: AtomicU32 = AtomicU32::new(0);
static LOG_STREAM_DROPPED_UNAVAILABLE: AtomicU32 = AtomicU32::new(0);
static LOG_STREAM_DROPPED_BUSY: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogStreamWriteResult {
    Queued(FramedStreamStats),
    DroppedFull(FramedStreamStats),
    DroppedOversized(FramedStreamStats),
    /// Startup has not installed the fixed log queue yet.
    DroppedUnavailable,
    /// A transport drain holds the queue. Producers must drop rather than
    /// wait for it, including from timing-sensitive firmware tasks.
    DroppedBusy,
}

/// Aggregate producer-side state.  This is available independently of a
/// watcher or bearer so status can report that logging was intentionally
/// lossy under backpressure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogStreamProducerStats {
    pub queue: Option<FramedStreamStats>,
    pub dropped_unavailable: u32,
    pub dropped_busy: u32,
}

struct TelemetryCommand {
    name: &'static str,
    settings: SharedSettings,
}

impl TelemetryCommand {
    fn new(name: &'static str, settings: SharedSettings) -> Self {
        Self { name, settings }
    }
}

impl CommandHandler for TelemetryCommand {
    fn name(&self) -> &'static str {
        self.name
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        match self.name {
            "status" => Ok(CommandResponse::ok(status_text(&self.settings))),
            "xstatus" => self.xstatus(request),
            "stats" => self.stats(request),
            "logs" => self.logs(request),
            "messages" => self.messages(request),
            "local_messages" => self.local_messages(request),
            _ => Ok(CommandResponse::error("invalid telemetry command")),
        }
    }
}

impl TelemetryCommand {
    fn xstatus(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if request
            .arg("reset")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            reset();
        }
        Ok(CommandResponse::ok(xstatus_text(&self.settings)))
    }

    fn stats(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if request
            .arg("reset")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            reset();
        }
        Ok(CommandResponse::ok(stats_text(&self.settings)))
    }

    fn logs(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if request
            .arg("clear")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            clear_logs();
        }
        let count = self.depth(request, "log.depth")?;
        let max_bytes = response_max_bytes(request)?;
        Ok(CommandResponse::ok(logs_text(count, max_bytes)))
    }

    fn messages(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if request.arg("pull").is_some() {
            let max_bytes = response_max_bytes(request)?;
            let after_seq = request
                .arg("after_seq")
                .map(parse_u64)
                .transpose()?
                .unwrap_or(0);
            let transport = request.arg("transport");
            return Ok(CommandResponse::ok(companion_pull_text(
                after_seq, max_bytes, transport,
            )));
        }
        if request.arg("ack").is_some() {
            let seq = request.arg("seq").map(parse_u64).transpose()?.unwrap_or(0);
            let hash = request.arg("hash").map(parse_u32).transpose()?.unwrap_or(0);
            return Ok(CommandResponse::ok(companion_ack_text(seq, hash)));
        }
        if request
            .arg("clear")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            clear_messages();
        }
        let count = self.depth(request, "msg.depth")?;
        let max_bytes = response_max_bytes(request)?;
        let transport = request.arg("transport");
        let direction = request.arg("direction");
        Ok(CommandResponse::ok(messages_text(
            count,
            max_bytes,
            transport,
            direction,
            MessageQueue::General,
        )))
    }

    fn local_messages(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if request
            .arg("clear")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            clear_local_messages();
        }
        let count = self.depth(request, "local_msg.depth")?;
        let max_bytes = response_max_bytes(request)?;
        Ok(CommandResponse::ok(messages_text(
            count,
            max_bytes,
            request.arg("transport"),
            request.arg("direction"),
            MessageQueue::Local,
        )))
    }

    fn depth(&mut self, request: &CommandRequest, key: &str) -> Result<usize> {
        if let Some(depth) = request.arg_i32("depth")? {
            self.settings
                .borrow_mut()
                .set_i32(key, depth.clamp(1, MAX_DEPTH as i32))?;
        }
        if let Some(count) = request.arg_i32("count")? {
            return Ok(count.clamp(1, MAX_DEPTH as i32) as usize);
        }
        Ok(self
            .settings
            .borrow()
            .get_i32(key, DEFAULT_DEPTH as i32)?
            .clamp(1, MAX_DEPTH as i32) as usize)
    }
}

/// Install the fixed record queue before enabling normal firmware logging.
/// This performs no connection or bearer work, and is safe to call repeatedly.
pub fn initialize_log_stream() {
    let _ = log_stream_slot().set(Mutex::new(FramedStream::new()));
}

/// Queue one trace/log/event record without waiting for QUIC credit, a
/// connected watcher, or a contended transport lock. The caller gets an
/// immediate result; normal logging deliberately drops on every failure mode.
pub fn record_log(line: impl AsRef<str>) -> LogStreamWriteResult {
    let line = bounded_log_line(line.as_ref());
    let record = format!("log ts={} {line}", format_ts(now_ms()));
    let stream_result = enqueue_log_stream(record.as_bytes(), now_us());
    if let Ok(mut state) = telemetry().try_lock() {
        push_bounded(&mut state.logs, record, MAX_DEPTH);
    }
    stream_result
}

/// Consume one complete queued record from the log stream. The transport
/// owner calls this from its normal poll loop; it must not be called by a log
/// producer. A future watcher maps each returned record to one STREAM frame.
pub fn take_log_stream_record()
-> Option<quic_lite::framed_stream::FramedStreamRecord<LOG_STREAM_RECORD_BYTES>> {
    log_stream_slot().get()?.try_lock().ok()?.pop()
}

pub fn log_stream_producer_stats() -> LogStreamProducerStats {
    let queue = log_stream_slot()
        .get()
        .and_then(|stream| stream.try_lock().ok().map(|stream| stream.stats()));
    LogStreamProducerStats {
        queue,
        dropped_unavailable: LOG_STREAM_DROPPED_UNAVAILABLE.load(Ordering::Relaxed),
        dropped_busy: LOG_STREAM_DROPPED_BUSY.load(Ordering::Relaxed),
    }
}

fn log_stream_slot()
-> &'static OnceLock<Mutex<FramedStream<LOG_STREAM_RECORDS, LOG_STREAM_RECORD_BYTES>>> {
    static LOG_STREAM: OnceLock<Mutex<FramedStream<LOG_STREAM_RECORDS, LOG_STREAM_RECORD_BYTES>>> =
        OnceLock::new();
    &LOG_STREAM
}

fn enqueue_log_stream(bytes: &[u8], now_us: u64) -> LogStreamWriteResult {
    let Some(stream) = log_stream_slot().get() else {
        LOG_STREAM_DROPPED_UNAVAILABLE.fetch_add(1, Ordering::Relaxed);
        return LogStreamWriteResult::DroppedUnavailable;
    };
    let Ok(mut stream) = stream.try_lock() else {
        LOG_STREAM_DROPPED_BUSY.fetch_add(1, Ordering::Relaxed);
        return LogStreamWriteResult::DroppedBusy;
    };
    let outcome = stream.try_enqueue(bytes, now_us);
    let stats = stream.stats();
    match outcome {
        FramedStreamEnqueue::Queued => LogStreamWriteResult::Queued(stats),
        FramedStreamEnqueue::DroppedFull => LogStreamWriteResult::DroppedFull(stats),
        FramedStreamEnqueue::DroppedOversized => LogStreamWriteResult::DroppedOversized(stats),
    }
}

fn bounded_log_line(line: &str) -> &str {
    // Timestamp and prefix consume a small, bounded portion of the 512-byte
    // stream record. Trim only at a UTF-8 boundary so a malformed trace never
    // causes another allocation while being dropped/recorded.
    const MAX_LINE_BYTES: usize = LOG_STREAM_RECORD_BYTES - 64;
    if line.len() <= MAX_LINE_BYTES {
        return line;
    }
    let mut end = MAX_LINE_BYTES;
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    &line[..end]
}

pub fn record_packet(
    transport: &'static str,
    direction: Direction,
    data: &[u8],
    detail: impl Into<String>,
) {
    count_packet(transport, direction, data.len());
    if direction == Direction::Rx {
        record_packet_sample(transport, direction, data, detail);
    }
}

pub fn record_packet_sample(
    transport: &'static str,
    direction: Direction,
    data: &[u8],
    detail: impl Into<String>,
) {
    if let Ok(mut state) = telemetry().try_lock() {
        state.seq = state.seq.saturating_add(1);
        let record = MessageRecord {
            seq: state.seq,
            ts_ms: now_ms(),
            transport,
            direction,
            len: data.len(),
            detail: detail.into(),
            data: hex_preview(data),
        };
        push_bounded(&mut state.messages, record, MAX_DEPTH);
    }
    if transport == "lora" && direction == Direction::Rx {
        record_companion_packet(transport, data);
    }
}

pub fn count_packet(transport: &'static str, direction: Direction, len: usize) {
    counter_for(transport).record(direction, len);
}

pub fn lora_rx_packets() -> u32 {
    LORA_COUNTER.snapshot().rx_packets
}

/// Rate-limit per-packet LoRa wake notifications. Packet counters remain
/// lossless; this only prevents a busy radio from flooding UART and the
/// bounded event log with one notification per received packet.
pub fn take_lora_wake_event_slot() -> bool {
    let now = now_ms().max(0) as u32;
    let mut previous = LAST_LORA_WAKE_EVENT_MS.load(Ordering::Relaxed);
    loop {
        if previous != 0 && now.saturating_sub(previous) < LORA_WAKE_EVENT_INTERVAL_MS {
            return false;
        }
        match LAST_LORA_WAKE_EVENT_MS.compare_exchange_weak(
            previous,
            now,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(observed) => previous = observed,
        }
    }
}

/// Compact, event-triggered statistics emitted after a LoRa packet wakes a
/// sleepy node. Keep this deliberately smaller than `status`/`xstatus` so
/// long-running tests can consume it without turning the wake report into a
/// second source of UART framing pressure.
pub fn lora_wake_stats_text() -> String {
    let lora = LORA_COUNTER.snapshot();
    format!(
        "event type=lora.wake_stats uptime_ms={} {} lora_rx={} lora_rx_bytes={} lora_tx={} lora_tx_bytes={} {}",
        now_ms(),
        super::power::compact_status_fields(),
        lora.rx_packets,
        lora.rx_bytes,
        lora.tx_packets,
        lora.tx_bytes,
        super::mode::raw_nan_wake_summary(),
    )
}

pub fn record_local_packet(
    transport: &'static str,
    direction: Direction,
    data: &[u8],
    detail: impl Into<String>,
) {
    if let Ok(mut state) = telemetry().try_lock() {
        state.seq = state.seq.saturating_add(1);
        let record = MessageRecord {
            seq: state.seq,
            ts_ms: now_ms(),
            transport,
            direction,
            len: data.len(),
            detail: detail.into(),
            data: hex_preview(data),
        };
        push_bounded(&mut state.local_messages, record, MAX_DEPTH);
    }
}

pub fn stats_text(settings: &SharedSettings) -> String {
    let state = telemetry().lock().unwrap();
    let lora = LORA_COUNTER.snapshot();
    let ble = BLE_COUNTER.snapshot();
    let wifi = WIFI_COUNTER.snapshot();
    format!(
        "stats lora_rx={} lora_rx_bytes={} lora_tx={} lora_tx_bytes={} ble_rx={} ble_rx_bytes={} ble_tx={} ble_tx_bytes={} wifi_rx={} wifi_rx_bytes={} wifi_tx={} wifi_tx_bytes={} logs={} messages={} local_messages={} companion={} main_loops={} main_uart_reads={} main_uart_bytes={} main_uart_timeouts={} uart_rx_bytes={} uart_text={} uart_framed={} uart_drop={} uart_oversize={} main_raw_polls={} main_raw_cmds={} {} {} {}",
        lora.rx_packets,
        lora.rx_bytes,
        lora.tx_packets,
        lora.tx_bytes,
        ble.rx_packets,
        ble.rx_bytes,
        ble.tx_packets,
        ble.tx_bytes,
        wifi.rx_packets,
        wifi.rx_bytes,
        wifi.tx_packets,
        wifi.tx_bytes,
        state.logs.len(),
        state.messages.len(),
        state.local_messages.len(),
        state.companion_messages.len(),
        MAIN_LOOP_COUNTER.load(Ordering::Relaxed),
        MAIN_UART_READ_COUNTER.load(Ordering::Relaxed),
        MAIN_UART_BYTE_COUNTER.load(Ordering::Relaxed),
        MAIN_UART_TIMEOUT_COUNTER.load(Ordering::Relaxed),
        UART_INGRESS_BYTES.load(Ordering::Relaxed),
        UART_INGRESS_TEXT.load(Ordering::Relaxed),
        UART_INGRESS_FRAMED.load(Ordering::Relaxed),
        UART_INGRESS_DROPPED.load(Ordering::Relaxed),
        UART_INGRESS_OVERSIZE.load(Ordering::Relaxed),
        MAIN_RAW_POLL_COUNTER.load(Ordering::Relaxed),
        MAIN_RAW_COMMAND_COUNTER.load(Ordering::Relaxed),
        super::wake::stats_fields(),
        runtime_stats_text(),
        super::battery::stats_fields(settings)
    )
}

pub fn status_text(settings: &SharedSettings) -> String {
    let state = telemetry().lock().unwrap();
    let lora = LORA_COUNTER.snapshot();
    let ble = BLE_COUNTER.snapshot();
    let wifi = WIFI_COUNTER.snapshot();
    let runtime = runtime_snapshot();
    format!(
        "status uptime_ms={} {} {} idle_pct={} top={} top_pct={} lora_rx={} lora_tx={} ble_rx={} ble_tx={} wifi_rx={} wifi_tx={} logs={} messages={} companion={} {}",
        now_ms(),
        super::power::compact_status_fields(),
        super::power::resource_status_fields(),
        runtime.idle_pct,
        runtime.top_name,
        runtime.top_pct,
        lora.rx_packets,
        lora.tx_packets,
        ble.rx_packets,
        ble.tx_packets,
        wifi.rx_packets,
        wifi.tx_packets,
        state.logs.len(),
        state.messages.len(),
        state.companion_messages.len(),
        super::battery::stats_fields(settings)
    )
}

pub fn xstatus_text(settings: &SharedSettings) -> String {
    format!(
        "xstatus uptime_ms={} {} {} {} {} {} {} {} {} {} {} {}",
        now_ms(),
        super::power::compact_status_fields(),
        super::power::sleep_metrics_fields(),
        super::power::resource_status_fields(),
        runtime_stats_text(),
        super::wake::stats_fields(),
        main_loop_fields(),
        queue_fields(),
        super::battery::stats_fields(settings),
        super::sleep::status_summary_fields(),
        super::mode::raw_nan_status_fields(),
        radio_summary_fields(settings)
    )
}

fn main_loop_fields() -> String {
    format!(
        "main_loops={} main_uart_reads={} main_uart_bytes={} main_uart_timeouts={} main_raw_polls={} main_raw_cmds={}",
        MAIN_LOOP_COUNTER.load(Ordering::Relaxed),
        MAIN_UART_READ_COUNTER.load(Ordering::Relaxed),
        MAIN_UART_BYTE_COUNTER.load(Ordering::Relaxed),
        MAIN_UART_TIMEOUT_COUNTER.load(Ordering::Relaxed),
        MAIN_RAW_POLL_COUNTER.load(Ordering::Relaxed),
        MAIN_RAW_COMMAND_COUNTER.load(Ordering::Relaxed)
    )
}

fn queue_fields() -> String {
    let state = telemetry().lock().unwrap();
    format!(
        "logs={} messages={} local_messages={} companion={}",
        state.logs.len(),
        state.messages.len(),
        state.local_messages.len(),
        state.companion_messages.len()
    )
}

fn radio_summary_fields(settings: &SharedSettings) -> String {
    let lora = LORA_COUNTER.snapshot();
    let ble = BLE_COUNTER.snapshot();
    let wifi = WIFI_COUNTER.snapshot();
    format!(
        "lora_rx={} lora_rx_bytes={} lora_tx={} lora_tx_bytes={} ble_rx={} ble_rx_bytes={} ble_tx={} ble_tx_bytes={} wifi_rx={} wifi_rx_bytes={} wifi_tx={} wifi_tx_bytes={} lora_status={}",
        lora.rx_packets,
        lora.rx_bytes,
        lora.tx_packets,
        lora.tx_bytes,
        ble.rx_packets,
        ble.rx_bytes,
        ble.tx_packets,
        ble.tx_bytes,
        wifi.rx_packets,
        wifi.rx_bytes,
        wifi.tx_packets,
        wifi.tx_bytes,
        quote_text_value(&super::lora::status_text(settings))
    )
}

fn runtime_stats_text() -> String {
    let snapshot = runtime_snapshot();
    if snapshot.tasks == 0 {
        return "rt_tasks=0 rt_total=0 rt_reported=0 rt_idle=0 rt_idle_pct=0 rt_top=none rt_top_runtime=0 rt_top_pct=0".to_string();
    }
    if snapshot.total == 0 {
        return format!(
            "rt_tasks={} rt_total=0 rt_reported={} rt_idle=0 rt_idle_pct=0 rt_top=none rt_top_runtime=0 rt_top_pct=0",
            snapshot.tasks, snapshot.reported
        );
    }

    format!(
        "rt_tasks={} rt_total={} rt_reported={} rt_idle={} rt_idle_pct={} rt_top={} rt_top_runtime={} rt_top_pct={}",
        snapshot.tasks,
        snapshot.total,
        snapshot.reported,
        snapshot.idle,
        snapshot.idle_pct,
        snapshot.top_name,
        snapshot.top_runtime,
        snapshot.top_pct
    )
}

struct RuntimeSnapshot {
    tasks: usize,
    total: u32,
    reported: u32,
    idle: u32,
    idle_pct: u32,
    top_name: String,
    top_runtime: u32,
    top_pct: u32,
}

fn runtime_snapshot() -> RuntimeSnapshot {
    const MAX_TASKS: usize = 24;
    let mut tasks = [esp_idf_sys::TaskStatus_t::default(); MAX_TASKS];
    let mut reported_runtime = 0_u32;
    let count = unsafe {
        esp_idf_sys::uxTaskGetSystemState(
            tasks.as_mut_ptr(),
            tasks.len() as esp_idf_sys::UBaseType_t,
            &mut reported_runtime,
        )
    } as usize;
    if count == 0 {
        return RuntimeSnapshot {
            tasks: 0,
            total: 0,
            reported: 0,
            idle: 0,
            idle_pct: 0,
            top_name: "none".to_string(),
            top_runtime: 0,
            top_pct: 0,
        };
    }

    let mut total_runtime = 0_u32;
    let mut idle_runtime = 0_u32;
    let mut top_name = "none".to_string();
    let mut top_runtime = 0_u32;
    for task in tasks.iter().take(count.min(MAX_TASKS)) {
        let name = task_name(task.pcTaskName);
        total_runtime = total_runtime.saturating_add(task.ulRunTimeCounter);
        if is_idle_task_name(&name) {
            idle_runtime = idle_runtime.saturating_add(task.ulRunTimeCounter);
        } else if task.ulRunTimeCounter > top_runtime {
            top_runtime = task.ulRunTimeCounter;
            top_name = sanitize_task_name(&name);
        }
    }
    RuntimeSnapshot {
        tasks: count,
        total: total_runtime,
        reported: reported_runtime,
        idle: idle_runtime,
        idle_pct: pct_u32(idle_runtime, total_runtime),
        top_name,
        top_runtime,
        top_pct: pct_u32(top_runtime, total_runtime),
    }
}

fn task_name(name: *const core::ffi::c_char) -> String {
    if name.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(name) }
        .to_string_lossy()
        .into_owned()
}

fn is_idle_task_name(name: &str) -> bool {
    name.starts_with("IDLE")
}

fn sanitize_task_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len().min(24));
    for ch in name.chars().take(24) {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

fn pct_u32(part: u32, total: u32) -> u32 {
    if total == 0 {
        0
    } else {
        ((part as u64) * 100 / (total as u64)) as u32
    }
}

pub fn record_main_loop() {
    MAIN_LOOP_COUNTER.fetch_add(1, Ordering::Relaxed);
}

pub fn record_uart_read(bytes: usize) {
    MAIN_UART_READ_COUNTER.fetch_add(1, Ordering::Relaxed);
    MAIN_UART_BYTE_COUNTER.fetch_add(bytes.min(u32::MAX as usize) as u32, Ordering::Relaxed);
}

pub fn record_uart_timeout() {
    MAIN_UART_TIMEOUT_COUNTER.fetch_add(1, Ordering::Relaxed);
}

pub fn record_raw_poll() {
    MAIN_RAW_POLL_COUNTER.fetch_add(1, Ordering::Relaxed);
}

pub fn record_raw_command() {
    MAIN_RAW_COMMAND_COUNTER.fetch_add(1, Ordering::Relaxed);
}

pub fn pending_message_count() -> u8 {
    let state = telemetry().lock().unwrap();
    state.companion_messages.len().min(u8::MAX as usize) as u8
}

pub fn record_companion_packet(transport: &'static str, data: &[u8]) {
    if let Ok(mut state) = telemetry().try_lock() {
        state.companion_seq = state.companion_seq.saturating_add(1);
        let record = CompanionRecord {
            seq: state.companion_seq,
            ts_ms: now_ms(),
            transport,
            len: data.len(),
            hash: fnv1a32(data),
            data: data.to_vec(),
        };
        push_bounded(&mut state.companion_messages, record, MAX_COMPANION_DEPTH);
    }
    super::ble_bt::companion_message_ready(data);
}

pub fn companion_notify_text(max_bytes: usize) -> String {
    companion_pull_text(0, max_bytes, None)
}

fn logs_text(count: usize, max_bytes: usize) -> String {
    let state = telemetry().lock().unwrap();
    let skip = state.logs.len().saturating_sub(count);
    let selected = state.logs.iter().skip(skip).collect::<Vec<_>>();
    if selected.is_empty() {
        "logs count=0".to_string()
    } else {
        let mut out = String::new();
        let mut rendered = 0;
        for line in &selected {
            if !append_bounded_line(&mut out, line, max_bytes) {
                break;
            }
            rendered += 1;
        }
        let more = rendered < selected.len();
        if more {
            let marker = format!(
                "logs partial=true count={} total={} more=true max_bytes={}",
                rendered,
                selected.len(),
                max_bytes
            );
            let _ = append_bounded_line(&mut out, &marker, max_bytes);
        }
        if out.is_empty() {
            format!(
                "logs partial=true count=0 total={} more=true max_bytes={}",
                selected.len(),
                max_bytes
            )
        } else {
            out
        }
    }
}

#[derive(Clone, Copy)]
enum MessageQueue {
    General,
    Local,
}

fn messages_text(
    count: usize,
    max_bytes: usize,
    transport: Option<&str>,
    direction: Option<&str>,
    queue: MessageQueue,
) -> String {
    let state = telemetry().lock().unwrap();
    let source = match queue {
        MessageQueue::General => &state.messages,
        MessageQueue::Local => &state.local_messages,
    };
    let mut records = source
        .iter()
        .filter(|record| {
            transport
                .map(|value| value == record.transport)
                .unwrap_or(true)
        })
        .filter(|record| {
            direction
                .map(|value| value == record.direction.as_str())
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();
    let skip = records.len().saturating_sub(count);
    records.drain(0..skip);
    if records.is_empty() {
        return match queue {
            MessageQueue::General => "messages count=0".to_string(),
            MessageQueue::Local => "local_messages count=0".to_string(),
        };
    }
    let mut out = String::new();
    let mut rendered = 0;
    for record in &records {
        let line = format_message_record(record);
        if !append_bounded_line(&mut out, &line, max_bytes) {
            break;
        }
        rendered += 1;
    }
    let more = rendered < records.len();
    if more {
        let name = match queue {
            MessageQueue::General => "messages",
            MessageQueue::Local => "local_messages",
        };
        let next_seq = records.get(rendered).map(|record| record.seq).unwrap_or(0);
        let marker = format!(
            "{} partial=true count={} total={} more=true next_seq={} max_bytes={}",
            name,
            rendered,
            records.len(),
            next_seq,
            max_bytes
        );
        let _ = append_bounded_line(&mut out, &marker, max_bytes);
    }
    if out.is_empty() {
        let name = match queue {
            MessageQueue::General => "messages",
            MessageQueue::Local => "local_messages",
        };
        format!(
            "{} partial=true count=0 total={} more=true next_seq={} max_bytes={}",
            name,
            records.len(),
            records.first().map(|record| record.seq).unwrap_or(0),
            max_bytes
        )
    } else {
        out
    }
}

fn companion_pull_text(after_seq: u64, max_bytes: usize, transport: Option<&str>) -> String {
    let state = telemetry().lock().unwrap();
    let records = state
        .companion_messages
        .iter()
        .filter(|record| record.seq > after_seq)
        .filter(|record| {
            transport
                .map(|value| value == record.transport)
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();
    if records.is_empty() {
        return format!(
            "messages pull=true count=0 pending={} more=false",
            state.companion_messages.len()
        );
    }
    let mut out = String::new();
    let mut rendered = 0;
    for record in &records {
        let line = format_companion_record(record);
        if !append_bounded_line(&mut out, &line, max_bytes) {
            break;
        }
        rendered += 1;
    }
    let more = rendered < records.len();
    let marker = format!(
        "messages pull=true count={} pending={} more={} next_seq={} max_bytes={}",
        rendered,
        state.companion_messages.len(),
        more,
        records.get(rendered).map(|record| record.seq).unwrap_or(0),
        max_bytes
    );
    let _ = append_bounded_line(&mut out, &marker, max_bytes);
    if out.is_empty() { marker } else { out }
}

fn companion_ack_text(seq: u64, hash: u32) -> String {
    let mut state = telemetry().lock().unwrap();
    let Some(pos) = state
        .companion_messages
        .iter()
        .position(|record| record.seq == seq)
    else {
        return format!(
            "messages ack=true seq={} hash=0x{:08x} deleted=false duplicate=true pending={}",
            seq,
            hash,
            state.companion_messages.len()
        );
    };
    if state
        .companion_messages
        .get(pos)
        .map(|record| record.hash != hash)
        .unwrap_or(true)
    {
        return format!(
            "messages ack=false seq={} hash=0x{:08x} error=hash_mismatch pending={}",
            seq,
            hash,
            state.companion_messages.len()
        );
    }
    let _ = state.companion_messages.remove(pos);
    let pending = state.companion_messages.len();
    drop(state);
    if pending == 0 {
        super::ble_bt::companion_queue_empty();
    }
    format!(
        "messages ack=true seq={} hash=0x{:08x} deleted=true pending={}",
        seq, hash, pending
    )
}

pub fn emit_console(line: &str) {
    // Log delivery is a stream service.  Do not recreate the retired UART or
    // raw-Wi-Fi command packet encoders here; the shared transport attachment
    // will drain this bounded telemetry history for log-watch subscribers.
    record_log(line.to_owned());
}

fn reset() {
    super::power::reset_sleep_metrics();
    LORA_COUNTER.reset();
    BLE_COUNTER.reset();
    WIFI_COUNTER.reset();
    MAIN_LOOP_COUNTER.store(0, Ordering::Relaxed);
    MAIN_UART_READ_COUNTER.store(0, Ordering::Relaxed);
    MAIN_UART_BYTE_COUNTER.store(0, Ordering::Relaxed);
    MAIN_UART_TIMEOUT_COUNTER.store(0, Ordering::Relaxed);
    MAIN_RAW_POLL_COUNTER.store(0, Ordering::Relaxed);
    MAIN_RAW_COMMAND_COUNTER.store(0, Ordering::Relaxed);
    super::wake::reset_stats();
    let mut state = telemetry().lock().unwrap();
    state.messages.clear();
    state.local_messages.clear();
    state.logs.clear();
}

fn clear_logs() {
    telemetry().lock().unwrap().logs.clear();
}

fn clear_messages() {
    telemetry().lock().unwrap().messages.clear();
}

fn clear_local_messages() {
    telemetry().lock().unwrap().local_messages.clear();
}

fn counter_for(transport: &str) -> &'static AtomicCounter {
    match transport {
        "lora" => &LORA_COUNTER,
        "ble" | "bt" => &BLE_COUNTER,
        "wifi" | "nan" => &WIFI_COUNTER,
        _ => &WIFI_COUNTER,
    }
}

fn telemetry() -> &'static Mutex<TelemetryState> {
    static TELEMETRY: OnceLock<Mutex<TelemetryState>> = OnceLock::new();
    TELEMETRY.get_or_init(|| Mutex::new(TelemetryState::default()))
}

fn push_bounded<T>(queue: &mut VecDeque<T>, item: T, max: usize) {
    while queue.len() >= max {
        let _ = queue.pop_front();
    }
    queue.push_back(item);
}

fn response_max_bytes(request: &CommandRequest) -> Result<usize> {
    Ok(request
        .arg_i32("max_bytes")?
        .unwrap_or(DEFAULT_RESPONSE_MAX_BYTES as i32)
        .clamp(MIN_RESPONSE_MAX_BYTES as i32, MAX_RESPONSE_MAX_BYTES as i32) as usize)
}

fn parse_u64(value: &str) -> Result<u64> {
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|err| anyhow::anyhow!("invalid u64 {value}: {err}"))
    } else {
        value
            .parse::<u64>()
            .map_err(|err| anyhow::anyhow!("invalid u64 {value}: {err}"))
    }
}

fn parse_u32(value: &str) -> Result<u32> {
    if let Some(hex) = value.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).map_err(|err| anyhow::anyhow!("invalid u32 {value}: {err}"))
    } else {
        value.parse::<u32>().or_else(|_| {
            u32::from_str_radix(value, 16)
                .map_err(|err| anyhow::anyhow!("invalid u32 {value}: {err}"))
        })
    }
}

fn append_bounded_line(out: &mut String, line: &str, max_bytes: usize) -> bool {
    let extra = line.len() + usize::from(!out.is_empty());
    if out.len().saturating_add(extra) > max_bytes {
        return false;
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(line);
    true
}

fn format_message_record(record: &MessageRecord) -> String {
    format!(
        "msg ts={} seq={} t={} dir={} len={} {} data={}",
        format_ts(record.ts_ms),
        record.seq,
        record.transport,
        record.direction.as_str(),
        record.len,
        record.detail,
        quote_text_value(&record.data)
    )
}

fn format_companion_record(record: &CompanionRecord) -> String {
    format!(
        "msg ts={} seq={} t={} dir=rx len={} hash=0x{:08x} data=hex:{}",
        format_ts(record.ts_ms),
        record.seq,
        record.transport,
        record.len,
        record.hash,
        encode_hex(&record.data)
    )
}

fn encode_hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push(hex_char(byte >> 4));
        out.push(hex_char(byte & 0x0f));
    }
    out
}

fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5_u32;
    for byte in data {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn hex_preview(data: &[u8]) -> String {
    let mut out = String::new();
    for byte in data.iter().take(PREVIEW_BYTES) {
        out.push(hex_char(byte >> 4));
        out.push(hex_char(byte & 0x0f));
    }
    if data.len() > PREVIEW_BYTES {
        out.push_str("...");
    }
    out
}

fn hex_char(nibble: u8) -> char {
    b"0123456789abcdef"[(nibble & 0x0f) as usize] as char
}

fn now_ms() -> i64 {
    unsafe { esp_idf_sys::esp_timer_get_time() / 1000 }
}

fn now_us() -> u64 {
    unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 }
}

fn format_ts(ms: i64) -> String {
    format!("{}.{:03}s", ms / 1000, ms.rem_euclid(1000))
}
