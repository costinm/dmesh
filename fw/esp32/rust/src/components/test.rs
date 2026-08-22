use std::mem::size_of;
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{anyhow, Result};
use esp_idf_sys as sys;

use super::telemetry;
use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

const RTC_MAGIC: u32 = 0x4454_5354;
const RTC_VERSION: u16 = 1;
const DEFAULT_DISCOVERY_COUNT: u32 = 2;
const DEFAULT_WAKE_MS: u32 = 4_000;
const DEFAULT_ACTIVE_MS: u32 = 500;
const DEFAULT_INTERVAL_MS: u64 = 512;

static NEXT_MAIN_POLL_MS: AtomicU32 = AtomicU32::new(0);

#[repr(C)]
#[derive(Clone, Copy)]
struct RtcTestState {
    magic: u32,
    version: u16,
    len: u16,
    checksum: u32,
    enabled: u8,
    _pad0: [u8; 3],
    total: u32,
    remaining: u32,
    discovery_remaining: u32,
    sent: u32,
    seq: u32,
    start_resp_rx: u32,
    wake_ms: u32,
    active_ms: u32,
    last_send_us_lo: u32,
    last_send_us_hi: u32,
}

impl RtcTestState {
    const fn empty() -> Self {
        Self {
            magic: 0,
            version: 0,
            len: 0,
            checksum: 0,
            enabled: 0,
            _pad0: [0; 3],
            total: 0,
            remaining: 0,
            discovery_remaining: 0,
            sent: 0,
            seq: 0,
            start_resp_rx: 0,
            wake_ms: DEFAULT_WAKE_MS,
            active_ms: DEFAULT_ACTIVE_MS,
            last_send_us_lo: 0,
            last_send_us_hi: 0,
        }
    }
}

#[link_section = ".rtc.data"]
static mut RTC_TEST_STATE: RtcTestState = RtcTestState::empty();

pub fn register_commands(registry: &mut CommandRegistry) {
    registry.register(TestCommand);
}

pub fn poll_main() {
    let now = now_ms();
    let next = NEXT_MAIN_POLL_MS.load(Ordering::Relaxed);
    if next != 0 && now < next {
        return;
    }
    NEXT_MAIN_POLL_MS.store(
        now.saturating_add(DEFAULT_INTERVAL_MS as u32),
        Ordering::Relaxed,
    );
    let _ = send_one_if_active("main");
}

pub fn poll_nan_active_window() {
    let _ = send_one_if_active("sleep_active");
}

pub fn has_active_send_test() -> bool {
    let state = read_state();
    valid_state(&state) && state.enabled != 0 && pending_count(&state) > 0
}

pub fn wake_ms() -> u32 {
    let state = read_state();
    if valid_state(&state) && state.wake_ms > 0 {
        state.wake_ms
    } else {
        DEFAULT_WAKE_MS
    }
}

pub fn active_ms() -> u32 {
    let state = read_state();
    if valid_state(&state) && state.active_ms > 0 {
        state.active_ms
    } else {
        DEFAULT_ACTIVE_MS
    }
}

struct TestCommand;

impl CommandHandler for TestCommand {
    fn name(&self) -> &'static str {
        "test"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if request.arg("stop").is_some() {
            write_state(RtcTestState::empty());
            return Ok(CommandResponse::ok(format!(
                "test stopped {}",
                status_text()
            )));
        }
        if request.arg("status").is_some() || request.arg("stats").is_some() {
            return Ok(CommandResponse::ok(status_text()));
        }
        let Some(cnt) = request.arg("cnt").or_else(|| request.arg("count")) else {
            return Ok(CommandResponse::ok(status_text()));
        };
        let total = parse_u32(cnt, "cnt")?.clamp(1, 10_000);
        let discovery = request
            .arg("discovery")
            .or_else(|| request.arg("discover"))
            .map(|value| parse_u32(value, "discovery"))
            .transpose()?
            .unwrap_or(DEFAULT_DISCOVERY_COUNT)
            .clamp(0, 10);
        let wake_ms = request
            .arg("wake_ms")
            .map(|value| parse_u32(value, "wake_ms"))
            .transpose()?
            .unwrap_or(DEFAULT_WAKE_MS)
            .clamp(100, 60_000);
        let active_ms = request
            .arg("active_ms")
            .map(|value| parse_u32(value, "active_ms"))
            .transpose()?
            .unwrap_or(DEFAULT_ACTIVE_MS)
            .clamp(50, 60_000);
        let state = update_checksum(RtcTestState {
            magic: RTC_MAGIC,
            version: RTC_VERSION,
            len: size_of::<RtcTestState>() as u16,
            checksum: 0,
            enabled: 1,
            _pad0: [0; 3],
            total,
            remaining: total,
            discovery_remaining: discovery,
            sent: 0,
            seq: 0,
            start_resp_rx: super::nan::raw_response_rx_count(),
            wake_ms,
            active_ms,
            last_send_us_lo: 0,
            last_send_us_hi: 0,
        });
        write_state(state);
        NEXT_MAIN_POLL_MS.store(0, Ordering::Relaxed);
        telemetry::record_log(format!(
            "event type=test.start total={} discovery={} wake_ms={} active_ms={}",
            total, discovery, wake_ms, active_ms
        ));
        Ok(CommandResponse::ok(status_text()))
    }
}

fn send_one_if_active(source: &'static str) -> Result<bool> {
    let mut state = read_state();
    if !valid_state(&state) || state.enabled == 0 || pending_count(&state) == 0 {
        return Ok(false);
    }
    if !super::nan::raw_tx_active() {
        return Ok(false);
    }
    let kind = if state.discovery_remaining > 0 {
        "discover"
    } else {
        "status"
    };
    let seq = state.seq.saturating_add(1);
    // Raw NAN accepts the same compact-CBOR envelope as the other modem
    // transports. Include the sequence so the receiver's ping de-duplication
    // does not collapse a continuous test into a single request.
    let payload = test_ping_packet(seq);
    let queued = super::nan::queue_raw_broadcast(&payload)?;
    let sent_now = super::nan::drain_raw_queue();
    if sent_now > 0 {
        if kind == "discover" {
            state.discovery_remaining = state.discovery_remaining.saturating_sub(1);
        } else {
            state.remaining = state.remaining.saturating_sub(1);
        }
        state.seq = seq;
        state.sent = state.sent.saturating_add(sent_now as u32);
        let now = now_us();
        state.last_send_us_lo = now as u32;
        state.last_send_us_hi = (now >> 32) as u32;
        if pending_count(&state) == 0 {
            state.enabled = 0;
        }
        state = update_checksum(state);
        write_state(state);
    }
    telemetry::record_log(format!(
        "event type=test.ping source={} kind={} seq={} queued={} sent_now={} remaining={} discovery_remaining={} resp_rx={}",
        source,
        kind,
        seq,
        queued,
        sent_now,
        state.remaining,
        state.discovery_remaining,
        responses_seen(&state)
    ));
    Ok(sent_now > 0)
}

fn test_ping_packet(seq: u32) -> Vec<u8> {
    crate::commands::protocol::encode_binary(
        &CommandRequest::new_binary(33).arg_pair_by_tag(220, seq.to_string()),
    )
}

fn status_text() -> String {
    let state = read_state();
    let valid = valid_state(&state);
    format!(
        "test valid={} enabled={} total={} remaining={} discovery_remaining={} sent={} seq={} resp_rx={} wake_ms={} active_ms={} last_send_us={}",
        valid,
        valid && state.enabled != 0,
        if valid { state.total } else { 0 },
        if valid { state.remaining } else { 0 },
        if valid { state.discovery_remaining } else { 0 },
        if valid { state.sent } else { 0 },
        if valid { state.seq } else { 0 },
        if valid { responses_seen(&state) } else { 0 },
        if valid { state.wake_ms } else { 0 },
        if valid { state.active_ms } else { 0 },
        if valid { last_send_us(&state) } else { 0 }
    )
}

fn pending_count(state: &RtcTestState) -> u32 {
    state.remaining.saturating_add(state.discovery_remaining)
}

fn responses_seen(state: &RtcTestState) -> u32 {
    super::nan::raw_response_rx_count().saturating_sub(state.start_resp_rx)
}

fn read_state() -> RtcTestState {
    unsafe { core::ptr::addr_of!(RTC_TEST_STATE).read_volatile() }
}

fn write_state(state: RtcTestState) {
    unsafe {
        core::ptr::addr_of_mut!(RTC_TEST_STATE).write_volatile(state);
    }
}

fn valid_state(state: &RtcTestState) -> bool {
    state.magic == RTC_MAGIC
        && state.version == RTC_VERSION
        && state.len as usize == size_of::<RtcTestState>()
        && checksum_for_validation(state) == state.checksum
}

fn update_checksum(mut state: RtcTestState) -> RtcTestState {
    state.checksum = 0;
    state.checksum = checksum(&state);
    state
}

fn checksum_for_validation(state: &RtcTestState) -> u32 {
    let mut copy = *state;
    copy.checksum = 0;
    checksum(&copy)
}

fn checksum(state: &RtcTestState) -> u32 {
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (state as *const RtcTestState).cast::<u8>(),
            size_of::<RtcTestState>(),
        )
    };
    let mut hash = 0x811c_9dc5_u32;
    for byte in bytes {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn last_send_us(state: &RtcTestState) -> u64 {
    ((state.last_send_us_hi as u64) << 32) | state.last_send_us_lo as u64
}

fn parse_u32(value: &str, name: &str) -> Result<u32> {
    value
        .parse::<u32>()
        .map_err(|err| anyhow!("invalid {name}={value}: {err}"))
}

fn now_us() -> u64 {
    unsafe { sys::esp_timer_get_time().max(0) as u64 }
}

fn now_ms() -> u32 {
    (now_us() / 1000).min(u32::MAX as u64) as u32
}
