use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use esp_idf_sys as sys;
use minicbor::{Encoder, data::Tag};

use super::settings::SharedSettings;

/// Keep the debug transport usable long enough to issue a command after it wakes.
///
/// UART is re-opened by its next raw-NAN wake window, so an interactive
/// console window need only cover one command/response exchange.
pub const DEFAULT_ACTIVE_MS: u32 = 4_000;
/// Send a compact tagged wake event on every raw-NAN wake unless NVS overrides it.
///
/// This is the battery-node host rendezvous: it lets lmesh flush one queued
/// CBOR command during the already scheduled radio window.  It does not add a
/// wake or keep UART powered between raw-NAN windows.
/// Keep the console rendezvous out of most battery wake windows. Infrastructure
/// mode overrides this with its continuously active UART policy.
pub const DEFAULT_RAW_NAN_HEARTBEAT_EVERY: i32 = 8;
const MIN_ACTIVE_MS: u32 = 4_000;
/// Classic ESP32 retains UART/GPIO wake for its explicit raw-NAN sleep path.
/// ESP32-S3 uses the same explicit sleep path and its console wakes through
/// the normal UART/GPIO interrupt path.
#[cfg(not(target_feature = "esp32s3ops"))]
pub const RAW_NAN_UART_WAKE: bool = true;
#[cfg(not(target_feature = "esp32s3ops"))]
pub const RAW_NAN_BUTTON_WAKE: bool = true;

static UART0_SUSPEND_AFTER_RESPONSE: AtomicBool = AtomicBool::new(false);
static UART0_TX_DROPS_IDLE: AtomicU32 = AtomicU32::new(0);
static UART0_TX_DROPS_QUEUE: AtomicU32 = AtomicU32::new(0);
static UART0_OUTPUT_PROBE_DEADLINE_MS: AtomicU32 = AtomicU32::new(0);
static UART0_OUTPUT_PROBE_ATTEMPTS: AtomicU32 = AtomicU32::new(0);
static UART0_OUTPUT_PROBE_SENT: AtomicU32 = AtomicU32::new(0);
static UART0_OUTPUT_PROBE_DROPPED: AtomicU32 = AtomicU32::new(0);
static UART0_HEARTBEAT_EVERY: AtomicU32 = AtomicU32::new(DEFAULT_RAW_NAN_HEARTBEAT_EVERY as u32);
static UART0_HEARTBEAT_WAKES: AtomicU32 = AtomicU32::new(0);
static UART0_HEARTBEAT_SENT: AtomicU32 = AtomicU32::new(0);
static UART0_HEARTBEAT_DROPPED: AtomicU32 = AtomicU32::new(0);
static UART0_HEARTBEAT_WINDOW_MS: AtomicU32 = AtomicU32::new(0);

/// Retired UART-driver removal power measurement.
///
/// The shared L2 task owns the driver for the full process lifetime; a Main
/// component must not remove it beneath a live bearer.
pub fn request_uninstall_for_measurement() {
    // The common UART L2 task owns the driver and its queues.  A component
    // command cannot safely tear it down; keep the measurement request
    // explicitly unsupported rather than retaining a second lifecycle path.
}

pub fn measurement_status_fields() -> String {
    format!(
        "uart_active={} uart_tx_drop_idle={} uart_tx_drop_queue={} uart_hb_every={} uart_hb_wakes={} uart_hb_sent={} uart_hb_dropped={} uart_hb_window_ms={} uart_probe_attempts={} uart_probe_sent={} uart_probe_dropped={}",
        is_active(),
        UART0_TX_DROPS_IDLE.load(Ordering::Relaxed),
        UART0_TX_DROPS_QUEUE.load(Ordering::Relaxed),
        UART0_HEARTBEAT_EVERY.load(Ordering::Relaxed),
        UART0_HEARTBEAT_WAKES.load(Ordering::Relaxed),
        UART0_HEARTBEAT_SENT.load(Ordering::Relaxed),
        UART0_HEARTBEAT_DROPPED.load(Ordering::Relaxed),
        UART0_HEARTBEAT_WINDOW_MS.load(Ordering::Relaxed),
        UART0_OUTPUT_PROBE_ATTEMPTS.load(Ordering::Relaxed),
        UART0_OUTPUT_PROBE_SENT.load(Ordering::Relaxed),
        UART0_OUTPUT_PROBE_DROPPED.load(Ordering::Relaxed),
    )
}

/// Schedule one debug-only output attempt after `delay_ms`.
///
/// The power command uses this to verify that output really is gated after a
/// console active window expires. It never changes radio or sleep policy.
pub fn schedule_output_probe(delay_ms: u32) -> u32 {
    let deadline = now_ms().wrapping_add(delay_ms).max(1);
    UART0_OUTPUT_PROBE_DEADLINE_MS.store(deadline, Ordering::Release);
    deadline
}

/// Clear output-gate probe state before a bounded verification run.
pub fn reset_output_probe() {
    UART0_OUTPUT_PROBE_DEADLINE_MS.store(0, Ordering::Release);
    UART0_OUTPUT_PROBE_ATTEMPTS.store(0, Ordering::Relaxed);
    UART0_OUTPUT_PROBE_SENT.store(0, Ordering::Relaxed);
    UART0_OUTPUT_PROBE_DROPPED.store(0, Ordering::Relaxed);
}

pub fn configure_active_window(settings: &SharedSettings) {
    let configured_ms = settings
        .borrow()
        .get_i32("uart.active_ms", DEFAULT_ACTIVE_MS as i32)
        .unwrap_or(DEFAULT_ACTIVE_MS as i32)
        .max(0) as u32;
    // Delimiter framing makes the first complete CBOR command self-synchronizing,
    // so a short window is sufficient and avoids holding PM locks for 20 seconds.
    let active_ms = configured_ms.max(MIN_ACTIVE_MS);
    dmesh_fw_transport::uart_esp::configure_active_window(active_ms);
    set_heartbeat_every(
        settings
            .borrow()
            .get_i32("uart.hb_every", DEFAULT_RAW_NAN_HEARTBEAT_EVERY)
            .unwrap_or(DEFAULT_RAW_NAN_HEARTBEAT_EVERY)
            .max(0) as u32,
    );
    activate_window();
}

/// Configure the raw-NAN wake heartbeat cadence.
///
/// Zero suppresses both periodic heartbeats and radio-event UART activation.
/// A nonzero value emits one tagged event on every Nth raw-NAN wake.
pub fn set_heartbeat_every(every: u32) {
    let previous = UART0_HEARTBEAT_EVERY.swap(every, Ordering::AcqRel);
    if previous != every {
        UART0_HEARTBEAT_WAKES.store(0, Ordering::Release);
    }
}

/// Open the bounded UART console window from an authenticated/in-band wake
/// trigger such as a targeted NAN service advertisement.
pub fn activate_window_for(window_ms: u32) {
    dmesh_fw_transport::uart_esp::activate_window_for(window_ms);
}

const NAN_SLEEPY_START_TAG: u64 = 6;
const NAN_SLEEPY_START_FLAGS: u16 = 0;
const NAN_SLEEPY_START_RECENT_NAN: u16 = 1 << 0;
const NAN_SLEEPY_START_RECENT_RADIO: u16 = 1 << 1;
const NAN_SLEEPY_START_CLUSTER_CHANGED: u16 = 1 << 2;

static LAST_WAKE_LORA_RX: AtomicU32 = AtomicU32::new(0);
static LAST_WAKE_NAN_BEACON_RX: AtomicU32 = AtomicU32::new(0);
static LAST_WAKE_NAN_CLUSTER_RESELECTS: AtomicU32 = AtomicU32::new(0);

/// Build the compact DMesh-private NAN sleepy-start event.
///
/// Tag 6 is one byte on the wire. The unchanged event is `c6 a0`; optional
/// integer keys carry only deltas, so an idle 64 ms window remains two CBOR
/// bytes while useful radio/NAN changes fit without text diagnostics.
fn nan_sleepy_start_payload() -> Vec<u8> {
    let lora_rx = super::telemetry::lora_rx_packets();
    let nan_beacons = super::nan::nan_beacon_snapshot().count;
    let cluster_reselects = super::nan::nan_cluster_reselects();
    let lora_delta = lora_rx.saturating_sub(LAST_WAKE_LORA_RX.swap(lora_rx, Ordering::AcqRel));
    let nan_delta =
        nan_beacons.saturating_sub(LAST_WAKE_NAN_BEACON_RX.swap(nan_beacons, Ordering::AcqRel));
    let cluster_changed = cluster_reselects
        != LAST_WAKE_NAN_CLUSTER_RESELECTS.swap(cluster_reselects, Ordering::AcqRel);
    let mut flags = NAN_SLEEPY_START_FLAGS;
    if nan_delta != 0 {
        flags |= NAN_SLEEPY_START_RECENT_NAN;
    }
    if lora_delta != 0 {
        flags |= NAN_SLEEPY_START_RECENT_RADIO;
    }
    if cluster_changed {
        flags |= NAN_SLEEPY_START_CLUSTER_CHANGED;
    }

    let optional_count = usize::from(lora_delta != 0) + usize::from(nan_delta != 0);
    let field_count = usize::from(flags != 0) + optional_count;
    let mut payload = Vec::with_capacity(3 + field_count * 3);
    let mut encoder = Encoder::new(&mut payload);
    encoder
        .tag(Tag::new(NAN_SLEEPY_START_TAG))
        .expect("CBOR tag");
    encoder.map(field_count as u64).expect("CBOR map");
    if flags != 0 {
        encoder
            .u8(0)
            .expect("CBOR flags")
            .u16(flags)
            .expect("CBOR flags value");
        if lora_delta != 0 {
            encoder
                .u8(1)
                .expect("CBOR lora key")
                .u32(lora_delta)
                .expect("CBOR lora delta");
        }
        if nan_delta != 0 {
            encoder
                .u8(2)
                .expect("CBOR NAN key")
                .u32(nan_delta)
                .expect("CBOR NAN delta");
        }
    }
    payload
}

fn emit_nan_sleepy_start(window_ms: u32) -> bool {
    UART0_HEARTBEAT_WINDOW_MS.store(window_ms, Ordering::Relaxed);
    activate_window_for(window_ms);
    let payload = nan_sleepy_start_payload();
    if write_direct_record(&payload) {
        UART0_HEARTBEAT_SENT.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        UART0_HEARTBEAT_DROPPED.fetch_add(1, Ordering::Relaxed);
        false
    }
}

/// Account for a raw-NAN duty wake and emit its configured tagged wake event.
pub fn on_raw_nan_wake(active_ms: u32) -> bool {
    let every = UART0_HEARTBEAT_EVERY.load(Ordering::Acquire);
    if every == 0 {
        return false;
    }
    let wake = UART0_HEARTBEAT_WAKES.fetch_add(1, Ordering::AcqRel) + 1;
    wake % every == 0 && emit_nan_sleepy_start(active_ms)
}

/// Keep the local UART recovery path alive when NAN synchronization is absent.
/// This is deliberately independent of `uart.hb_every`: without a beacon the
/// host has no other way to learn that the device is awake and send a command.
/// The window is bounded to the current raw-NAN active dwell and is only used
/// by the sleepy-mode no-sync fallback; it does not make the UART permanent.
pub fn on_uart_recovery_wake(window_ms: u32) -> bool {
    emit_nan_sleepy_start(window_ms)
}

/// Return whether the shared UART L2 task has a complete direct exception
/// record or QUIC-lite datagram ready. This deliberately does not touch the
/// UART driver; sleep policy only needs a bounded dispatcher-work hint.
pub fn has_pending_ingress() -> bool {
    dmesh_fw_transport::uart_esp::has_pending_ingress()
}

/// Retired measurement hook retained only until the old power-command source
/// is deleted. The shared UART L2 owner cannot safely be torn down from a
/// component-level deferred response.
pub fn finish_pending_uninstall() -> std::result::Result<bool, sys::esp_err_t> {
    // The old task pair could be deleted with its UART driver. The shared
    // `dmesh_fw_transport::uart_esp` task now owns that driver and the
    // bounded queues used by sleepy wake. Deleting it here would leave a live
    // L2 task with invalid driver state, so fail closed until a coordinated
    // common-adapter stop/restart lifecycle is intentionally designed.
    Err(sys::ESP_ERR_NOT_SUPPORTED)
}

pub fn activate_window() {
    poll_output_probe();
    dmesh_fw_transport::uart_esp::activate_window();
}

pub fn poll_active_window() {
    dmesh_fw_transport::uart_esp::poll_active_window();
}

/// Run a due output-gate probe from the control task.
pub fn poll_output_probe() {
    let deadline = UART0_OUTPUT_PROBE_DEADLINE_MS.load(Ordering::Acquire);
    if deadline == 0 || !time_after_or_equal(now_ms(), deadline) {
        return;
    }
    if UART0_OUTPUT_PROBE_DEADLINE_MS
        .compare_exchange(deadline, 0, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let attempt = UART0_OUTPUT_PROBE_ATTEMPTS.fetch_add(1, Ordering::Relaxed) + 1;
    if is_active() {
        UART0_OUTPUT_PROBE_SENT.fetch_add(1, Ordering::Relaxed);
        super::telemetry::record_log(format!(
            "event type=uart.output_probe n={} sent=true",
            attempt
        ));
    } else {
        UART0_OUTPUT_PROBE_DROPPED.fetch_add(1, Ordering::Relaxed);
        // Keep this on the normal write path so uart_tx_drop_idle confirms the
        // output gate, while the dedicated counter distinguishes this test
        // from expected background notification drops.
        super::telemetry::record_log(format!(
            "event type=uart.output_probe n={} sent=false",
            attempt
        ));
    }
}

pub fn is_active() -> bool {
    dmesh_fw_transport::uart_esp::is_active()
}

/// Whether UART was explicitly opened as a bounded interactive window.
///
/// Infrastructure nodes hold the UART power lock permanently so that the
/// managed lmesh forward never disappears.  That persistent lock must not
/// turn a queued NAN packet into an arbitrary-time transmission to a sleepy
/// peer; callers that need to bypass DW gating must use this predicate.
pub fn interactive_active() -> bool {
    dmesh_fw_transport::uart_esp::interactive_active()
}

/// Keep the infrastructure UART and its power lock active continuously.
pub fn set_always_on(enabled: bool) {
    dmesh_fw_transport::uart_esp::set_always_on(enabled);
}

pub fn set_debug_enabled(enabled: bool) {
    dmesh_fw_transport::uart_esp::set_debug_enabled(enabled);
}

/// Restore UART RX after a light-sleep wake.
///
/// The common L2 owner re-arms the interrupt and wake threshold before the
/// host sends the first command.
pub fn rearm_after_wake() {
    dmesh_fw_transport::uart_esp::rearm_after_wake();
}

/// Close the console immediately after the current command response is sent.
/// The next scheduled UART/radio rendezvous can reopen it.
pub fn request_suspend_after_response() {
    UART0_SUSPEND_AFTER_RESPONSE.store(true, Ordering::Relaxed);
}

/// Consume the post-response close request. Call only after writing the
/// response to the command that requested the transition.
pub fn finish_pending_suspend() -> bool {
    if !UART0_SUSPEND_AFTER_RESPONSE.swap(false, Ordering::SeqCst) {
        return false;
    }
    // "quiet" suppresses TX and permits light sleep. RX remains armed so a
    // line (or its wake preamble) is sufficient to reopen the console.
    dmesh_fw_transport::uart_esp::set_debug_enabled(false);
    true
}

/// Release UART power locks while retaining the normal framed RX wake.
pub fn suspend_for_light_sleep() {
    // Keep RX interrupt and UART wake armed. The shared ingress task turns
    // received bytes into a console-active window; disabling RX here would
    // strand sleeping boards from their next rendezvous.
    dmesh_fw_transport::uart_esp::suspend_for_light_sleep();
}

/// Emit one opaque QUIC-lite datagram over the UART PPP L2 bearer. Command
/// encoding is deliberately above this adapter.
pub fn write_transport_packet(packet: &[u8]) -> bool {
    // QUIC-lite replies are bearer protocol traffic, not console output. An
    // inbound framed packet already proves that this bearer is in use; gating
    // its bootstrap ACK on the human-console window deadlocks a sleeping
    // device before connection flow control can provide backpressure.
    if !dmesh_fw_transport::uart_esp::send_transport_packet(packet) {
        UART0_TX_DROPS_QUEUE.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    true
}

/// Emit a bounded direct-CBOR exception record through Main's sole UART
/// writer.  This is intentionally limited to bootstrap/boot identity paths;
/// normal operations must use QUIC-lite streams.
pub fn write_direct_record(record: &[u8]) -> bool {
    if !is_active() {
        UART0_TX_DROPS_IDLE.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    if !dmesh_fw_transport::uart_esp::send_direct_record(record) {
        UART0_TX_DROPS_QUEUE.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    true
}

fn now_ms() -> u32 {
    unsafe { (sys::esp_timer_get_time() / 1000) as u32 }
}

fn time_after_or_equal(now: u32, deadline: u32) -> bool {
    now.wrapping_sub(deadline) < i32::MAX as u32
}

#[cfg(test)]
mod tests {
    use super::nan_sleepy_start_payload;
    use uart_codec::codec::{UART_ESCAPE, UART_FLAG, encode_payload};

    const UART_MAX_BODY: usize = dmesh_fw_transport::TRANSPORT_MTU + 1;

    fn new_uart_parser() -> uart_codec::codec::Decoder {
        uart_codec::codec::Decoder::with_max(UART_MAX_BODY)
    }

    fn framed(payload: &[u8]) -> Vec<u8> {
        encode_payload(payload, UART_MAX_BODY).unwrap()
    }

    #[test]
    fn binary_uart_round_trips_cbor_payload() {
        let mut parser = new_uart_parser();
        let frame = framed(&[1, 2, 3, 4, 5]);
        assert_eq!(parser.push(&frame).unwrap(), vec![vec![1, 2, 3, 4, 5]]);
    }

    #[test]
    fn binary_uart_accepts_transport_mtu_record() {
        let mut parser = new_uart_parser();
        let input = framed(&vec![0_u8; UART_MAX_BODY]);
        assert_eq!(parser.push(&input).unwrap()[0].len(), UART_MAX_BODY);
    }

    #[test]
    fn binary_uart_ignores_unframed_boot_noise() {
        let mut parser = new_uart_parser();
        let mut input = b"rst:0x1 (POWERON_RESET)\r\n".to_vec();
        input.extend_from_slice(&framed(&[1]));
        assert_eq!(parser.push(&input).unwrap(), vec![vec![1]]);
    }

    #[test]
    fn escaped_flag_and_escape_round_trip() {
        let mut parser = new_uart_parser();
        let payload = [UART_FLAG, UART_ESCAPE, 0x01];
        let frame = framed(&payload);
        assert!(frame.contains(&UART_ESCAPE));
        assert_eq!(parser.push(&frame).unwrap(), vec![payload.to_vec()]);
    }

    #[test]
    fn nan_sleepy_start_without_deltas_is_two_cbor_bytes() {
        let payload = nan_sleepy_start_payload();
        assert_eq!(payload, vec![0xc6, 0xa0]);
        assert_eq!(framed(&payload), vec![UART_FLAG, 0xc6, 0xa0, UART_FLAG]);
    }
}
