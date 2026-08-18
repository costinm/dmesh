use std::collections::VecDeque;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uchar, c_ushort};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::settings::{parse_bool, parse_i32, SharedSettings};
use super::telemetry::{self, Direction};

extern "C" {
    fn dmesh_nimble_init() -> c_int;
    fn dmesh_nimble_start_advertising(
        adv: *const c_uchar,
        adv_len: c_uchar,
        min_units: c_ushort,
        max_units: c_ushort,
    ) -> c_int;
    fn dmesh_nimble_start_pairing_advertising(min_units: c_ushort, max_units: c_ushort) -> c_int;
    fn dmesh_nimble_stop_advertising() -> c_int;
    fn dmesh_nimble_start_scan(duration_ms: u32, active: c_uchar) -> c_int;
    fn dmesh_nimble_stop_scan() -> c_int;
    fn dmesh_nimble_notify(data: *const c_uchar, len: c_ushort) -> c_int;
    fn dmesh_nimble_clear_bonds() -> c_int;
    fn dmesh_nimble_set_bonding(enabled: c_uchar) -> c_int;
    fn dmesh_nimble_set_raw_nan_link_profile(enabled: c_uchar) -> c_int;
    fn dmesh_nimble_tx_handle() -> c_ushort;
    fn dmesh_nimble_rx_handle() -> c_ushort;
    fn dmesh_nimble_enable_sleep() -> c_int;
    fn dmesh_nimble_disable_sleep() -> c_int;
    fn dmesh_nimble_start_coc_server(psm: c_ushort) -> c_int;
    fn dmesh_nimble_coc_server_psm() -> c_ushort;
    fn dmesh_nimble_coc_connected() -> bool;
    fn dmesh_nimble_coc_send(data: *const c_uchar, len: c_ushort) -> c_int;
}

static BLE_STARTED: AtomicBool = AtomicBool::new(false);
static BLE_ADV_STARTED: AtomicBool = AtomicBool::new(false);
static BLE_SCAN_STARTED: AtomicBool = AtomicBool::new(false);
static BLE_MODE: AtomicU8 = AtomicU8::new(BLE_MODE_OFF);
static BLE_SCAN_REPORTS: AtomicU32 = AtomicU32::new(0);
static BLE_SCAN_MATCHED: AtomicU32 = AtomicU32::new(0);
static BLE_SCAN_LAST_RSSI: AtomicI32 = AtomicI32::new(0);
static BLE_FILTER_DMESH: AtomicBool = AtomicBool::new(true);
static BLE_FILTER_UUID16: AtomicU32 = AtomicU32::new(0);
static BLE_FILTER_ADDR_ENABLED: AtomicBool = AtomicBool::new(false);
static BLE_ANNOUNCE_TX: AtomicU32 = AtomicU32::new(0);
static BLE_ANNOUNCE_RX: AtomicU32 = AtomicU32::new(0);
static BLE_WAKE_REQUEST_RX: AtomicU32 = AtomicU32::new(0);
static BLE_PENDING_SWITCHES: AtomicU32 = AtomicU32::new(0);
static BLE_GATT_STARTED: AtomicBool = AtomicBool::new(false);
static BLE_GATT_CONNECTED: AtomicBool = AtomicBool::new(false);
static BLE_GATT_NOTIFY_ENABLED: AtomicBool = AtomicBool::new(false);
static BLE_GATT_AUTHENTICATED: AtomicBool = AtomicBool::new(false);
static BLE_GATT_RX_TEXT: AtomicU32 = AtomicU32::new(0);
static BLE_GATT_RX_BINARY: AtomicU32 = AtomicU32::new(0);
static BLE_GATT_TX: AtomicU32 = AtomicU32::new(0);
static BLE_GATT_CONN_ID: AtomicU32 = AtomicU32::new(0xffff);
static BLE_GATT_TX_HANDLE: AtomicU32 = AtomicU32::new(0);
static BLE_GATT_RX_HANDLE: AtomicU32 = AtomicU32::new(0);
static BLE_COMMAND_QUEUE: OnceLock<Mutex<VecDeque<BleCommand>>> = OnceLock::new();
static BLE_COMPANION_ENABLED: AtomicBool = AtomicBool::new(false);
static BLE_COMPANION_SAVE_PENDING: AtomicBool = AtomicBool::new(false);
static BLE_PAIRING_DEADLINE_MS: AtomicU32 = AtomicU32::new(0);
static BLE_PAIRING_ACCEPTED: AtomicBool = AtomicBool::new(false);
static BLE_PAIRING_REQUEST_DEADLINE_MS: AtomicU32 = AtomicU32::new(0);
static BLE_PAIRING_CONFIRM_TIMEOUT_MS: AtomicU32 = AtomicU32::new(60_000);
static BLE_FIXED_PIN: AtomicU32 = AtomicU32::new(0);
static BLE_PENDING_NOTIFY: AtomicBool = AtomicBool::new(false);
static BLE_COMPANION_ADV_PERIOD_MS: AtomicU32 = AtomicU32::new(0);
static BLE_COMPANION_ADV_WINDOW_MS: AtomicU32 = AtomicU32::new(0);
static BLE_COMPANION_ADV_STATE: AtomicBool = AtomicBool::new(false);
static BLE_COMPANION_ADV_NEXT_MS: AtomicU32 = AtomicU32::new(0);
static BLE_COMPANION_ACTIVE_MS: AtomicU32 = AtomicU32::new(10_000);
static BLE_COMPANION_ACTIVE_DEADLINE_MS: AtomicU32 = AtomicU32::new(0);
static BLE_COMPANION_ACTIVE_CHANGED: AtomicBool = AtomicBool::new(false);
static BLE_ADV_INT_MIN: AtomicU32 = AtomicU32::new(0x20);
static BLE_ADV_INT_MAX: AtomicU32 = AtomicU32::new(0x40);
static BLE_READY: AtomicBool = AtomicBool::new(false);
static BLE_BONDS_CLEARED: AtomicU32 = AtomicU32::new(0);
static BLE_RENDEZVOUS_SCAN_DEADLINE_MS: AtomicU32 = AtomicU32::new(0);
static BLE_RENDEZVOUS_WAKE_SEEN: AtomicBool = AtomicBool::new(false);
static BLE_RENDEZVOUS_ADV_DEADLINE_MS: AtomicU32 = AtomicU32::new(0);
static BLE_RENDEZVOUS_SCAN_MS: AtomicU32 = AtomicU32::new(250);
static BLE_RENDEZVOUS_ADV_MS: AtomicU32 = AtomicU32::new(1_000);
static BLE_COC_PSM: AtomicU32 = AtomicU32::new(0);
static BLE_COC_CONNECTED: AtomicBool = AtomicBool::new(false);
static BLE_COC_RX: AtomicU32 = AtomicU32::new(0);
static BLE_COC_TX: AtomicU32 = AtomicU32::new(0);
static BLE_BONDING_ENABLED: AtomicBool = AtomicBool::new(false);
static BLE_RAW_NAN_LINK_PROFILE: AtomicBool = AtomicBool::new(false);
// Lab-only policy switch: retain connectable BLE across raw-NAN's Wi-Fi-off
// interval so GATT and CoC can be compared with the same 4-second scheduler.
static BLE_RAW_NAN_KEEP_ACTIVE: AtomicBool = AtomicBool::new(false);

static BLE_CONNECTED_ADDR: [AtomicU8; 6] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
];
static BLE_PAIRED_ADDR: [AtomicU8; 6] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
];
static BLE_PAIRING_REQUEST_ADDR: [AtomicU8; 6] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
];
static BLE_LOCAL_ADDR: [AtomicU8; 6] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
];
static BLE_LOCAL_ADDR_TYPE: AtomicU8 = AtomicU8::new(0xff);

#[allow(dead_code)]
/// Temporary adopted IPSP identity used for compact legacy discovery records.
/// The actual DMesh GATT characteristics remain under the 128-bit DMesh UUID.
pub const DMESH_BLE_SERVICE_UUID16: u16 = 0x1820;
pub const DMESH_BLE_PAIRING_UUID: [u8; 16] = [
    0x01, 0x00, 0x68, 0x73, 0x65, 0x4d, 0x42, 0x8c, 0x6f, 0x4a, 0x2a, 0x4f, 0x80, 0x6f, 0x6b, 0x5f,
];
pub const DMESH_BLE_OPERATIONAL_UUID: [u8; 16] = [
    0x02, 0x00, 0x68, 0x73, 0x65, 0x4d, 0x42, 0x8c, 0x6f, 0x4a, 0x2a, 0x4f, 0x80, 0x6f, 0x6b, 0x5f,
];
pub const DMESH_GATT_SERVICE_UUID: [u8; 16] = [
    0x03, 0x00, 0x68, 0x73, 0x65, 0x4d, 0x42, 0x8c, 0x6f, 0x4a, 0x2a, 0x4f, 0x80, 0x6f, 0x6b, 0x5f,
];
pub const DMESH_GATT_RX_UUID: [u8; 16] = [
    0x04, 0x00, 0x68, 0x73, 0x65, 0x4d, 0x42, 0x8c, 0x6f, 0x4a, 0x2a, 0x4f, 0x80, 0x6f, 0x6b, 0x5f,
];
pub const DMESH_GATT_TX_UUID: [u8; 16] = [
    0x05, 0x00, 0x68, 0x73, 0x65, 0x4d, 0x42, 0x8c, 0x6f, 0x4a, 0x2a, 0x4f, 0x80, 0x6f, 0x6b, 0x5f,
];

pub const PAIRING_RECOVERY_WINDOW_MS: u32 = 300_000;
const BLE_MODE_OFF: u8 = 0;
const BLE_MODE_LISTEN: u8 = 1;
const BLE_MODE_ANNOUNCE: u8 = 2;
const BLE_MODE_CONNECTABLE: u8 = 3;

#[derive(Clone, Copy)]
enum BleTransport {
    Gatt,
    Coc,
}

struct BleCommand {
    transport: BleTransport,
    data: Vec<u8>,
}

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    {
        let settings_ref = settings.borrow();
        BLE_COMPANION_ENABLED.store(
            settings_ref.get_bool("ble.comp", false).unwrap_or(false),
            Ordering::Relaxed,
        );
        BLE_FIXED_PIN.store(
            settings_ref
                .get_i32("ble.fixed_pin", 0)
                .unwrap_or(0)
                .clamp(0, 999_999) as u32,
            Ordering::Relaxed,
        );
        BLE_RENDEZVOUS_SCAN_MS.store(
            settings_ref
                .get_i32("bc.scan_ms", 250)
                .unwrap_or(250)
                .clamp(50, 2_000) as u32,
            Ordering::Relaxed,
        );
        BLE_RENDEZVOUS_ADV_MS.store(
            settings_ref
                .get_i32("bc.adv_ms", 1_000)
                .unwrap_or(1_000)
                .clamp(100, 10_000) as u32,
            Ordering::Relaxed,
        );
    }
    registry.register(RadioCommand::with_settings("ble", settings));
}

pub fn advertised_identity() -> String {
    format!(
        "mac={} addr_type={} adv_uuid={} pair_uuid={} transport=coc gatt_service=false",
        public_bt_address_string(),
        BLE_LOCAL_ADDR_TYPE.load(Ordering::Relaxed),
        uuid128_string(&DMESH_BLE_OPERATIONAL_UUID),
        uuid128_string(&DMESH_BLE_PAIRING_UUID)
    )
}

pub fn uuid128_string(uuid: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid[15], uuid[14], uuid[13], uuid[12], uuid[11], uuid[10], uuid[9], uuid[8],
        uuid[7], uuid[6], uuid[5], uuid[4], uuid[3], uuid[2], uuid[1], uuid[0]
    )
}

pub fn forward_packet_for_window(packet: &[u8], window_ms: u32) -> Result<bool> {
    ensure_ble()?;
    announce_packet(DmeshBleEvent::PayloadPending, packet, None)?;
    send_coc(packet);
    let deadline = Instant::now() + Duration::from_millis(window_ms as u64);
    while Instant::now() < deadline {
        task_delay(Duration::from_millis(100));
    }
    Ok(true)
}

pub fn start_listen_mode() -> Result<()> {
    ensure_ble()?;
    start_scan_params(0, true)?;
    BLE_MODE.store(BLE_MODE_LISTEN, Ordering::Relaxed);
    Ok(())
}

pub fn enable_controller_sleep() -> Result<()> {
    if !BLE_STARTED.load(Ordering::Relaxed) {
        return Ok(());
    }
    let rc = unsafe { dmesh_nimble_enable_sleep() };
    if rc != 0 {
        bail!("nimble controller sleep enable rc={rc}");
    }
    telemetry::record_log("event type=ble.controller_sleep enabled=true");
    Ok(())
}

pub fn disable_controller_sleep() -> Result<()> {
    if !BLE_STARTED.load(Ordering::Relaxed) {
        return Ok(());
    }
    let rc = unsafe { dmesh_nimble_disable_sleep() };
    if rc != 0 {
        bail!("nimble controller sleep disable rc={rc}");
    }
    telemetry::record_log("event type=ble.controller_sleep enabled=false");
    Ok(())
}

pub fn stop_radio_activity() {
    if BLE_RAW_NAN_KEEP_ACTIVE.load(Ordering::Relaxed) {
        telemetry::record_log("event type=ble.radio_stop deferred=keep_active");
        return;
    }
    force_stop_radio_activity();
}

/// Stop BLE activity even while the explicit connectivity-test override is set.
pub fn force_stop_radio_activity() {
    if BLE_STARTED.load(Ordering::Relaxed) {
        unsafe {
            let _ = dmesh_nimble_stop_advertising();
            let _ = dmesh_nimble_stop_scan();
        }
    }
    BLE_ADV_STARTED.store(false, Ordering::Relaxed);
    BLE_SCAN_STARTED.store(false, Ordering::Relaxed);
    BLE_MODE.store(BLE_MODE_OFF, Ordering::Relaxed);
}

/// Whether an Android client currently owns the ESP GATT server connection.
/// Raw-NAN uses this to avoid entering a CPU light-sleep interval that would
/// exceed the negotiated BLE supervision timeout.
pub fn gatt_connected() -> bool {
    BLE_GATT_CONNECTED.load(Ordering::Relaxed)
}

/// A live companion transport keeps the ESP awake for the short transfer.
/// CoC and GATT have the same raw-NAN sleep policy: disconnect before the
/// next idle interval, then resume rendezvous advertising/scanning.
pub fn companion_connected() -> bool {
    BLE_GATT_CONNECTED.load(Ordering::Relaxed)
        || BLE_COC_CONNECTED.load(Ordering::Relaxed)
        || unsafe { dmesh_nimble_coc_connected() }
}

/// True while a bounded scan or response advertisement owns the current
/// raw-NAN awake window. This deliberately does not include idle BLE state.
pub fn rendezvous_active() -> bool {
    let now = now_ms();
    let scan = BLE_RENDEZVOUS_SCAN_DEADLINE_MS.load(Ordering::Relaxed);
    let adv = BLE_RENDEZVOUS_ADV_DEADLINE_MS.load(Ordering::Relaxed);
    BLE_GATT_CONNECTED.load(Ordering::Relaxed)
        || (scan != 0 && now.wrapping_sub(scan) >= i32::MAX as u32)
        || (adv != 0 && now.wrapping_sub(adv) >= i32::MAX as u32)
}

/// Start the bounded BLE rendezvous for a raw-NAN active window.
///
/// This only makes the ESP discoverable. Android treats the advertisement as a
/// pending-data signal and opens a short-lived CoC channel; DMesh does not use
/// GATT for payloads. This is active after either the saved companion policy
/// (`ble.comp=true`) or an explicit current-boot `ble start=true` request.
/// The latter keeps the transport probe independent of pairing/encryption
/// policy.
pub fn raw_nan_wake_window() {
    if !BLE_COMPANION_ENABLED.load(Ordering::Relaxed) && !BLE_STARTED.load(Ordering::Relaxed) {
        return;
    }
    if companion_connected() {
        telemetry::record_log("event type=ble.raw_nan state=connection_retained");
        return;
    }
    if BLE_RAW_NAN_KEEP_ACTIVE.load(Ordering::Relaxed) {
        if !BLE_ADV_STARTED.load(Ordering::Relaxed) {
            if let Err(err) = start_connectable_idle() {
                telemetry::record_log(format!(
                    "event type=ble.raw_nan state=retain_failed msg={}",
                    crate::commands::protocol::escape_value(&err.to_string())
                ));
                return;
            }
        }
        telemetry::record_log("event type=ble.raw_nan state=advertising_retained");
        return;
    }
    let pending = telemetry::pending_message_count() > 0;
    let scan_ms = companion_scan_ms();
    if pending {
        match start_connectable_event(DmeshBleEvent::PayloadPending, &[]) {
            Ok(()) => {
                open_companion_active_window(companion_adv_ms());
                telemetry::record_log("event type=ble.raw_nan state=payload_advertising");
            }
            Err(err) => {
                telemetry::record_log(format!(
                    "event type=ble.raw_nan state=advertise_failed msg={}",
                    crate::commands::protocol::escape_value(&err.to_string())
                ));
            }
        }
    } else if scan_ms == 0 {
        return;
    } else {
        match start_scan_params(scan_ms, true) {
            Ok(()) => {
                BLE_RENDEZVOUS_WAKE_SEEN.store(false, Ordering::Relaxed);
                BLE_RENDEZVOUS_SCAN_DEADLINE_MS
                    .store(now_ms().wrapping_add(scan_ms), Ordering::Relaxed);
                telemetry::record_log(format!(
                    "event type=ble.raw_nan state=wake_scan scan_ms={scan_ms}"
                ));
            }
            Err(err) => {
                telemetry::record_log(format!(
                    "event type=ble.raw_nan state=scan_failed msg={}",
                    crate::commands::protocol::escape_value(&err.to_string())
                ));
            }
        }
    }
}

/// Align disconnected BLE radio-off time with raw-NAN's Wi-Fi-off interval.
/// A connected link remains up so explicit light sleep can prove whether it
/// survives the interval or must use the next advertisement to reconnect.
pub fn raw_nan_idle_window() {
    if !BLE_COMPANION_ENABLED.load(Ordering::Relaxed) && !BLE_STARTED.load(Ordering::Relaxed) {
        return;
    }
    if companion_connected() {
        telemetry::record_log("event type=ble.raw_nan state=connection_retained");
    } else if BLE_RAW_NAN_KEEP_ACTIVE.load(Ordering::Relaxed) {
        if let Err(err) = enable_controller_sleep() {
            telemetry::record_log(format!(
                "event type=ble.raw_nan state=retain_sleep_failed msg={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
        }
        telemetry::record_log("event type=ble.raw_nan state=advertising_retained");
    } else {
        stop_radio_activity();
        telemetry::record_log("event type=ble.raw_nan state=off");
    }
}

pub fn raw_nan_keep_active() -> bool {
    BLE_RAW_NAN_KEEP_ACTIVE.load(Ordering::Relaxed)
}

pub fn configure_companion_advertising(period_ms: u32, window_ms: u32) {
    let window_ms = window_ms.min(period_ms);
    BLE_COMPANION_ADV_PERIOD_MS.store(period_ms, Ordering::Relaxed);
    BLE_COMPANION_ADV_WINDOW_MS.store(window_ms, Ordering::Relaxed);
    BLE_COMPANION_ADV_STATE.store(false, Ordering::Relaxed);
    BLE_COMPANION_ADV_NEXT_MS.store(now_ms().wrapping_add(200), Ordering::Relaxed);
}

pub fn configure_companion_active_window(timeout_ms: u32) {
    BLE_COMPANION_ACTIVE_MS.store(timeout_ms.max(1_000), Ordering::Relaxed);
}

pub fn open_companion_active_window(timeout_ms: u32) {
    if timeout_ms == 0 {
        BLE_COMPANION_ACTIVE_DEADLINE_MS.store(0, Ordering::Relaxed);
        BLE_COMPANION_ACTIVE_CHANGED.store(true, Ordering::Relaxed);
        stop_radio_activity();
        return;
    }
    BLE_COMPANION_ACTIVE_DEADLINE_MS.store(now_ms().wrapping_add(timeout_ms), Ordering::Relaxed);
    BLE_COMPANION_ACTIVE_CHANGED.store(true, Ordering::Relaxed);
    // The mode transition has already started the connectable advertisement.
    // Replacing it again here races the controller's asynchronous stop/start
    // sequence and can wedge the classic ESP32 host before it processes the
    // next console request.  Only start it when this window is opened by a
    // caller that did not already create an advertisement.
    if BLE_COMPANION_ENABLED.load(Ordering::Relaxed) && !BLE_ADV_STARTED.load(Ordering::Relaxed) {
        let _ = start_connectable_idle();
    }
    telemetry::record_log(format!(
        "event type=ble.companion active=true timeout_ms={}",
        timeout_ms
    ));
}

pub fn companion_active() -> bool {
    let deadline = BLE_COMPANION_ACTIVE_DEADLINE_MS.load(Ordering::Relaxed);
    deadline != 0 && deadline.wrapping_sub(now_ms()) < i32::MAX as u32
}

#[allow(dead_code)]
pub fn take_companion_active_changed() -> bool {
    BLE_COMPANION_ACTIVE_CHANGED.swap(false, Ordering::Relaxed)
}

pub fn poll_text_commands(registry: &mut CommandRegistry) {
    let _ = registry;
    poll_raw_nan_rendezvous();
    poll_companion_advertising();
    if BLE_COMPANION_SAVE_PENDING.swap(false, Ordering::Relaxed) {
        telemetry::record_log("event type=ble.companion save_deferred=true");
    }
    if BLE_PENDING_NOTIFY.load(Ordering::Relaxed) && companion_link_ready() {
        notify_companion_pending();
    }
    // GATT and CoC payloads are bearer traffic, not direct commands.  Their
    // QUIC-lite attachment is added with the shared transport runtime; drop
    // queued legacy records until then rather than dispatching them through a
    // separate registry or response encoder.
    for _ in 0..4 {
        let command = {
            let mut queue = ble_command_queue().lock().unwrap();
            queue.pop_front()
        };
        let Some(command) = command else {
            return;
        };
        if command.data.is_empty() {
            continue;
        }
        telemetry::record_log(format!(
            "event type=ble.legacy_record dropped=true bearer={}",
            match command.transport {
                BleTransport::Gatt => "gatt",
                BleTransport::Coc => "coc",
            }
        ));
    }
}

pub fn announce_lora_packet(packet: &[u8], rssi: i32, snr: f32) -> Result<()> {
    announce_packet(DmeshBleEvent::LoraRx, packet, Some((rssi, snr)))
}

pub fn announce_packet(
    event: DmeshBleEvent,
    packet: &[u8],
    metrics: Option<(i32, f32)>,
) -> Result<()> {
    ensure_ble()?;
    let adv = dmesh_adv_data(event, packet, metrics)?;
    start_raw_adv(&adv)?;
    send_coc(packet);
    BLE_ANNOUNCE_TX.fetch_add(1, Ordering::Relaxed);
    BLE_MODE.store(BLE_MODE_CONNECTABLE, Ordering::Relaxed);
    telemetry::record_packet("ble", Direction::Tx, &adv, "announce=true");
    Ok(())
}

pub fn open_pairing_window(timeout_ms: u32) {
    if timeout_ms == 0 {
        BLE_PAIRING_DEADLINE_MS.store(0, Ordering::Relaxed);
        BLE_PAIRING_ACCEPTED.store(false, Ordering::Relaxed);
        BLE_PAIRING_REQUEST_DEADLINE_MS.store(0, Ordering::Relaxed);
        telemetry::record_log("event type=ble.pairing state=closed");
        return;
    }
    BLE_PAIRING_DEADLINE_MS.store(now_ms().wrapping_add(timeout_ms), Ordering::Relaxed);
    BLE_PAIRING_ACCEPTED.store(false, Ordering::Relaxed);
    telemetry::record_log(format!(
        "event type=ble.pairing state=open timeout_ms={}",
        timeout_ms
    ));
    if let Err(err) = start_pairable_advertising() {
        telemetry::record_log(format!(
            "event type=ble.pairing advertise=false msg={}",
            crate::commands::protocol::escape_value(&err.to_string())
        ));
    }
}

pub fn request_pairing(request_timeout_ms: u32, confirm_timeout_ms: u32) {
    let request_timeout_ms = request_timeout_ms.clamp(1_000, 300_000);
    let confirm_timeout_ms = confirm_timeout_ms.clamp(1_000, 300_000);
    let addr = connected_addr();
    set_pairing_request_addr(&addr);
    BLE_PAIRING_CONFIRM_TIMEOUT_MS.store(confirm_timeout_ms, Ordering::Relaxed);
    BLE_PAIRING_REQUEST_DEADLINE_MS
        .store(now_ms().wrapping_add(request_timeout_ms), Ordering::Relaxed);
    BLE_PAIRING_DEADLINE_MS.store(0, Ordering::Relaxed);
    BLE_PAIRING_ACCEPTED.store(false, Ordering::Relaxed);
    telemetry::record_log(format!(
        "event type=ble.pairing state=requested request_timeout_ms={} confirm_timeout_ms={} peer={}",
        request_timeout_ms,
        confirm_timeout_ms,
        format_mac(&addr)
    ));
    let _ = start_connectable_idle();
}

pub fn start_pairing_recovery(settings: &SharedSettings) -> Result<usize> {
    super::nan::stop_nan().ok();
    super::wifi::stop_raw_monitor().ok();
    super::lora::sleep_radio(settings).ok();
    ensure_ble()?;
    start_gatt()?;
    wait_gatt_service_ready(Duration::from_millis(1_000))?;
    let removed = reset_pairing_state();
    {
        let mut settings = settings.borrow_mut();
        settings.set_str("mode", "infra")?;
        settings.set_bool("ble.comp", false)?;
        settings.set_str("ble.peer", "")?;
    }
    open_pairing_window(PAIRING_RECOVERY_WINDOW_MS);
    if !BLE_ADV_STARTED.load(Ordering::Relaxed) {
        bail!("pairing recovery advertising did not start");
    }
    telemetry::emit_console(&format!(
        "event type=ble.pairing_recovery advertise=true bonds_removed={} {}",
        removed,
        advertised_identity()
    ));
    telemetry::record_log(format!(
        "event type=ble.pairing_recovery active=true bonds_removed={}",
        removed
    ));
    Ok(removed)
}

pub fn confirm_pairing_request() -> bool {
    if !pairing_requested() {
        telemetry::record_log("event type=ble.pairing state=ignored reason=no_request");
        return false;
    }
    let timeout_ms = BLE_PAIRING_CONFIRM_TIMEOUT_MS.load(Ordering::Relaxed);
    let requested = pairing_request_addr();
    BLE_PAIRING_REQUEST_DEADLINE_MS.store(0, Ordering::Relaxed);
    open_pairing_window(timeout_ms);
    telemetry::record_log(format!(
        "event type=ble.pairing state=confirmed timeout_ms={} peer={}",
        timeout_ms,
        format_mac(&requested)
    ));
    true
}

pub fn companion_message_ready(packet: &[u8]) {
    if !BLE_COMPANION_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    if companion_link_ready() {
        notify_companion_pending();
    } else if let Err(err) = announce_packet(DmeshBleEvent::PayloadPending, packet, None) {
        telemetry::record_log(format!(
            "event type=ble.companion action=advertise ok=false err={}",
            crate::commands::protocol::escape_value(&err.to_string())
        ));
    } else {
        BLE_PENDING_NOTIFY.store(true, Ordering::Relaxed);
    }
}

pub fn companion_queue_empty() {
    BLE_PENDING_NOTIFY.store(false, Ordering::Relaxed);
    if BLE_COMPANION_ENABLED.load(Ordering::Relaxed)
        && BLE_COMPANION_ADV_WINDOW_MS.load(Ordering::Relaxed) == 0
    {
        stop_radio_activity();
    }
}

pub fn start_connectable_advertising() -> Result<()> {
    start_connectable_idle()
}

/// Start a bounded BLE CoC rendezvous requested by a targeted NAN control
/// advertisement. This is deliberately separate from the Wi-Fi wake hold:
/// the caller may bring up BLE without keeping raw NAN Wi-Fi active.
pub fn request_coc_wake(duration_ms: u32) -> Result<()> {
    ensure_ble()?;
    start_connectable_event(DmeshBleEvent::WakeRequest, &[])?;
    let psm = 0x80_u16;
    let rc = unsafe { dmesh_nimble_start_coc_server(psm as c_ushort) };
    if rc != 0 {
        bail!("nimble CoC server rc={rc} psm=0x{psm:04x}");
    }
    BLE_COC_PSM.store(psm as u32, Ordering::Relaxed);
    open_companion_active_window(duration_ms.clamp(1_000, 300_000));
    telemetry::record_log(format!(
        "event type=ble.nan_wake state=connectable_coc duration_ms={} psm=0x{psm:04x}",
        duration_ms
    ));
    Ok(())
}

pub fn set_advertising_interval_ms(min_ms: u32, max_ms: u32) {
    let min = adv_ms_to_units(min_ms);
    let max = adv_ms_to_units(max_ms).max(min);
    BLE_ADV_INT_MIN.store(min, Ordering::Relaxed);
    BLE_ADV_INT_MAX.store(max, Ordering::Relaxed);
    telemetry::record_log(format!(
        "event type=ble.adv_interval min_ms={} max_ms={} min_units={} max_units={}",
        min_ms, max_ms, min, max
    ));
}

#[derive(Clone, Copy)]
pub enum DmeshBleEvent {
    Generic,
    LoraRx,
    IdleHello,
    WakeRequest,
    PayloadPending,
}

impl DmeshBleEvent {
    fn code(self) -> u8 {
        match self {
            Self::Generic => 0,
            Self::LoraRx => 1,
            Self::IdleHello => 2,
            Self::WakeRequest => 3,
            Self::PayloadPending => 4,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::LoraRx => "lora_rx",
            Self::IdleHello => "idle_hello",
            Self::WakeRequest => "wake_request",
            Self::PayloadPending => "payload_pending",
        }
    }
}

struct RadioCommand {
    name: &'static str,
    enabled: bool,
    mtu: usize,
    settings: Option<SharedSettings>,
}

impl RadioCommand {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            enabled: true,
            mtu: 512,
            settings: None,
        }
    }

    fn with_settings(name: &'static str, settings: SharedSettings) -> Self {
        let mut command = Self::new(name);
        command.settings = Some(settings);
        command
    }

    fn ensure_ble(&mut self) -> Result<()> {
        ensure_ble()
    }

    fn handle_bt_placeholder(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if let Some(enable) = request.arg("enable") {
            self.enabled = parse_bool(enable)?;
        }
        Ok(CommandResponse::ok(format!(
            "bt classic placeholder enabled={} mtu={}",
            self.enabled, self.mtu
        )))
    }
}

impl CommandHandler for RadioCommand {
    fn name(&self) -> &'static str {
        self.name
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if self.name == "bt" {
            return self.handle_bt_placeholder(request);
        }
        if let Some(enable) = request.arg("enable") {
            self.enabled = parse_bool(enable)?;
        }
        if let Some(mtu) = request.arg_i32("mtu")? {
            self.mtu = mtu.max(1) as usize;
        }
        if let Some(pin) = request
            .arg_i32("fixed_pin")?
            .or(request.arg_i32("pin")?)
            .or(request.arg_i32("passkey")?)
        {
            let pin = pin.clamp(0, 999_999) as u32;
            BLE_FIXED_PIN.store(pin, Ordering::Relaxed);
            if request
                .arg("save")
                .map(parse_bool)
                .transpose()?
                .unwrap_or(false)
            {
                if let Some(settings) = &self.settings {
                    settings.borrow_mut().set_i32("ble.fixed_pin", pin as i32)?;
                }
            }
        }
        if request.arg("adv_ms").is_some()
            || request.arg("adv_min_ms").is_some()
            || request.arg("adv_max_ms").is_some()
        {
            let min_ms = request
                .arg_i32("adv_min_ms")?
                .or(request.arg_i32("adv_ms")?)
                .unwrap_or(1000)
                .max(20) as u32;
            let max_ms = request
                .arg_i32("adv_max_ms")?
                .or(request.arg_i32("adv_ms")?)
                .unwrap_or(min_ms as i32)
                .max(min_ms as i32) as u32;
            set_advertising_interval_ms(min_ms, max_ms);
        }
        if request.arg("rendezvous_scan_ms").is_some() || request.arg("rendezvous_adv_ms").is_some()
        {
            let scan_ms = request
                .arg_i32("rendezvous_scan_ms")?
                .unwrap_or(BLE_RENDEZVOUS_SCAN_MS.load(Ordering::Relaxed) as i32)
                .clamp(50, 2_000) as u32;
            let adv_ms = request
                .arg_i32("rendezvous_adv_ms")?
                .unwrap_or(BLE_RENDEZVOUS_ADV_MS.load(Ordering::Relaxed) as i32)
                .clamp(100, 10_000) as u32;
            BLE_RENDEZVOUS_SCAN_MS.store(scan_ms, Ordering::Relaxed);
            BLE_RENDEZVOUS_ADV_MS.store(adv_ms, Ordering::Relaxed);
            if request
                .arg("save")
                .map(parse_bool)
                .transpose()?
                .unwrap_or(false)
            {
                if let Some(settings) = &self.settings {
                    let mut settings = settings.borrow_mut();
                    settings.set_i32("bc.scan_ms", scan_ms as i32)?;
                    settings.set_i32("bc.adv_ms", adv_ms as i32)?;
                }
            }
        }
        if let Some(uuid16) = request.arg("filter_uuid16") {
            let uuid16 = parse_i32(uuid16)? as u32;
            BLE_FILTER_UUID16.store(uuid16 & 0xffff, Ordering::Relaxed);
        }
        if let Some(filter) = request.arg("filter") {
            match filter {
                "dmesh" => BLE_FILTER_DMESH.store(true, Ordering::Relaxed),
                "all" | "none" => BLE_FILTER_DMESH.store(false, Ordering::Relaxed),
                _ => bail!("unsupported BLE filter {filter}"),
            }
        }
        if let Some(addr) = request.arg("filter_addr") {
            BLE_FILTER_ADDR_ENABLED.store(addr != "none" && addr != "false", Ordering::Relaxed);
        }
        if request
            .arg("pairing_recovery")
            .or_else(|| request.arg("recovery"))
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            let Some(settings) = &self.settings else {
                bail!("pairing_recovery requires settings");
            };
            let removed = start_pairing_recovery(settings)?;
            return Ok(CommandResponse::ok(format!(
                "ble pairing_recovery=true bonds_removed={} {}",
                removed,
                ble_stats()
            )));
        }
        if let Some(companion) = request.arg("companion") {
            let enabled = parse_bool(companion)?;
            BLE_COMPANION_ENABLED.store(enabled, Ordering::Relaxed);
            if request
                .arg("save")
                .map(parse_bool)
                .transpose()?
                .unwrap_or(false)
            {
                if let Some(settings) = &self.settings {
                    let mut settings = settings.borrow_mut();
                    settings.set_bool("ble.comp", enabled)?;
                    if let Some(peer) = request.arg("peer") {
                        settings.set_str("ble.peer", peer)?;
                    }
                }
            }
            if enabled
                && matches!(
                    request.arg("pairing"),
                    Some("request" | "true" | "1" | "yes" | "on")
                )
            {
                let request_timeout_ms = request
                    .arg_i32("timeout_ms")?
                    .or(request.arg_i32("request_ms")?)
                    .or(request.arg_i32("ms")?)
                    .unwrap_or(120_000)
                    .clamp(1_000, 300_000) as u32;
                let confirm_timeout_ms = request
                    .arg_i32("confirm_timeout_ms")?
                    .or(request.arg_i32("confirm_ms")?)
                    .unwrap_or(60_000)
                    .clamp(1_000, 300_000) as u32;
                self.ensure_ble()?;
                start_gatt()?;
                request_pairing(request_timeout_ms, confirm_timeout_ms);
                open_pairing_window(request_timeout_ms);
                return Ok(CommandResponse::ok(format!(
                    "ble companion=true pairing=open {}",
                    ble_stats()
                )));
            }
            if enabled {
                start_companion_runtime()?;
            }
            return Ok(CommandResponse::ok(ble_stats()));
        }
        if request
            .arg("reset_pairing")
            .or_else(|| request.arg("clear_pairing"))
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            self.ensure_ble()?;
            let removed = reset_pairing_state();
            if request
                .arg("save")
                .map(parse_bool)
                .transpose()?
                .unwrap_or(true)
            {
                if let Some(settings) = &self.settings {
                    let mut settings = settings.borrow_mut();
                    settings.set_bool("ble.comp", false)?;
                    settings.set_str("ble.peer", "")?;
                }
            }
            return Ok(CommandResponse::ok(format!(
                "ble reset_pairing=true bonds_removed={} {}",
                removed,
                ble_stats()
            )));
        }
        if let Some(pairing) = request.arg("pairing") {
            match pairing {
                "request" | "true" | "1" | "yes" | "on" => {
                    let request_timeout_ms = request
                        .arg_i32("timeout_ms")?
                        .or(request.arg_i32("request_ms")?)
                        .or(request.arg_i32("ms")?)
                        .unwrap_or(120_000)
                        .clamp(1_000, 300_000) as u32;
                    let confirm_timeout_ms = request
                        .arg_i32("confirm_timeout_ms")?
                        .or(request.arg_i32("confirm_ms")?)
                        .unwrap_or(60_000)
                        .clamp(1_000, 300_000) as u32;
                    self.ensure_ble()?;
                    start_gatt()?;
                    request_pairing(request_timeout_ms, confirm_timeout_ms);
                    open_pairing_window(request_timeout_ms);
                    return Ok(CommandResponse::ok(ble_stats()));
                }
                "confirm" | "accept" => {
                    self.ensure_ble()?;
                    start_gatt()?;
                    let ok = confirm_pairing_request();
                    return Ok(CommandResponse::ok(format!(
                        "ble pairing_confirmed={} {}",
                        ok,
                        ble_stats()
                    )));
                }
                "false" | "0" | "no" | "off" => {
                    BLE_PAIRING_DEADLINE_MS.store(0, Ordering::Relaxed);
                    BLE_PAIRING_ACCEPTED.store(false, Ordering::Relaxed);
                    BLE_PAIRING_REQUEST_DEADLINE_MS.store(0, Ordering::Relaxed);
                    return Ok(CommandResponse::ok(ble_stats()));
                }
                _ => bail!("unsupported BLE pairing action {pairing}"),
            }
        }
        if request.arg("cancel").is_some() {
            BLE_PAIRING_DEADLINE_MS.store(0, Ordering::Relaxed);
            BLE_PAIRING_ACCEPTED.store(false, Ordering::Relaxed);
            BLE_PAIRING_REQUEST_DEADLINE_MS.store(0, Ordering::Relaxed);
            return Ok(CommandResponse::ok(ble_stats()));
        }
        if request.arg("start").is_some() {
            self.ensure_ble()?;
            // An earlier bounded raw-NAN rendezvous may have left an expired
            // deadline behind.  A manual CoC listener start is an explicit
            // advertising request and must not be immediately cancelled by
            // that old window.
            BLE_RENDEZVOUS_SCAN_DEADLINE_MS.store(0, Ordering::Relaxed);
            BLE_RENDEZVOUS_ADV_DEADLINE_MS.store(0, Ordering::Relaxed);
            start_connectable_idle()?;
            return Ok(CommandResponse::ok("ble started"));
        }
        if let Some(keep_active) = request.arg("keep_active").map(parse_bool).transpose()? {
            BLE_RAW_NAN_KEEP_ACTIVE.store(keep_active, Ordering::Relaxed);
            if keep_active {
                self.ensure_ble()?;
                start_connectable_idle()?;
                if let Err(err) = enable_controller_sleep() {
                    telemetry::record_log(format!(
                        "event type=ble.controller_sleep enabled=false reason={}",
                        crate::commands::protocol::escape_value(&err.to_string())
                    ));
                }
            }
            return Ok(CommandResponse::ok(format!(
                "ble keep_active={} {}",
                keep_active,
                ble_stats()
            )));
        }
        if let Some(bonding) = request.arg("bonding").map(parse_bool).transpose()? {
            self.ensure_ble()?;
            let rc = unsafe { dmesh_nimble_set_bonding(bonding as c_uchar) };
            if rc != 0 {
                bail!("nimble bonding policy rc={rc}");
            }
            BLE_BONDING_ENABLED.store(bonding, Ordering::Relaxed);
            return Ok(CommandResponse::ok(format!(
                "ble bonding={} existing_links_unchanged=true",
                bonding
            )));
        }
        if let Some(profile) = request.arg("link_profile") {
            let raw_nan = match profile {
                "raw_nan" => true,
                "default" => false,
                other => bail!("ble link_profile must be raw_nan or default, got {other:?}"),
            };
            self.ensure_ble()?;
            let rc = unsafe { dmesh_nimble_set_raw_nan_link_profile(raw_nan as c_uchar) };
            if rc != 0 {
                bail!("nimble link profile rc={rc}");
            }
            BLE_RAW_NAN_LINK_PROFILE.store(raw_nan, Ordering::Relaxed);
            return Ok(CommandResponse::ok(if raw_nan {
                "ble link_profile=raw_nan interval_ms=1000 latency=3 supervision_ms=30000"
            } else {
                "ble link_profile=default"
            }));
        }
        if request
            .arg("stop")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
            || request
                .arg("advertise")
                .map(parse_bool)
                .transpose()?
                .is_some_and(|advertise| !advertise)
        {
            force_stop_radio_activity();
            return Ok(CommandResponse::ok("ble stopped"));
        }
        if request.arg("stats").is_some() {
            return Ok(CommandResponse::ok(ble_stats()));
        }
        if request.arg("identity").is_some() {
            self.ensure_ble()?;
            return Ok(CommandResponse::ok(advertised_identity()));
        }
        if request.arg("coc").is_some() {
            self.ensure_ble()?;
            let psm = request
                .arg("psm")
                .map(parse_coc_psm)
                .transpose()?
                .unwrap_or(0x80);
            if !(0x80..=0xff).contains(&psm) {
                bail!("CoC PSM must be in 0x80..0xff, got 0x{psm:04x}");
            }
            let rc = unsafe { dmesh_nimble_start_coc_server(psm as c_ushort) };
            if rc != 0 {
                bail!("nimble CoC server rc={rc} psm=0x{psm:04x}");
            }
            BLE_COC_PSM.store(psm as u32, Ordering::Relaxed);
            return Ok(CommandResponse::ok(format!(
                "ble coc started=true psm=0x{psm:04x} echo=true"
            )));
        }
        if request.arg("bonds").is_some() || request.arg("paired").is_some() {
            return Ok(CommandResponse::ok(ble_bond_status(self.settings.as_ref())));
        }
        if request.arg("scan_stop").is_some() {
            BLE_SCAN_STARTED.store(false, Ordering::Relaxed);
            return Ok(CommandResponse::ok("ble scan stopped"));
        }
        if request
            .arg("scan")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            self.ensure_ble()?;
            start_scan(request)?;
            return Ok(CommandResponse::ok(format!(
                "ble scan started {}",
                ble_stats()
            )));
        }
        if request
            .arg("pairable")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            self.ensure_ble()?;
            start_pairable_advertising()?;
            return Ok(CommandResponse::ok(format!(
                "ble pairable started {}",
                ble_stats()
            )));
        }
        if let Some(raw) = request.arg("raw_adv") {
            self.ensure_ble()?;
            let data = parse_bytes(raw)?;
            start_raw_adv(&data)?;
            telemetry::record_packet("ble", Direction::Tx, &data, "raw_adv=true");
            return Ok(CommandResponse::ok(format!(
                "ble raw_adv started bytes={}",
                data.len()
            )));
        }
        if request
            .arg("advertise")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
            || request.arg("announce").is_some()
        {
            self.ensure_ble()?;
            let payload = request
                .arg("payload")
                .or_else(|| request.arg("data"))
                .or_else(|| request.arg("announce"))
                .map(parse_bytes)
                .transpose()?
                .unwrap_or_default();
            let event = parse_event(request.arg("event").unwrap_or("payload_pending"))?;
            let rssi = request.arg_i32("rssi")?.unwrap_or(0);
            let snr = request
                .arg("snr")
                .and_then(|value| value.parse::<f32>().ok());
            let metrics = snr.map(|snr| (rssi, snr));
            announce_packet(event, &payload, metrics)?;
            return Ok(CommandResponse::ok(format!(
                "ble announce event={} bytes={} {}",
                event.name(),
                payload.len(),
                ble_stats()
            )));
        }
        if request.arg("gatt").is_some() {
            bail!("GATT payload transport is disabled; use CoC after rendezvous advertising");
        }
        if let Some(mode) = request.arg("mode") {
            if mode == "listen" || mode == "scan" {
                self.ensure_ble()?;
                start_scan_params(0, true)?;
                BLE_MODE.store(BLE_MODE_LISTEN, Ordering::Relaxed);
                return Ok(CommandResponse::ok(format!(
                    "ble listen started {}",
                    ble_stats()
                )));
            }
            if mode == "announce" || mode == "connectable" {
                self.ensure_ble()?;
                let payload = request
                    .arg("payload")
                    .or_else(|| request.arg("data"))
                    .map(parse_bytes)
                    .transpose()?
                    .unwrap_or_default();
                let event = request
                    .arg("event")
                    .map(parse_event)
                    .transpose()?
                    .unwrap_or(DmeshBleEvent::PayloadPending);
                announce_packet(event, &payload, None)?;
                return Ok(CommandResponse::ok(format!(
                    "ble connectable started {}",
                    ble_stats()
                )));
            }
            if mode == "gatt" || mode == "nus" || mode == "meshcore" {
                bail!("GATT application mode is disabled; use CoC after rendezvous advertising");
            }
        }
        Ok(CommandResponse::ok(ble_stats()))
    }
}

fn parse_coc_psm(value: &str) -> Result<u16> {
    let value = value.trim();
    let parsed = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map(|hex| u16::from_str_radix(hex, 16))
        .unwrap_or_else(|| value.parse::<u16>())
        .map_err(|err| anyhow::anyhow!("invalid CoC PSM {value:?}: {err}"))?;
    Ok(parsed)
}

pub fn start_companion_runtime() -> Result<()> {
    ensure_ble()?;
    start_connectable_idle()?;
    Ok(())
}

fn ensure_ble() -> Result<()> {
    if BLE_STARTED.load(Ordering::Relaxed) {
        return Ok(());
    }
    let rc = unsafe { dmesh_nimble_init() };
    if rc != 0 {
        bail!("nimble init rc={rc}");
    }
    BLE_STARTED.store(true, Ordering::Relaxed);
    Ok(())
}

fn start_gatt() -> Result<()> {
    ensure_ble()?;
    let tx = unsafe { dmesh_nimble_tx_handle() };
    let rx = unsafe { dmesh_nimble_rx_handle() };
    if tx != 0 {
        BLE_GATT_TX_HANDLE.store(tx as u32, Ordering::Relaxed);
    }
    if rx != 0 {
        BLE_GATT_RX_HANDLE.store(rx as u32, Ordering::Relaxed);
    }
    BLE_GATT_STARTED.store(true, Ordering::Relaxed);
    Ok(())
}

fn wait_gatt_service_ready(timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        start_gatt()?;
        if BLE_READY.load(Ordering::Relaxed)
            && BLE_GATT_TX_HANDLE.load(Ordering::Relaxed) != 0
            && BLE_GATT_RX_HANDLE.load(Ordering::Relaxed) != 0
        {
            return Ok(());
        }
        task_delay(Duration::from_millis(20));
    }
    bail!("BLE NimBLE GATT service not ready")
}

fn task_delay(timeout: Duration) {
    unsafe {
        sys::vTaskDelay(duration_to_ticks(timeout).max(1));
    }
}

fn duration_to_ticks(timeout: Duration) -> sys::TickType_t {
    let hz = sys::configTICK_RATE_HZ as u128;
    let ticks = timeout.as_millis().saturating_mul(hz).div_ceil(1000);
    ticks.min(sys::TickType_t::MAX as u128) as sys::TickType_t
}

fn start_raw_adv(data: &[u8]) -> Result<()> {
    if data.len() > 31 {
        bail!("BLE legacy advertising data is limited to 31 bytes");
    }
    ensure_ble()?;
    stop_scan_for_advertising()?;
    let rc = unsafe {
        dmesh_nimble_start_advertising(
            data.as_ptr(),
            data.len() as c_uchar,
            BLE_ADV_INT_MIN.load(Ordering::Relaxed) as c_ushort,
            BLE_ADV_INT_MAX.load(Ordering::Relaxed) as c_ushort,
        )
    };
    if rc != 0 {
        bail!("nimble advertise rc={rc}");
    }
    BLE_ADV_STARTED.store(true, Ordering::Relaxed);
    Ok(())
}

fn start_connectable_idle() -> Result<()> {
    announce_packet(DmeshBleEvent::IdleHello, &[], None)
}

fn start_pairable_advertising() -> Result<()> {
    ensure_ble()?;
    stop_scan_for_advertising()?;
    let rc = unsafe {
        dmesh_nimble_start_pairing_advertising(
            BLE_ADV_INT_MIN.load(Ordering::Relaxed) as c_ushort,
            BLE_ADV_INT_MAX.load(Ordering::Relaxed) as c_ushort,
        )
    };
    if rc != 0 {
        bail!("nimble pairing advertise rc={rc}");
    }
    BLE_ADV_STARTED.store(true, Ordering::Relaxed);
    BLE_MODE.store(BLE_MODE_CONNECTABLE, Ordering::Relaxed);
    let line = format!(
        "event type=ble.pairing state=advertising uuid={} name=DMesh adv_raw={} {}",
        uuid128_string(&DMESH_BLE_PAIRING_UUID),
        "nimble_fields",
        advertised_identity()
    );
    // NimBLE invokes this on its host task.  Do not forward a console event
    // from here: emit_console may start raw Wi-Fi to reach a previous command
    // peer, which blocks the host before it can process ATT/GATT traffic.
    telemetry::record_log(line);
    Ok(())
}

/// A classic ESP32 controller cannot perform the continuous discovery scan and
/// the connectable advertising procedure needed by Android at the same time.
/// Always end a pending scan before handing the controller to an advertising
/// transition; otherwise NimBLE can report advertising enabled while Android
/// never receives a connectable advertisement or callback.
fn stop_scan_for_advertising() -> Result<()> {
    if !BLE_STARTED.load(Ordering::Relaxed) {
        return Ok(());
    }
    let rc = unsafe { dmesh_nimble_stop_scan() };
    if rc != 0 {
        bail!("nimble stop scan before advertising rc={rc}");
    }
    BLE_SCAN_STARTED.store(false, Ordering::Relaxed);
    Ok(())
}

fn start_scan(_request: &CommandRequest) -> Result<()> {
    start_scan_params(0, true)
}

fn start_scan_params(_duration: u32, _active: bool) -> Result<()> {
    ensure_ble()?;
    let rc = unsafe { dmesh_nimble_start_scan(_duration, _active as c_uchar) };
    if rc != 0 {
        bail!("nimble scan rc={rc}");
    }
    BLE_SCAN_STARTED.store(true, Ordering::Relaxed);
    BLE_MODE.store(BLE_MODE_LISTEN, Ordering::Relaxed);
    Ok(())
}

fn companion_scan_ms() -> u32 {
    BLE_RENDEZVOUS_SCAN_MS.load(Ordering::Relaxed)
}

fn companion_adv_ms() -> u32 {
    BLE_RENDEZVOUS_ADV_MS.load(Ordering::Relaxed)
}

fn start_connectable_event(event: DmeshBleEvent, packet: &[u8]) -> Result<()> {
    ensure_ble()?;
    announce_packet(event, packet, None)?;
    BLE_MODE.store(BLE_MODE_CONNECTABLE, Ordering::Relaxed);
    Ok(())
}

/// Advance the bounded scan/advertise state before raw-NAN decides whether it
/// may enter its next light-sleep interval.
pub fn poll_raw_nan_rendezvous() {
    let now = now_ms();
    let scan_deadline = BLE_RENDEZVOUS_SCAN_DEADLINE_MS.load(Ordering::Relaxed);
    if scan_deadline != 0 && now.wrapping_sub(scan_deadline) < i32::MAX as u32 {
        BLE_RENDEZVOUS_SCAN_DEADLINE_MS.store(0, Ordering::Relaxed);
        unsafe {
            let _ = dmesh_nimble_stop_scan();
        }
        BLE_SCAN_STARTED.store(false, Ordering::Relaxed);
        if BLE_RENDEZVOUS_WAKE_SEEN.swap(false, Ordering::Relaxed) {
            match start_connectable_event(DmeshBleEvent::IdleHello, &[]) {
                Ok(()) => {
                    let adv_ms = companion_adv_ms();
                    BLE_RENDEZVOUS_ADV_DEADLINE_MS
                        .store(now.wrapping_add(adv_ms), Ordering::Relaxed);
                    telemetry::record_log(format!(
                        "event type=ble.rendezvous state=connectable wake=true adv_ms={adv_ms}"
                    ));
                }
                Err(err) => {
                    telemetry::record_log(format!(
                        "event type=ble.rendezvous state=advertise_failed msg={}",
                        crate::commands::protocol::escape_value(&err.to_string())
                    ));
                }
            }
        } else {
            telemetry::record_log("event type=ble.rendezvous state=no_wake");
        }
    }
    let adv_deadline = BLE_RENDEZVOUS_ADV_DEADLINE_MS.load(Ordering::Relaxed);
    if adv_deadline != 0
        && now.wrapping_sub(adv_deadline) < i32::MAX as u32
        && !BLE_GATT_CONNECTED.load(Ordering::Relaxed)
    {
        BLE_RENDEZVOUS_ADV_DEADLINE_MS.store(0, Ordering::Relaxed);
        stop_radio_activity();
        telemetry::record_log("event type=ble.rendezvous state=expired");
    }
}

fn dmesh_adv_data(
    event: DmeshBleEvent,
    packet: &[u8],
    _metrics: Option<(i32, f32)>,
) -> Result<Vec<u8>> {
    let (source, packet_id) = dmesh_adv_ids(packet);
    let pending = telemetry::pending_message_count();
    let battery = battery_level();
    // Legacy advertisements permit 31 bytes total.  A 128-bit service-data
    // UUID plus flags and the DMesh rendezvous fields needs 32 bytes, so the
    // broadcast discovery marker uses the compact registered 16-bit UUID.
    // The operational 128-bit UUID remains the GATT service after Android
    // connects; it is not repeated in the advertisement.
    let mut service = Vec::with_capacity(13);
    service.extend_from_slice(&DMESH_BLE_SERVICE_UUID16.to_le_bytes());
    service.extend_from_slice(&source.to_le_bytes());
    service.extend_from_slice(&packet_id.to_le_bytes());
    // v2 marker: Android can distinguish wake/idle/pending without treating
    // an event code as a queue depth. The one-byte extension still fits in a
    // legacy 31-byte advertisement with no payload prefix.
    service.push(0x80 | pending.min(0x7f));
    service.push(battery);
    service.push(event.code());

    let mut adv = Vec::with_capacity(31);
    adv.extend_from_slice(&[0x02, 0x01, 0x06]);
    adv.push((service.len() + 1).min(0xff) as u8);
    adv.push(0x16); // Service Data - 16-bit UUID.
    adv.extend_from_slice(&service);
    if adv.len() > 31 {
        bail!("DMesh BLE announcement exceeded legacy advertising limit");
    }
    Ok(adv)
}

fn dmesh_adv_ids(packet: &[u8]) -> (u32, u32) {
    // Main no longer owns the Meshtastic codec. Keep only this tiny wire
    // compatibility shim for BLE advertisement deduplication; the complete
    // frame parser/encoder lives with mod_lora.
    if packet.len() >= 16 {
        let from = u32::from_le_bytes([packet[4], packet[5], packet[6], packet[7]]);
        let id = u32::from_le_bytes([packet[8], packet[9], packet[10], packet[11]]);
        let to = u32::from_le_bytes([packet[0], packet[1], packet[2], packet[3]]);
        if to != 0 || from != 0 || id != 0 {
            return (from, id);
        }
    }
    // Non-Meshtastic/raw packets still get stable opaque identifiers.
    let mut hash = 0x811c9dc5u32;
    for byte in packet {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x01000193);
    }
    (0, hash)
}

fn battery_level() -> u8 {
    super::battery::battery_level_default()
}

fn parse_event(value: &str) -> Result<DmeshBleEvent> {
    match value {
        "generic" => Ok(DmeshBleEvent::Generic),
        "lora" | "lora_rx" => Ok(DmeshBleEvent::LoraRx),
        "idle" | "idle_hello" => Ok(DmeshBleEvent::IdleHello),
        "wake" | "wake_request" => Ok(DmeshBleEvent::WakeRequest),
        "pending" | "payload_pending" => Ok(DmeshBleEvent::PayloadPending),
        other => bail!("unsupported BLE advertise event {other}"),
    }
}

fn pairing_open() -> bool {
    let deadline = BLE_PAIRING_DEADLINE_MS.load(Ordering::Relaxed);
    deadline != 0
        && deadline.wrapping_sub(now_ms()) < i32::MAX as u32
        && !BLE_PAIRING_ACCEPTED.load(Ordering::Relaxed)
}

fn pairing_requested() -> bool {
    let deadline = BLE_PAIRING_REQUEST_DEADLINE_MS.load(Ordering::Relaxed);
    deadline != 0 && deadline.wrapping_sub(now_ms()) < i32::MAX as u32
}

fn companion_link_ready() -> bool {
    BLE_COMPANION_ENABLED.load(Ordering::Relaxed)
        && BLE_GATT_CONNECTED.load(Ordering::Relaxed)
        && BLE_GATT_NOTIFY_ENABLED.load(Ordering::Relaxed)
        && BLE_GATT_AUTHENTICATED.load(Ordering::Relaxed)
}

fn poll_companion_advertising() {
    if !BLE_COMPANION_ENABLED.load(Ordering::Relaxed)
        || companion_active()
        || BLE_GATT_CONNECTED.load(Ordering::Relaxed)
        || BLE_PENDING_NOTIFY.load(Ordering::Relaxed)
    {
        return;
    }
    let period_ms = BLE_COMPANION_ADV_PERIOD_MS.load(Ordering::Relaxed);
    let window_ms = BLE_COMPANION_ADV_WINDOW_MS.load(Ordering::Relaxed);
    if period_ms == 0 || window_ms == 0 {
        return;
    }
    let now = now_ms();
    let next = BLE_COMPANION_ADV_NEXT_MS.load(Ordering::Relaxed);
    if next.wrapping_sub(now) < i32::MAX as u32 {
        return;
    }
    if BLE_COMPANION_ADV_STATE.load(Ordering::Relaxed) {
        stop_radio_activity();
        BLE_COMPANION_ADV_STATE.store(false, Ordering::Relaxed);
        BLE_COMPANION_ADV_NEXT_MS.store(now.wrapping_add(period_ms - window_ms), Ordering::Relaxed);
    } else if start_connectable_idle().is_ok() {
        BLE_COMPANION_ADV_STATE.store(true, Ordering::Relaxed);
        BLE_COMPANION_ADV_NEXT_MS.store(now.wrapping_add(window_ms), Ordering::Relaxed);
    } else {
        BLE_COMPANION_ADV_NEXT_MS.store(now.wrapping_add(period_ms), Ordering::Relaxed);
    }
}

fn notify_companion_pending() {
    if !companion_link_ready() {
        return;
    }
    let text = telemetry::companion_notify_text(1200);
    if text.contains("count=0") {
        BLE_PENDING_NOTIFY.store(false, Ordering::Relaxed);
        return;
    }
    send_gatt(text.as_bytes());
    BLE_PENDING_NOTIFY.store(false, Ordering::Relaxed);
}

fn reset_pairing_state() -> usize {
    BLE_COMPANION_ENABLED.store(false, Ordering::Relaxed);
    BLE_COMPANION_SAVE_PENDING.store(false, Ordering::Relaxed);
    BLE_PAIRING_DEADLINE_MS.store(0, Ordering::Relaxed);
    BLE_PAIRING_ACCEPTED.store(false, Ordering::Relaxed);
    BLE_PAIRING_REQUEST_DEADLINE_MS.store(0, Ordering::Relaxed);
    BLE_GATT_AUTHENTICATED.store(false, Ordering::Relaxed);
    set_paired_addr(&[0; 6]);
    set_pairing_request_addr(&[0; 6]);
    let rc = unsafe { dmesh_nimble_clear_bonds() };
    let removed = if rc == 0 { 1 } else { 0 };
    BLE_BONDS_CLEARED.fetch_add(removed, Ordering::Relaxed);
    telemetry::record_log(format!(
        "event type=ble.pairing reset=true bonds_clear_rc={} bonds_removed={}",
        rc, removed
    ));
    removed as usize
}

fn ble_stats() -> String {
    format!(
        "ble backend=nimble started={} ready={} mode={} adv={} scan={} keep_active={} bonding={} link_profile={} reports={} matched={} last_rssi={} filter=dmesh:{} filter_uuid16=0x{:04x} filter_addr={} announce_tx={} announce_rx={} wake_rx={} pending_switches={} gatt_started={} gatt_connected={} notify={} auth={} coc_psm=0x{:04x} coc_ready={} coc_connected={} coc_rx={} coc_tx={} pairing_requested={} pairing_open={} fixed_pin={} gatt_rx_text={} gatt_rx_binary={} gatt_tx={} rx_handle={} tx_handle={}",
        BLE_STARTED.load(Ordering::Relaxed),
        BLE_READY.load(Ordering::Relaxed),
        ble_mode_name(),
        BLE_ADV_STARTED.load(Ordering::Relaxed),
        BLE_SCAN_STARTED.load(Ordering::Relaxed),
        BLE_RAW_NAN_KEEP_ACTIVE.load(Ordering::Relaxed),
        BLE_BONDING_ENABLED.load(Ordering::Relaxed),
        if BLE_RAW_NAN_LINK_PROFILE.load(Ordering::Relaxed) { "raw_nan" } else { "default" },
        BLE_SCAN_REPORTS.load(Ordering::Relaxed),
        BLE_SCAN_MATCHED.load(Ordering::Relaxed),
        BLE_SCAN_LAST_RSSI.load(Ordering::Relaxed),
        BLE_FILTER_DMESH.load(Ordering::Relaxed),
        BLE_FILTER_UUID16.load(Ordering::Relaxed),
        BLE_FILTER_ADDR_ENABLED.load(Ordering::Relaxed),
        BLE_ANNOUNCE_TX.load(Ordering::Relaxed),
        BLE_ANNOUNCE_RX.load(Ordering::Relaxed),
        BLE_WAKE_REQUEST_RX.load(Ordering::Relaxed),
        BLE_PENDING_SWITCHES.load(Ordering::Relaxed),
        BLE_GATT_STARTED.load(Ordering::Relaxed),
        BLE_GATT_CONNECTED.load(Ordering::Relaxed),
        BLE_GATT_NOTIFY_ENABLED.load(Ordering::Relaxed),
        BLE_GATT_AUTHENTICATED.load(Ordering::Relaxed),
        BLE_COC_PSM.load(Ordering::Relaxed),
        unsafe { dmesh_nimble_coc_server_psm() },
        BLE_COC_CONNECTED.load(Ordering::Relaxed),
        BLE_COC_RX.load(Ordering::Relaxed),
        BLE_COC_TX.load(Ordering::Relaxed),
        pairing_requested(),
        pairing_open(),
        BLE_FIXED_PIN.load(Ordering::Relaxed),
        BLE_GATT_RX_TEXT.load(Ordering::Relaxed),
        BLE_GATT_RX_BINARY.load(Ordering::Relaxed),
        BLE_GATT_TX.load(Ordering::Relaxed),
        BLE_GATT_RX_HANDLE.load(Ordering::Relaxed),
        BLE_GATT_TX_HANDLE.load(Ordering::Relaxed)
    )
}

fn ble_bond_status(settings: Option<&SharedSettings>) -> String {
    let (saved_mode, saved_companion, saved_peer) = settings
        .map(|settings| {
            let settings = settings.borrow();
            (
                settings.get_str("mode").ok().flatten().unwrap_or_default(),
                settings
                    .get_bool("ble.comp", false)
                    .map(|value| value.to_string())
                    .unwrap_or_else(|_| "err".to_string()),
                settings
                    .get_str("ble.peer")
                    .ok()
                    .flatten()
                    .unwrap_or_default(),
            )
        })
        .unwrap_or_else(|| ("".to_string(), "".to_string(), "".to_string()));
    format!(
        "ble backend=nimble bonds=unknown bonds_cleared={} connected={} connected_peer={} paired_peer={} auth={} companion={} save_pending={} saved_mode={} saved_ble_comp={} saved_peer={}",
        BLE_BONDS_CLEARED.load(Ordering::Relaxed),
        BLE_GATT_CONNECTED.load(Ordering::Relaxed),
        format_mac(&connected_addr()),
        paired_addr_string(),
        BLE_GATT_AUTHENTICATED.load(Ordering::Relaxed),
        BLE_COMPANION_ENABLED.load(Ordering::Relaxed),
        BLE_COMPANION_SAVE_PENDING.load(Ordering::Relaxed),
        crate::commands::protocol::quote_text_value(&saved_mode),
        saved_companion,
        crate::commands::protocol::quote_text_value(&saved_peer)
    )
}

fn ble_mode_name() -> &'static str {
    match BLE_MODE.load(Ordering::Relaxed) {
        BLE_MODE_LISTEN => "listen",
        BLE_MODE_ANNOUNCE => "announce",
        BLE_MODE_CONNECTABLE => "connectable",
        BLE_MODE_OFF => "off",
        _ => "unknown",
    }
}

fn handle_ble_rx(data: &[u8], transport: BleTransport) -> Vec<u8> {
    let source = match transport {
        BleTransport::Gatt => "source=gatt_rx",
        BleTransport::Coc => "source=coc_rx",
    };
    telemetry::record_packet("ble", Direction::Rx, data, source);
    // The companion encryption flag is the legacy GATT pairing policy.  LE
    // CoC uses its own short-lived channel and must not be rejected merely
    // because no GATT authentication callback has run; otherwise a queued
    // radio message can advertise successfully but can never be pulled over
    // the CoC-only transport.
    if matches!(transport, BleTransport::Gatt)
        && BLE_COMPANION_ENABLED.load(Ordering::Relaxed)
        && !BLE_GATT_AUTHENTICATED.load(Ordering::Relaxed)
    {
        return b"error message=companion_requires_encryption\n".to_vec();
    }
    if matches!(transport, BleTransport::Gatt)
        && data
            .first()
            .map(|byte| is_meshcore_binary_tag(*byte))
            .unwrap_or(false)
    {
        BLE_GATT_RX_BINARY.fetch_add(1, Ordering::Relaxed);
        return meshcore_response(data);
    }
    BLE_GATT_RX_BINARY.fetch_add(1, Ordering::Relaxed);
    queue_ble_command(transport, data);
    Vec::new()
}

fn is_meshcore_binary_tag(byte: u8) -> bool {
    (0x01..=0x1b).contains(&byte) || byte >= 0x80
}

fn meshcore_response(data: &[u8]) -> Vec<u8> {
    match data[0] {
        0x01 => meshcore_self_info(),
        0x16 => meshcore_device_info(),
        _ => Vec::new(),
    }
}

fn meshcore_self_info() -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.push(0x05);
    out.push(0);
    out.push(13);
    out.push(20);
    out.extend_from_slice(&[0x44; 32]);
    out.extend_from_slice(&0_i32.to_le_bytes());
    out.extend_from_slice(&0_i32.to_le_bytes());
    out.push(0);
    out.push(0);
    out.push(0);
    out.push(0);
    out.extend_from_slice(&915_000_u32.to_le_bytes());
    out.extend_from_slice(&250_000_u32.to_le_bytes());
    out.push(9);
    out.push(5);
    out.extend_from_slice(b"dmesh-rs");
    out
}

fn meshcore_device_info() -> Vec<u8> {
    let mut out = Vec::with_capacity(76);
    out.push(0x0d);
    out.push(3);
    out.push(32);
    out.push(8);
    out.extend_from_slice(&0_u32.to_le_bytes());
    push_fixed_ascii(&mut out, b"dmesh-rs", 12);
    push_fixed_ascii(&mut out, b"ESP32 Rust GATT", 40);
    push_fixed_ascii(&mut out, b"meshcore-uuid", 20);
    out
}

fn push_fixed_ascii(out: &mut Vec<u8>, value: &[u8], width: usize) {
    let used = value.len().min(width);
    out.extend_from_slice(&value[..used]);
    out.resize(out.len() + width - used, 0);
}

fn queue_ble_command(transport: BleTransport, data: &[u8]) {
    let mut queue = ble_command_queue().lock().unwrap();
    if queue.len() >= 8 {
        let _ = queue.pop_front();
    }
    queue.push_back(BleCommand {
        transport,
        data: data.to_vec(),
    });
    super::wake::notify();
}

fn ble_command_queue() -> &'static Mutex<VecDeque<BleCommand>> {
    BLE_COMMAND_QUEUE.get_or_init(|| Mutex::new(VecDeque::new()))
}

fn send_gatt(data: &[u8]) {
    if !BLE_GATT_CONNECTED.load(Ordering::Relaxed)
        || !BLE_GATT_NOTIFY_ENABLED.load(Ordering::Relaxed)
    {
        return;
    }
    for chunk in data.chunks(180) {
        let rc = unsafe { dmesh_nimble_notify(chunk.as_ptr(), chunk.len() as c_ushort) };
        if rc == 0 {
            BLE_GATT_TX.fetch_add(1, Ordering::Relaxed);
            telemetry::record_packet("ble", Direction::Tx, chunk, "source=gatt_notify");
        } else {
            telemetry::record_log(format!("event type=ble.gatt_notify ok=false rc={rc}"));
            break;
        }
    }
}

fn send_coc(data: &[u8]) {
    if !BLE_COC_CONNECTED.load(Ordering::Relaxed) || data.is_empty() {
        return;
    }
    if data.len() > 256 {
        telemetry::record_log(format!(
            "event type=ble.coc_send ok=false reason=oversize len={}",
            data.len()
        ));
        return;
    }
    let rc = unsafe { dmesh_nimble_coc_send(data.as_ptr(), data.len() as c_ushort) };
    if rc == 0 {
        BLE_COC_TX.fetch_add(1, Ordering::Relaxed);
        telemetry::record_packet("ble", Direction::Tx, data, "source=coc_tx");
    } else {
        telemetry::record_log(format!("event type=ble.coc_send ok=false rc={rc}"));
    }
}

fn adv_ms_to_units(ms: u32) -> u32 {
    ((ms.max(20) as u64 * 1000) / 625).clamp(0x20, 0x4000) as u32
}

fn parse_bytes(value: &str) -> Result<Vec<u8>> {
    if let Some(hex) = value
        .strip_prefix("hex:")
        .or_else(|| value.strip_prefix("0x"))
    {
        let mut out = Vec::with_capacity(hex.len() / 2);
        let mut chars = hex
            .as_bytes()
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace());
        while let Some(hi) = chars.next() {
            let Some(lo) = chars.next() else {
                bail!("odd number of hex digits");
            };
            let hi = (hi as char)
                .to_digit(16)
                .ok_or_else(|| anyhow::anyhow!("bad hex digit"))?;
            let lo = (lo as char)
                .to_digit(16)
                .ok_or_else(|| anyhow::anyhow!("bad hex digit"))?;
            out.push(((hi << 4) | lo) as u8);
        }
        Ok(out)
    } else {
        Ok(value.as_bytes().to_vec())
    }
}

fn public_bt_address_string() -> String {
    let addr = local_addr();
    if addr != [0; 6] {
        format_mac(&addr)
    } else {
        let mut mac = [0_u8; 6];
        let ret = unsafe { sys::esp_read_mac(mac.as_mut_ptr(), sys::esp_mac_type_t_ESP_MAC_BT) };
        if ret == sys::ESP_OK {
            format_mac(&mac)
        } else {
            format!("unavailable err={ret}")
        }
    }
}

fn local_addr() -> [u8; 6] {
    let mut mac = [0_u8; 6];
    for (idx, byte) in mac.iter_mut().enumerate() {
        *byte = BLE_LOCAL_ADDR[idx].load(Ordering::Relaxed);
    }
    mac
}

fn set_connected_addr(addr: &[u8; 6]) {
    for (idx, byte) in addr.iter().enumerate() {
        BLE_CONNECTED_ADDR[idx].store(*byte, Ordering::Relaxed);
    }
}

fn connected_addr() -> [u8; 6] {
    let mut mac = [0_u8; 6];
    for (idx, byte) in mac.iter_mut().enumerate() {
        *byte = BLE_CONNECTED_ADDR[idx].load(Ordering::Relaxed);
    }
    mac
}

fn set_paired_addr(addr: &[u8; 6]) {
    for (idx, byte) in addr.iter().enumerate() {
        BLE_PAIRED_ADDR[idx].store(*byte, Ordering::Relaxed);
    }
}

fn set_pairing_request_addr(addr: &[u8; 6]) {
    for (idx, byte) in addr.iter().enumerate() {
        BLE_PAIRING_REQUEST_ADDR[idx].store(*byte, Ordering::Relaxed);
    }
}

fn pairing_request_addr() -> [u8; 6] {
    let mut mac = [0_u8; 6];
    for (idx, byte) in mac.iter_mut().enumerate() {
        *byte = BLE_PAIRING_REQUEST_ADDR[idx].load(Ordering::Relaxed);
    }
    mac
}

fn paired_addr_string() -> String {
    let mut mac = [0_u8; 6];
    for (idx, byte) in mac.iter_mut().enumerate() {
        *byte = BLE_PAIRED_ADDR[idx].load(Ordering::Relaxed);
    }
    format_mac(&mac)
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        // NimBLE stores BLE address bytes least-significant first.  Keep all
        // human-facing identities in the canonical Android / Bluetooth order.
        mac[5],
        mac[4],
        mac[3],
        mac[2],
        mac[1],
        mac[0]
    )
}

fn now_ms() -> u32 {
    unsafe { (sys::esp_timer_get_time() / 1000) as u32 }
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_nimble_on_ready(addr: *const c_uchar, addr_type: c_uchar) {
    if !addr.is_null() {
        let addr = core::slice::from_raw_parts(addr, 6);
        for (idx, byte) in addr.iter().enumerate() {
            BLE_LOCAL_ADDR[idx].store(*byte, Ordering::Relaxed);
        }
    }
    BLE_LOCAL_ADDR_TYPE.store(addr_type, Ordering::Relaxed);
    BLE_READY.store(true, Ordering::Relaxed);
    let line = format!(
        "event type=nimble.ready mac={} addr_type={} {}",
        public_bt_address_string(),
        addr_type,
        advertised_identity()
    );
    // Keep NimBLE callbacks nonblocking; normal command polling publishes
    // telemetry outside the Bluetooth host task.
    telemetry::record_log(line);
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_nimble_on_connect(
    conn_handle: c_ushort,
    addr: *const c_uchar,
    encrypted: c_uchar,
    authenticated: c_uchar,
    bonded: c_uchar,
) {
    let mut peer = [0_u8; 6];
    if !addr.is_null() {
        peer.copy_from_slice(core::slice::from_raw_parts(addr, 6));
    }
    BLE_GATT_CONN_ID.store(conn_handle as u32, Ordering::Relaxed);
    BLE_GATT_CONNECTED.store(true, Ordering::Relaxed);
    BLE_GATT_AUTHENTICATED.store(
        encrypted != 0 || authenticated != 0 || bonded != 0,
        Ordering::Relaxed,
    );
    set_connected_addr(&peer);
    if pairing_open() && (encrypted != 0 || bonded != 0) {
        BLE_PAIRING_ACCEPTED.store(true, Ordering::Relaxed);
        BLE_PAIRING_DEADLINE_MS.store(0, Ordering::Relaxed);
        set_paired_addr(&peer);
        BLE_COMPANION_ENABLED.store(true, Ordering::Relaxed);
        BLE_COMPANION_SAVE_PENDING.store(true, Ordering::Relaxed);
    }
    // NimBLE invokes this from its host task.  Keep connection establishment
    // allocation- and I/O-free so ATT service discovery can run immediately.
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_nimble_on_disconnect(reason: c_ushort) {
    BLE_GATT_CONNECTED.store(false, Ordering::Relaxed);
    BLE_GATT_NOTIFY_ENABLED.store(false, Ordering::Relaxed);
    BLE_GATT_AUTHENTICATED.store(false, Ordering::Relaxed);
    let _ = reason;
}

/// Record Android's short-lived `wake_request` advertisement.  This callback
/// runs on the NimBLE host task; the normal firmware polling loop performs the
/// scan-to-advertise transition after the bounded scan window completes.
#[no_mangle]
pub unsafe extern "C" fn dmesh_nimble_on_scan(
    service_data: *const c_uchar,
    len: c_ushort,
    rssi: i8,
) {
    if service_data.is_null() || len < 11 {
        return;
    }
    let data = core::slice::from_raw_parts(service_data, len as usize);
    let data = if data.len() >= 18 && data[..16] == DMESH_BLE_OPERATIONAL_UUID {
        &data[16..]
    } else {
        data
    };
    if data.len() < 11 || data[0..2] != DMESH_BLE_SERVICE_UUID16.to_le_bytes() {
        return;
    }
    BLE_SCAN_REPORTS.fetch_add(1, Ordering::Relaxed);
    BLE_SCAN_LAST_RSSI.store(rssi as i32, Ordering::Relaxed);
    let event = if data[10] & 0x80 != 0 && data.len() >= 13 {
        data[12]
    } else {
        // Pre-v2 Android builds overloaded this field with the event.
        data[10]
    };
    if event == 3 {
        BLE_SCAN_MATCHED.fetch_add(1, Ordering::Relaxed);
        BLE_WAKE_REQUEST_RX.fetch_add(1, Ordering::Relaxed);
        BLE_RENDEZVOUS_WAKE_SEEN.store(true, Ordering::Relaxed);
    }
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_nimble_on_subscribe(attr_handle: c_ushort, notify: c_uchar) {
    BLE_GATT_NOTIFY_ENABLED.store(notify != 0, Ordering::Relaxed);
    let _ = attr_handle;
    if notify != 0 {
        notify_companion_pending();
    }
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_nimble_on_write(data: *const c_uchar, len: c_ushort) {
    if data.is_null() || len == 0 {
        return;
    }
    let data = core::slice::from_raw_parts(data, len as usize);
    let line = format!("event type=ble.gatt_write target=rx len={}", data.len());
    telemetry::record_log(line);
    let response = handle_ble_rx(data, BleTransport::Gatt);
    if !response.is_empty() {
        send_gatt(&response);
    }
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_nimble_on_coc_write(data: *const c_uchar, len: c_ushort) {
    if data.is_null() || len == 0 {
        return;
    }
    let data = core::slice::from_raw_parts(data, len as usize);
    BLE_COC_RX.fetch_add(1, Ordering::Relaxed);
    telemetry::record_log(format!("event type=ble.coc_write len={}", data.len()));
    let response = handle_ble_rx(data, BleTransport::Coc);
    if !response.is_empty() {
        send_coc(&response);
    }
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_nimble_on_coc_state(connected: c_uchar) {
    BLE_COC_CONNECTED.store(connected != 0, Ordering::Relaxed);
    telemetry::record_log(format!(
        "event type=ble.coc state={}",
        if connected != 0 {
            "connected"
        } else {
            "disconnected"
        }
    ));
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_nimble_on_log(line: *const c_char) {
    if line.is_null() {
        return;
    }
    if let Ok(line) = CStr::from_ptr(line).to_str() {
        // Called by the NimBLE host task.  Recording is try-lock based and
        // bounded; console forwarding can synchronously touch Wi-Fi.
        telemetry::record_log(line.to_string());
    }
}
