//! Non-promiscuous NAN discovery receive evidence.
//!
//! This uses the normal ESP-IDF vendor-IE monitor, not the ESP-NOW library
//! and not `esp_wifi_set_promiscuous_rx_cb`.  ESP-IDF documents this monitor
//! for beacon/probe/association IEs only; action frames are deliberately not
//! inferred from it. NAN public actions are received only during the bounded
//! promiscuous discovery window in `wifi_nan_dw_capture_esp`.

use core::{
    ffi::c_void,
    mem::MaybeUninit,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};

static STARTED: AtomicBool = AtomicBool::new(false);
static BEACON_IES: AtomicU32 = AtomicU32::new(0);
static NAN_BEACON_IES: AtomicU32 = AtomicU32::new(0);
static OTHER_IES: AtomicU32 = AtomicU32::new(0);
static ACTION_RX: AtomicU32 = AtomicU32::new(0);
static ACTION_RX_BYTES: AtomicU32 = AtomicU32::new(0);
static ACTION_LISTEN_REQUESTS: AtomicU32 = AtomicU32::new(0);
static ACTION_LISTEN_FAILURES: AtomicU32 = AtomicU32::new(0);
static ESPNOW_ACTION_RX: AtomicU32 = AtomicU32::new(0);
static NAN_ACTION_RX: AtomicU32 = AtomicU32::new(0);
static OTHER_ACTION_RX: AtomicU32 = AtomicU32::new(0);
static ROC_LOOP_ENABLED: AtomicBool = AtomicBool::new(false);
static ROC_LOOP_DURATION_MS: AtomicU32 = AtomicU32::new(0);
static ROC_LOOP_NEXT_US: AtomicU32 = AtomicU32::new(0);
// `esp_wifi_remain_on_channel` retains the request pointer until its done
// callback. This is intentionally one static slot rather than a stack local:
// a control handler returns immediately, but the Wi-Fi task dereferences the
// request for the entire ROC lease. One slot also makes the transport's memory
// bound explicit and prevents overlapping leases from racing the driver.
static ROC_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
static mut ROC_REQUEST: MaybeUninit<esp_idf_sys::wifi_roc_req_t> = MaybeUninit::uninit();
// ESP-IDF's ROC completion is asynchronous. Do not reissue at the nominal
// expiry instant: on C6 that can overlap the old lease in the Wi-Fi task and
// trip its watchdog. The bounded guard leaves a 98.75% requested duty cycle
// for the four-second measurement dwell, while keeping driver ownership
// unambiguous.
const ROC_REISSUE_GUARD_MS: u32 = 50;

/// Whether ESP-IDF still owns the static ROC request slot.  DW policy must
/// not toggle promiscuous mode during this interval: that transition can
/// block the C6 Wi-Fi control task.
pub fn roc_in_flight() -> bool {
    ROC_IN_FLIGHT.load(Ordering::Acquire)
}
/// `(beacon_vendor_ies, nan_beacon_vendor_ies, other_vendor_ies)` observed
/// through ESP-IDF while promiscuous mode remains disabled.
pub fn stats() -> (u32, u32, u32) {
    (
        BEACON_IES.load(Ordering::Relaxed),
        NAN_BEACON_IES.load(Ordering::Relaxed),
        OTHER_IES.load(Ordering::Relaxed),
    )
}

/// `(action_frames, action_bytes, listen_requests, listen_failures,
/// espnow_actions, nan_actions, other_actions)`. These are received by the
/// optional bounded ROC listener; NAN's operational receive path is DW
/// capture, not a continuous driver dispatcher.
pub fn action_stats() -> (u32, u32, u32, u32, u32, u32, u32) {
    (
        ACTION_RX.load(Ordering::Relaxed),
        ACTION_RX_BYTES.load(Ordering::Relaxed),
        ACTION_LISTEN_REQUESTS.load(Ordering::Relaxed),
        ACTION_LISTEN_FAILURES.load(Ordering::Relaxed),
        ESPNOW_ACTION_RX.load(Ordering::Relaxed),
        NAN_ACTION_RX.load(Ordering::Relaxed),
        OTHER_ACTION_RX.load(Ordering::Relaxed),
    )
}

/// Reset observation-only counters without unregistering callbacks or
/// changing Wi-Fi/ROC state. Radio handlers use this to make a test batch's
/// before/after delta independent of prior discovery traffic.
pub fn reset_stats() {
    BEACON_IES.store(0, Ordering::Release);
    NAN_BEACON_IES.store(0, Ordering::Release);
    OTHER_IES.store(0, Ordering::Release);
    ACTION_RX.store(0, Ordering::Release);
    ACTION_RX_BYTES.store(0, Ordering::Release);
    ACTION_LISTEN_REQUESTS.store(0, Ordering::Release);
    ACTION_LISTEN_FAILURES.store(0, Ordering::Release);
    ESPNOW_ACTION_RX.store(0, Ordering::Release);
    NAN_ACTION_RX.store(0, Ordering::Release);
    OTHER_ACTION_RX.store(0, Ordering::Release);
}

/// Register once; this must never change promiscuous state or Wi-Fi filters.
pub fn start() -> bool {
    if STARTED.swap(true, Ordering::AcqRel) {
        return true;
    }
    let result = crate::wifi_esp::register_vendor_ie_callback(Some(callback));
    if result != esp_idf_sys::ESP_OK {
        STARTED.store(false, Ordering::Release);
        return false;
    }
    true
}

/// Ask the Wi-Fi driver to deliver action management frames for one bounded
/// discovery window. ESP-IDF's own NAN USD implementation uses this API. It
/// does not enable promiscuous mode; `allow_broadcast` additionally allows
/// discovery peers whose Address3/BSSID is not the associated AP.
///
/// The caller owns cadence (DW0/DW8 today), so Recovery and Main can apply
/// their different power policies while sharing this receive primitive.
pub fn listen_for_actions(channel: u8, duration_ms: u32) -> bool {
    if ROC_IN_FLIGHT
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        ACTION_LISTEN_FAILURES.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    // ESP-IDF keeps this pointer after `esp_wifi_remain_on_channel` returns;
    // do not replace this with a local `wifi_roc_req_t`. The driver owns the
    // completed request until `roc_done_callback` clears `ROC_IN_FLIGHT`.
    let request = unsafe {
        let request = core::ptr::addr_of_mut!(ROC_REQUEST)
            .cast::<esp_idf_sys::wifi_roc_req_t>();
        request.write(core::mem::zeroed());
        (*request).ifx = crate::wifi_esp::radio_interface_id(crate::wifi_esp::RadioInterface::Sta);
        (*request).type_ = esp_idf_sys::wifi_roc_t_WIFI_ROC_REQ;
        (*request).channel = channel;
        (*request).sec_channel = esp_idf_sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE;
        (*request).wait_time_ms = duration_ms;
        (*request).rx_cb = Some(action_rx_callback);
        (*request).done_cb = Some(roc_done_callback);
        (*request).allow_broadcast = true;
        request
    };
    ACTION_LISTEN_REQUESTS.fetch_add(1, Ordering::Relaxed);
    let result = crate::wifi_esp::remain_on_channel(request);
    if result != esp_idf_sys::ESP_OK {
        ROC_IN_FLIGHT.store(false, Ordering::Release);
        ACTION_LISTEN_FAILURES.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    true
}

/// ESP-IDF invokes this from its Wi-Fi task after it has stopped using the
/// request slot. It is deliberately allocation-free and does not call back
/// into Wi-Fi: the next control/poll request may now reuse the single slot.
unsafe extern "C" fn roc_done_callback(
    _context: u32,
    _op_id: u8,
    _status: esp_idf_sys::wifi_roc_done_status_t,
) {
    ROC_IN_FLIGHT.store(false, Ordering::Release);
}

/// Schedule one listener on the channel currently retained by the radio. A
/// connected STA therefore remains on its AP channel; a future sleepy policy
/// may instead call [`listen_for_actions`] after it has selected DW0/DW8.
pub fn listen_on_current_channel(duration_ms: u32) -> bool {
    let Some((primary, _secondary)) = crate::wifi_esp::current_channel() else {
        ACTION_LISTEN_FAILURES.fetch_add(1, Ordering::Relaxed);
        return false;
    };
    if primary == 0 {
        ACTION_LISTEN_FAILURES.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    listen_for_actions(primary, duration_ms)
}

/// Configure a repeating same-channel ROC observer. The common transport
/// worker calls [`poll`] so this has no task, queue, or packet allocation.
pub fn configure_loop(enabled: bool, duration_ms: u32) -> bool {
    // The shared schema allows the ESP-IDF-tested ten-second maximum. Normal
    // measurements use four seconds; the bound remains finite so the common
    // worker can cancel or retune it through the runtime control handler.
    if enabled && !(10..=10_000).contains(&duration_ms) {
        return false;
    }
    ROC_LOOP_DURATION_MS.store(duration_ms, Ordering::Release);
    ROC_LOOP_NEXT_US.store(0, Ordering::Release);
    ROC_LOOP_ENABLED.store(enabled, Ordering::Release);
    true
}

/// Reissue ROC after each requested window. The driver is the completion
/// authority; request/failure counters remain explicit evidence of coverage.
/// This is a deadline service, not a packet loop: the ESP-IDF completion
/// callback only releases `ROC_IN_FLIGHT`, and the Main owner calls `poll`
/// after the bounded lease expires so no callback blocks or re-enters Wi-Fi.
pub fn poll() {
    if !ROC_LOOP_ENABLED.load(Ordering::Acquire) {
        return;
    }
    let now = unsafe { esp_idf_sys::esp_timer_get_time() }.max(0) as u32;
    let next = ROC_LOOP_NEXT_US.load(Ordering::Acquire);
    if next != 0 && now.wrapping_sub(next) > 0x8000_0000 {
        return;
    }
    let duration = ROC_LOOP_DURATION_MS.load(Ordering::Acquire);
    // A ROC lease and the bounded permissive NAN DW must never overlap.  A
    // 400-ms lease plus the 64-ms DW and C6's 50-ms completion guard fits in
    // one 512-TU cadence; a nominal 512-ms lease does not.  Defer rather than
    // ask the driver to race the two receive modes.
    if crate::wifi_nan_dw_capture_esp::roc_conflicts(
        duration.saturating_add(ROC_REISSUE_GUARD_MS),
    ) {
        ROC_LOOP_NEXT_US.store(now.wrapping_add(10_000), Ordering::Release);
        return;
    }
    let _ = listen_on_current_channel(duration);
    let next_us = duration
        .saturating_add(ROC_REISSUE_GUARD_MS)
        .saturating_mul(1_000);
    ROC_LOOP_NEXT_US.store(now.wrapping_add(next_us), Ordering::Release);
}

/// Return the next ROC-service deadline in milliseconds relative to `now`.
/// The Main owner uses this as a task-notification timeout; it does not wake
/// on a fixed polling cadence when no ROC lease is active.
pub fn next_service_delay_ms() -> Option<u32> {
    if !ROC_LOOP_ENABLED.load(Ordering::Acquire) {
        return None;
    }
    let next_us = ROC_LOOP_NEXT_US.load(Ordering::Acquire);
    if next_us == 0 {
        return Some(0);
    }
    let now_us = unsafe { esp_idf_sys::esp_timer_get_time() }.max(0) as u32;
    let remaining_us = next_us.wrapping_sub(now_us);
    if remaining_us > 0x8000_0000 {
        Some(0)
    } else {
        Some((remaining_us / 1_000).max(1))
    }
}

unsafe extern "C" fn callback(
    _ctx: *mut c_void,
    kind: esp_idf_sys::wifi_vendor_ie_type_t,
    _source: *const u8,
    ie: *const esp_idf_sys::vendor_ie_data_t,
    _rssi: i32,
) {
    if ie.is_null() {
        return;
    }
    if kind != esp_idf_sys::wifi_vendor_ie_type_t_WIFI_VND_IE_TYPE_BEACON {
        OTHER_IES.fetch_add(1, Ordering::Relaxed);
        return;
    }
    BEACON_IES.fetch_add(1, Ordering::Relaxed);
    let ie = unsafe { &*ie };
    if ie.vendor_oui == dmesh_rawnan::NAN_BSSID_OUI && ie.vendor_oui_type == 0x13 {
        NAN_BEACON_IES.fetch_add(1, Ordering::Relaxed);
    }
}

unsafe extern "C" fn action_rx_callback(
    header: *mut u8,
    payload: *mut u8,
    len: usize,
    _channel: u8,
) -> i32 {
    ACTION_RX.fetch_add(1, Ordering::Relaxed);
    ACTION_RX_BYTES.fetch_add(len.min(u32::MAX as usize) as u32, Ordering::Relaxed);
    // ROC supplies the management body without the 802.11 header.  Classify
    // only fixed prefix bytes here: this callback must neither allocate nor
    // enqueue. The host-tested rawnan parser remains authoritative when a
    // recognized frame is copied into the shared ingress pool.
    let body = if payload.is_null() {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(payload, len) }
    };
    if body.starts_with(&dmesh_rawnan::espnow::ACTION_PREFIX) {
        ESPNOW_ACTION_RX.fetch_add(1, Ordering::Relaxed);
        // The unassociated-STA check holds this bounded ROC lease so
        // broadcast-BSSID NOW-like actions enter the normal shared parser
        // without enabling promiscuous capture.
        crate::wifi_espnow_esp::receive_roc_action_parts(header, payload, len);
    } else if body.starts_with(&[0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13]) {
        NAN_ACTION_RX.fetch_add(1, Ordering::Relaxed);
    } else {
        OTHER_ACTION_RX.fetch_add(1, Ordering::Relaxed);
    }
    esp_idf_sys::ESP_OK
}
