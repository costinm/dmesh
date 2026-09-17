// IMPORTANT: This is shared no-std ESP firmware code. QUIC-lite and CBOR
// service mechanics remain in quic-lite/dmesh-server; this file owns ESP-IDF
// STA and FreeRTOS bearer scheduling for Recovery and Main.
//! Wi-Fi STA setup and raw Ethernet transport adapter.
//!
//! This module owns all bearer concerns: static STA configuration, raw frame
//! bootstrap, datagram receive/send, and QUIC-lite scheduling. The
//! flashing module sees only ordered application stream callbacks.

use crate::{commands as uart, TransportProfile};
use alloc::{boxed::Box, vec::Vec};
use core::{
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU16, AtomicU32, AtomicU8, AtomicUsize, Ordering},
};

// Recovery-only PHY policy. It is deliberately not an NVS setting: normal
// images retain their default protocol set.  ESP-IDF does not support an
// 802.11n-only 2.4 GHz STA bitmap; the supported set is b/g/n.  Including n
// lets the association negotiate HT20 and use AMPDU for bulk UDP traffic.
const RECOVERY_STA_PROTOCOL: u8 = (esp_idf_sys::WIFI_PROTOCOL_11B
    | esp_idf_sys::WIFI_PROTOCOL_11G
    | esp_idf_sys::WIFI_PROTOCOL_11N) as u8;
// Keep the normal STA lane at HT20.  The data bearer must coexist with NAN
// and NOW on 2.4 GHz, where an HT40 secondary channel is both less robust and
// needlessly complicates retry/performance diagnosis.  A future dedicated
// lab mode may opt into HT40, but it must not change the normal association.
const RECOVERY_STA_HT40: bool = false;
/// AP beacons are the soft-NAN timing fallback when an Android NAN cluster is
/// unavailable.  ESP-IDF expresses the interval in TUs; 500 TU is about
/// 512 ms and is a supported SoftAP interval.
const NAN_FALLBACK_AP_BEACON_TU: u16 = 500;

/// The one hardware radio personality currently allowed to own ESP-IDF.
/// Bearers can share packet/QUIC code, but they must not independently alter
/// Wi-Fi callbacks, promiscuous state, or channel while another personality
/// is live.  All transitions are serialized and logged here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RadioMode {
    Idle = 0,
    // Test only modes
    StaRawUdp6 = 1,
    EspNowAction = 2,
    NanPromiscuous = 3,
    RadioLab = 4,

    // Prod modes
    // - Nan means promiscuous in DW (512ms or 4 sec for sleepy)
    // - Now means action frames callback/tx
    // Both must work along with AP (with other devices connected), APSta ()
    ApRawUdp6 = 5,
    /// Associated raw-UDP6 with independently selected NOW and NAN/DW
    /// extensions. This is one hardware personality, not separate owners of
    /// global Wi-Fi state.
    StaRawUdp6Extensions = 6,
}

impl RadioMode {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::Idle => b"idle",
            Self::StaRawUdp6 => b"sta_raw_udp6",
            Self::EspNowAction => b"espnow_action",
            Self::NanPromiscuous => b"nan_promiscuous",
            Self::RadioLab => b"radio_lab",
            Self::ApRawUdp6 => b"ap_raw_udp6",
            Self::StaRawUdp6Extensions => b"sta_raw_udp6_extensions",
        }
    }
}

static RADIO_MODE: AtomicU8 = AtomicU8::new(RadioMode::Idle as u8);
static LAST_SCAN_LEN: AtomicU8 = AtomicU8::new(0);
static LAST_SCAN_TOTAL: AtomicU16 = AtomicU16::new(0);
static LAST_SCAN_DMESH_TOTAL: AtomicU16 = AtomicU16::new(0);
static LAST_SCAN_AT_MS: AtomicU32 = AtomicU32::new(0);
/// `u8::MAX` means the configured STA SSID was not present in the most recent
/// completed scan. Other values are ESP-IDF `wifi_auth_mode_t` discriminants.
static LAST_SCAN_CONFIGURED_STA_AUTH: AtomicU8 = AtomicU8::new(u8::MAX);
static mut LAST_SCAN: [dmesh_server::raw_wifi::RawWifiScanEntry;
    dmesh_server::raw_wifi::RAW_WIFI_SCAN_MAX_RECORDS] =
    [dmesh_server::raw_wifi::RawWifiScanEntry {
        ssid: [0; 32],
        ssid_len: 0,
        bssid: [0; 6],
        channel: 0,
        signal_dbm: 0,
    }; dmesh_server::raw_wifi::RAW_WIFI_SCAN_MAX_RECORDS];
// ESP-IDF's `esp_wifi_get_channel` can return an error while an unassociated
// STA has already accepted `esp_wifi_set_channel`. Retain only a channel that
// this Wi-Fi owner successfully applied, so connectionless NOW TX has the
// same concrete channel as the idle receiver.
static APPLIED_CHANNEL: AtomicU8 = AtomicU8::new(0);

/// Return the channel selected by the Wi-Fi owner without calling ESP-IDF.
///
/// Receive callbacks may use this as a bounded capture fact.  It is not a
/// substitute for `current_channel()` in worker-context status reporting,
/// where the driver query remains authoritative for an associated STA.
pub fn selected_channel() -> Option<u8> {
    let channel = APPLIED_CHANNEL.load(Ordering::Acquire);
    (1..=13).contains(&channel).then_some(channel)
}

/// Claim the radio for exactly one named mode.  Returning false is an
/// explicit mode conflict, never a best-effort change to global ESP-IDF
/// settings.  The caller must stop the existing owner first.
pub fn enter_radio_mode(mode: RadioMode) -> bool {
    let previous = RADIO_MODE.load(Ordering::Acquire);
    if previous == mode as u8 {
        return true;
    }
    if previous != RadioMode::Idle as u8 {
        uart::send_stat(b"wifi mode conflict active=", previous as u64);
        uart::send_stat(b"wifi mode requested=", mode as u8 as u64);
        return false;
    }
    if RADIO_MODE
        .compare_exchange(previous, mode as u8, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    // TODO: one response (packet) with both
    uart::send_response(b"wifi mode start");
    uart::send_response(mode.label());
    true
}

/// Release one named owner after it has disabled callbacks and radio state.
/// A mismatched stop is retained as a diagnostic rather than tearing down
/// the active owner.
pub fn leave_radio_mode(mode: RadioMode) {
    if RADIO_MODE
        .compare_exchange(
            mode as u8,
            RadioMode::Idle as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
    {
        uart::send_response(b"wifi mode stop");
        uart::send_response(mode.label());
    }
}

pub fn radio_mode() -> RadioMode {
    match RADIO_MODE.load(Ordering::Acquire) {
        1 => RadioMode::StaRawUdp6,
        2 => RadioMode::EspNowAction,
        3 => RadioMode::NanPromiscuous,
        4 => RadioMode::RadioLab,
        5 => RadioMode::ApRawUdp6,
        6 => RadioMode::StaRawUdp6Extensions,
        _ => RadioMode::Idle,
    }
}

// Lab-only switch: retain the initialized STA radio and channel but prevent
// the normal recovery task from re-associating after an explicit disconnect.
// It is intentionally volatile and never touches the persisted profile/NVS.
static LAB_FORCE_UNASSOCIATED: AtomicBool = AtomicBool::new(false);
// The continuous `(127, 0)` NOW callback is global driver state. Preserve the
// requested state across a lab STA/AP restart: ROC-only rows must not have
// `ensure_lab_main_style_raw_sta` silently re-enable it before ROC is armed.
static NOW_DISPATCHER_ENABLED: AtomicBool = AtomicBool::new(true);
// Volatile APSTA owner used only by the common raw-radio laboratory handler.
// It intentionally creates no esp-netif or network-stack endpoint: AP beacons and the
// radio driver's management/action receive path are the subject of the test.
static LAB_OPEN_AP: AtomicBool = AtomicBool::new(false);
static STA_BSSID_CHECK_DISABLED: AtomicBool = AtomicBool::new(true);

static ACTION_CALLBACK_DROPS: AtomicU32 = AtomicU32::new(0);
static ACTION_CALLBACK_NOW: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" {
    fn esp_wifi_config_11b_rate(interface: esp_idf_sys::wifi_interface_t, disable: bool) -> i32;
    // Private libpp receive-filter hooks. C6 exposes only the STA/AP lanes;
    // there is no RISC-V NAN interface to program. Keep these declarations
    // beside the Wi-Fi lifecycle so the raw receive baseline is visible with
    // the driver setup rather than hidden in an extra C component.
    fn ic_rx_disable_bssid_check(interface_id: u8);
    fn ic_rx_enable_bssid_check(interface_id: u8);
    fn ic_set_rx_policy_ubssid_check(interface_id: u8, enabled: bool) -> bool;
    // Private libnet80211 receive registration. It is lifecycle state, not
    // ESP-NOW framing: all firmware images use the same Wi-Fi owner and may
    // select it at runtime alongside bounded ROC observation.
    fn ieee80211_recv_action_register(
        category: u8,
        action: u8,
        callback: Option<unsafe extern "C" fn(*mut c_void, usize, *mut u8, *mut u8) -> i32>,
    ) -> i32;
}

/// Configure the private BSSID policy on one real Wi-Fi receive lane.
///
/// This is intentionally an explicit per-lane operation: the paired NOW
/// matrix needs to distinguish the STA policy from the AP/APSTA policy. NAN
/// has no continuous private action dispatcher; it is received only in DW.
pub fn set_bssid_check_disabled(interface_id: u8, disabled: bool) -> bool {
    let applied = unsafe {
        if disabled {
            let policy_updated = ic_set_rx_policy_ubssid_check(interface_id, false);
            ic_rx_disable_bssid_check(interface_id);
            policy_updated
        } else {
            ic_rx_enable_bssid_check(interface_id);
            ic_set_rx_policy_ubssid_check(interface_id, true)
        }
    };
    if applied && interface_id == 0 {
        STA_BSSID_CHECK_DISABLED.store(disabled, Ordering::Release);
    }
    applied
}

pub fn sta_bssid_check_disabled() -> bool {
    STA_BSSID_CHECK_DISABLED.load(Ordering::Acquire)
}

/// Compatibility wrapper for action/NAN callers that intentionally need the
/// bypass. Associated raw UDP6 selects its policy from its runtime profile.
pub fn disable_bssid_check(interface_id: u8) {
    let _ = set_bssid_check_disabled(interface_id, true);
}

/// Install the connectionless NOW management-action callback after Wi-Fi is
/// live. NAN public actions deliberately have no continuous dispatcher: NAN
/// receive is bounded to its scheduled promiscuous discovery windows.
pub fn register_now_dispatcher() -> bool {
    // This private `ieee80211_action_vendor` hook is intentionally NOW-only.
    // Its category/action table accepts other entries, but on C6 an
    // unassociated STA admits continuous unsolicited vendor action `(127, 0)`
    // while it does not deliver NAN/Public Vendor Specific `(4, 9)` through
    // this callback. This was verified with DW and promiscuous receive off,
    // with both A1 and A3 broadcast (the same address shape as working NOW),
    // and again with AP=1, a directed public P2P action, and DW/promiscuous
    // receive off. Do not add NAN, P2P SD, GAS, or GO-negotiation registration
    // here. NAN stays in bounded DW capture; ROC is the bounded generic-action
    // experiment/alternative but cannot coexist with APSTA.
    if !NOW_DISPATCHER_ENABLED.load(Ordering::Acquire) {
        // ESP-IDF's private registration path does not document a null
        // callback as an unregister operation. Keep the already-installed
        // driver hook and make the Rust callback inert instead; ROC owns its
        // separate receive lease without a null function pointer transition.
        return true;
    }
    unsafe { ieee80211_recv_action_register(127, 0, Some(action_rx_callback)) == 0 }
}

unsafe extern "C" fn action_rx_callback(
    peer_context: *mut c_void,
    second: usize,
    third: *mut u8,
    fourth: *mut u8,
) -> i32 {
    if !now_dispatcher_enabled() || peer_context.is_null() || third.is_null() {
        return 0;
    }
    ACTION_CALLBACK_NOW.fetch_add(1, Ordering::Relaxed);
    crate::wifi_espnow_esp::receive_registered_action_payload(peer_context, second, third, fourth);
    0
}

pub fn action_dispatch_stats() -> (u32, u32, u32, u32) {
    // Keep the existing snapshot tuple stable. NAN/P2P stay zero because no
    // continuous registered callback admits them on C6.
    (
        0,
        ACTION_CALLBACK_NOW.load(Ordering::Relaxed),
        0,
        ACTION_CALLBACK_DROPS.load(Ordering::Relaxed),
    )
}

/// Select the continuous private NOW dispatcher. ROC-only tests turn this off
/// so an action classification can be attributed solely to ROC.
pub fn set_now_dispatcher(enabled: bool) -> bool {
    NOW_DISPATCHER_ENABLED.store(enabled, Ordering::Release);
    if !enabled {
        return true;
    }
    // `ieee80211_recv_action_register` is a private Wi-Fi-driver entry
    // point.  On C6 it may block indefinitely when invoked after an
    // operator has deliberately disconnected an otherwise live STA for a
    // ROC-only experiment.  The hook is global and was installed while the
    // radio was live; disabling the dispatcher only makes its Rust callback
    // inert, it does not unregister that hook.  Therefore a re-enable during
    // the unassociated hold must restore only the admission policy.  The
    // existing association and Wi-Fi stop/start paths re-register after the
    // driver has a valid STA context.
    if lab_force_unassociated() && !sta_associated() {
        return true;
    }
    register_now_dispatcher()
}

/// Whether the continuous driver callback should admit a NOW frame. ROC-only
/// tests retain the driver hook but turn this off before their lease begins.
pub(crate) fn now_dispatcher_enabled() -> bool {
    NOW_DISPATCHER_ENABLED.load(Ordering::Acquire)
}

/// Convert a raw-injection rate to ESP-IDF's PHY enum.
fn raw_tx_rate(mbps: u8) -> Option<esp_idf_sys::wifi_phy_rate_t> {
    Some(match mbps {
        0 => esp_idf_sys::wifi_phy_rate_t_WIFI_PHY_RATE_1M_L,
        6 => esp_idf_sys::wifi_phy_rate_t_WIFI_PHY_RATE_6M,
        9 => esp_idf_sys::wifi_phy_rate_t_WIFI_PHY_RATE_9M,
        12 => esp_idf_sys::wifi_phy_rate_t_WIFI_PHY_RATE_12M,
        18 => esp_idf_sys::wifi_phy_rate_t_WIFI_PHY_RATE_18M,
        24 => esp_idf_sys::wifi_phy_rate_t_WIFI_PHY_RATE_24M,
        36 => esp_idf_sys::wifi_phy_rate_t_WIFI_PHY_RATE_36M,
        48 => esp_idf_sys::wifi_phy_rate_t_WIFI_PHY_RATE_48M,
        54 => esp_idf_sys::wifi_phy_rate_t_WIFI_PHY_RATE_54M,
        _ => return None,
    })
}

/// Select a non-default data rate used by raw-injected STA frames.
///
/// `esp_wifi_80211_tx` has its own documented rate setting and otherwise
/// emits at 1 Mbit/s. Use the public raw-802.11 API here so UDP6 and
/// action/NOW share the same setting.
/// `0` must leave ESP-IDF untouched: it is the documented raw-frame default
/// of 1 Mbit/s, and programming the 1M enum after we reject 11b basic rates
/// is invalid on the C6 driver.
///
/// This deliberately lives beside the ESP-IDF raw adapter: the command
/// schema/profile is host-testable, but PHY programming is not.
pub fn configure_raw_tx_rate(mbps: u8) -> bool {
    if mbps == 0 {
        return true;
    }
    let interface = esp_idf_sys::wifi_interface_t_WIFI_IF_STA;
    let Some(rate) = raw_tx_rate(mbps) else {
        return false;
    };
    unsafe { esp_idf_sys::esp_wifi_config_80211_tx_rate(interface, rate) == esp_idf_sys::ESP_OK }
}

static STA_RECONNECT_TASK_STARTED: AtomicBool = AtomicBool::new(false);
// `esp_wifi_sta_get_ap_info` can retain a record after the AP has discarded
// the station.  Keep the driver transition as the association authority and
// use the AP record only to refresh diagnostic addressing while connected.
// These are deliberately static atomics: the ESP-IDF default event loop owns
// the callback for the process lifetime and must never retain a Rust object.
static STA_EVENT_HANDLER_REGISTERED: AtomicBool = AtomicBool::new(false);
static STA_ASSOCIATED_EVENT: AtomicBool = AtomicBool::new(false);
static STA_LAST_DISCONNECT_REASON: AtomicU8 = AtomicU8::new(0);
// ESP-IDF `WIFI_REASON_STA_LEAVING`: emitted after our own
// `esp_wifi_disconnect` during an intentional radio-epoch replacement.  It
// is not an association failure and must not arm Main's periodic STA retry.
const WIFI_REASON_STA_LEAVING: u8 = 36;
static STA_CONNECT_STARTED_MS: AtomicU32 = AtomicU32::new(0);
static STA_CONNECT_TO_ASSOCIATED_MS: AtomicU32 = AtomicU32::new(0);
/// Observe loss frequently enough to notice an AP restart promptly, but do
/// not blindly call `esp_wifi_connect` on every observation.  Candidate scans
/// and association requests happen only after a sustained loss.
const STA_ASSOCIATION_OBSERVE_TICKS: u32 = 10;
const STA_ASSOCIATION_LOSS_OBSERVATIONS: u8 = 20;
const STA_RECONNECT_SCAN_COOLDOWN_OBSERVATIONS: u8 = 20;
const STA_MINIMUM_RSSI_DBM: i8 = -70;
const STA_SCAN_MAX_RECORDS: usize = 16;

/// Request one explicit reconnect after an ESP-IDF disconnect completion.
/// Main calls this at most once per queued disconnect event and then waits for
/// the next connected/disconnected callback; it is not a timer or retry loop.
pub fn reconnect_sta_once() -> bool {
    if STA_ASSOCIATED_EVENT.load(Ordering::Acquire) {
        return true;
    }
    STA_CONNECT_TO_ASSOCIATED_MS.store(0, Ordering::Release);
    STA_CONNECT_STARTED_MS.store(
        (unsafe { esp_idf_sys::esp_timer_get_time() }.max(0) as u64 / 1_000) as u32,
        Ordering::Release,
    );
    let result = unsafe { esp_idf_sys::esp_wifi_connect() };
    if result == esp_idf_sys::ESP_OK || result == esp_idf_sys::ESP_ERR_WIFI_CONN {
        uart::send_response(b"wifi STA reconnect requested");
        true
    } else {
        uart::send_stat(b"wifi STA reconnect result=", result as u32 as u64);
        false
    }
}

/// Task-owned copy of the ephemeral transport.start association target. An
/// explicit BSSID is authoritative and reconnects directly; SSID-only starts
/// may scan to select an eligible DMesh AP.
struct StaReconnectConfig {
    preferred_ssid: [u8; 33],
    preferred_ssid_len: usize,
    bssid: [u8; 6],
    bssid_set: bool,
}

/// Owned scan result retained only until the immediately following
/// `esp_wifi_set_config` call.  It prevents a reconnect scan from reserving
/// packet memory or retaining heap allocations between association epochs.
struct ScannedStaCandidate {
    ssid: [u8; 33],
    ssid_len: usize,
    bssid: [u8; 6],
    channel: u8,
    authmode: esp_idf_sys::wifi_auth_mode_t,
    preferred: bool,
}

/// Apply one scan-selected AP to the already-started STA driver. The caller
/// owns scan timing and subsequent connection; this keeps ESP-IDF setup in
/// the Wi-Fi owner for both initial association and reconnect.
unsafe fn apply_sta_candidate(selection: &ScannedStaCandidate, allow_open: bool) -> bool {
    // Keep the credential installed by the epoch owner.  Rebuilding this from
    // `default()` erased the passphrase while selecting a BSSID from a scan.
    let mut wifi = esp_idf_sys::wifi_config_t::default();
    if esp_idf_sys::esp_wifi_get_config(esp_idf_sys::wifi_interface_t_WIFI_IF_STA, &mut wifi)
        != esp_idf_sys::ESP_OK
    {
        return false;
    }
    let sta = unsafe { &mut wifi.sta };
    for (dst, src) in sta
        .ssid
        .iter_mut()
        .zip(selection.ssid[..selection.ssid_len].iter())
    {
        *dst = *src;
    }
    sta.bssid_set = true;
    sta.bssid.copy_from_slice(&selection.bssid);
    sta.channel = selection.channel;
    match selection.authmode {
        mode if mode == esp_idf_sys::wifi_auth_mode_t_WIFI_AUTH_OPEN => {
            if !allow_open {
                return false;
            }
            sta.threshold.authmode = mode;
            sta.pmf_cfg.capable = false;
            sta.pmf_cfg.required = false;
        }
        mode if mode == esp_idf_sys::wifi_auth_mode_t_WIFI_AUTH_WPA2_PSK => {
            sta.threshold.authmode = mode;
            sta.pmf_cfg.capable = true;
            sta.pmf_cfg.required = false;
        }
        mode if mode == esp_idf_sys::wifi_auth_mode_t_WIFI_AUTH_WPA3_PSK => {
            sta.threshold.authmode = mode;
            sta.pmf_cfg.capable = true;
            sta.pmf_cfg.required = true;
            // A zeroed `wifi_sta_config_t` selects UNSPECIFIED.  Advertise
            // both derivation methods so a WPA3 AP that requires SAE-H2E and
            // an older WPA3 AP can use the same provisioned PSK.
            sta.sae_pwe_h2e = esp_idf_sys::wifi_sae_pwe_method_t_WPA3_SAE_PWE_BOTH;
        }
        mode if mode == esp_idf_sys::wifi_auth_mode_t_WIFI_AUTH_WPA2_WPA3_PSK => {
            sta.threshold.authmode = mode;
            sta.pmf_cfg.capable = true;
            sta.pmf_cfg.required = false;
            sta.sae_pwe_h2e = esp_idf_sys::wifi_sae_pwe_method_t_WPA3_SAE_PWE_BOTH;
        }
        _ => return false,
    }
    esp_idf_sys::esp_wifi_set_config(esp_idf_sys::wifi_interface_t_WIFI_IF_STA, &mut wifi)
        == esp_idf_sys::ESP_OK
}
// Main may keep NAN/raw Wi-Fi initialized while the STA association retries.
// The default STA netif is an ESP-IDF singleton: recreating it on a retry
// asserts in `esp_netif_create_default_wifi_sta`.  Retain this adapter-owned
// handle for the lifetime of the firmware and reuse it after `stop_sta()`.
static STA_NETIF: AtomicPtr<esp_idf_sys::esp_netif_t> = AtomicPtr::new(core::ptr::null_mut());
static STA_DRIVER_INITIALIZED: AtomicBool = AtomicBool::new(false);
// An image that booted from a complete, provisioned WPA profile may connect
// directly.  This is consumed by exactly one `init_sta` call: subsequent
// explicit Main transport starts and bounded reconnects retain their normal
// scan/select policy.  Recovery uses the same path, so an NVS-provisioned
// Main and Recovery cannot differ merely because one rebuilt its BSSID from
// an initial scan.
static STA_SKIP_INITIAL_SCAN: AtomicBool = AtomicBool::new(false);
static STA_AMPDU_ENABLED: AtomicBool = AtomicBool::new(true);
static STA_11B_RATES_DISABLED: AtomicBool = AtomicBool::new(true);
// `esp_wifi_init` may allocate part of its driver state before returning
// ESP_ERR_NO_MEM. Retrying that exact initialization leaks/fragmentates the
// remaining heap, so a reboot or a changed image/profile is required.
static STA_DRIVER_INIT_FAILED: AtomicBool = AtomicBool::new(false);
/// Optional product lifecycle hook. Main registers a fixed queue producer at
/// boot; Recovery leaves it unset and continues to use the shared adapter
/// without pulling Main policy into this module.
pub type StaLifecycleHandler = fn(bool, u8);
static STA_LIFECYCLE_HANDLER: AtomicUsize = AtomicUsize::new(0);
// PHY calibration requires an initialized NVS partition even though the Wi-Fi
// driver is forbidden from loading or saving a persisted STA configuration.
static PHY_NVS_INITIALIZED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    fn nvs_flash_init() -> i32;
}

fn initialize_phy_nvs() -> bool {
    if PHY_NVS_INITIALIZED.load(Ordering::Acquire) {
        return true;
    }
    let result = unsafe { nvs_flash_init() };
    if result == esp_idf_sys::ESP_OK || result == esp_idf_sys::ESP_ERR_INVALID_STATE {
        PHY_NVS_INITIALIZED.store(true, Ordering::Release);
        true
    } else {
        uart::send_stat(b"wifi PHY NVS init result=", result as u32 as u64);
        false
    }
}

unsafe extern "C" fn sta_event_handler(
    _argument: *mut c_void,
    _event_base: esp_idf_sys::esp_event_base_t,
    event_id: i32,
    event_data: *mut c_void,
) {
    if event_id == esp_idf_sys::wifi_event_t_WIFI_EVENT_STA_CONNECTED as i32 {
        let started = STA_CONNECT_STARTED_MS.load(Ordering::Acquire);
        if started != 0 {
            let now_ms =
                (unsafe { esp_idf_sys::esp_timer_get_time() }.max(0) as u64 / 1_000) as u32;
            // A STA attempt is bounded to seconds, so wrapping subtraction
            // remains correct even though the ESP target has no AtomicU64.
            STA_CONNECT_TO_ASSOCIATED_MS.store(now_ms.wrapping_sub(started), Ordering::Release);
        }
        STA_ASSOCIATED_EVENT.store(true, Ordering::Release);
        notify_sta_lifecycle(true, 0);
    } else if event_id == esp_idf_sys::wifi_event_t_WIFI_EVENT_STA_DISCONNECTED as i32 {
        let reason = if event_data.is_null() {
            0
        } else {
            unsafe { (*(event_data.cast::<esp_idf_sys::wifi_event_sta_disconnected_t>())).reason }
        };
        STA_ASSOCIATED_EVENT.store(false, Ordering::Release);
        STA_CONNECT_TO_ASSOCIATED_MS.store(0, Ordering::Release);
        if reason != WIFI_REASON_STA_LEAVING {
            STA_LAST_DISCONNECT_REASON.store(reason, Ordering::Release);
            notify_sta_lifecycle(false, reason);
        }
    }
}

/// Register a product callback that copies ESP-IDF association transitions to
/// its own queue. Called once during Main startup; the Wi-Fi event task never
/// performs radio work or takes a profile lock through this hook.
pub fn set_sta_lifecycle_handler(handler: Option<StaLifecycleHandler>) {
    STA_LIFECYCLE_HANDLER.store(
        handler.map(|handler| handler as usize).unwrap_or(0),
        Ordering::Release,
    );
}

fn notify_sta_lifecycle(associated: bool, reason: u8) {
    let handler = STA_LIFECYCLE_HANDLER.load(Ordering::Acquire);
    if handler != 0 {
        // Installed only through `set_sta_lifecycle_handler`; the callback
        // has no captured state and only copies a bounded event to Main.
        let handler: StaLifecycleHandler = unsafe { core::mem::transmute(handler) };
        handler(associated, reason);
    }
}

/// Subscribe once to ESP-IDF's STA transitions.  A stop/start keeps the
/// default event loop alive, so re-registering would produce duplicate state
/// transitions and diagnostic noise.
unsafe fn register_sta_event_handlers() -> bool {
    if STA_EVENT_HANDLER_REGISTERED.load(Ordering::Acquire) {
        return true;
    }
    let connected = unsafe {
        esp_idf_sys::esp_event_handler_register(
            esp_idf_sys::WIFI_EVENT,
            esp_idf_sys::wifi_event_t_WIFI_EVENT_STA_CONNECTED as i32,
            Some(sta_event_handler),
            core::ptr::null_mut(),
        )
    };
    let disconnected = unsafe {
        esp_idf_sys::esp_event_handler_register(
            esp_idf_sys::WIFI_EVENT,
            esp_idf_sys::wifi_event_t_WIFI_EVENT_STA_DISCONNECTED as i32,
            Some(sta_event_handler),
            core::ptr::null_mut(),
        )
    };
    if connected == esp_idf_sys::ESP_OK && disconnected == esp_idf_sys::ESP_OK {
        STA_EVENT_HANDLER_REGISTERED.store(true, Ordering::Release);
        true
    } else {
        uart::send_stat(
            b"wifi STA event registration result=",
            if connected != esp_idf_sys::ESP_OK {
                connected as u32 as u64
            } else {
                disconnected as u32 as u64
            },
        );
        false
    }
}

fn wifi_init_config(params: &TransportProfile) -> esp_idf_sys::wifi_init_config_t {
    esp_idf_sys::wifi_init_config_t {
        osi_funcs: core::ptr::addr_of_mut!(esp_idf_sys::g_wifi_osi_funcs),
        wpa_crypto_funcs: unsafe { esp_idf_sys::g_wifi_default_wpa_crypto_funcs },
        static_rx_buf_num: esp_idf_sys::CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM as i32,
        dynamic_rx_buf_num: esp_idf_sys::CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM as i32,
        tx_buf_type: esp_idf_sys::CONFIG_ESP_WIFI_TX_BUFFER_TYPE as i32,
        static_tx_buf_num: esp_idf_sys::WIFI_STATIC_TX_BUFFER_NUM as i32,
        dynamic_tx_buf_num: esp_idf_sys::WIFI_DYNAMIC_TX_BUFFER_NUM as i32,
        rx_mgmt_buf_type: esp_idf_sys::CONFIG_ESP_WIFI_DYNAMIC_RX_MGMT_BUF as i32,
        rx_mgmt_buf_num: esp_idf_sys::WIFI_RX_MGMT_BUF_NUM_DEF as i32,
        cache_tx_buf_num: esp_idf_sys::WIFI_CACHE_TX_BUFFER_NUM as i32,
        csi_enable: esp_idf_sys::WIFI_CSI_ENABLED as i32,
        // ESP-IDF consumes both settings only in esp_wifi_init.  The runtime
        // profile therefore performs a full, logged STA driver reinit rather
        // than pretending that a stop/start changes aggregation.
        ampdu_rx_enable: if params.sta_ampdu_enabled {
            esp_idf_sys::WIFI_AMPDU_RX_ENABLED as i32
        } else {
            0
        },
        ampdu_tx_enable: if params.sta_ampdu_enabled {
            esp_idf_sys::WIFI_AMPDU_TX_ENABLED as i32
        } else {
            0
        },
        amsdu_tx_enable: esp_idf_sys::WIFI_AMSDU_TX_ENABLED as i32,
        // `transport.start` supplies the complete transient STA profile.
        // Do not let ESP-IDF reopen NVS for a stale Wi-Fi configuration: it
        // is outside the radio-epoch owner and fails on a newly provisioned
        // device with no Wi-Fi NVS namespace.
        nvs_enable: 0,
        nano_enable: esp_idf_sys::WIFI_NANO_FORMAT_ENABLED as i32,
        // The ESP-IDF default itself uses a zero BA window whenever AMPDU RX
        // is compiled out. Keep that invariant for the runtime diagnostic:
        // retaining the build-time window while the enable bit is false still
        // lets the peer negotiate ADDBA on C6.
        rx_ba_win: if params.sta_ampdu_enabled {
            esp_idf_sys::WIFI_DEFAULT_RX_BA_WIN as i32
        } else {
            0
        },
        wifi_task_core_id: esp_idf_sys::WIFI_TASK_CORE_ID as i32,
        beacon_max_len: esp_idf_sys::WIFI_SOFTAP_BEACON_MAX_LEN as i32,
        mgmt_sbuf_num: esp_idf_sys::WIFI_MGMT_SBUF_NUM as i32,
        feature_caps: esp_idf_sys::WIFI_FEATURE_CAPS as u64,
        sta_disconnected_pm: esp_idf_sys::WIFI_STA_DISCONNECTED_PM_ENABLED != 0,
        espnow_max_encrypt_num: esp_idf_sys::CONFIG_ESP_WIFI_ESPNOW_MAX_ENCRYPT_NUM as i32,
        tx_hetb_queue_num: esp_idf_sys::WIFI_TX_HETB_QUEUE_NUM as i32,
        dump_hesigb_enable: esp_idf_sys::WIFI_DUMP_HESIGB_ENABLED != 0,
        magic: esp_idf_sys::WIFI_INIT_CONFIG_MAGIC as i32,
    }
}

/// Associate a STA for the raw Ethernet bearer without constructing an
/// DHCP client, IPv4 profile, or transport endpoint. The raw adapter
/// registers its own single RX callback after this bounded association wait.
pub fn init_sta(params: &TransportProfile) {
    unsafe {
        // `transport.start {mode: Sta}` is the only transition that permits
        // association.  Clear the unassociated epoch guard before starting
        // this new STA driver epoch so its reconnect observer may act again.
        LAB_FORCE_UNASSOCIATED.store(false, Ordering::Release);
        if !enter_radio_mode(RadioMode::StaRawUdp6) {
            return;
        }
        let init_started_us = esp_idf_sys::esp_timer_get_time();
        uart::send_stat(b"wifi raw sta init_ms=", 0);
        if !initialize_phy_nvs() {
            uart::send_response(b"wifi PHY NVS init failed");
            return;
        }
        if STA_DRIVER_INIT_FAILED.load(Ordering::Acquire) {
            uart::send_response(b"wifi raw driver init previously failed");
            return;
        }
        if !params.has_flash_profile() {
            uart::send_response(b"recovery profile missing");
            return;
        }
        uart::send_response(b"wifi raw init begin");
        // Main creates its infrastructure radio after this worker is
        // scheduled. Its ESP-IDF Wi-Fi initialization requires the netif and
        // default event-loop base to exist first; Recovery already has these
        // globals available through its minimal startup. This is only ESP-IDF
        // driver setup, not a DMesh transport endpoint.
        let netif = esp_idf_sys::esp_netif_init();
        if netif != esp_idf_sys::ESP_OK && netif != esp_idf_sys::ESP_ERR_INVALID_STATE {
            uart::send_response(b"wifi raw netif init failed");
            return;
        }
        let event_loop = esp_idf_sys::esp_event_loop_create_default();
        if event_loop != esp_idf_sys::ESP_OK && event_loop != esp_idf_sys::ESP_ERR_INVALID_STATE {
            uart::send_response(b"wifi raw event loop init failed");
            return;
        }
        if !register_sta_event_handlers() {
            uart::send_response(b"wifi STA event handler failed");
            return;
        }
        // This is the standard ESP-IDF ordering: create the default Wi-Fi
        // STA glue after esp-netif/event-loop initialization but *before*
        // esp_wifi_init.  `esp_wifi_internal_tx` is the glue's egress API;
        // creating it only after the driver was initialized accepted frames
        // but left the associated Ethernet path undrained on e6.
        if STA_NETIF.load(Ordering::Acquire).is_null() {
            let netif = esp_idf_sys::esp_netif_create_default_wifi_sta();
            if netif.is_null() {
                uart::send_response(b"wifi raw STA netif create failed");
                return;
            }
            STA_NETIF.store(netif, Ordering::Release);
        }
        if !STA_DRIVER_INITIALIZED.swap(true, Ordering::AcqRel) {
            STA_AMPDU_ENABLED.store(params.sta_ampdu_enabled, Ordering::Release);
            STA_11B_RATES_DISABLED.store(params.sta_11b_rates_disabled, Ordering::Release);
            uart::send_stat(
                b"wifi raw heap free=",
                esp_idf_sys::heap_caps_get_free_size(esp_idf_sys::MALLOC_CAP_8BIT) as u64,
            );
            uart::send_stat(
                b"wifi raw heap largest=",
                esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_8BIT) as u64,
            );
            uart::send_response(if params.sta_ampdu_enabled {
                b"wifi STA AMPDU enabled"
            } else {
                b"wifi STA AMPDU disabled"
            });
            let mut init = wifi_init_config(params);
            let result = esp_idf_sys::esp_wifi_init(&mut init);
            if result != esp_idf_sys::ESP_OK && result != esp_idf_sys::ESP_ERR_INVALID_STATE {
                STA_DRIVER_INITIALIZED.store(false, Ordering::Release);
                STA_DRIVER_INIT_FAILED.store(true, Ordering::Release);
                uart::send_stat(b"wifi raw driver init result=", result as u64);
                uart::send_response(b"wifi driver init failed");
                return;
            }
        }
        let _ = esp_idf_sys::esp_wifi_set_storage(esp_idf_sys::wifi_storage_t_WIFI_STORAGE_RAM);
        let mut sta = esp_idf_sys::wifi_sta_config_t::default();
        let ssid = if params.ssid_len != 0 {
            &params.ssid[..params.ssid_len]
        } else {
            b"Direct-Recovery"
        };
        for (dst, src) in sta.ssid.iter_mut().zip(ssid.iter().copied()) {
            *dst = src;
        }
        let configured_recovery_fallback = STA_SKIP_INITIAL_SCAN.load(Ordering::Acquire);
        // The selected BSSID's scan record decides the actual RSN mode below.
        // This initial configuration only starts the driver to perform that
        // scan while retaining the supplied credential for the selected AP.
        let passphrase = if params.sta_passphrase_len != 0 {
            &params.sta_passphrase[..params.sta_passphrase_len]
        } else {
            DMESH_AP_PASSPHRASE
        };
        if !params.open {
            for (dst, src) in sta.password.iter_mut().zip(passphrase.iter().copied()) {
                *dst = src;
            }
        }
        if configured_recovery_fallback && !params.open {
            // NVS carries a WPA PSK but not an AP scan record.  Set the
            // strongest interoperable configured policy up front; WPA2/WPA3
            // transition APs may then negotiate either method without a
            // scan-derived BSSID/authmode rewrite.
            sta.threshold.authmode = esp_idf_sys::wifi_auth_mode_t_WIFI_AUTH_WPA2_WPA3_PSK;
            sta.pmf_cfg.capable = true;
            sta.pmf_cfg.required = false;
            sta.sae_pwe_h2e = esp_idf_sys::wifi_sae_pwe_method_t_WPA3_SAE_PWE_BOTH;
        } else {
            sta.threshold.authmode = esp_idf_sys::wifi_auth_mode_t_WIFI_AUTH_OPEN;
            sta.pmf_cfg.capable = false;
            sta.pmf_cfg.required = false;
        }
        let mut config = esp_idf_sys::wifi_config_t { sta };
        // `transport.start { mode=sta, ap=1 }` is a complete APSTA epoch,
        // not an after-the-fact lab toggle.  Configure both personalities
        // before the single Wi-Fi start so the STA association and NAN/NOW
        // callback ownership survive the colocated WPA2 AP.
        let ap_enabled = params.ap == 1;
        let mode = if ap_enabled {
            esp_idf_sys::wifi_mode_t_WIFI_MODE_APSTA
        } else {
            esp_idf_sys::wifi_mode_t_WIFI_MODE_STA
        };
        let mode_result = esp_idf_sys::esp_wifi_set_mode(mode);
        if mode_result != esp_idf_sys::ESP_OK && mode_result != esp_idf_sys::ESP_ERR_INVALID_STATE {
            uart::send_stat(b"wifi STA mode result=", mode_result as u32 as u64);
            return;
        }
        if ap_enabled {
            let channel = if params.sta_channel == 0 {
                6
            } else {
                params.sta_channel.clamp(1, 13)
            };
            if !configure_unassociated_dmesh_ap(channel, NAN_FALLBACK_AP_BEACON_TU, params.open)
                || !configure_passive_p2p_advertisement(true)
            {
                uart::send_response(b"wifi STA+AP setup failed");
                return;
            }
        } else if !configure_passive_p2p_advertisement(false) {
            uart::send_response(b"wifi STA P2P marker clear failed");
            return;
        }
        let config_result = esp_idf_sys::esp_wifi_set_config(
            esp_idf_sys::wifi_interface_t_WIFI_IF_STA,
            &mut config,
        );
        if config_result != esp_idf_sys::ESP_OK {
            uart::send_stat(b"wifi STA config result=", config_result as u32 as u64);
            return;
        }
        let mut protocols = esp_idf_sys::wifi_protocols_t {
            ghz_2g: RECOVERY_STA_PROTOCOL as u16,
            ghz_5g: 0,
        };
        if esp_idf_sys::esp_wifi_set_protocols(
            esp_idf_sys::wifi_interface_t_WIFI_IF_STA,
            &mut protocols,
        ) != esp_idf_sys::ESP_OK
        {
            uart::send_response(b"wifi bgn set failed");
            return;
        }
        let bandwidth = if RECOVERY_STA_HT40 {
            esp_idf_sys::wifi_bandwidth_t_WIFI_BW40
        } else {
            esp_idf_sys::wifi_bandwidth_t_WIFI_BW20
        };
        if esp_idf_sys::esp_wifi_set_bandwidth(esp_idf_sys::wifi_interface_t_WIFI_IF_STA, bandwidth)
            != esp_idf_sys::ESP_OK
        {
            uart::send_response(b"wifi STA bandwidth set failed");
            return;
        }
        // This must happen after init and before start. Its effect includes
        // the negotiated legacy/basic-rate set, so the direct profile applies
        // it through the full driver reinit used by AMPDU, never live.
        let legacy_rate = esp_wifi_config_11b_rate(
            esp_idf_sys::wifi_interface_t_WIFI_IF_STA,
            params.sta_11b_rates_disabled,
        );
        if legacy_rate != esp_idf_sys::ESP_OK {
            uart::send_stat(b"wifi STA 11b policy result=", legacy_rate as u32 as u64);
            return;
        }
        STA_ASSOCIATED_EVENT.store(false, Ordering::Release);
        let started = esp_idf_sys::esp_wifi_start();
        if started != esp_idf_sys::ESP_OK && started != esp_idf_sys::ESP_ERR_INVALID_STATE {
            uart::send_response(b"wifi STA start failed");
            return;
        }
        LAB_OPEN_AP.store(ap_enabled, Ordering::Release);
        if !set_bssid_check_disabled(0, params.sta_bssid_check_disabled) {
            uart::send_response(b"wifi STA BSSID policy failed");
            return;
        }
        uart::send_stat(b"wifi raw sta started_ms=", elapsed_ms(init_started_us));
        let _ = esp_idf_sys::esp_wifi_set_ps(esp_idf_sys::wifi_ps_type_t_WIFI_PS_NONE);
        let mut association_candidate_ready = STA_SKIP_INITIAL_SCAN.swap(false, Ordering::AcqRel);
        if !association_candidate_ready {
            if let Some(selection) = scan_dmesh_sta_candidate(
                &params.ssid[..params.ssid_len],
                params.sta_bssid_set.then_some(params.sta_bssid),
            ) {
                if apply_sta_candidate(&selection, params.open) {
                    association_candidate_ready = true;
                    uart::send_response(if selection.preferred {
                        b"wifi initial preferred candidate"
                    } else {
                        b"wifi initial fallback candidate"
                    });
                } else {
                    uart::send_response(b"wifi initial candidate config failed");
                }
            }
            if !association_candidate_ready {
                uart::send_response(b"wifi initial scan no eligible AP");
            }
        } else {
            // Recovery's WPA fallback keeps the configured SSID/PSK in the
            // driver and lets ESP-IDF perform its ordinary connect scan.
            // It must not inherit a stale BSSID from a former epoch.
            uart::send_response(b"wifi configured STA fallback");
        }
        if !association_candidate_ready {
            // Do not enter ESP-IDF's indefinite connecting state when the
            // selected STA is not even visible. Main will restore its normal
            // unassociated NAN+NOW epoch and schedule the next bounded scan.
            uart::send_response(b"wifi STA association skipped no candidate");
            // ESP-IDF emits no disconnect callback when Main deliberately
            // declines to call `esp_wifi_connect`.  Queue the same lifecycle
            // completion so Main restores NAN/NOW and schedules the bounded
            // periodic retry instead of remaining in a half-started STA epoch.
            notify_sta_lifecycle(false, 0);
            return;
        }
        STA_CONNECT_TO_ASSOCIATED_MS.store(0, Ordering::Release);
        // Do not present the intentional disconnect used to replace the
        // prior radio epoch as this attempt's failure reason. A subsequent
        // non-`STA_LEAVING` driver callback supplies the useful diagnostic.
        STA_LAST_DISCONNECT_REASON.store(0, Ordering::Release);
        STA_CONNECT_STARTED_MS.store(
            (esp_idf_sys::esp_timer_get_time().max(0) as u64 / 1_000) as u32,
            Ordering::Release,
        );
        let connect = esp_idf_sys::esp_wifi_connect();
        uart::send_stat(b"wifi raw sta connect_ms=", elapsed_ms(init_started_us));
        if connect != esp_idf_sys::ESP_OK && connect != esp_idf_sys::ESP_ERR_WIFI_CONN {
            uart::send_stat(b"wifi raw sta connect_result=", connect as u32 as u64);
        }
        // Association is asynchronous.  Do not spend five seconds in a
        // delay/check loop here: ESP-IDF's STA event callback reports the
        // authoritative connected/disconnected completion to Main's bounded
        // queue, which starts raw UDP6 only after the association exists.
        uart::send_response(b"wifi raw STA connecting");
        // Action/NOW registration is a separately requested radio mode.
        // Do not install it as a side effect of raw UDP6 association: its
        // driver callback is global and would make Recovery run two modes.
    }
}

/// Start one ordinary WPA STA association from its configured SSID/PSK without
/// waiting in the ESP-IDF scan path.  This is Recovery's bounded fallback;
/// it owns no raw bearer, NAN, NOW, or UART transport.
pub fn init_sta_configured(params: &TransportProfile) {
    STA_SKIP_INITIAL_SCAN.store(true, Ordering::Release);
    init_sta(params);
}

/// Use the complete NVS STA profile for Main's next initial radio epoch.
///
/// This only selects the initial association method.  It does not alter the
/// peer credentials, bypass later scan-based reconnects, or change the
/// Main-only NAN/NOW extension policy.
pub(crate) fn use_configured_sta_profile_once() {
    STA_SKIP_INITIAL_SCAN.store(true, Ordering::Release);
}

/// Start the unassociated NAN+NOW radio epoch.  This deliberately duplicates
/// the proven STA driver's setup sequence instead of making `init_sta` carry
/// a second, conditional personality: STA association/raw-UDP6 must retain
/// its established control flow.  NAN here means the unassociated Wi-Fi
/// channel owner; `nan_dw_interval=0` keeps promiscuous DW capture disabled
/// while the NOW action callback remains available.
pub fn init_nan_now(
    params: &TransportProfile,
    handler: crate::wifi_espnow_esp::EspNowHandler,
) -> bool {
    unsafe {
        // An unassociated NAN+NOW epoch must remain unassociated. A prior
        // STA epoch may have left the bounded reconnect observer alive; stop
        // it from issuing `esp_wifi_connect` before this mode replaces the
        // driver and pins the connectionless channel.
        LAB_FORCE_UNASSOCIATED.store(true, Ordering::Release);
        if !enter_radio_mode(RadioMode::StaRawUdp6) {
            uart::send_response(b"wifi NAN/NOW radio claim failed");
            return false;
        }
        if !initialize_phy_nvs() {
            uart::send_response(b"wifi NAN/NOW PHY NVS failed");
            leave_radio_mode(RadioMode::StaRawUdp6);
            return false;
        }
        let netif = esp_idf_sys::esp_netif_init();
        let event_loop = esp_idf_sys::esp_event_loop_create_default();
        if (netif != esp_idf_sys::ESP_OK && netif != esp_idf_sys::ESP_ERR_INVALID_STATE)
            || (event_loop != esp_idf_sys::ESP_OK
                && event_loop != esp_idf_sys::ESP_ERR_INVALID_STATE)
            || !register_sta_event_handlers()
        {
            uart::send_stat(b"wifi NAN/NOW netif result=", netif as u32 as u64);
            uart::send_stat(b"wifi NAN/NOW event result=", event_loop as u32 as u64);
            uart::send_response(b"wifi NAN/NOW netif/event setup failed");
            leave_radio_mode(RadioMode::StaRawUdp6);
            return false;
        }
        if STA_NETIF.load(Ordering::Acquire).is_null() {
            let netif = esp_idf_sys::esp_netif_create_default_wifi_sta();
            if netif.is_null() {
                uart::send_response(b"wifi NAN/NOW default netif failed");
                leave_radio_mode(RadioMode::StaRawUdp6);
                return false;
            }
            STA_NETIF.store(netif, Ordering::Release);
        }
        if !STA_DRIVER_INITIALIZED.swap(true, Ordering::AcqRel) {
            STA_AMPDU_ENABLED.store(params.sta_ampdu_enabled, Ordering::Release);
            STA_11B_RATES_DISABLED.store(params.sta_11b_rates_disabled, Ordering::Release);
            let mut init = wifi_init_config(params);
            let result = esp_idf_sys::esp_wifi_init(&mut init);
            if result != esp_idf_sys::ESP_OK && result != esp_idf_sys::ESP_ERR_INVALID_STATE {
                STA_DRIVER_INITIALIZED.store(false, Ordering::Release);
                STA_DRIVER_INIT_FAILED.store(true, Ordering::Release);
                uart::send_stat(b"wifi NAN/NOW driver init result=", result as u32 as u64);
                uart::send_response(b"wifi NAN/NOW driver init failed");
                leave_radio_mode(RadioMode::StaRawUdp6);
                return false;
            }
        }
        let _ = esp_idf_sys::esp_wifi_set_storage(esp_idf_sys::wifi_storage_t_WIFI_STORAGE_RAM);
        let nan_channel = if params.sta_channel == 0 {
            6
        } else {
            params.sta_channel.clamp(1, 13)
        };
        // The default unassociated setup starts APSTA once. Its WPA2 AP
        // provides the channel anchor for NOW/NAN validation; it is not a
        // later lab overlay on top of a running STA driver.
        let mode = if params.ap == 1 {
            esp_idf_sys::wifi_mode_t_WIFI_MODE_APSTA
        } else {
            esp_idf_sys::wifi_mode_t_WIFI_MODE_STA
        };
        if esp_idf_sys::esp_wifi_set_mode(mode) != esp_idf_sys::ESP_OK
            || (params.ap == 1
                && !configure_unassociated_dmesh_ap(
                    nan_channel,
                    NAN_FALLBACK_AP_BEACON_TU,
                    params.open,
                ))
            || !configure_passive_p2p_advertisement(params.ap == 1)
        {
            uart::send_response(b"wifi NAN/NOW AP setup failed");
            leave_radio_mode(RadioMode::StaRawUdp6);
            return false;
        }
        let mut protocols = esp_idf_sys::wifi_protocols_t {
            ghz_2g: RECOVERY_STA_PROTOCOL as u16,
            ghz_5g: 0,
        };
        let protocols_result = esp_idf_sys::esp_wifi_set_protocols(
            esp_idf_sys::wifi_interface_t_WIFI_IF_STA,
            &mut protocols,
        );
        if protocols_result != esp_idf_sys::ESP_OK {
            uart::send_stat(
                b"wifi NAN/NOW protocol result=",
                protocols_result as u32 as u64,
            );
            uart::send_response(b"wifi NAN/NOW protocol setup failed");
            leave_radio_mode(RadioMode::StaRawUdp6);
            return false;
        }
        let bandwidth = if RECOVERY_STA_HT40 {
            esp_idf_sys::wifi_bandwidth_t_WIFI_BW40
        } else {
            esp_idf_sys::wifi_bandwidth_t_WIFI_BW20
        };
        let bandwidth_result = esp_idf_sys::esp_wifi_set_bandwidth(
            esp_idf_sys::wifi_interface_t_WIFI_IF_STA,
            bandwidth,
        );
        let rate_result = esp_wifi_config_11b_rate(
            esp_idf_sys::wifi_interface_t_WIFI_IF_STA,
            params.sta_11b_rates_disabled,
        );
        if bandwidth_result != esp_idf_sys::ESP_OK || rate_result != esp_idf_sys::ESP_OK {
            uart::send_stat(
                b"wifi NAN/NOW bandwidth result=",
                bandwidth_result as u32 as u64,
            );
            uart::send_stat(b"wifi NAN/NOW 11b result=", rate_result as u32 as u64);
            uart::send_response(b"wifi NAN/NOW PHY setup failed");
            leave_radio_mode(RadioMode::StaRawUdp6);
            return false;
        }
        STA_ASSOCIATED_EVENT.store(false, Ordering::Release);
        let started = esp_idf_sys::esp_wifi_start();
        if started != esp_idf_sys::ESP_OK && started != esp_idf_sys::ESP_ERR_INVALID_STATE {
            uart::send_stat(b"wifi NAN/NOW start result=", started as u32 as u64);
            uart::send_response(b"wifi NAN/NOW driver start failed");
            leave_radio_mode(RadioMode::StaRawUdp6);
            return false;
        }
        if !set_bssid_check_disabled(0, params.sta_bssid_check_disabled) {
            uart::send_response(b"wifi NAN/NOW BSSID policy failed");
            leave_radio_mode(RadioMode::StaRawUdp6);
            return false;
        }
        // An unassociated sleepy NAN profile has no infrastructure DTIM to
        // serve. Keep modem power-save enabled between explicitly armed DW
        // captures; the capture owner temporarily disables it while the
        // radio must receive management actions.
        let power_save = params.now == 2 && params.ap == 0;
        let _ = esp_idf_sys::esp_wifi_set_ps(if power_save {
            esp_idf_sys::wifi_ps_type_t_WIFI_PS_MAX_MODEM
        } else {
            esp_idf_sys::wifi_ps_type_t_WIFI_PS_NONE
        });
        if params.ap == 1 {
            // APSTA selects its configured channel as it starts. Read the
            // live value instead of calling `set_channel` after start, which
            // would add a driver transition to the out-of-box NOW test.
            let mut primary = 0u8;
            let mut secondary = esp_idf_sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE;
            if esp_idf_sys::esp_wifi_get_channel(&mut primary, &mut secondary)
                != esp_idf_sys::ESP_OK
                || primary != nan_channel
            {
                uart::send_response(b"wifi NAN/NOW AP channel failed");
                leave_radio_mode(RadioMode::StaRawUdp6);
                return false;
            }
            APPLIED_CHANNEL.store(primary, Ordering::Release);
        } else {
            let _ = esp_idf_sys::esp_wifi_disconnect();
            esp_idf_sys::vTaskDelay(5);
            if !set_ht20_channel(nan_channel) {
                uart::send_response(b"wifi NAN/NOW channel pin failed");
                leave_radio_mode(RadioMode::StaRawUdp6);
                return false;
            }
        }
    }
    LAB_OPEN_AP.store(params.ap == 1, Ordering::Release);
    let enabled = start_sta_extensions(handler, params.nan_dw_interval, params.now);
    uart::send_response(if enabled {
        b"wifi NAN/NOW started"
    } else {
        b"wifi NAN/NOW start failed"
    });
    enabled
}

/// Restore the classic ESP32 sleepy NAN/NOW radio after explicit light sleep.
///
/// Unlike `init_nan_now`, this path owns no IP STA and therefore does not
/// create an esp-netif, register association handlers, disconnect, or wait for
/// an association transition.  The first prototype used this exact lifecycle:
/// fully deinitialize classic ESP32 before sleep, then rebuild only the raw
/// STA radio, pin its channel, and attach the NAN/NOW callbacks.
pub fn resume_sleepy_nan_now(
    params: &TransportProfile,
    handler: crate::wifi_espnow_esp::EspNowHandler,
) -> bool {
    #[cfg(any(target_arch = "riscv32", target_feature = "esp32s3ops"))]
    {
        return init_nan_now(params, handler);
    }

    #[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
    unsafe {
        let started_us = esp_idf_sys::esp_timer_get_time();
        LAB_FORCE_UNASSOCIATED.store(true, Ordering::Release);
        if !enter_radio_mode(RadioMode::StaRawUdp6) || !initialize_phy_nvs() {
            return false;
        }

        STA_AMPDU_ENABLED.store(params.sta_ampdu_enabled, Ordering::Release);
        STA_11B_RATES_DISABLED.store(params.sta_11b_rates_disabled, Ordering::Release);
        let mut init = wifi_init_config(params);
        let initialized = esp_idf_sys::esp_wifi_init(&mut init);
        if initialized != esp_idf_sys::ESP_OK && initialized != esp_idf_sys::ESP_ERR_INVALID_STATE {
            STA_DRIVER_INITIALIZED.store(false, Ordering::Release);
            STA_DRIVER_INIT_FAILED.store(true, Ordering::Release);
            leave_radio_mode(RadioMode::StaRawUdp6);
            return false;
        }
        STA_DRIVER_INITIALIZED.store(true, Ordering::Release);
        let driver_init_us = (esp_idf_sys::esp_timer_get_time() - started_us).max(0) as u64;

        let _ = esp_idf_sys::esp_wifi_set_storage(esp_idf_sys::wifi_storage_t_WIFI_STORAGE_RAM);
        if esp_idf_sys::esp_wifi_set_mode(esp_idf_sys::wifi_mode_t_WIFI_MODE_STA)
            != esp_idf_sys::ESP_OK
        {
            leave_radio_mode(RadioMode::StaRawUdp6);
            return false;
        }
        let mut protocols = esp_idf_sys::wifi_protocols_t {
            ghz_2g: RECOVERY_STA_PROTOCOL as u16,
            ghz_5g: 0,
        };
        if esp_idf_sys::esp_wifi_set_protocols(
            esp_idf_sys::wifi_interface_t_WIFI_IF_STA,
            &mut protocols,
        ) != esp_idf_sys::ESP_OK
            || esp_idf_sys::esp_wifi_set_bandwidth(
                esp_idf_sys::wifi_interface_t_WIFI_IF_STA,
                esp_idf_sys::wifi_bandwidth_t_WIFI_BW20,
            ) != esp_idf_sys::ESP_OK
            || esp_wifi_config_11b_rate(
                esp_idf_sys::wifi_interface_t_WIFI_IF_STA,
                params.sta_11b_rates_disabled,
            ) != esp_idf_sys::ESP_OK
        {
            leave_radio_mode(RadioMode::StaRawUdp6);
            return false;
        }
        let started = esp_idf_sys::esp_wifi_start();
        if started != esp_idf_sys::ESP_OK && started != esp_idf_sys::ESP_ERR_INVALID_STATE {
            leave_radio_mode(RadioMode::StaRawUdp6);
            return false;
        }
        let wifi_start_us = (esp_idf_sys::esp_timer_get_time() - started_us).max(0) as u64;
        let channel = if params.sta_channel == 0 {
            6
        } else {
            params.sta_channel.clamp(1, 13)
        };
        if !set_bssid_check_disabled(0, params.sta_bssid_check_disabled)
            || esp_idf_sys::esp_wifi_set_ps(esp_idf_sys::wifi_ps_type_t_WIFI_PS_MAX_MODEM)
                != esp_idf_sys::ESP_OK
            || !set_ht20_channel(channel)
        {
            leave_radio_mode(RadioMode::StaRawUdp6);
            return false;
        }
        let channel_ready_us = (esp_idf_sys::esp_timer_get_time() - started_us).max(0) as u64;
        LAB_OPEN_AP.store(false, Ordering::Release);
        let enabled = start_sta_extensions(handler, params.nan_dw_interval, params.now);
        let extensions_ready_us = (esp_idf_sys::esp_timer_get_time() - started_us).max(0) as u64;
        uart::send_stats(&[
            (b"wifi wake driver_init_us", driver_init_us),
            (b"wifi wake start_us", wifi_start_us),
            (b"wifi wake channel_ready_us", channel_ready_us),
            (b"wifi wake extensions_ready_us", extensions_ready_us),
        ]);
        enabled
    }
}

fn elapsed_ms(started_us: i64) -> u64 {
    (unsafe { esp_idf_sys::esp_timer_get_time() } - started_us).max(0) as u64 / 1_000
}

/// Radio interface selected by a bearer.  This is deliberately not the
/// ESP-IDF enum: protocol adapters request a logical lane while this file
/// remains the only location that maps it onto hardware APIs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RadioInterface {
    Sta,
    Ap,
    Nan,
}

fn radio_interface_native(interface: RadioInterface) -> esp_idf_sys::wifi_interface_t {
    match interface {
        RadioInterface::Sta => esp_idf_sys::wifi_interface_t_WIFI_IF_STA,
        RadioInterface::Ap => esp_idf_sys::wifi_interface_t_WIFI_IF_AP,
        RadioInterface::Nan => esp_idf_sys::wifi_interface_t_WIFI_IF_NAN,
    }
}

/// ABI-only interface value for a request structure owned by a protocol
/// adapter. It performs no radio operation; all ESP-IDF calls stay here.
pub fn radio_interface_id(interface: RadioInterface) -> esp_idf_sys::wifi_interface_t {
    radio_interface_native(interface)
}

/// ESP-IDF Ethernet callback ABI. The handler is protocol-owned, while its
/// registration, buffer lifetime, and hardware interface remain centralized.
pub type EthernetRxCallback =
    unsafe extern "C" fn(*mut c_void, u16, *mut c_void) -> esp_idf_sys::esp_err_t;

pub fn register_ethernet_rx_callback(
    interface: RadioInterface,
    callback: Option<EthernetRxCallback>,
) -> i32 {
    unsafe { esp_idf_sys::esp_wifi_internal_reg_rxcb(radio_interface_native(interface), callback) }
}

pub fn release_ethernet_rx_buffer(buffer: *mut c_void) {
    unsafe { esp_idf_sys::esp_wifi_internal_free_rx_buffer(buffer) }
}

pub fn interface_mac(interface: RadioInterface) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    (unsafe { esp_idf_sys::esp_wifi_get_mac(radio_interface_native(interface), mac.as_mut_ptr()) }
        == esp_idf_sys::ESP_OK)
        .then_some(mac)
}

/// Return the factory STA address without requiring a running Wi-Fi interface.
///
/// Runtime connection IDs are created before the radio personality is fully
/// configured and must remain stable across NAN/NOW and STA transitions.  The
/// eFuse-backed address is available at that point, unlike `interface_mac`,
/// which asks the active driver.  Callers use it only as local identity; it
/// does not transmit or change radio state.
pub fn factory_sta_mac() -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    (unsafe {
        esp_idf_sys::esp_read_mac(
            mac.as_mut_ptr(),
            esp_idf_sys::esp_mac_type_t_ESP_MAC_WIFI_STA,
        )
    } == esp_idf_sys::ESP_OK)
        .then_some(mac)
}

/// Submit an Ethernet-II frame through the driver-owned data path.
pub fn transmit_ethernet(interface: RadioInterface, frame: &[u8]) -> i32 {
    unsafe {
        esp_idf_sys::esp_wifi_internal_tx(
            radio_interface_native(interface),
            frame.as_ptr().cast_mut().cast(),
            frame.len() as u16,
        )
    }
}

/// Submit one complete raw station data frame.  The caller owns only frame
/// construction; rate/queue semantics and the ESP-IDF call stay here.
pub fn transmit_raw_station(frame: &[u8]) -> i32 {
    unsafe {
        esp_idf_sys::esp_wifi_80211_tx(
            radio_interface_native(RadioInterface::Sta),
            frame.as_ptr().cast(),
            frame.len() as i32,
            true,
        )
    }
}

/// Register the bounded completion observer for public raw-802.11 TX. The
/// callback runs on ESP-IDF's Wi-Fi task and must only update atomics.
pub fn register_raw_tx_done_callback(
    callback: Option<unsafe extern "C" fn(*const esp_idf_sys::esp_80211_tx_info_t)>,
) -> i32 {
    unsafe { esp_idf_sys::esp_wifi_register_80211_tx_cb(callback) }
}

pub fn current_channel() -> Option<(u8, esp_idf_sys::wifi_second_chan_t)> {
    let applied = APPLIED_CHANNEL.load(Ordering::Acquire);
    // ESP-IDF reports its idle STA default (channel 1) while unassociated,
    // even after the NAN/NOW owner selected channel 6. For unassociated NOW
    // action TX the selected channel is authoritative; associated STA always
    // retains the live driver query below.
    if !sta_associated() && (1..=13).contains(&applied) {
        return Some((
            applied,
            esp_idf_sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE,
        ));
    }
    let mut channel = 0u8;
    let mut secondary = esp_idf_sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE;
    if unsafe { esp_idf_sys::esp_wifi_get_channel(&mut channel, &mut secondary) }
        == esp_idf_sys::ESP_OK
        && (1..=13).contains(&channel)
    {
        APPLIED_CHANNEL.store(channel, Ordering::Release);
        return Some((channel, secondary));
    }
    if (1..=13).contains(&applied) {
        Some((
            applied,
            esp_idf_sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE,
        ))
    } else {
        None
    }
}

/// Pin the radio to a 2.4 GHz primary channel with no secondary channel.
/// Callers select policy; the hardware mutation remains with the radio owner.
pub fn set_ht20_channel(channel: u8) -> bool {
    let channel = channel.clamp(1, 13);
    unsafe {
        if esp_idf_sys::esp_wifi_set_channel(
            channel,
            esp_idf_sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE,
        ) != esp_idf_sys::ESP_OK
        {
            return false;
        }
    }
    APPLIED_CHANNEL.store(channel, Ordering::Release);
    true
}

/// Fixed Android-compatible credentials for every ESP-owned fallback AP.
///
/// Android's `WifiController` uses these values for both P2P and local-only
/// hotspot qualification. Keeping the ESP fallback AP identical lets one
/// ordinary WPA2 STA credential set work across Android and ESP peers; these
/// are intentionally not NVS settings or per-board secrets.
const DMESH_AP_SSID: &[u8] = b"DIRECT-dmesh";
const DMESH_AP_PASSPHRASE: &[u8] = b"untrusted-open-mode";

/// Configure the fixed WPA2 fallback AP before the one Wi-Fi start for an
/// unassociated or APSTA epoch. Called only while the radio owner creates an
/// epoch, never from a receive callback or service tick. A later AP policy
/// change requires a replacement epoch so NOW's driver callbacks stay owned
/// by one complete radio setup.
unsafe fn configure_unassociated_dmesh_ap(channel: u8, beacon_interval: u16, open: bool) -> bool {
    let mut ap = esp_idf_sys::wifi_ap_config_t::default();
    ap.ssid[..DMESH_AP_SSID.len()].copy_from_slice(DMESH_AP_SSID);
    ap.ssid_len = DMESH_AP_SSID.len() as u8;
    if !open {
        ap.password[..DMESH_AP_PASSPHRASE.len()].copy_from_slice(DMESH_AP_PASSPHRASE);
    }
    ap.channel = channel;
    ap.authmode = if open {
        esp_idf_sys::wifi_auth_mode_t_WIFI_AUTH_OPEN
    } else {
        esp_idf_sys::wifi_auth_mode_t_WIFI_AUTH_WPA2_PSK
    };
    // Android's app-scoped WPA2 requests must not require PMF, but accepting
    // it permits modern Android devices to negotiate PMF when they select it.
    ap.pmf_cfg.capable = !open;
    ap.pmf_cfg.required = false;
    ap.max_connection = 4;
    ap.beacon_interval = beacon_interval.clamp(100, 60_000);
    let mut config = esp_idf_sys::wifi_config_t { ap };
    esp_idf_sys::esp_wifi_set_config(esp_idf_sys::wifi_interface_t_WIFI_IF_AP, &mut config)
        == esp_idf_sys::ESP_OK
}

/// Attach the one shared passive P2P capability marker to the AP's beacon and
/// probe response.  This is radio-owner work because ESP-IDF stores the
/// vendor IE in the driver. It does not start active P2P Service Discovery or
/// alter NAN/NOW receive, association, or packet-buffer ownership.
unsafe fn configure_passive_p2p_advertisement(enabled: bool) -> bool {
    let mut marker = [0u8; 64];
    let marker_len = if enabled {
        let mut ap_mac = [0u8; 6];
        if esp_idf_sys::esp_read_mac(
            ap_mac.as_mut_ptr(),
            esp_idf_sys::esp_mac_type_t_ESP_MAC_WIFI_SOFTAP,
        ) != esp_idf_sys::ESP_OK
        {
            return false;
        }
        match dmesh_rawnan::p2p::encode_discovery_advertisement(&mut marker, ap_mac, 6) {
            Ok(used) => used,
            Err(_) => return false,
        }
    } else {
        0
    };
    for kind in [
        esp_idf_sys::wifi_vendor_ie_type_t_WIFI_VND_IE_TYPE_BEACON,
        esp_idf_sys::wifi_vendor_ie_type_t_WIFI_VND_IE_TYPE_PROBE_RESP,
    ] {
        // A radio epoch may replace an AP-enabled profile with another AP
        // profile. Clear the slot first so ESP-IDF does not reject a repeated
        // identical configuration as a duplicate.
        let _ = esp_idf_sys::esp_wifi_set_vendor_ie(
            false,
            kind,
            esp_idf_sys::wifi_vendor_ie_id_t_WIFI_VND_IE_ID_0,
            core::ptr::null(),
        );
        if enabled
            && esp_idf_sys::esp_wifi_set_vendor_ie(
                true,
                kind,
                esp_idf_sys::wifi_vendor_ie_id_t_WIFI_VND_IE_ID_0,
                marker[..marker_len].as_ptr().cast(),
            ) != esp_idf_sys::ESP_OK
        {
            return false;
        }
    }
    true
}

/// Submit one caller-constructed ESP-IDF action TX request.  Framing remains
/// bearer-specific, but the only actual radio submit operation is here.
pub fn submit_action_tx(request: *mut esp_idf_sys::wifi_action_tx_req_t) -> i32 {
    unsafe { esp_idf_sys::esp_wifi_action_tx_req(request) }
}

pub type PromiscuousRxCallback =
    unsafe extern "C" fn(*mut c_void, esp_idf_sys::wifi_promiscuous_pkt_type_t);

pub fn configure_promiscuous_rx(
    callback: Option<PromiscuousRxCallback>,
    filter: &mut esp_idf_sys::wifi_promiscuous_filter_t,
) -> bool {
    unsafe {
        esp_idf_sys::esp_wifi_set_promiscuous(false) == esp_idf_sys::ESP_OK
            && esp_idf_sys::esp_wifi_set_promiscuous_rx_cb(callback) == esp_idf_sys::ESP_OK
            && esp_idf_sys::esp_wifi_set_promiscuous_filter(filter) == esp_idf_sys::ESP_OK
    }
}

pub fn set_promiscuous(enabled: bool) -> bool {
    unsafe { esp_idf_sys::esp_wifi_set_promiscuous(enabled) == esp_idf_sys::ESP_OK }
}

/// Select modem power-save for the unassociated NAN DW owner.  The owner
/// turns it off only for a bounded receive window, then restores it after the
/// paired NAN/NOW window. Associated STA and AP personalities retain their
/// existing policy.
pub fn set_nan_dw_power_save(enabled: bool) -> bool {
    unsafe {
        esp_idf_sys::esp_wifi_set_ps(if enabled {
            esp_idf_sys::wifi_ps_type_t_WIFI_PS_MAX_MODEM
        } else {
            esp_idf_sys::wifi_ps_type_t_WIFI_PS_NONE
        }) == esp_idf_sys::ESP_OK
    }
}

pub fn set_promiscuous_filter(filter: &mut esp_idf_sys::wifi_promiscuous_filter_t) -> bool {
    unsafe { esp_idf_sys::esp_wifi_set_promiscuous_filter(filter) == esp_idf_sys::ESP_OK }
}

pub type VendorIeRxCallback =
    unsafe extern "C" fn(*mut c_void, u32, *const u8, *const esp_idf_sys::vendor_ie_data_t, i32);

pub fn register_vendor_ie_callback(callback: Option<VendorIeRxCallback>) -> i32 {
    unsafe { esp_idf_sys::esp_wifi_set_vendor_ie_cb(callback, core::ptr::null_mut()) }
}

pub fn remain_on_channel(request: *mut esp_idf_sys::wifi_roc_req_t) -> i32 {
    unsafe { esp_idf_sys::esp_wifi_remain_on_channel(request) }
}

/// Attach a caller-owned QUIC-lite handler to the generic raw Ethernet
/// adapter. The caller owns all DCID and application state; this module owns
/// only STA lifecycle and ESP Wi-Fi registration.
pub fn start_raw_udp6(
    handler: crate::wifi_raw_udp6_esp::RawUdp6Handler,
    connectionless_handler: crate::wifi_raw_udp6_esp::ConnectionlessUdp6Handler,
) -> bool {
    let mut mac = [0u8; 6];
    let mut ap = esp_idf_sys::wifi_ap_record_t::default();
    let read = unsafe {
        esp_idf_sys::esp_read_mac(
            mac.as_mut_ptr(),
            esp_idf_sys::esp_mac_type_t_ESP_MAC_WIFI_STA,
        )
    };
    if read != esp_idf_sys::ESP_OK
        || unsafe { esp_idf_sys::esp_wifi_sta_get_ap_info(&mut ap) } != esp_idf_sys::ESP_OK
    {
        return false;
    }
    crate::wifi_raw_udp6_esp::start(mac, ap.bssid, handler, connectionless_handler)
}

/// Start raw UDP6 for an unassociated open-AP epoch.  This has no STA AP
/// record by design, so it selects the AP Ethernet ingress directly.
pub fn start_raw_udp6_ap(
    handler: crate::wifi_raw_udp6_esp::RawUdp6Handler,
    connectionless_handler: crate::wifi_raw_udp6_esp::ConnectionlessUdp6Handler,
) -> bool {
    crate::wifi_raw_udp6_esp::start_ap(handler, connectionless_handler)
}

/// Bind the caller-owned QUIC-lite action handler to the shared radio ingress.
///
/// This does not start an ESP-NOW subsystem or decide radio state. Wi-Fi
/// startup registers the global NOW action callback; all received frames
/// then enter the common bounded ingress pool, and this function supplies the
/// action decoder/QUIC dispatch only. Association is a raw-UDP peer-selection
/// condition, not an action-dispatch condition.
pub fn install_action_ingress(handler: crate::wifi_espnow_esp::EspNowHandler) -> bool {
    if !enter_radio_mode(RadioMode::EspNowAction) {
        return false;
    }
    let mut mac = [0u8; 6];
    let read = unsafe {
        esp_idf_sys::esp_read_mac(
            mac.as_mut_ptr(),
            esp_idf_sys::esp_mac_type_t_ESP_MAC_WIFI_STA,
        )
    };
    if read != esp_idf_sys::ESP_OK {
        leave_radio_mode(RadioMode::EspNowAction);
        return false;
    }
    let installed = crate::wifi_espnow_esp::install_action_ingress(mac, handler);
    if !installed {
        leave_radio_mode(RadioMode::EspNowAction);
    }
    installed
}

/// Start the associated STA+UDP6+NOW extension, optionally with NAN DW
/// capture on channel 6. `nan_dw_interval` is forced to zero by Main for a
/// STA on any other channel; NOW then remains available co-channel and UDP6
/// remains the normal shared-network bearer.
/// Wi-Fi owns the callback, ingress-pool, and radio lifecycle in either case.
pub fn start_sta_extensions(
    handler: crate::wifi_espnow_esp::EspNowHandler,
    nan_dw_interval: u8,
    now: u8,
) -> bool {
    if RADIO_MODE
        .compare_exchange(
            RadioMode::StaRawUdp6 as u8,
            RadioMode::StaRawUdp6Extensions as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        uart::send_stat(b"wifi NAN/NOW requested mode=", radio_mode() as u8 as u64);
        return false;
    }
    uart::send_response(b"wifi mode upgrade sta_raw_udp6_nan_now");
    let Some(mac) = interface_mac(RadioInterface::Sta) else {
        RADIO_MODE.store(RadioMode::StaRawUdp6 as u8, Ordering::Release);
        return false;
    };
    if !crate::wifi_espnow_esp::install_action_ingress(mac, handler)
        || !crate::shared_ingress_esp::start(
            crate::shared_ingress_esp::IngressKind::EspNow,
            crate::wifi_espnow_esp::dispatch_ingress,
        )
        || !set_now_dispatcher(true)
        // `init_nan_now` marks the unassociated epoch before the Wi-Fi
        // driver starts. `set_now_dispatcher` intentionally avoids the
        // private registration call during a later ROC-only unassociated
        // hold, where the driver hook is already live. A fresh NAN+NOW boot
        // has no prior hook, though, so register it here after Wi-Fi startup
        // and ingress installation. This remains wholly owned by wifi_esp.
        || (lab_force_unassociated() && !register_now_dispatcher())
    {
        crate::shared_ingress_esp::stop(crate::shared_ingress_esp::IngressKind::EspNow);
        crate::wifi_espnow_esp::stop_action_ingress();
        set_now_dispatcher(false);
        RADIO_MODE.store(RadioMode::StaRawUdp6 as u8, Ordering::Release);
        uart::send_response(b"wifi STA/NAN/NOW start failed");
        return false;
    }
    if nan_dw_interval != 0 && !crate::wifi_nan_dw_capture_esp::start(nan_dw_interval) {
        stop_sta_extensions();
        uart::send_response(b"wifi STA/NAN/NOW DW start failed");
        return false;
    }
    // Active DW1 NOW is the standing unassociated control plane.  Keep the
    // management receiver armed so an idle peer can receive an initiating
    // action; the narrow DW8/now=2 profile remains sleepy/windowed.
    if nan_dw_interval != 0
        && !crate::wifi_nan_dw_capture_esp::set_active_now_receive(now != 2 && nan_dw_interval == 1)
    {
        stop_sta_extensions();
        uart::send_response(b"wifi STA/NAN/NOW active receive failed");
        return false;
    }
    // NAN+NOW owns the same callback/capture extension set whether or not a
    // STA is associated.  Mark that ownership explicitly so a later
    // transport.start {mode: sta} quiesces DW capture and NOW ingress before
    // it stops/reinitializes the ESP-IDF driver.
    RADIO_MODE.store(RadioMode::StaRawUdp6Extensions as u8, Ordering::Release);
    uart::send_response(if nan_dw_interval == 0 {
        b"wifi STA/NOW-only started"
    } else {
        b"wifi STA/NAN/NOW with DW started"
    });
    true
}

/// Apply the volatile NAN/DW portion of an active STA extension set. `0`
/// leaves the proven STA+UDP6+NOW path with promiscuous receive off.
pub fn set_nan_dw_interval(nan_dw_interval: u8) -> bool {
    if radio_mode() != RadioMode::StaRawUdp6Extensions {
        return false;
    }
    crate::wifi_nan_dw_capture_esp::set_interval(nan_dw_interval)
}

/// Stop the associated STA+UDP6+NAN+NOW mode completely. The next requested
/// mode starts from the known STA lifecycle rather than retaining a callback
/// or driver state across personalities.
pub fn stop_sta_extensions() {
    let extensions_active = radio_mode() == RadioMode::StaRawUdp6Extensions;
    crate::wifi_nan_dw_capture_esp::stop();
    // Wi-Fi owns the packet-pool admission lifetime for the hardware action
    // callback. The NOW module only consumes packets that this owner has
    // already copied into the shared pool.
    crate::shared_ingress_esp::stop(crate::shared_ingress_esp::IngressKind::EspNow);
    crate::wifi_espnow_esp::stop_action_ingress();
    set_now_dispatcher(false);
    if extensions_active {
        RADIO_MODE.store(RadioMode::StaRawUdp6 as u8, Ordering::Release);
        uart::send_response(b"wifi STA/NAN/NOW stopped");
    }
}

/// Admit one already-decoded NOW payload through the Wi-Fi-owned shared pool.
/// The private action callback and all driver-buffer copies terminate above
/// this boundary; no bearer module may allocate, retain, or enqueue a second
/// radio packet queue.
pub(crate) fn enqueue_now_payload(source: [u8; 6], payload: &[u8]) -> bool {
    crate::shared_ingress_esp::enqueue(
        crate::shared_ingress_esp::IngressKind::EspNow,
        source,
        payload,
    )
}

/// End a bounded sleepy-node STA session.  The caller owns the session policy;
/// this adapter only releases the ESP-IDF STA bearer so the normal light-sleep
/// scheduler can resume. Infrastructure callers intentionally never use it.
fn stop_sta_with_leave_grace(leave_grace_ms: u32) {
    stop_sta_extensions();
    crate::wifi_raw_udp6_esp::stop();
    unsafe {
        STA_ASSOCIATED_EVENT.store(false, Ordering::Release);
        let _ = esp_idf_sys::esp_wifi_disconnect();
        // `esp_wifi_disconnect` initiates the 802.11 leave asynchronously.
        // Normally a radio-epoch replacement may stop immediately, but a
        // device reset must give the driver a short chance to put the leave
        // frame on air. Otherwise an infrastructure AP can retain a stale
        // station entry through its inactivity timeout after ROM restarts.
        if leave_grace_ms != 0 {
            let ticks = ((u64::from(leave_grace_ms) * u64::from(esp_idf_sys::configTICK_RATE_HZ))
                .div_ceil(1_000)
                .max(1)) as esp_idf_sys::TickType_t;
            esp_idf_sys::vTaskDelay(ticks);
        }
        let _ = esp_idf_sys::esp_wifi_stop();
        let netif = STA_NETIF.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !netif.is_null() {
            esp_idf_sys::esp_netif_destroy_default_wifi(netif.cast());
        }
        leave_radio_mode(RadioMode::StaRawUdp6);
    }
}

pub fn stop_sta() {
    stop_sta_with_leave_grace(0);
}

/// Stop the sleepy raw radio before explicit light sleep. Classic ESP32 must
/// fully release the driver; S3/C6 retain their initialized-driver behavior.
pub fn stop_sleepy_nan_now_for_light_sleep() {
    stop_sta();
    #[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
    deinit_for_light_sleep();
}

/// Explicitly leave the infrastructure AP before a controlled device reset.
/// The grace period belongs only to reset semantics, never normal radio epoch
/// replacement, because its purpose is peer-visible STA disassociation.
pub fn stop_sta_for_reset() {
    stop_sta_with_leave_grace(100);
}

/// Release the stopped Wi-Fi driver's power-management locks before an
/// explicit Main light-sleep boundary.  `stop_sta()` intentionally retains
/// the initialized driver for normal radio-profile replacements; that is not
/// sufficient on classic ESP32, where an initialized-but-stopped driver can
/// make `esp_light_sleep_start()` return immediately.  Main calls this only
/// for its physical DW8 sleep path and `init_nan_now()` recreates the driver
/// after the timer wake.
pub fn deinit_for_light_sleep() {
    unsafe {
        let result = esp_idf_sys::esp_wifi_deinit();
        if result != esp_idf_sys::ESP_OK
            && result != esp_idf_sys::ESP_ERR_WIFI_NOT_INIT
            && result != esp_idf_sys::ESP_ERR_INVALID_STATE
        {
            uart::send_stat(b"wifi light-sleep deinit result=", result as u32 as u64);
        }
    }
    STA_DRIVER_INITIALIZED.store(false, Ordering::Release);
}

/// Replace an already selected STA radio epoch. This is the sole Wi-Fi-owner
/// transition used by `transport.start`: it unregisters the prior raw/NOW
/// ingress, recreates the STA driver, then initializes the supplied immutable
/// profile. A stop/start alone retains `wifi_init_config_t` values such as
/// AMPDU and the 11b policy, which violates the radio-epoch contract.
/// Runtime policy code never manipulates callbacks, promiscuous mode, ESP
/// buffers, or ESP-IDF radio functions itself.
pub fn replace_sta(params: &TransportProfile) {
    stop_sta();
    restart_sta_driver_runtime();
    init_sta(params);
}

/// Stop only the ESP-IDF STA runtime so a changed pre-association receive
/// policy can be applied by the existing `init_sta` path.  The caller owns
/// bearer shutdown and immediately reinitializes the same radio mode; this is
/// a controlled Wi-Fi restart, not a device reboot or a second Wi-Fi owner.
pub fn restart_sta_runtime() {
    STA_ASSOCIATED_EVENT.store(false, Ordering::Release);
    unsafe {
        let _ = esp_idf_sys::esp_wifi_disconnect();
        let _ = esp_idf_sys::esp_wifi_stop();
    }
    uart::send_response(b"wifi STA restarting for policy");
}

/// Recreate the Wi-Fi driver so an updated `wifi_init_config_t` is actually
/// consumed.  Stop/start alone leaves ESP-IDF's AMPDU settings unchanged.
/// The default netif is also released, avoiding a second persistent adapter
/// or a stale binding across the driver epoch.
pub fn restart_sta_driver_runtime() {
    STA_ASSOCIATED_EVENT.store(false, Ordering::Release);
    unsafe {
        let _ = esp_idf_sys::esp_wifi_disconnect();
        let _ = esp_idf_sys::esp_wifi_stop();
        let result = esp_idf_sys::esp_wifi_deinit();
        if result != esp_idf_sys::ESP_OK
            && result != esp_idf_sys::ESP_ERR_WIFI_NOT_INIT
            && result != esp_idf_sys::ESP_ERR_INVALID_STATE
        {
            uart::send_stat(b"wifi STA driver deinit result=", result as u32 as u64);
        }
        STA_DRIVER_INITIALIZED.store(false, Ordering::Release);
        let netif = STA_NETIF.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !netif.is_null() {
            esp_idf_sys::esp_netif_destroy_default_wifi(netif.cast());
        }
    }
    uart::send_response(b"wifi STA driver restarting for policy");
}

/// The AMPDU configuration of the current Wi-Fi-driver epoch.
pub fn sta_ampdu_enabled() -> bool {
    STA_AMPDU_ENABLED.load(Ordering::Acquire)
}

/// Best-effort receive-side RSSI for the associated AP. The event-driven
/// association flag remains authoritative: ESP-IDF may retain an AP record
/// after the host has silently removed a station, so this is telemetry only.
pub fn sta_ap_rssi_dbm() -> Option<i8> {
    if !STA_ASSOCIATED_EVENT.load(Ordering::Acquire) {
        return None;
    }
    let mut ap = esp_idf_sys::wifi_ap_record_t::default();
    (unsafe { esp_idf_sys::esp_wifi_sta_get_ap_info(&mut ap) } == esp_idf_sys::ESP_OK)
        .then_some(ap.rssi)
}

/// ESP-IDF's currently applied maximum Wi-Fi TX power in quarter-dBm units.
/// It is local configuration telemetry, not peer-visible RF evidence.
pub fn max_tx_power_qdbm() -> Option<i8> {
    let mut power = 0i8;
    (unsafe { esp_idf_sys::esp_wifi_get_max_tx_power(&mut power) } == esp_idf_sys::ESP_OK)
        .then_some(power)
}

/// Whether the current STA-driver epoch suppresses 802.11b rates.
pub fn sta_11b_rates_disabled() -> bool {
    STA_11B_RATES_DISABLED.load(Ordering::Acquire)
}

/// Disconnect without stopping the radio, for a bounded connectionless-action
/// experiment. `start_espnow` must already have installed its receiver while
/// associated.  The caller can later clear this switch and let the normal
/// beacon-led reconnect task resume; no NVS setting is modified.
pub fn set_lab_force_unassociated(enabled: bool, channel: u8) {
    LAB_FORCE_UNASSOCIATED.store(enabled, Ordering::Release);
    if !enabled {
        // Resume immediately for an operator-controlled UART test rather
        // than waiting for the bounded reconnect observer to notice it.
        unsafe {
            let _ = esp_idf_sys::esp_wifi_connect();
        }
        return;
    }
    unsafe {
        let _ = esp_idf_sys::esp_wifi_disconnect();
        let _ = esp_idf_sys::esp_wifi_set_channel(
            channel.clamp(1, 13),
            esp_idf_sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE,
        );
    }
}

/// Current volatile state of the raw-radio disassociation laboratory switch.
pub fn lab_force_unassociated() -> bool {
    LAB_FORCE_UNASSOCIATED.load(Ordering::Acquire)
}

/// Enable or disable the shared, WPA2 APSTA laboratory owner. This is an
/// ephemeral radio transition for Recovery and Main alike; it does not touch
/// the persisted STA profile/NVS and deliberately does not create an IP data
/// plane.  Its SSID is deterministically derived from the AP MAC so a peer
/// can identify the test AP without another configuration channel.
pub fn set_lab_open_ap(enabled: bool, channel: u8, beacon_tu: u16) -> bool {
    let channel = channel.clamp(1, 13);
    unsafe {
        let _ = esp_idf_sys::esp_wifi_stop();
        let _ = esp_idf_sys::esp_wifi_set_promiscuous(false);
        let mode = if enabled {
            esp_idf_sys::wifi_mode_t_WIFI_MODE_APSTA
        } else {
            esp_idf_sys::wifi_mode_t_WIFI_MODE_STA
        };
        if esp_idf_sys::esp_wifi_set_mode(mode) != esp_idf_sys::ESP_OK {
            return false;
        }
        if enabled {
            // The raw-radio lab's `Open` spelling remains an explicit
            // unauthenticated diagnostic. Main transport.start has the same
            // behavior through its `open=1` profile field.
            if !configure_unassociated_dmesh_ap(channel, beacon_tu, true) {
                return false;
            }
        }
        if esp_idf_sys::esp_wifi_start() != esp_idf_sys::ESP_OK {
            return false;
        }
        // `esp_wifi_stop()` drops raw Ethernet/TX-completion callbacks even
        // though the shared raw bearer remains logically active. Restore its
        // driver bindings before returning from this single radio-owner
        // transition; otherwise the next NDP/UDP6 exchange can silently lose
        // replies while the bearer still reports itself as started.
        if !crate::wifi_raw_udp6_esp::rebind_sta_after_wifi_restart() {
            return false;
        }
        // `wifi_ap_config_t::channel` is a requested AP configuration.  Read
        // the live radio back after start: APSTA arbitration (or a future
        // ESP-IDF change) must not let a channel-6 lab test silently run on
        // the driver's fallback channel.
        let mut primary = 0u8;
        let mut secondary = esp_idf_sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE;
        // This assertion applies to an enabled AP only.  On disable the radio
        // becomes STA-owned again and its association controller is free to
        // select its AP's channel; treating that normal transition as an AP
        // setup failure leaves the volatile `ap_active` state stale.
        if enabled
            && (esp_idf_sys::esp_wifi_get_channel(&mut primary, &mut secondary)
                != esp_idf_sys::ESP_OK
                || primary != channel)
        {
            return false;
        }
        if enabled && !crate::wifi_raw_udp6_esp::ensure_ap_rx_callback() {
            // AP raw Ethernet is a separate ESP-IDF RX interface.  Do not
            // claim the AP lab data plane is active if its callback could
            // not be installed; action-frame hooks are global and unaffected.
            return false;
        }
        // NOW's hook is global rather than STA/AP-specific, but ESP-IDF owns
        // it inside the Wi-Fi driver. Reinstall it after this
        // stop/start transition; their `STARTED` state only owns Rust-side
        // queue allocation and must not stand in for driver registration.
        if !register_now_dispatcher() {
            return false;
        }
        if enabled {
            disable_bssid_check(1); // AP
        }
        // The AP is a powered infrastructure/timebase owner during this lab
        // case. Do not let modem power-save hide management/action reception
        // or inject multi-beacon receive gaps into a non-promiscuous test.
        if esp_idf_sys::esp_wifi_set_ps(esp_idf_sys::wifi_ps_type_t_WIFI_PS_NONE)
            != esp_idf_sys::ESP_OK
        {
            return false;
        }
        if LAB_FORCE_UNASSOCIATED.load(Ordering::Acquire) {
            let _ = esp_idf_sys::esp_wifi_disconnect();
            let _ = esp_idf_sys::esp_wifi_set_channel(
                channel,
                esp_idf_sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE,
            );
        }
    }
    LAB_OPEN_AP.store(enabled, Ordering::Release);
    true
}

/// Reproduce Main's raw idle-STA bring-up tail on an already initialized
/// shared driver.  The action/data dispatcher is registered separately by
/// `wifi_espnow_esp::start`; this routine deliberately neither replaces it
/// nor enables promiscuous capture.  It is a volatile lab mode, not a new
/// connection/profile owner.
pub fn ensure_lab_main_style_raw_sta(channel: u8) -> bool {
    let channel = channel.clamp(1, 13);
    unsafe {
        let mut mode = esp_idf_sys::wifi_mode_t_WIFI_MODE_NULL;
        let _ = esp_idf_sys::esp_wifi_get_mode(&mut mode);
        if mode == esp_idf_sys::wifi_mode_t_WIFI_MODE_NULL
            && esp_idf_sys::esp_wifi_set_mode(esp_idf_sys::wifi_mode_t_WIFI_MODE_STA)
                != esp_idf_sys::ESP_OK
        {
            return false;
        }
        let started = esp_idf_sys::esp_wifi_start();
        if started != esp_idf_sys::ESP_OK && started != esp_idf_sys::ESP_ERR_INVALID_STATE {
            return false;
        }
        if esp_idf_sys::esp_wifi_set_ps(esp_idf_sys::wifi_ps_type_t_WIFI_PS_NONE)
            != esp_idf_sys::ESP_OK
        {
            return false;
        }
        // Wi-Fi start/disconnect transitions can discard the driver's private
        // vendor-action hook even though the Rust-side callback pointer is
        // still installed. Re-register after the driver is live and before
        // entering the unassociated hold: this is the normal, non-promiscuous
        // `(127,0)` receiver used by both Recovery and Main, not a NAN DW
        // fallback. Reapply the real STA-lane policy at the same boundary.
        if !register_now_dispatcher() {
            return false;
        }
        disable_bssid_check(0);
        let _ = esp_idf_sys::esp_wifi_disconnect();
        let _ = esp_idf_sys::esp_wifi_set_channel(
            channel,
            esp_idf_sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE,
        );
        if esp_idf_sys::esp_wifi_set_promiscuous(false) != esp_idf_sys::ESP_OK {
            return false;
        }
    }
    LAB_FORCE_UNASSOCIATED.store(true, Ordering::Release);
    LAB_OPEN_AP.store(false, Ordering::Release);
    true
}

/// Whether the volatile raw-radio APSTA owner is currently enabled.
pub fn lab_open_ap_active() -> bool {
    LAB_OPEN_AP.load(Ordering::Acquire)
}

/// Cheap association observation for Main's nonblocking session owner.
pub fn sta_associated() -> bool {
    STA_ASSOCIATED_EVENT.load(Ordering::Acquire)
}

/// Driver-observed association phase only. This excludes lifecycle work such
/// as stopping NAN+NOW, recreating the STA netif, and starting ESP-IDF Wi-Fi.
pub fn sta_connect_to_associated_ms() -> Option<u32> {
    let elapsed = STA_CONNECT_TO_ASSOCIATED_MS.load(Ordering::Acquire);
    (elapsed != 0).then_some(elapsed)
}

/// Most recent ESP-IDF STA disconnect reason. Zero means no disconnect event
/// was observed in this radio epoch; callers must not treat it as success.
pub fn sta_last_disconnect_reason() -> u8 {
    STA_LAST_DISCONNECT_REASON.load(Ordering::Acquire)
}

/// Read the driver's actual promiscuous-mode state for diagnostics. This is
/// intentionally observation-only: NAN power policy owns any transition,
/// while the raw UDP6 and NOW-like bearers must be able to prove that they
/// operate with promiscuous capture disabled.
pub fn promiscuous_enabled() -> Result<bool, esp_idf_sys::esp_err_t> {
    let mut enabled = false;
    let result = unsafe { esp_idf_sys::esp_wifi_get_promiscuous(&mut enabled) };
    if result == esp_idf_sys::ESP_OK {
        Ok(enabled)
    } else {
        Err(result)
    }
}

/// Keep the shared Recovery/Main STA associated across an AP restart or
/// channel move.  The task observes association loss, then scans and selects
/// an eligible DMesh beacon; it never turns a transient missing AP into a
/// blind `esp_wifi_connect` loop.  The selected BSSID is also the advertised
/// server MAC: `quic_lite::raw_udp6::link_local_from_mac` derives its IPv6 LL
/// endpoint without a separate raw-UDP address setting.
/// Start Recovery's legacy STA observation/reconnect worker.
///
/// This is called exactly once by the frozen Recovery entry point after its
/// initial STA setup.  It remains outside `init_sta` so Main cannot retain a
/// periodic observer merely by using the shared ESP-IDF association setup;
/// Main owns reconnects through queued connect/disconnect callbacks instead.
/// Recovery will remove this worker when its RTC-supplied open-AP client is
/// implemented.
pub fn start_legacy_sta_reconnect_task(params: &TransportProfile) {
    if STA_RECONNECT_TASK_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let mut config = StaReconnectConfig {
        preferred_ssid: [0; 33],
        preferred_ssid_len: params.ssid_len.min(33),
        bssid: params.sta_bssid,
        bssid_set: params.sta_bssid_set,
    };
    config.preferred_ssid[..config.preferred_ssid_len]
        .copy_from_slice(&params.ssid[..config.preferred_ssid_len]);
    let config = Box::into_raw(Box::new(config));
    let mut task = core::ptr::null_mut();
    let result = unsafe {
        esp_idf_sys::xTaskCreatePinnedToCore(
            Some(sta_reconnect_task),
            b"wifi_recon\0".as_ptr().cast(),
            3072,
            config.cast(),
            3,
            &mut task,
            0,
        )
    };
    if result != 1 || task.is_null() {
        unsafe { drop(Box::from_raw(config)) };
        STA_RECONNECT_TASK_STARTED.store(false, Ordering::Release);
        uart::send_response(b"wifi reconnect task failed");
    } else {
        // One boot-time proof that the long-lived shared STA owner exists.
        // Subsequent messages are transition-only so an AP outage cannot
        // turn the diagnostic path into a periodic UART event source.
        uart::send_response(b"wifi reconnect task started");
    }
}

unsafe extern "C" fn sta_reconnect_task(argument: *mut c_void) {
    let config = unsafe { Box::from_raw(argument.cast::<StaReconnectConfig>()) };
    let preferred_ssid = &config.preferred_ssid[..config.preferred_ssid_len];
    // Do not report the normal interval between `esp_wifi_connect` and the
    // first CONNECTED event as a loss.  Once an association has been seen,
    // a DISCONNECTED event is authoritative even if get_ap_info is stale.
    let mut seen_association = false;
    let mut missing_observations = 0u8;
    let mut scan_cooldown = 0u8;
    uart::send_response(b"wifi reconnect task running");
    loop {
        esp_idf_sys::vTaskDelay(STA_ASSOCIATION_OBSERVE_TICKS);
        if LAB_FORCE_UNASSOCIATED.load(Ordering::Acquire) {
            continue;
        }
        if STA_ASSOCIATED_EVENT.load(Ordering::Acquire) {
            seen_association = true;
            missing_observations = 0;
            scan_cooldown = 0;
            let mut ap = esp_idf_sys::wifi_ap_record_t::default();
            if esp_idf_sys::esp_wifi_sta_get_ap_info(&mut ap) == esp_idf_sys::ESP_OK {
                crate::wifi_raw_udp6_esp::update_ap_bssid(ap.bssid);
            }
            continue;
        }
        if !seen_association {
            continue;
        }
        missing_observations = missing_observations.saturating_add(1);
        if missing_observations == 1 {
            uart::send_response(b"wifi reconnect association lost");
            uart::send_stat(
                b"wifi reconnect disconnect_reason=",
                STA_LAST_DISCONNECT_REASON.load(Ordering::Acquire) as u64,
            );
        }
        if missing_observations < STA_ASSOCIATION_LOSS_OBSERVATIONS {
            continue;
        }
        if scan_cooldown != 0 {
            scan_cooldown -= 1;
            continue;
        }
        scan_cooldown = STA_RECONNECT_SCAN_COOLDOWN_OBSERVATIONS;
        let reconnect_started_us = esp_idf_sys::esp_timer_get_time();
        if config.bssid_set {
            // Preserve the precise transport.start target across a temporary
            // loss. The STA config already contains its BSSID/channel, so a
            // disconnect/connect is sufficient and must not start a scan.
            let _ = esp_idf_sys::esp_wifi_disconnect();
            let connect = esp_idf_sys::esp_wifi_connect();
            uart::send_response(b"wifi reconnect explicit BSSID");
            uart::send_stat(
                b"wifi reconnect connect_ms=",
                elapsed_ms(reconnect_started_us),
            );
            if connect != esp_idf_sys::ESP_OK && connect != esp_idf_sys::ESP_ERR_WIFI_CONN {
                uart::send_stat(b"wifi reconnect result=", connect as u32 as u64);
            }
        } else {
            uart::send_stat(b"wifi reconnect scan_ms=", elapsed_ms(reconnect_started_us));
            if let Some(selection) = scan_dmesh_sta_candidate(preferred_ssid, None) {
                if apply_sta_candidate(&selection, false) {
                    // A reset of the association state is necessary after a host
                    // AP restart; a bare connect can otherwise retain the old
                    // BSSID/channel in ESP-IDF's fast-scan cache.
                    let _ = esp_idf_sys::esp_wifi_disconnect();
                    let connect = esp_idf_sys::esp_wifi_connect();
                    uart::send_response(if selection.preferred {
                        b"wifi reconnect preferred candidate"
                    } else {
                        b"wifi reconnect fallback candidate"
                    });
                    uart::send_stat(
                        b"wifi reconnect connect_ms=",
                        elapsed_ms(reconnect_started_us),
                    );
                    if connect != esp_idf_sys::ESP_OK && connect != esp_idf_sys::ESP_ERR_WIFI_CONN {
                        uart::send_stat(b"wifi reconnect result=", connect as u32 as u64);
                    }
                } else {
                    uart::send_response(b"wifi reconnect config failed");
                }
            } else {
                uart::send_response(b"wifi reconnect no candidate");
            }
        }
    }
}

/// Convert an ESP-IDF scan into the host-tested selection inputs.  The BSSID
/// comes from the management-frame beacon itself; it is therefore both the
/// AP association target and the MAC from which raw UDP6 derives the host LL
/// endpoint.  No duplicate IPv6 setting or vendor IE is required.
unsafe fn scan_dmesh_sta_candidate(
    preferred_ssid: &[u8],
    required_bssid: Option<[u8; 6]>,
) -> Option<ScannedStaCandidate> {
    let scan = esp_idf_sys::esp_wifi_scan_start(core::ptr::null(), true);
    if scan != esp_idf_sys::ESP_OK {
        uart::send_stat(b"wifi reconnect scan_result=", scan as u32 as u64);
        return None;
    }
    let mut total = 0u16;
    let count_result = esp_idf_sys::esp_wifi_scan_get_ap_num(&mut total);
    if count_result != esp_idf_sys::ESP_OK {
        uart::send_stat(
            b"wifi reconnect scan_count_result=",
            count_result as u32 as u64,
        );
        return None;
    }
    uart::send_stat(b"wifi reconnect scan_aps=", total as u64);
    if total == 0 {
        return None;
    }
    let count = usize::from(total).min(STA_SCAN_MAX_RECORDS);
    let mut records = Vec::with_capacity(count);
    records.resize(count, esp_idf_sys::wifi_ap_record_t::default());
    let mut returned = count as u16;
    let records_result =
        esp_idf_sys::esp_wifi_scan_get_ap_records(&mut returned, records.as_mut_ptr());
    if records_result != esp_idf_sys::ESP_OK {
        uart::send_stat(
            b"wifi reconnect scan_records_result=",
            records_result as u32 as u64,
        );
        return None;
    }
    records.truncate(usize::from(returned));
    store_scan_observations(&records, total, preferred_ssid);

    let mut candidates = Vec::with_capacity(records.len());
    for record in records.iter().filter(|record| {
        required_bssid
            .map(|bssid| record.bssid == bssid)
            .unwrap_or(true)
    }) {
        let len = record
            .ssid
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(record.ssid.len());
        candidates.push(dmesh_server::sta_selection::StaCandidate {
            ssid: &record.ssid[..len],
            bssid: record.bssid,
            rssi_dbm: record.rssi,
            channel: record.primary,
        });
    }
    let selection = dmesh_server::sta_selection::select_sta_candidate(
        &candidates,
        preferred_ssid,
        STA_MINIMUM_RSSI_DBM,
    );
    if selection.is_none() {
        uart::send_response(b"wifi reconnect scan no eligible AP");
    }
    let selection = selection?;
    let mut ssid = [0; 33];
    ssid[..selection.candidate.ssid.len()].copy_from_slice(selection.candidate.ssid);
    Some(ScannedStaCandidate {
        ssid,
        ssid_len: selection.candidate.ssid.len(),
        bssid: selection.candidate.bssid,
        channel: selection.candidate.channel,
        authmode: records
            .iter()
            .find(|record| record.bssid == selection.candidate.bssid)
            .map(|record| record.authmode)?,
        preferred: selection.preferred,
    })
}

fn scan_now_ms() -> u32 {
    (unsafe { esp_idf_sys::esp_timer_get_time() }.max(0) as u64 / 1_000) as u32
}

fn dmesh_ssid(record: &esp_idf_sys::wifi_ap_record_t) -> bool {
    record.ssid.starts_with(b"dmesh")
}

fn store_scan_observations(
    records: &[esp_idf_sys::wifi_ap_record_t],
    total: u16,
    configured_sta_ssid: &[u8],
) {
    let direct_dmesh_total = records.iter().filter(|record| dmesh_ssid(record)).count() as u16;
    let count =
        direct_dmesh_total.min(dmesh_server::raw_wifi::RAW_WIFI_SCAN_MAX_RECORDS as u16) as usize;
    unsafe {
        for (index, record) in records
            .iter()
            .filter(|record| dmesh_ssid(record))
            .take(count)
            .enumerate()
        {
            let ssid_len = record
                .ssid
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(record.ssid.len())
                .min(32);
            let mut entry = dmesh_server::raw_wifi::RawWifiScanEntry::default();
            entry.ssid[..ssid_len].copy_from_slice(&record.ssid[..ssid_len]);
            entry.ssid_len = ssid_len as u8;
            entry.bssid = record.bssid;
            entry.channel = record.primary;
            entry.signal_dbm = record.rssi;
            LAST_SCAN[index] = entry;
        }
    }
    LAST_SCAN_LEN.store(count as u8, Ordering::Release);
    LAST_SCAN_TOTAL.store(total, Ordering::Release);
    LAST_SCAN_DMESH_TOTAL.store(direct_dmesh_total, Ordering::Release);
    let configured_auth = records
        .iter()
        .find(|record| {
            let length = record
                .ssid
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(record.ssid.len());
            configured_sta_ssid == &record.ssid[..length]
        })
        .map(|record| record.authmode as u8)
        .unwrap_or(u8::MAX);
    LAST_SCAN_CONFIGURED_STA_AUTH.store(configured_auth, Ordering::Release);
    LAST_SCAN_AT_MS.store(scan_now_ms(), Ordering::Release);
}

fn cached_scan_observations(
    out: &mut [dmesh_server::raw_wifi::RawWifiScanEntry],
) -> dmesh_server::raw_wifi::RawWifiScanResponse {
    let count = usize::from(LAST_SCAN_LEN.load(Ordering::Acquire)).min(out.len());
    unsafe {
        out[..count].copy_from_slice(&LAST_SCAN[..count]);
    }
    let now = scan_now_ms();
    let mut configured_sta_ssid = [0u8; 32];
    let configured_sta_ssid_len =
        crate::main_runtime::read_setting(b"sta_ssid", &mut configured_sta_ssid)
            .unwrap_or(0)
            .min(configured_sta_ssid.len());
    dmesh_server::raw_wifi::RawWifiScanResponse {
        entries: count,
        total_aps: LAST_SCAN_TOTAL.load(Ordering::Acquire),
        direct_dmesh_aps: LAST_SCAN_DMESH_TOTAL.load(Ordering::Acquire),
        age_ms: now.wrapping_sub(LAST_SCAN_AT_MS.load(Ordering::Acquire)),
        fresh: false,
        configured_sta_ssid,
        configured_sta_ssid_len: configured_sta_ssid_len as u8,
        configured_sta_auth_mode: match LAST_SCAN_CONFIGURED_STA_AUTH.load(Ordering::Acquire) {
            u8::MAX => None,
            auth_mode => Some(auth_mode),
        },
    }
}

/// Return bounded AP observations for `wifi.scan` without changing association.
pub fn scan_observations(
    request: dmesh_server::raw_wifi::RawWifiScanRequest,
    out: &mut [dmesh_server::raw_wifi::RawWifiScanEntry],
) -> Result<dmesh_server::raw_wifi::RawWifiScanResponse, &'static str> {
    const CACHE_MAX_AGE_MS: u32 = 30_000;
    let cached = cached_scan_observations(out);
    if cached.total_aps != 0
        && (request.last_results || (!request.fresh && cached.age_ms <= CACHE_MAX_AGE_MS))
    {
        return Ok(cached);
    }
    let profile = crate::profile_store::snapshot();
    let configured_sta_ssid = &profile.ssid[..profile.ssid_len];
    unsafe {
        if esp_idf_sys::esp_wifi_scan_start(core::ptr::null(), true) != esp_idf_sys::ESP_OK {
            return (cached.total_aps != 0)
                .then_some(cached)
                .ok_or("wifi scan start");
        }
        let mut total = 0u16;
        if esp_idf_sys::esp_wifi_scan_get_ap_num(&mut total) != esp_idf_sys::ESP_OK {
            return Err("wifi scan count");
        }
        let count = usize::from(total).min(out.len());
        if count == 0 {
            store_scan_observations(&[], total, configured_sta_ssid);
            return Ok(cached_scan_observations(out));
        }
        let mut records = Vec::with_capacity(count);
        records.resize(count, esp_idf_sys::wifi_ap_record_t::default());
        let mut returned = count as u16;
        if esp_idf_sys::esp_wifi_scan_get_ap_records(&mut returned, records.as_mut_ptr())
            != esp_idf_sys::ESP_OK
        {
            return Err("wifi scan records");
        }
        store_scan_observations(
            &records[..usize::from(returned)],
            total,
            configured_sta_ssid,
        );
        let mut response = cached_scan_observations(out);
        response.fresh = true;
        Ok(response)
    }
}
