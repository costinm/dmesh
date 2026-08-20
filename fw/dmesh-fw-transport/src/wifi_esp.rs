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
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, Ordering},
};

// TODO: duplicated in nvs.rs, don't belong here.
extern "C" {
    fn nvs_flash_init() -> i32;
    fn nvs_open(namespace: *const i8, mode: i32, handle: *mut u32) -> i32;
    fn nvs_get_str(handle: u32, key: *const i8, value: *mut i8, length: *mut usize) -> i32;
    fn nvs_close(handle: u32);
}

/// Load the one Wi-Fi setting needed before a stream handler exists. All
/// ordinary NVS reads/writes use Main's registered `nvs` handler instead.
pub unsafe fn initialize_nvs() -> bool {
    let initialized = unsafe { nvs_flash_init() };
    initialized == esp_idf_sys::ESP_OK || initialized == esp_idf_sys::ESP_ERR_INVALID_STATE
}

pub unsafe fn load_preferred_ssid(profile: &mut TransportProfile) {
    if !unsafe { initialize_nvs() } {
        return;
    }
    let mut handle = 0_u32;
    if unsafe { nvs_open(b"dmesh\0".as_ptr().cast(), 0, &mut handle) } != esp_idf_sys::ESP_OK {
        return;
    }
    let mut capacity = profile.ssid.len();
    let result = unsafe {
        nvs_get_str(
            handle,
            b"ssid\0".as_ptr().cast(),
            profile.ssid.as_mut_ptr().cast(),
            &mut capacity,
        )
    };
    unsafe { nvs_close(handle) };
    if result == esp_idf_sys::ESP_OK && capacity != 0 {
        profile.ssid_len = capacity.saturating_sub(1).min(profile.ssid.len());
    }
}

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
    ApRawUdp6 = 5, // Plus NanNow
    /// Associated raw-UDP6, plus the bounded NAN discovery-window receiver
    /// and the connectionless NOW action dispatcher.  This is one hardware
    /// personality, not three independent owners of global Wi-Fi state.
    StaRawUdp6NanNow = 6,
    // Also UnasocStaRawUdp6NanNow.
    // Also ApStaUdp6NanNow
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
            Self::StaRawUdp6NanNow => b"sta_raw_udp6_nan_now",
        }
    }
}

static RADIO_MODE: AtomicU8 = AtomicU8::new(RadioMode::Idle as u8);

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
        .compare_exchange(mode as u8, RadioMode::Idle as u8, Ordering::AcqRel, Ordering::Acquire)
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
        6 => RadioMode::StaRawUdp6NanNow,
        _ => RadioMode::Idle,
    }
}

// Lab-only switch: retain the initialized STA radio and channel but prevent
// the normal recovery task from re-associating after an explicit disconnect.
// It is intentionally volatile and never touches the persisted profile/NVS.
static LAB_FORCE_UNASSOCIATED: AtomicBool = AtomicBool::new(false);
// The continuous `(127,0)` NOW callback is global driver state. Preserve the
// requested state across a lab STA/AP restart: ROC-only rows must not have
// `ensure_lab_main_style_raw_sta` silently re-enable it before ROC is armed.
static NOW_DISPATCHER_ENABLED: AtomicBool = AtomicBool::new(true);
// Volatile APSTA owner used only by the common raw-radio laboratory handler.
// It intentionally creates no esp-netif or network-stack endpoint: AP beacons and the
// radio driver's management/action receive path are the subject of the test.
static LAB_OPEN_AP: AtomicBool = AtomicBool::new(false);
static STA_BSSID_CHECK_DISABLED: AtomicBool = AtomicBool::new(true);

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
        callback: Option<unsafe extern "C" fn(*mut c_void, *mut u8, *mut u8, *mut u8) -> i32>,
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
    // Vendor-public action `(127, 0)` is the continuous, non-promiscuous
    // NOW-like receive style. ROC remains an explicit bounded alternative in
    // `wifi_nonpromisc_probe_esp`; NAN production receive is DW capture.
    // Registration is global (not STA/AP scoped) and must be repeated after
    // an ESP-IDF Wi-Fi stop/start transition.
    if !NOW_DISPATCHER_ENABLED.load(Ordering::Acquire) {
        // ESP-IDF's private registration path does not document a null
        // callback as an unregister operation. Keep the already-installed
        // driver hook and make the Rust callback inert instead; ROC owns its
        // separate receive lease without a null function pointer transition.
        return true;
    }
    unsafe {
        ieee80211_recv_action_register(127, 0, Some(crate::wifi_espnow_esp::action_rx_callback))
            == 0
    }
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
    let Some(rate) = raw_tx_rate(mbps) else { return false; };
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
/// Observe loss frequently enough to notice an AP restart promptly, but do
/// not blindly call `esp_wifi_connect` on every observation.  Candidate scans
/// and association requests happen only after a sustained loss.
const STA_ASSOCIATION_OBSERVE_TICKS: u32 = 10;
const STA_ASSOCIATION_LOSS_OBSERVATIONS: u8 = 20;
const STA_RECONNECT_SCAN_COOLDOWN_OBSERVATIONS: u8 = 20;
const STA_MINIMUM_RSSI_DBM: i8 = -70;
const STA_SCAN_MAX_RECORDS: usize = 16;

/// Task-owned copy of the preference loaded from NVS.  It is a hint only:
/// scan observations choose a stronger eligible `DIRECT-*-dmesh` AP when the
/// preferred AP is absent or below the RSSI floor.
struct StaReconnectConfig {
    preferred_ssid: [u8; 33],
    preferred_ssid_len: usize,
}

/// Owned scan result retained only until the immediately following
/// `esp_wifi_set_config` call.  It prevents a reconnect scan from reserving
/// packet memory or retaining heap allocations between association epochs.
struct ScannedStaCandidate {
    ssid: [u8; 33],
    ssid_len: usize,
    bssid: [u8; 6],
    channel: u8,
    preferred: bool,
}
// Main may keep NAN/raw Wi-Fi initialized while the STA association retries.
// The default STA netif is an ESP-IDF singleton: recreating it on a retry
// asserts in `esp_netif_create_default_wifi_sta`.  Retain this adapter-owned
// handle for the lifetime of the firmware and reuse it after `stop_sta()`.
static STA_NETIF: AtomicPtr<esp_idf_sys::esp_netif_t> = AtomicPtr::new(core::ptr::null_mut());
static STA_DRIVER_INITIALIZED: AtomicBool = AtomicBool::new(false);
static STA_AMPDU_ENABLED: AtomicBool = AtomicBool::new(true);
static STA_11B_RATES_DISABLED: AtomicBool = AtomicBool::new(true);
// `esp_wifi_init` may allocate part of its driver state before returning
// ESP_ERR_NO_MEM. Retrying that exact initialization leaks/fragmentates the
// remaining heap, so a reboot or a changed image/profile is required.
static STA_DRIVER_INIT_FAILED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn sta_event_handler(
    _argument: *mut c_void,
    _event_base: esp_idf_sys::esp_event_base_t,
    event_id: i32,
    event_data: *mut c_void,
) {
    if event_id == esp_idf_sys::wifi_event_t_WIFI_EVENT_STA_CONNECTED as i32 {
        STA_ASSOCIATED_EVENT.store(true, Ordering::Release);
    } else if event_id == esp_idf_sys::wifi_event_t_WIFI_EVENT_STA_DISCONNECTED as i32 {
        let reason = if event_data.is_null() {
            0
        } else {
            unsafe {
                (*(event_data.cast::<esp_idf_sys::wifi_event_sta_disconnected_t>())).reason
            }
        };
        STA_LAST_DISCONNECT_REASON.store(reason, Ordering::Release);
        STA_ASSOCIATED_EVENT.store(false, Ordering::Release);
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
        nvs_enable: esp_idf_sys::WIFI_NVS_ENABLED as i32,
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
        if !enter_radio_mode(RadioMode::StaRawUdp6) {
            return;
        }
        let init_started_us = esp_idf_sys::esp_timer_get_time();
        uart::send_stat(b"wifi raw sta init_ms=", 0);
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
        let mut config = esp_idf_sys::wifi_config_t { sta };
        let _ = esp_idf_sys::esp_wifi_set_mode(esp_idf_sys::wifi_mode_t_WIFI_MODE_STA);
        let _ = esp_idf_sys::esp_wifi_set_config(
            esp_idf_sys::wifi_interface_t_WIFI_IF_STA,
            &mut config,
        );
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
        if esp_idf_sys::esp_wifi_set_bandwidth(
            esp_idf_sys::wifi_interface_t_WIFI_IF_STA,
            bandwidth,
        ) != esp_idf_sys::ESP_OK
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
        if !set_bssid_check_disabled(0, params.sta_bssid_check_disabled) {
            uart::send_response(b"wifi STA BSSID policy failed");
            return;
        }
        uart::send_stat(b"wifi raw sta started_ms=", elapsed_ms(init_started_us));
        let _ = esp_idf_sys::esp_wifi_set_ps(esp_idf_sys::wifi_ps_type_t_WIFI_PS_NONE);
        let connect = esp_idf_sys::esp_wifi_connect();
        uart::send_stat(b"wifi raw sta connect_ms=", elapsed_ms(init_started_us));
        if connect != esp_idf_sys::ESP_OK && connect != esp_idf_sys::ESP_ERR_WIFI_CONN {
            uart::send_stat(b"wifi raw sta connect_result=", connect as u32 as u64);
        }
        start_sta_reconnect_task(params);
        let mut associated = false;
        for attempt in 0..50 {
            esp_idf_sys::vTaskDelay(100);
            associated = STA_ASSOCIATED_EVENT.load(Ordering::Acquire);
            if associated {
                break;
            }
            if attempt != 0 && attempt % 10 == 0 {
                let _ = esp_idf_sys::esp_wifi_connect();
            }
        }
        uart::send_response(if associated {
            b"wifi raw STA associated"
        } else {
            b"wifi raw STA association failed"
        });
        uart::send_stat(b"wifi raw sta associated_ms=", elapsed_ms(init_started_us));
        // Action/NOW registration is a separately requested radio mode.
        // Do not install it as a side effect of raw UDP6 association: its
        // driver callback is global and would make Recovery run two modes.
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
    let mut channel = 0u8;
    let mut secondary = esp_idf_sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE;
    (unsafe { esp_idf_sys::esp_wifi_get_channel(&mut channel, &mut secondary) } == esp_idf_sys::ESP_OK)
        .then_some((channel, secondary))
}

/// Pin the radio to a 2.4 GHz primary channel with no secondary channel.
/// Callers select policy; the hardware mutation remains with the radio owner.
pub fn set_ht20_channel(channel: u8) -> bool {
    unsafe {
        esp_idf_sys::esp_wifi_set_channel(
            channel.clamp(1, 13),
            esp_idf_sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE,
        ) == esp_idf_sys::ESP_OK
    }
}

/// Submit one caller-constructed ESP-IDF action TX request.  Framing remains
/// bearer-specific, but the only actual radio submit operation is here.
pub fn submit_action_tx(request: *mut esp_idf_sys::wifi_action_tx_req_t) -> i32 {
    unsafe { esp_idf_sys::esp_wifi_action_tx_req(request) }
}

pub type PromiscuousRxCallback = unsafe extern "C" fn(
    *mut c_void,
    esp_idf_sys::wifi_promiscuous_pkt_type_t,
);

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

pub fn set_promiscuous_filter(filter: &mut esp_idf_sys::wifi_promiscuous_filter_t) -> bool {
    unsafe { esp_idf_sys::esp_wifi_set_promiscuous_filter(filter) == esp_idf_sys::ESP_OK }
}

pub type VendorIeRxCallback = unsafe extern "C" fn(
    *mut c_void,
    u32,
    *const u8,
    *const esp_idf_sys::vendor_ie_data_t,
    i32,
);

pub fn register_vendor_ie_callback(callback: Option<VendorIeRxCallback>) -> i32 {
    unsafe { esp_idf_sys::esp_wifi_set_vendor_ie_cb(callback, core::ptr::null_mut()) }
}

pub fn remain_on_channel(request: *mut esp_idf_sys::wifi_roc_req_t) -> i32 {
    unsafe { esp_idf_sys::esp_wifi_remain_on_channel(request) }
}

/// Attach a caller-owned QUIC-lite handler to the generic raw Ethernet
/// adapter. The caller owns all DCID and application state; this module owns
/// only STA lifecycle and ESP Wi-Fi registration.
pub fn start_raw_udp6(handler: crate::wifi_raw_udp6_esp::RawUdp6Handler) -> bool {
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
    crate::wifi_raw_udp6_esp::start(mac, ap.bssid, handler)
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

/// Upgrade an already-associated STA/UDP6 personality to the production
/// coexistence configuration.  The baseline remains pure STA until this is
/// called; NAN's bounded promiscuous DW and NOW's global action callback are
/// installed together and are removed together by [`stop_nan_now`].
pub fn start_nan_now(handler: crate::wifi_espnow_esp::EspNowHandler) -> bool {
    if RADIO_MODE
        .compare_exchange(
            RadioMode::StaRawUdp6 as u8,
            RadioMode::StaRawUdp6NanNow as u8,
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
        || !set_now_dispatcher(true)
        || !crate::wifi_nan_dw_capture_esp::start()
    {
        crate::wifi_nan_dw_capture_esp::stop();
        crate::wifi_espnow_esp::stop_action_ingress();
        set_now_dispatcher(false);
        RADIO_MODE.store(RadioMode::StaRawUdp6 as u8, Ordering::Release);
        uart::send_response(b"wifi NAN/NOW start failed");
        return false;
    }
    uart::send_response(b"wifi NAN/NOW started");
    true
}

/// Return the combined coexistence personality to a pure STA/UDP6 baseline.
/// Call this before a baseline measurement or before stopping the STA.
pub fn stop_nan_now() {
    if radio_mode() != RadioMode::StaRawUdp6NanNow {
        return;
    }
    crate::wifi_nan_dw_capture_esp::stop();
    crate::wifi_espnow_esp::stop_action_ingress();
    set_now_dispatcher(false);
    RADIO_MODE.store(RadioMode::StaRawUdp6 as u8, Ordering::Release);
    uart::send_response(b"wifi NAN/NOW stopped");
}

/// End a bounded sleepy-node STA session.  The caller owns the session policy;
/// this adapter only releases the ESP-IDF STA bearer so the normal light-sleep
/// scheduler can resume. Infrastructure callers intentionally never use it.
pub fn stop_sta() {
    stop_nan_now();
    crate::wifi_raw_udp6_esp::stop();
    unsafe {
        STA_ASSOCIATED_EVENT.store(false, Ordering::Release);
        let _ = esp_idf_sys::esp_wifi_disconnect();
        let _ = esp_idf_sys::esp_wifi_stop();
        let netif = STA_NETIF.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !netif.is_null() {
            esp_idf_sys::esp_netif_destroy_default_wifi(netif.cast());
        }
        leave_radio_mode(RadioMode::StaRawUdp6);
    }
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

/// Enable or disable the shared, open APSTA laboratory owner.  This is an
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
            let mut ap = esp_idf_sys::wifi_ap_config_t::default();
            let mut mac = [0u8; 6];
            let _ = esp_idf_sys::esp_wifi_get_mac(
                esp_idf_sys::wifi_interface_t_WIFI_IF_AP,
                mac.as_mut_ptr(),
            );
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            let mut ssid = *b"DIRECT-000000-dmesh";
            for (index, byte) in mac[3..].iter().enumerate() {
                ssid[7 + index * 2] = HEX[(byte >> 4) as usize];
                ssid[8 + index * 2] = HEX[(byte & 0x0f) as usize];
            }
            ap.ssid[..ssid.len()].copy_from_slice(&ssid);
            ap.ssid_len = ssid.len() as u8;
            ap.channel = channel;
            ap.authmode = esp_idf_sys::wifi_auth_mode_t_WIFI_AUTH_OPEN;
            ap.max_connection = 4;
            ap.beacon_interval = beacon_tu.clamp(100, 60_000);
            let mut config = esp_idf_sys::wifi_config_t { ap };
            if esp_idf_sys::esp_wifi_set_config(
                esp_idf_sys::wifi_interface_t_WIFI_IF_AP,
                &mut config,
            ) != esp_idf_sys::ESP_OK
            {
                return false;
            }
        }
        if esp_idf_sys::esp_wifi_start() != esp_idf_sys::ESP_OK {
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
fn start_sta_reconnect_task(params: &TransportProfile) {
    if STA_RECONNECT_TASK_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let mut config = StaReconnectConfig {
        preferred_ssid: [0; 33],
        preferred_ssid_len: params.ssid_len.min(33),
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
        uart::send_stat(b"wifi reconnect scan_ms=", elapsed_ms(reconnect_started_us));
        if let Some(selection) = scan_dmesh_sta_candidate(preferred_ssid) {
            let mut sta = esp_idf_sys::wifi_sta_config_t::default();
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
            let mut wifi = esp_idf_sys::wifi_config_t { sta };
            if esp_idf_sys::esp_wifi_set_config(
                esp_idf_sys::wifi_interface_t_WIFI_IF_STA,
                &mut wifi,
            ) == esp_idf_sys::ESP_OK
            {
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

/// Convert an ESP-IDF scan into the host-tested selection inputs.  The BSSID
/// comes from the management-frame beacon itself; it is therefore both the
/// AP association target and the MAC from which raw UDP6 derives the host LL
/// endpoint.  No duplicate IPv6 setting or vendor IE is required.
unsafe fn scan_dmesh_sta_candidate(preferred_ssid: &[u8]) -> Option<ScannedStaCandidate> {
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

    let mut candidates = Vec::with_capacity(records.len());
    for record in &records {
        let len = record
            .ssid
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(record.ssid.len());
        candidates.push(quic_lite::sta_selection::StaCandidate {
            ssid: &record.ssid[..len],
            bssid: record.bssid,
            rssi_dbm: record.rssi,
            channel: record.primary,
        });
    }
    let selection = quic_lite::sta_selection::select_sta_candidate(
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
        preferred: selection.preferred,
    })
}
