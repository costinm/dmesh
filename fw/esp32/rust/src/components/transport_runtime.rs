//! Main ownership of the shared Recovery-derived STA/transport runtime.
//!
//! Infra starts the shared STA bearer at boot and leaves it active. Sleepy
//! keeps the same profile and handlers available but does not start STA on a
//! periodic wake: only a UART or NAN service-discovery request creates a
//! bounded active session.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};

use super::settings::SharedSettings;
use super::telemetry;

pub const INITIAL_ACTIVE_MS: u32 = 3_000;
pub const COMMAND_GRACE_MS: u32 = 200;
const RETRY_MS: u32 = 1_000;

static PROFILE: OnceLock<Mutex<dmesh_fw_transport::TransportProfile>> = OnceLock::new();
static EPHEMERAL_PROFILE: OnceLock<Mutex<Option<dmesh_fw_transport::TransportProfile>>> =
    OnceLock::new();
// This is deliberately distinct from `STA_ACTIVE`: association can disappear
// while the shared STA reconnect task still owns the ESP-IDF Wi-Fi driver.
// Main uses this ownership bit only to keep its NAN/AP policy from racing the
// shared Recovery/Main transport during that interval.
static STA_BEARER_OWNS_WIFI: AtomicBool = AtomicBool::new(false);
static STA_ACTIVE: AtomicBool = AtomicBool::new(false);
static STA_STARTING: AtomicBool = AtomicBool::new(false);
static SESSION_DEADLINE_MS: AtomicU32 = AtomicU32::new(0);
static NEXT_RETRY_MS: AtomicU32 = AtomicU32::new(0);
static ACTIVE_STREAMS: AtomicU32 = AtomicU32::new(0);
static GRACE_ARMED: AtomicBool = AtomicBool::new(false);

fn receive_raw_udp6(
    peer: dmesh_fw_transport::wifi_raw_udp6_esp::RawUdp6Peer,
    packet: &[u8],
    response: &mut [u8; dmesh_fw_transport::TRANSPORT_MTU],
) -> Option<usize> {
    dmesh_fw_transport::recovery_runtime::receive_raw_service(
        dmesh_server::raw_transport::IngressPath {
            transport_id: 1,
            peer: peer.mac,
        },
        packet,
        response,
    )
}
fn poll_raw_udp6(
    peer: dmesh_fw_transport::wifi_raw_udp6_esp::RawUdp6Peer,
    response: &mut [u8; dmesh_fw_transport::TRANSPORT_MTU],
) -> Option<usize> {
    dmesh_fw_transport::recovery_runtime::poll_raw_service(
        dmesh_server::raw_transport::IngressPath {
            transport_id: 1,
            peer: peer.mac,
        },
        response,
    )
}
fn receive_espnow(
    peer: dmesh_fw_transport::wifi_espnow_esp::EspNowPeer,
    packet: &[u8],
    response: &mut [u8; dmesh_fw_transport::TRANSPORT_MTU],
) -> Option<usize> {
    dmesh_fw_transport::recovery_runtime::receive_raw_service(
        dmesh_server::raw_transport::IngressPath {
            transport_id: 2,
            peer: peer.mac,
        },
        packet,
        response,
    )
}
fn poll_espnow(
    peer: dmesh_fw_transport::wifi_espnow_esp::EspNowPeer,
    response: &mut [u8; dmesh_fw_transport::TRANSPORT_MTU],
) -> Option<usize> {
    dmesh_fw_transport::recovery_runtime::poll_raw_service(
        dmesh_server::raw_transport::IngressPath {
            transport_id: 2,
            peer: peer.mac,
        },
        response,
    )
}

struct StaStartTask {
    profile: dmesh_fw_transport::TransportProfile,
    source: &'static str,
}

fn profile() -> &'static Mutex<dmesh_fw_transport::TransportProfile> {
    PROFILE.get_or_init(|| Mutex::new(dmesh_fw_transport::TransportProfile::new()))
}

fn ephemeral_profile() -> &'static Mutex<Option<dmesh_fw_transport::TransportProfile>> {
    EPHEMERAL_PROFILE.get_or_init(|| Mutex::new(None))
}

pub fn initialize(settings: &SharedSettings, infra: bool) {
    let Ok(mut profile) = profile().lock() else {
        return;
    };
    if let Ok(Some(ssid)) = settings.borrow().get_str("ssid") {
        let bytes = ssid.as_bytes();
        if bytes.len() <= profile.ssid.len() {
            profile.ssid[..bytes.len()].copy_from_slice(bytes);
            profile.ssid_len = bytes.len();
        } else {
            telemetry::record_log("event type=transport.profile invalid_ssid=true");
        }
    }
    telemetry::record_log(format!(
        "event type=transport.profile loaded={} role={}",
        profile.has_flash_profile(),
        if infra { "infra" } else { "sleepy" }
    ));
    if infra {
        start_sta_locked(&profile, "boot_infra");
    }
}

/// Apply the shared direct Recovery control envelope in Main as well as
/// Recovery. The only Main-local consequence is waking a sleepy association;
/// raw-rate programming is the shared ESP adapter and affects either raw
/// UDP6 data frames or raw ESP-NOW action frames.
pub fn apply_direct_record(record: &[u8]) -> bool {
    let Ok(mut profile) = profile().lock() else {
        return false;
    };
    if dmesh_fw_transport::commands::apply_profile_command(record, &mut profile).is_none() {
        return false;
    }
    dmesh_fw_transport::state::direct_record_accepted();
    let rate = profile.raw_tx_rate;
    drop(profile);
    if STA_ACTIVE.load(Ordering::Acquire)
        && !dmesh_fw_transport::wifi_esp::configure_raw_tx_rate(rate)
    {
        dmesh_fw_transport::commands::send_response(b"main raw tx rate failed");
        return false;
    }
    dmesh_fw_transport::commands::send_stat(b"main raw tx rate=", rate as u64);
    request_active_session("uart_bootstrap");
    true
}

/// True while the shared STA transport owns (or is taking ownership of) the
/// Wi-Fi driver. Raw NAN/AP control-plane work must not reconfigure the same
/// driver during this interval. A future AP+STA integration will make that
/// coexistence explicit; it must not be simulated by competing start calls.
pub fn sta_bearer_owns_wifi() -> bool {
    STA_BEARER_OWNS_WIFI.load(Ordering::Acquire) || STA_STARTING.load(Ordering::Acquire)
}

/// Request a sleepy-node active transport session after an explicit control
/// plane event. This is intentionally not called from ordinary wake polling.
pub fn request_active_session(source: &'static str) {
    if super::mode::infra_mode() {
        return;
    }
    if let Ok(mut ephemeral) = ephemeral_profile().lock() {
        *ephemeral = None;
    }
    let now = now_ms();
    SESSION_DEADLINE_MS.store(now.wrapping_add(INITIAL_ACTIVE_MS), Ordering::Release);
    GRACE_ARMED.store(false, Ordering::Release);
    if let Ok(profile) = profile().lock() {
        start_sta_locked(&profile, source);
    }
}

/// Start one sleepy STA session with parameters learned through NAN service
/// discovery. The profile is intentionally memory-only: a discovery peer must
/// never overwrite the device's configured infrastructure profile.
pub fn request_ephemeral_nan_session(
    profile: dmesh_fw_transport::TransportProfile,
    source: &'static str,
) {
    if super::mode::infra_mode() {
        return;
    }
    if !profile.has_flash_profile() {
        return;
    }
    if let Ok(mut ephemeral) = ephemeral_profile().lock() {
        *ephemeral = Some(profile);
    }
    let now = now_ms();
    SESSION_DEADLINE_MS.store(now.wrapping_add(INITIAL_ACTIVE_MS), Ordering::Release);
    GRACE_ARMED.store(false, Ordering::Release);
    start_sta_locked(&profile, source);
}

/// A handler calls this once it accepts a stream. Completion extends the
/// session by the small grace tail so a command batch can arrive without a
/// second NAN/UART rendezvous.
pub fn stream_started() {
    ACTIVE_STREAMS.fetch_add(1, Ordering::AcqRel);
}

pub fn stream_completed() {
    let _ = ACTIVE_STREAMS.fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
        count.checked_sub(1)
    });
    if ACTIVE_STREAMS.load(Ordering::Acquire) == 0 {
        SESSION_DEADLINE_MS.store(now_ms().wrapping_add(COMMAND_GRACE_MS), Ordering::Release);
        GRACE_ARMED.store(true, Ordering::Release);
    }
}

/// Main's normal loop owns the deadline; no FreeRTOS callback sleeps or
/// blocks waiting for it. Sleepy STA is released only after all known streams
/// finish and the 200 ms command grace period expires.
pub fn poll() {
    dmesh_fw_transport::wifi_nonpromisc_probe_esp::poll();
    let infra = super::mode::infra_mode();
    // A raw-radio matrix row may intentionally retain a started channel-held
    // STA without association. This common volatile switch must suppress
    // Main's infra session owner too; otherwise Main immediately recreates
    // the link and a purported connectionless NOW test is invalid.
    let force_unassociated = dmesh_fw_transport::wifi_esp::lab_force_unassociated();
    // `STA_ACTIVE` is Main's session/power ownership state, not an ESP-IDF
    // association notification. The shared STA controller can lose an AP
    // asynchronously, so refresh that cache before deciding whether an
    // infrastructure session needs a retry. Recovery has no sleepy-session
    // owner and therefore does not need this Main-specific bridge.
    if STA_ACTIVE.load(Ordering::Acquire) && !dmesh_fw_transport::wifi_esp::sta_associated() {
        STA_ACTIVE.store(false, Ordering::Release);
        telemetry::record_log("event type=transport.session association_lost=true");
    }
    let deadline = SESSION_DEADLINE_MS.load(Ordering::Acquire);
    let now = now_ms();
    let session_live = deadline != 0 && quic_lite::before_deadline_u32(now, deadline);
    if !force_unassociated
        && (infra || session_live)
        && !STA_ACTIVE.load(Ordering::Acquire)
        && !STA_STARTING.load(Ordering::Acquire)
        && retry_due(now)
    {
        let ephemeral = ephemeral_profile().lock().ok().and_then(|profile| *profile);
        if let Some(profile) = ephemeral {
            start_sta_locked(&profile, "nan_session_retry");
        } else if let Ok(profile) = profile().lock() {
            start_sta_locked(
                &profile,
                if infra {
                    "infra_retry"
                } else {
                    "session_retry"
                },
            );
        }
    }
    // A raw action client can be started by the shared radio handler while
    // infra owns the STA (or while a lab STA is explicitly unassociated).
    // Recovery polls it whenever Wi-Fi is live; conditioning Main on the
    // legacy STA bearer owner sent one bootstrap OPEN but suppressed all
    // retry, delayed-ACK, PTO, and timeout progress. The client itself is
    // inert when no association is active, so this has no idle allocation or
    // packet-queue cost.
    dmesh_fw_transport::wifi_espnow_esp::poll_raw_client();
    dmesh_fw_transport::wifi_nan_dw_capture_esp::poll();
    if infra || !STA_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    if ACTIVE_STREAMS.load(Ordering::Acquire) != 0 {
        return;
    }
    if deadline == 0 || quic_lite::before_deadline_u32(now, deadline) {
        return;
    }
    dmesh_fw_transport::wifi_esp::stop_sta();
    STA_ACTIVE.store(false, Ordering::Release);
    STA_BEARER_OWNS_WIFI.store(false, Ordering::Release);
    SESSION_DEADLINE_MS.store(0, Ordering::Release);
    if let Ok(mut ephemeral) = ephemeral_profile().lock() {
        *ephemeral = None;
    }
    telemetry::record_log(format!(
        "event type=transport.session stopped=true grace={}",
        GRACE_ARMED.load(Ordering::Acquire)
    ));
}

fn start_sta_locked(profile: &dmesh_fw_transport::TransportProfile, source: &'static str) {
    if STA_ACTIVE.load(Ordering::Acquire)
        || STA_STARTING.swap(true, Ordering::AcqRel)
        || !profile.has_flash_profile()
    {
        if !profile.has_flash_profile() {
            STA_STARTING.store(false, Ordering::Release);
        }
        return;
    }
    // Use the Recovery-proven shared STA initializer verbatim. Main's raw
    // NAN/AP/ESP-NOW lifecycle remains compiled for a later, explicitly
    // tested coexistence phase, but must not stop/deinit Wi-Fi or create a
    // competing netif while this baseline owns STA.
    let task_state = Box::into_raw(Box::new(StaStartTask {
        profile: *profile,
        source,
    }));
    NEXT_RETRY_MS.store(now_ms().wrapping_add(RETRY_MS), Ordering::Release);
    let mut task = core::ptr::null_mut();
    let started = unsafe {
        esp_idf_sys::xTaskCreatePinnedToCore(
            Some(sta_start_task),
            b"dmesh_sta\0".as_ptr().cast(),
            12 * 1024,
            task_state.cast(),
            4,
            &mut task,
            0,
        ) == 1
            && !task.is_null()
    };
    if !started {
        unsafe { drop(Box::from_raw(task_state)) };
        STA_STARTING.store(false, Ordering::Release);
        telemetry::record_log(format!(
            "event type=transport.session started=false source={source} reason=task"
        ));
    } else {
        STA_BEARER_OWNS_WIFI.store(true, Ordering::Release);
    }
}

unsafe extern "C" fn sta_start_task(argument: *mut core::ffi::c_void) {
    let task = unsafe { Box::from_raw(argument.cast::<StaStartTask>()) };
    dmesh_fw_transport::wifi_esp::init_sta(&task.profile);
    STA_STARTING.store(false, Ordering::Release);
    let associated = dmesh_fw_transport::wifi_esp::sta_associated();
    STA_ACTIVE.store(associated, Ordering::Release);
    if associated {
        dmesh_fw_transport::wifi_raw_udp6_esp::set_sta_driver_tx(task.profile.sta_driver_tx);
        let started = dmesh_fw_transport::wifi_esp::start_raw_udp6(receive_raw_udp6);
        if started {
            dmesh_fw_transport::wifi_raw_udp6_esp::set_poll_handler(Some(poll_raw_udp6));
        }
        dmesh_fw_transport::commands::send_response(if started {
            b"main raw udp6 bearer started"
        } else {
            b"main raw udp6 bearer failed"
        });
        telemetry::record_log(format!("event type=transport.raw_udp6 started={started}"));
    }
    if associated && task.profile.espnow_capture {
        let started = dmesh_fw_transport::wifi_esp::start_nan_now(receive_espnow);
        if started {
            let burst = profile()
                .lock()
                .map(|profile| {
                    dmesh_fw_transport::recovery_runtime::espnow_association(&profile)
                        .tx_burst_packets
                })
                .unwrap_or(1);
            dmesh_fw_transport::wifi_espnow_esp::set_tx_burst_packets(burst);
            dmesh_fw_transport::wifi_espnow_esp::set_poll_handler(Some(poll_espnow));
        }
        dmesh_fw_transport::commands::send_response(if started {
            b"main NAN/NOW coexistence enabled"
        } else {
            b"main NAN/NOW coexistence failed"
        });
        telemetry::record_log(format!(
            "event type=transport.nan_now_coexistence enabled={started}"
        ));
    }
    telemetry::record_log(format!(
        "event type=transport.session associated={} source={}",
        associated, task.source
    ));
    drop(task);
    unsafe { esp_idf_sys::vTaskDelete(core::ptr::null_mut()) };
}

fn retry_due(now: u32) -> bool {
    let deadline = NEXT_RETRY_MS.load(Ordering::Acquire);
    deadline == 0 || !quic_lite::before_deadline_u32(now, deadline)
}

fn now_ms() -> u32 {
    unsafe { (esp_idf_sys::esp_timer_get_time().max(0) as u64 / 1_000) as u32 }
}
