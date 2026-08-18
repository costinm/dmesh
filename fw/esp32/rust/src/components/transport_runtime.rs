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
static STA_ACTIVE: AtomicBool = AtomicBool::new(false);
static STA_STARTING: AtomicBool = AtomicBool::new(false);
static SESSION_DEADLINE_MS: AtomicU32 = AtomicU32::new(0);
static NEXT_RETRY_MS: AtomicU32 = AtomicU32::new(0);
static ACTIVE_STREAMS: AtomicU32 = AtomicU32::new(0);
static GRACE_ARMED: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "wifi-espnow")]
static mut ESPNOW_IPERF_SERVER: Option<Box<dmesh_fw_transport::RawIperfServer>> = None;
#[cfg(feature = "wifi-raw-udp6")]
static mut RAW_UDP6_IPERF_SERVER: Option<Box<dmesh_fw_transport::RawIperfServer>> = None;

#[cfg(feature = "wifi-raw-udp6")]
fn receive_raw_udp6(
    _peer: dmesh_fw_transport::wifi_raw_udp6_esp::RawUdp6Peer,
    packet: &[u8],
    response: &mut [u8; dmesh_fw_transport::TRANSPORT_MTU],
) -> Option<usize> {
    // Keep the raw IPv6 diagnostic bearer independent from Main's legacy
    // action-stream DCID table.  It uses the same host-tested server as
    // Recovery, while Main's application multipath state remains untouched.
    unsafe {
        let slot = core::ptr::addr_of_mut!(RAW_UDP6_IPERF_SERVER);
        if (*slot).is_none() {
            *slot = Some(Box::new(dmesh_server::raw_iperf::RawIperfServer::new(
                quic_lite::ConnectionId::new(0x4d55_4436).expect("nonzero Main raw UDP6 CID"),
            )));
        }
        (*slot).as_mut()?.receive(packet, response).ok().flatten()
    }
}

#[cfg(feature = "wifi-raw-udp6")]
fn poll_raw_udp6(
    _peer: dmesh_fw_transport::wifi_raw_udp6_esp::RawUdp6Peer,
    response: &mut [u8; dmesh_fw_transport::TRANSPORT_MTU],
) -> Option<usize> {
    unsafe {
        (*core::ptr::addr_of_mut!(RAW_UDP6_IPERF_SERVER))
            .as_mut()?
            .poll(response)
            .ok()
            .flatten()
    }
}

#[cfg(feature = "wifi-espnow")]
fn receive_espnow(
    _peer: dmesh_fw_transport::wifi_espnow_esp::EspNowPeer,
    packet: &[u8],
    response: &mut [u8; dmesh_fw_transport::TRANSPORT_MTU],
) -> Option<usize> {
    unsafe {
        let slot = core::ptr::addr_of_mut!(ESPNOW_IPERF_SERVER);
        if (*slot).is_none() {
            *slot = Some(Box::new(dmesh_server::raw_iperf::RawIperfServer::new(
                quic_lite::ConnectionId::new(0x4d45_5350).expect("nonzero Main ESP-NOW CID"),
            )));
        }
        (*slot).as_mut()?.receive(packet, response).ok().flatten()
    }
}

#[cfg(feature = "wifi-espnow-client")]
pub fn start_shared_espnow_iperf(peer: [u8; 6], bytes: u64) -> bool {
    dmesh_fw_transport::wifi_espnow_esp::start_iperf_client(
        dmesh_fw_transport::wifi_espnow_esp::EspNowPeer { mac: peer },
        bytes,
    )
}

#[cfg(feature = "wifi-raw-udp6-client")]
pub fn start_shared_raw_udp6_iperf(peer: [u8; 6], ip: [u8; 16], bytes: u64) -> bool {
    dmesh_fw_transport::wifi_raw_udp6_esp::start_iperf_client(
        dmesh_fw_transport::wifi_raw_udp6_esp::RawUdp6Peer {
            mac: peer,
            ip,
            port: dmesh_fw_transport::wifi_raw_udp6_esp::RAW_UDP6_PORT,
        },
        bytes,
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
    dmesh_fw_transport::load_profile(&mut *settings.borrow_mut(), &mut profile);
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
    if dmesh_fw_transport::commands::accept_packet(record, &mut profile).is_none() {
        return false;
    }
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
    #[cfg(feature = "e6-espnow-iperf-lab")]
    if dmesh_fw_transport::shared_ingress_esp::schedule_work(e6_espnow_lab_work) {
        dmesh_fw_transport::commands::send_response(b"main lab espnow rerun scheduled");
    }
    #[cfg(feature = "e6-raw-udp6-iperf-lab")]
    {
        let progress = dmesh_fw_transport::wifi_raw_udp6_esp::iperf_client_progress();
        dmesh_fw_transport::commands::send_benchmark_stats(&[
            (126, progress.0 as u64),
            (127, progress.1 as u64),
            (128, progress.2 as u64),
        ]);
        let _ = dmesh_fw_transport::shared_ingress_esp::schedule_work(e6_raw_udp6_lab_work);
    }
    true
}

/// True while the shared STA transport owns (or is taking ownership of) the
/// Wi-Fi driver. Raw NAN/AP control-plane work must not reconfigure the same
/// driver during this interval. A future AP+STA integration will make that
/// coexistence explicit; it must not be simulated by competing start calls.
pub fn sta_bearer_owns_wifi() -> bool {
    STA_ACTIVE.load(Ordering::Acquire) || STA_STARTING.load(Ordering::Acquire)
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
    let infra = super::mode::infra_mode();
    let deadline = SESSION_DEADLINE_MS.load(Ordering::Acquire);
    let now = now_ms();
    let session_live = deadline != 0 && quic_lite::before_deadline_u32(now, deadline);
    if (infra || session_live)
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
    // The UDP L2 task is independent from association establishment. Retry
    // its creation opportunistically while the shared STA bearer is known
    // active; this is nonblocking and does not create a second task once the
    // first spawn succeeded.
    if STA_ACTIVE.load(Ordering::Acquire) {
        #[cfg(not(feature = "wifi-raw-udp6"))]
        super::action_stream::set_udp_bearer_enabled(true);
    }
    if infra || !STA_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    if ACTIVE_STREAMS.load(Ordering::Acquire) != 0 {
        return;
    }
    if deadline == 0 || quic_lite::before_deadline_u32(now, deadline) {
        return;
    }
    super::action_stream::set_udp_bearer_enabled(false);
    dmesh_fw_transport::wifi_esp::stop_sta();
    STA_ACTIVE.store(false, Ordering::Release);
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
    }
}

unsafe extern "C" fn sta_start_task(argument: *mut core::ffi::c_void) {
    let task = unsafe { Box::from_raw(argument.cast::<StaStartTask>()) };
    dmesh_fw_transport::wifi_esp::init_sta(&task.profile);
    STA_STARTING.store(false, Ordering::Release);
    let associated = dmesh_fw_transport::wifi_esp::sta_associated();
    STA_ACTIVE.store(associated, Ordering::Release);
    #[cfg(feature = "wifi-raw-udp6")]
    if associated {
        #[cfg(feature = "wifi-raw-udp6")]
        if !dmesh_fw_transport::wifi_esp::configure_raw_tx_rate(task.profile.raw_tx_rate) {
            dmesh_fw_transport::commands::send_response(b"main raw udp6 tx rate failed");
        }
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
        #[cfg(feature = "e6-raw-udp6-iperf-lab")]
        if started {
            let scheduled =
                dmesh_fw_transport::shared_ingress_esp::schedule_work(e6_raw_udp6_lab_work);
            dmesh_fw_transport::commands::send_response(if scheduled {
                b"main lab raw udp6 e7-to-e6 scheduled"
            } else {
                b"main lab raw udp6 e7-to-e6 schedule failed"
            });
        }
    }
    #[cfg(feature = "wifi-espnow")]
    if associated {
        let started = dmesh_fw_transport::wifi_esp::start_espnow(receive_espnow);
        dmesh_fw_transport::commands::send_response(if started {
            b"main raw espnow bearer started"
        } else {
            b"main raw espnow bearer failed"
        });
        telemetry::record_log(format!("event type=transport.raw_espnow started={started}"));
        #[cfg(feature = "e6-espnow-iperf-lab")]
        if started {
            let scheduled =
                dmesh_fw_transport::shared_ingress_esp::schedule_work(e6_espnow_lab_work);
            dmesh_fw_transport::commands::send_response(if scheduled {
                b"main lab espnow e7-to-e6 scheduled"
            } else {
                b"main lab espnow e7-to-e6 schedule failed"
            });
        }
    }
    #[cfg(not(feature = "wifi-raw-udp6"))]
    super::action_stream::set_udp_bearer_enabled(associated);
    telemetry::record_log(format!(
        "event type=transport.session associated={} source={}",
        associated, task.source
    ));
    drop(task);
    unsafe { esp_idf_sys::vTaskDelete(core::ptr::null_mut()) };
}

#[cfg(feature = "e6-raw-udp6-iperf-lab")]
fn e6_raw_udp6_lab_work() {
    // E6's RFC 4291 link-local address derives from its STA MAC. The AP
    // forwards the Ethernet destination while the raw adapter addresses the
    // outer To-DS 802.11 frame to the associated AP BSSID.
    let started = start_shared_raw_udp6_iperf(
        [0x14, 0xc1, 0x9f, 0xe5, 0x98, 0x00],
        [
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x16, 0xc1, 0x9f, 0xff, 0xfe, 0xe5, 0x98, 0x00,
        ],
        64 * 1024,
    );
    dmesh_fw_transport::commands::send_response(if started {
        b"main lab raw udp6 e7-to-e6 started"
    } else {
        b"main lab raw udp6 e7-to-e6 failed"
    });
    if !started {
        dmesh_fw_transport::commands::send_stat(
            b"main lab raw udp6 start_status=",
            dmesh_fw_transport::wifi_raw_udp6_esp::iperf_client_start_status() as u64,
        );
        dmesh_fw_transport::commands::send_stat(
            b"main lab raw udp6 tx_result=",
            dmesh_fw_transport::wifi_raw_udp6_esp::last_tx_result() as u64,
        );
    }
}

#[cfg(feature = "e6-espnow-iperf-lab")]
fn e6_espnow_lab_work() {
    let started = start_shared_espnow_iperf([0x14, 0xc1, 0x9f, 0xe5, 0x98, 0x00], 64 * 1024);
    dmesh_fw_transport::commands::send_response(if started {
        b"main lab espnow e7-to-e6 started"
    } else {
        b"main lab espnow e7-to-e6 failed"
    });
}

fn retry_due(now: u32) -> bool {
    let deadline = NEXT_RETRY_MS.load(Ordering::Acquire);
    deadline == 0 || !quic_lite::before_deadline_u32(now, deadline)
}

fn now_ms() -> u32 {
    unsafe { (esp_idf_sys::esp_timer_get_time().max(0) as u64 / 1_000) as u32 }
}
