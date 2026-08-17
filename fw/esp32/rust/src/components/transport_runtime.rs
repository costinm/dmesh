//! Main ownership of the shared Recovery-derived STA/transport runtime.
//!
//! Infra starts the shared STA bearer at boot and leaves it active. Sleepy
//! keeps the same profile and handlers available but does not start STA on a
//! periodic wake: only a UART or NAN service-discovery request creates a
//! bounded active session.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;

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
    // Recovery's proven association sequence deliberately waits for link/IP
    // readiness. Run it in a dedicated Rust/FreeRTOS task so NAN RX, UART,
    // timer polling, and handler dispatch never block on that wait.
    let snapshot = *profile;
    NEXT_RETRY_MS.store(now_ms().wrapping_add(RETRY_MS), Ordering::Release);
    if thread::Builder::new()
        .name("dmesh-sta".to_owned())
        .spawn(move || {
            dmesh_fw_transport::wifi_esp::init_sta(&snapshot);
            STA_STARTING.store(false, Ordering::Release);
            let associated = dmesh_fw_transport::wifi_esp::sta_associated();
            STA_ACTIVE.store(associated, Ordering::Release);
            super::action_stream::set_udp_bearer_enabled(associated);
            telemetry::record_log(format!(
                "event type=transport.session associated={} source={source}",
                associated
            ));
        })
        .is_err()
    {
        STA_STARTING.store(false, Ordering::Release);
        telemetry::record_log(format!(
            "event type=transport.session started=false source={source} reason=task"
        ));
    }
}

fn retry_due(now: u32) -> bool {
    let deadline = NEXT_RETRY_MS.load(Ordering::Acquire);
    deadline == 0 || !quic_lite::before_deadline_u32(now, deadline)
}

fn now_ms() -> u32 {
    unsafe { (esp_idf_sys::esp_timer_get_time().max(0) as u64 / 1_000) as u32 }
}
