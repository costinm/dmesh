//! Process-wide activity tracking for mesh services (phase 2a).
//!
//! Services built on the mesh library get exact idle tracking: connections,
//! dispatched requests and app-defined holds count as activity. When all
//! counters have been zero for the idle grace period, the tracker reports
//! idle over an sd_notify-compatible datagram channel so the supervisor can
//! freeze the service. Any counter above zero immediately reports busy.
//!
//! The supervisor decides when to freeze; this module only reports. Managers
//! never wait for a busy report — `mesh-init` pairs the handshake reply with
//! the freeze epoch instead.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Default idle grace: reports idle after this much quiet time.
pub const DEFAULT_IDLE_GRACE: Duration = Duration::from_secs(2);

/// Notification polling cadence; also the busy→idle resolution.
const NOTIFY_POLL_INTERVAL: Duration = Duration::from_millis(250);

static CONNECTIONS: AtomicU32 = AtomicU32::new(0);
static REQUESTS: AtomicU32 = AtomicU32::new(0);
static HOLDS: AtomicU32 = AtomicU32::new(0);
/// µs since some fixed origin of the last activity change. Zero = "no record".
static LAST_CHANGE_US: AtomicU64 = AtomicU64::new(0);
/// Next CLOCK_MONOTONIC deadline the app asked to be woken at (µs), if any.
static WAKE_AT_US: AtomicU64 = AtomicU64::new(0);
static REPORTER_STARTED: AtomicBool = AtomicBool::new(false);

fn monotonic_us() -> u64 {
    // CLOCK_MONOTONIC µs so X_MESH_WAKE_AT is directly compatible with the
    // supervisor's timer expectations.
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 {
        return 0;
    }
    (ts.tv_sec as u64) * 1_000_000 + (ts.tv_nsec as u64 / 1_000)
}

fn idle_grace() -> Duration {
    std::env::var("MESH_IDLE_GRACE")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_IDLE_GRACE)
}

fn touch() {
    LAST_CHANGE_US.store(monotonic_us(), Ordering::Relaxed);
}

/// A snapshot of the tracker for tests and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Snapshot {
    pub connections: u32,
    pub requests: u32,
    pub holds: u32,
    /// µs since the last activity change.
    pub last_change_us: u64,
    /// The µs wake deadline the application registered, if any.
    pub wake_at_us: Option<u64>,
}

impl Snapshot {
    /// Whether every activity counter is zero.
    pub fn is_active(&self) -> bool {
        self.connections > 0 || self.requests > 0 || self.holds > 0
    }
}

/// Take a snapshot of the current counters.
pub fn snapshot() -> Snapshot {
    let wake_at_us = WAKE_AT_US.load(Ordering::Relaxed);
    Snapshot {
        connections: CONNECTIONS.load(Ordering::Acquire),
        requests: REQUESTS.load(Ordering::Acquire),
        holds: HOLDS.load(Ordering::Acquire),
        last_change_us: LAST_CHANGE_US.load(Ordering::Relaxed),
        wake_at_us: (wake_at_us != 0).then_some(wake_at_us),
    }
}

/// Whether the process currently counts as busy.
pub fn is_busy() -> bool {
    snapshot().is_active()
}

/// Register the next timer deadline the application must service.
///
/// The value reaches the supervisor as `X_MESH_WAKE_AT` (CLOCK_MONOTONIC µs)
/// on the next idle report, and `None` cancels a pending deadline.
pub fn wake_at(deadline: Option<Instant>) {
    let value = match deadline {
        Some(deadline) => {
            let now = monotonic_us();
            let after = deadline
                .checked_duration_since(std::time::Instant::now())
                .map(|remaining| u64::try_from(remaining.as_micros()).unwrap_or(u64::MAX))
                .unwrap_or(0);
            now.saturating_add(after)
        }
        None => 0,
    };
    WAKE_AT_US.store(value, Ordering::Relaxed);
}

/// Outcome the reporter computed for the current poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdleReport {
    pub idle: bool,
    pub snapshot: Snapshot,
}

/// Compute what the tracker would report right now (supervisor-neutral).
///
/// Busy is immediate; idle requires the grace period to have elapsed since the
/// last counter change. `now_us` is CLOCK_MONOTONIC microseconds, matching
/// `Snapshot::last_change_us`, which keeps the function injectable in tests.
pub fn compute_report(now_us: u64) -> IdleReport {
    let snap = snapshot();
    if snap.is_active() {
        return IdleReport {
            idle: false,
            snapshot: snap,
        };
    }
    let grace_us = idle_grace().as_micros().min(u64::MAX as u128) as u64;
    // Without a last_change record the process has been idle since start.
    let quiet = snap.last_change_us == 0 || now_us.saturating_sub(snap.last_change_us) >= grace_us;
    IdleReport {
        idle: quiet,
        snapshot: snap,
    }
}

/// A guard counting one active connection for its lifetime.
///
/// `MeshListener::accept` attaches these so long-lived sessions (SSH shells,
/// streaming responses, subscriptions) keep the service busy.
#[must_use = "dropping a connection guard immediately releases the activity hold"]
pub struct ConnectionGuard {
    _priv: (),
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        CONNECTIONS.fetch_sub(1, Ordering::Release);
        touch();
    }
}

/// A guard counting one in-flight request.
#[must_use = "dropping a request guard immediately releases the activity hold"]
pub struct RequestGuard {
    _priv: (),
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        REQUESTS.fetch_sub(1, Ordering::Release);
        touch();
    }
}

/// A guard tracking app-defined background work, named for traces.
#[must_use = "dropping a hold guard immediately releases the activity hold"]
pub struct HoldGuard {
    #[allow(dead_code)]
    name: &'static str,
}

impl Drop for HoldGuard {
    fn drop(&mut self) {
        HOLDS.fetch_sub(1, Ordering::Release);
        touch();
    }
}

/// Hold one activity slot for a live connection (used by `MeshListener`).
pub fn connection() -> ConnectionGuard {
    CONNECTIONS.fetch_add(1, Ordering::AcqRel);
    touch();
    ConnectionGuard { _priv: () }
}

/// Hold one activity slot around one dispatched request.
pub fn request() -> RequestGuard {
    REQUESTS.fetch_add(1, Ordering::AcqRel);
    touch();
    RequestGuard { _priv: () }
}

/// Hold one activity slot for app-defined background work.
pub fn hold(name: &'static str) -> HoldGuard {
    let _ = name;
    HOLDS.fetch_add(1, Ordering::AcqRel);
    touch();
    HoldGuard { name }
}

fn notify_socket_path() -> Option<String> {
    std::env::var("NOTIFY_SOCKET")
        .ok()
        .filter(|v| !v.is_empty())
}

/// Format one sd_notify-compatible idle/busy datagram body.
pub fn format_idle_message(report: &IdleReport) -> String {
    let head = if report.idle {
        "X_MESH_IDLE=1"
    } else {
        "X_MESH_BUSY=1"
    };
    let mut body = format!(
        "{}\nX_MESH_ACTIVE={}\nX_MESH_CONNS={}\n",
        head,
        report.snapshot.requests + report.snapshot.holds,
        report.snapshot.connections,
    );
    if let Some(wake_at_us) = report.snapshot.wake_at_us {
        body.push_str(&format!("X_MESH_WAKE_AT={wake_at_us}\n"));
    }
    body
}

/// The reporter thread loop: publishes state changes to NOTIFY_SOCKET.
fn reporter_loop(socket_path: String) {
    let socket = std::os::unix::net::UnixDatagram::unbound();
    let socket = match socket {
        Ok(socket) => socket,
        Err(_) => return,
    };
    let mut last_latch: Option<String> = None;
    loop {
        std::thread::sleep(NOTIFY_POLL_INTERVAL);
        let report = compute_report(monotonic_us());
        let body = format_idle_message(&report);
        if last_latch.as_deref() == Some(body.as_str()) {
            continue;
        }
        // The datagram channel never blocks a service.
        if socket.send_to(body.as_bytes(), &socket_path).is_err() {
            // A transient supervisor-side bind race must not kill the
            // reporter; retry on the next tick.
            if socket.connect(std::path::Path::new(&socket_path)).is_err() {
                continue;
            }
            let _ = socket.send(body.as_bytes());
        }
        last_latch = Some(body);
    }
}

fn ensure_reporter() {
    if REPORTER_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let Some(path) = notify_socket_path() else {
        // No supervisor channel configured; keep tracking so in-process
        // callers can still ask, and do not spawn anything.
        return;
    };
    std::thread::Builder::new()
        .name("mesh-activity".to_string())
        .spawn(move || reporter_loop(path))
        .ok();
}

/// Force one synchronous report to the supervisor (used at startup READY=1
/// boundaries and in tests). Returns whether a datagram was sent.
pub fn report_now() -> bool {
    ensure_reporter();
    let Some(path) = notify_socket_path() else {
        return false;
    };
    let socket = match std::os::unix::net::UnixDatagram::unbound() {
        Ok(socket) => socket,
        Err(_) => return false,
    };
    let report = compute_report(monotonic_us());
    let body = format_idle_message(&report);
    socket.send_to(body.as_bytes(), &path).is_ok()
}

/// Count of connection guards currently held; used by tests.
pub fn connections() -> u32 {
    CONNECTIONS.load(Ordering::Acquire)
}

/// Count of request guards currently held; used by tests.
pub fn requests() -> u32 {
    REQUESTS.load(Ordering::Acquire)
}

/// Count of hold guards currently held; used by tests.
pub fn holds() -> u32 {
    HOLDS.load(Ordering::Acquire)
}

/// Whether the activity reporter thread has been started for this process.
pub fn reporter_started() -> bool {
    REPORTER_STARTED.load(Ordering::Acquire)
}

static _SPAWN_HOOK: OnceLock<AtomicUsize> = OnceLock::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_guards_count_correctly() {
        let before = snapshot();
        let c = connection();
        assert_eq!(connections(), before.connections + 1);
        {
            let _r = request();
            assert_eq!(requests(), before.requests + 1);
            {
                let _h = hold("upload");
                assert_eq!(holds(), before.holds + 1);
                let snap = snapshot();
                assert!(snap.is_active());
            }
            assert_eq!(holds(), before.holds);
        }
        assert_eq!(requests(), before.requests);
        drop(c);
        assert_eq!(connections(), before.connections);
    }

    #[test]
    fn busy_is_immediate_and_format_has_counts() {
        let guard = hold("test");
        // Any far-future monotonic timestamp must still report busy.
        let report = compute_report(u64::MAX);
        assert!(!report.idle);
        let body = format_idle_message(&report);
        assert!(body.starts_with("X_MESH_BUSY=1"));
        assert!(body.contains("X_MESH_ACTIVE=1"));
        drop(guard);
    }

    #[test]
    fn idle_format_reports_wake_at() {
        // A wake deadline is included in the message.
        let deadline = Instant::now() + Duration::from_secs(30);
        wake_at(Some(deadline));
        let report = IdleReport {
            idle: true,
            snapshot: Snapshot {
                connections: 0,
                requests: 0,
                holds: 0,
                last_change_us: 1,
                wake_at_us: snapshot().wake_at_us,
            },
        };
        let body = format_idle_message(&report);
        assert!(body.starts_with("X_MESH_IDLE=1"));
        assert!(body.contains("X_MESH_WAKE_AT="));
        wake_at(None);
    }

    #[test]
    fn wake_at_cancels_with_none() {
        let deadline = Instant::now() + Duration::from_secs(60);
        wake_at(Some(deadline));
        assert!(snapshot().wake_at_us.is_some());
        wake_at(None);
        assert!(snapshot().wake_at_us.is_none());
    }

    #[test]
    fn depends_on_grace_environment() {
        // The grace is taken from MESH_IDLE_GRACE; the default is 2s.
        assert_eq!(
            idle_grace(),
            std::env::var("MESH_IDLE_GRACE")
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(Duration::from_secs)
                .unwrap_or(DEFAULT_IDLE_GRACE)
        );
    }
}
