//! Main daemon loop for mesh-init.
//!
//! Manages service lifecycle: loads configs, starts system services,
//! handles control requests, manages signal handling and zombie reaping.

use std::collections::{HashMap, VecDeque, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use anyhow::Result;

use parking_lot::Mutex;
use tracing::{debug, error, info, trace, warn};

use crate::config::{self, AppConfig, RestartPolicy};
use crate::observer::{self, ProcessDetailedInfo, ProcessObserver};
use crate::process::{self, ManagedProcess};
use crate::protocol::{
    ActivationContext, FreezeReason, NamespaceKind, Request, Response, ServiceState, ServiceStatus,
};
use crate::resource::ResourceManager;
use crate::states;

// ============================================================================
// Daemon
// ============================================================================

/// Default non-root UIDs permitted to act as a different user (i.e. spawn or
/// control a process whose UID differs from the peer's).
///
/// - `1000` — the `system` service account
///
/// The ssh-mesh UID (resolved via `mesh::auth::ssh_mesh_uid`, env var
/// `MESH_SSH_MESH_UID`, default 150) is included because it must spawn shells
/// as other users.
///
/// Root (UID 0) is always privileged. The full list can be overridden with the
/// `MESH_INIT_PRIVILEGED_UIDS` env var (comma-separated).
///
/// **Note:** UID 1000 (system) is root-equivalent for all mesh-init
/// permissions, including system-wide observer methods. The ssh-mesh UID
/// (default 150) is trusted for terminal/start operations and impersonation
/// but NOT for observer methods — see [`require_system_or_root`].
fn privileged_uids() -> Vec<u32> {
    if let Ok(v) = std::env::var("MESH_INIT_PRIVILEGED_UIDS") {
        let parsed: Vec<u32> = v
            .split(',')
            .filter_map(|s| s.trim().parse::<u32>().ok())
            .collect();
        if !parsed.is_empty() {
            return parsed;
        }
    }
    let mut uids = vec![0];
    if let Some(sys) = mesh::auth::system_uid() {
        uids.push(sys);
    }
    if let Some(mesh) = mesh::auth::ssh_mesh_uid() {
        if !uids.contains(&mesh) {
            uids.push(mesh);
        }
    }
    uids
}

/// Require that the peer is root (0) or the system UID.
///
/// Used by system-wide observer methods (`freeze_process`, `move_process`,
/// `cgroup_high`, `clear_refs`, `freeze_cgroup`) that operate on arbitrary
/// PIDs or cgroup paths. The ssh-mesh UID is **not**
/// sufficient for these operations — they must use the named-service APIs
/// (`start`/`stop`/`freeze`/`unfreeze`) instead.
fn require_system_or_root(peer_uid: u32) -> Result<(), Response> {
    if mesh::auth::is_system_or_root(peer_uid) {
        Ok(())
    } else {
        Err(Response::err(format!(
            "permission denied: system-wide observer methods require root or system UID; peer UID {} is not authorized",
            peer_uid
        )))
    }
}

/// Check whether `peer_uid` is permitted to act as `target_uid`/`target_gid`.
///
/// Privileged UIDs (see [`privileged_uids`]) may target any UID. A non-
/// privileged peer may only target its own UID. Returns `Ok(())` if allowed,
/// or `Err(Response)` with a permission-denied response.
fn check_impersonation(
    peer_uid: u32,
    peer_gid: u32,
    target_uid: u32,
    target_gid: Option<u32>,
    name: &str,
) -> Result<(), Response> {
    if privileged_uids().contains(&peer_uid) {
        return Ok(());
    }
    if target_uid != peer_uid {
        return Err(Response::err(format!(
            "permission denied: peer UID {} may not operate on service '{}' (UID {})",
            peer_uid, name, target_uid
        )));
    }
    if let Some(g) = target_gid
        && g != peer_gid
    {
        return Err(Response::err(format!(
            "permission denied: peer GID {} may not operate on service '{}' (GID {})",
            peer_gid, name, g
        )));
    }
    Ok(())
}

fn preferred_shell() -> &'static str {
    if std::path::Path::new("/opt/busybox/bin/sh").is_file() {
        "/opt/busybox/bin/sh"
    } else {
        "/bin/sh"
    }
}

/// Read the running kernel version and require at least `min_major.min_minor`.
///
/// mesh-init uses `pidfd_open(2)` / `pidfd_send_signal(2)` (Linux 5.3) to
/// make PID recycling impossible. On older kernels the daemon refuses to
/// start rather than silently falling back to `kill(2)` + `waitpid(2)`,
/// which can signal a recycled PID that no longer belongs to the service.
fn check_kernel_version(min_major: u32, min_minor: u32) {
    let raw = match std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        Ok(s) => s,
        Err(error) => {
            panic!(
                "mesh-init requires Linux >= {min_major}.{min_minor} for \
                 pidfd_open / pidfd_send_signal; cannot read /proc/sys/kernel/osrelease: {error}"
            );
        }
    };
    let mut parts = raw.trim().split('.');
    let major: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor: u32 = parts
        .next()
        .and_then(|p| p.split_once('-').map_or(Some(p), |(n, _)| Some(n)))
        .and_then(|p| p.parse().ok())
        .unwrap_or(0);
    if (major, minor) < (min_major, min_minor) {
        panic!(
            "mesh-init requires Linux >= {min_major}.{min_minor} for \
             pidfd_open / pidfd_send_signal; running kernel is {raw} (>= 5.3 required, 2019)"
        );
    }
}

/// Configuration for the daemon.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Directories to scan for system service configs.
    pub config_dirs: Vec<String>,
    /// Path for the UDS control socket.
    pub socket_path: String,
}

/// The mesh-init daemon.
///
/// Holds the registry of managed services and handles control requests.
pub struct Daemon {
    pub config: DaemonConfig,
    pub services: Arc<Mutex<HashMap<String, ManagedProcess>>>,
    /// All loaded configs, including those not yet started.
    pub configs: Arc<Mutex<HashMap<String, AppConfig>>>,
    /// Context prepared by a control request for a later socket activation.
    pub pending_activation_contexts: Arc<Mutex<HashMap<String, VecDeque<ActivationContext>>>>,
    terminal_sessions: Arc<Mutex<HashMap<String, TerminalSession>>>,
    next_terminal_id: AtomicU64,
    observer: Arc<ProcessObserver>,
    resource_manager: Option<ResourceManager>,
    /// Set of tracked child PIDs for the reaper (only used when not PID 1).
    pub tracked_child_pids: Mutex<Option<Arc<parking_lot::Mutex<std::collections::HashSet<u32>>>>>,
    pub shutdown_tx: tokio::sync::watch::Sender<bool>,
    pub service_exit_tx: tokio::sync::broadcast::Sender<String>,
    scheduler_tx: tokio::sync::watch::Sender<u64>,
    /// Notify channels by service, bound before each spawn (phase 2b).
    notify_receivers: Arc<Mutex<HashMap<String, NotifyReceiverHandle>>>,
}

/// Handle for one service's notify channel. `stop` ends the reader thread
/// and removes the socket file.
pub struct NotifyReceiverHandle {
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    #[allow(dead_code)]
    receiver: Arc<crate::notify::NotifyReceiver>,
}

impl NotifyReceiverHandle {
    /// Stop the reader thread and release the socket file.
    pub fn stop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for NotifyReceiverHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

struct TerminalSession {
    name: String,
    pid: u32,
    pty_fd: Option<OwnedFd>,
    /// pidfd for the terminal process. Used by `pidfd_send_signal(2)` to
    /// signal without PID-recycle risk. See `process::open_pidfd`.
    pidfd: Option<OwnedFd>,
}

/// How long a service may sit in `Stopping` with a live PID before the
/// scheduler escalates to SIGKILL. Covers both a failed signal and a process
/// that ignores (or is stuck in uninterruptible sleep against) SIGTERM.
const STOPPING_ESCALATION_SECS: u64 = 5;

/// How long `cgroup.freeze=1` may take to confirm `frozen 1` in
/// `cgroup.events` before the freeze attempt is rolled back.
const CONFIRM_FREEZE_TIMEOUT: Duration = Duration::from_secs(2);

/// What [`Daemon::ensure_running`] decided for a wake/activation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnsureRunningOutcome {
    /// A fresh child was spawned.
    Started(u32),
    /// A frozen child was thawed and keeps serving.
    Thawed { pid: Option<u32> },
    /// The service is user-frozen; activity cannot thaw it.
    ThawedRefused,
    /// A pending freeze was cancelled before the cgroup froze.
    FreezeCancelled,
    /// The service is stopping; the request restarts after exit.
    QueuedWhileStopping,
    /// The service is already running.
    AlreadyRunning { pid: Option<u32> },
}

/// Map the wire `reason` of a freeze request onto the lifecycle reasons.
/// An unknown or missing value freezes as a user freeze: activity may not
/// thaw it.
fn freeze_reason(requested: Option<String>) -> FreezeReason {
    match requested.as_deref().map(str::trim) {
        Some("pressure") => FreezeReason::Pressure,
        _ => FreezeReason::User,
    }
}

fn ensure_outcome_pid(outcome: &EnsureRunningOutcome) -> Option<u32> {
    match outcome {
        EnsureRunningOutcome::Started(pid) => Some(*pid),
        EnsureRunningOutcome::Thawed { pid } | EnsureRunningOutcome::AlreadyRunning { pid } => *pid,
        _ => None,
    }
}

fn ensure_outcome_label(outcome: &EnsureRunningOutcome) -> &'static str {
    match outcome {
        EnsureRunningOutcome::Started(_) => "started",
        EnsureRunningOutcome::Thawed { .. } => "thawed",
        EnsureRunningOutcome::ThawedRefused => "thaw_refused",
        EnsureRunningOutcome::FreezeCancelled => "freeze_cancelled",
        EnsureRunningOutcome::QueuedWhileStopping => "queued",
        EnsureRunningOutcome::AlreadyRunning { .. } => "already_running",
    }
}

/// Environment variables that are dangerous when set by a caller because they
/// can hijack the spawned process (library injection, shell-config, etc.).
///
/// `PATH` is also listed because a trusted peer could shadow system
/// binaries (e.g. inject a `su` in `/tmp`).
const DEFAULT_DANGEROUS_ENV_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_BIND_NOW",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "LD_DYNAMIC_WEAK",
    "LD_HWCAP_MASK",
    "LD_KEEPDIR",
    "LD_NOEXEC",
    "LD_ORIGIN_PATH",
    "LD_POINTER_GUARD",
    "LD_PROFILE",
    "LD_SHOW_AUXV",
    "LD_USE_LOAD_BIAS",
    "BASH_ENV",
    "ENV",
    "BASH_FUNC_*",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PERL5OPT",
    "PERL5LIB",
    "PERLLIB",
    "NODE_OPTIONS",
    "NODE_PATH",
    "RUBYOPT",
    "GEM_PATH",
    "JAVA_TOOL_OPTIONS",
    "PATH",
];

fn dangerous_env_patterns() -> Vec<String> {
    std::env::var("MESH_DANGEROUS_ENV")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_else(|| {
            DEFAULT_DANGEROUS_ENV_VARS
                .iter()
                .map(|entry| (*entry).to_string())
                .collect()
        })
}

fn env_name_matches(key: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        if let Some(prefix) = pattern.strip_suffix('*') {
            key.starts_with(prefix)
        } else {
            key == pattern
        }
    })
}

/// Strip dangerous caller-supplied environment variables unless the service
/// explicitly allowlists that name via `AllowDangerousEnv`.
pub(crate) fn scrub_dangerous_env(env: &mut HashMap<String, String>, config: &AppConfig) {
    let dangerous = dangerous_env_patterns();
    env.retain(|key, _| {
        !env_name_matches(key, &dangerous) || env_name_matches(key, &config.allow_dangerous_env)
    });
}

pub(crate) fn apply_activation_context_env(
    config: &mut AppConfig,
    context: Option<ActivationContext>,
) {
    if let Some(context) = context {
        let mut env = context.to_env();
        scrub_dangerous_env(&mut env, config);
        config.env.extend(env);
    }
}

fn run_service_commands(
    config: &AppConfig,
    commands: &[String],
    label: &str,
    timeout_secs: Option<u64>,
) -> Result<()> {
    for command in commands {
        let exit_code = process::run_service_command(config, command, timeout_secs)
            .map_err(|e| anyhow::anyhow!("{} command '{}' failed: {}", label, command, e))?;
        if exit_code != 0 {
            anyhow::bail!("{} command '{}' exited with {}", label, command, exit_code);
        }
    }
    Ok(())
}

fn should_restart_for_policy(policy: RestartPolicy, exit_code: i32) -> bool {
    match policy {
        RestartPolicy::No => false,
        RestartPolicy::Always => true,
        RestartPolicy::OnSuccess => exit_code == 0,
        RestartPolicy::OnFailure => exit_code != 0,
        RestartPolicy::OnAbnormal | RestartPolicy::OnAbort => exit_code < 0 || exit_code >= 128,
    }
}

fn is_exec_service(config: &AppConfig) -> bool {
    config
        .service_type
        .as_deref()
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("exec"))
}

fn start_exec_service_with_activation(daemon: Arc<Daemon>, config: AppConfig) {
    let expected_listener_fds = config.activation.iter().filter(|act| act.wait).count();
    if expected_listener_fds == 0 {
        return;
    }

    tokio::spawn(async move {
        let mut attempts = 0;
        let fds = loop {
            let fds = crate::activation::service_listener_fds(&config.name);
            if fds.len() >= expected_listener_fds || attempts >= 20 {
                break fds;
            }
            attempts += 1;
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        };

        if fds.is_empty() {
            error!(
                service = %config.name,
                "autostart_activation_service_no_listener_fds"
            );
            return;
        }

        let mut config = config;
        let config_name = config.name.clone();
        let context = daemon.take_activation_context(&config.name);
        apply_activation_context_env(&mut config, context);
        let passed_fd = Some(crate::process::ActivationFd::Listen(fds));
        if let Err(e) = daemon.start_service_with_config(config, passed_fd) {
            error!(
                service = %config_name,
                error = %e,
                "autostart_activation_service_failed"
            );
        }
    });
}

impl Daemon {
    /// Create a new daemon instance.
    pub fn new(config: DaemonConfig) -> Arc<Self> {
        // A10: Require Linux >= 5.3 (2019) for pidfd_open / pidfd_send_signal.
        // These syscalls make PID recycling impossible, which the
        // `kill + waitpid` flow cannot guarantee. Refuse to start on
        // older kernels rather than silently fall back to the unsafe flow.
        check_kernel_version(5, 3);

        let services = Arc::new(Mutex::new(HashMap::new()));
        let resource_manager = Some(ResourceManager::new(services.clone()));
        let observer = Arc::new(ProcessObserver::new().expect("create mesh-init process observer"));
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let (service_exit_tx, _) = tokio::sync::broadcast::channel(128);
        let (scheduler_tx, _) = tokio::sync::watch::channel(0_u64);

        Arc::new(Self {
            config,
            services,
            configs: Arc::new(Mutex::new(HashMap::new())),
            pending_activation_contexts: Arc::new(Mutex::new(HashMap::new())),
            terminal_sessions: Arc::new(Mutex::new(HashMap::new())),
            next_terminal_id: AtomicU64::new(1),
            observer,
            resource_manager,
            tracked_child_pids: Mutex::new(None),
            shutdown_tx,
            service_exit_tx,
            scheduler_tx,
            notify_receivers: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn notify_service_exit(&self, name: &str) {
        let _ = self.service_exit_tx.send(name.to_string());
    }

    /// Bind the sd_notify-compatible channel (phase 2b) for one service.
    ///
    /// The reader thread applies READY/WATCHDOG/activity messages to the
    /// service registry and wakes the scheduler when idle state changes.
    fn start_notify_receiver(&self, name: &str) -> Result<()> {
        let owning_name = name.to_string();
        let cgroup = crate::cgroup::cgroup_path_for(name).ok();
        let receiver = crate::notify::NotifyReceiver::bind_with(
            name,
            cgroup,
            self.services.clone(),
            self.scheduler_tx.clone(),
        )?;
        let receiver = Arc::new(receiver);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_ref = receiver.clone();
        let stop_ref = stop.clone();
        let thread = std::thread::Builder::new()
            .name(format!("notify-{name}"))
            .spawn({
                let thread_name = owning_name.clone();
                move || {
                    debug!(service = %thread_name, "notify_reader_started");
                    thread_ref.run_with_stop(&stop_ref);
                    debug!(service = %thread_name, "notify_reader_stopped");
                }
            })?;
        let _ = std::fs::metadata(crate::notify::notify_socket_path(name));
        let previous = self.notify_receivers.lock().insert(
            name.to_string(),
            NotifyReceiverHandle {
                stop,
                thread: Some(thread),
                receiver: receiver.clone(),
            },
        );
        if let Some(mut previous) = previous {
            previous.stop();
        }
        Ok(())
    }

    /// Stop a service's notify reader (also called on child exit).
    fn stop_notify_receiver(&self, name: &str) {
        if let Some(mut handle) = self.notify_receivers.lock().remove(name) {
            handle.stop();
        }
    }

    fn wake_scheduler(&self) {
        // `send_modify` panics when there are no receivers. The scheduler task
        // subscribes inside `start_child_manager`, but autostart and container
        // mode can call `wake_scheduler` synchronously before that task is
        // first polled. Wake-ups before subscription are safe to drop: the
        // scheduler computes deadlines from state on its first poll anyway.
        if self.scheduler_tx.receiver_count() == 0 {
            return;
        }
        self.scheduler_tx.send_modify(|revision| {
            *revision = revision.wrapping_add(1);
        });
    }

    /// Run the daemon main loop.
    ///
    /// 1. Load system configs
    /// 2. Start resource manager
    /// 3. Start child manager
    /// 4. Auto-start system services
    /// 5. Start UDS control server
    pub async fn run(self: &Arc<Self>) -> Result<()> {
        info!("daemon_starting");

        self.start_background_tasks();

        // Start control server (blocks)
        let server =
            crate::server::ControlServer::new(self.config.socket_path.clone(), self.clone());
        server.run().await?;

        Ok(())
    }

    /// Start resource manager and background monitoring tasks.
    pub fn start_background_tasks(self: &Arc<Self>) {
        // 1. Load configs
        let dirs: Vec<&str> = self.config.config_dirs.iter().map(|s| s.as_str()).collect();
        let loaded_configs = config::load_system_configs(&dirs);
        info!(count = loaded_configs.len(), "service_configs_loaded");

        {
            let mut configs = self.configs.lock();
            for cfg in &loaded_configs {
                configs.insert(cfg.name.clone(), cfg.clone());
            }
        }

        // A previous mesh-init can leave children alive after it exits or is
        // replaced.  Their parent PID is no longer meaningful, but their
        // service cgroup is.  Clear only scopes named by the current config
        // before any new service is spawned, so old listeners cannot steal
        // ports or sockets from the replacement service.
        for cfg in &loaded_configs {
            if cfg.name == "default" {
                continue;
            }
            if let Err(error) = crate::cgroup::terminate_stale_service_scope(&cfg.name) {
                warn!(
                    service = %cfg.name,
                    error = %error,
                    "stale_service_scope_cleanup_failed"
                );
            }
        }

        // 2. Pressure policy task (phase 3): event-driven ladder built on
        // the pure plan() function. ResourceManager stays for admission
        // checks (can_start / committed_memory_low); its 5-second monitor
        // loop is retired in favor of the policy task below.
        Self::spawn_pressure_policy_task(self.clone());

        self.start_process_observer();

        // 3. Spawn child process manager before autostart so non-PID1 runs
        // can register service PIDs for SIGCHLD reaping.
        self.start_child_manager();

        // 4. Auto-start system services or start activation listeners.
        // init-* services run first (sorted by priority), then the rest.
        let startup_configs: Vec<AppConfig> = self.configs.lock().values().cloned().collect();
        let mut init_configs: Vec<AppConfig> = Vec::new();
        let mut other_configs: Vec<AppConfig> = Vec::new();
        for cfg in startup_configs {
            if cfg.name == "default" {
                // default.toml only provides defaults for execution mode
                continue;
            }
            if cfg.name.starts_with("init-") {
                init_configs.push(cfg);
            } else {
                other_configs.push(cfg);
            }
        }
        init_configs.sort_by_key(|c| c.priority);
        other_configs.sort_by_key(|c| c.priority);

        for cfg in init_configs.iter().chain(other_configs.iter()) {
            if !cfg.activation.is_empty() {
                crate::activation::start_listeners(self.clone(), cfg);
                if is_exec_service(cfg) {
                    start_exec_service_with_activation(self.clone(), cfg.clone());
                }
            } else {
                let should_autostart = cfg
                    .service_type
                    .as_deref()
                    .map(|t| !t.trim().is_empty())
                    .unwrap_or(false);
                if should_autostart {
                    if let Err(e) = self.start_service_internal(&cfg.name) {
                        error!(service = %cfg.name, error = %e, "autostart_service_failed");
                    }
                } else {
                    debug!(service = %cfg.name, "service_not_autostarted_no_listeners_no_type");
                }
            }
        }
    }

    fn start_process_observer(&self) {
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(1024);
        match self.observer.start(true, true, Some(event_tx.clone())) {
            Ok(()) => {}
            Err(e) => {
                warn!(error = %e, "process_observer_start_failed");
                return;
            }
        }

        let running = self.observer.running.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = observer::proc_netlink::run_netlink_listener(event_tx, running) {
                debug!(error = %e, "netlink_listener_stopped");
            }
        });

        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                match event {
                    observer::MonitoringEvent::Netlink(event) => {
                        trace!(?event, "process observer netlink event");
                    }
                    observer::MonitoringEvent::Pressure(event) => {
                        trace!(
                            cgroup = %event.cgroup_path,
                            avg10 = event.pressure_data.avg10,
                            avg60 = event.pressure_data.avg60,
                            total = event.pressure_data.total,
                            "process observer pressure event"
                        );
                    }
                }
            }
        });
    }

    /// Spawn the child process manager (zombie reaper + restart loop).
    pub fn start_child_manager(self: &Arc<Self>) {
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);
        let tracked = process::start_child_reaper(tx);
        // Store the tracked PIDs set so spawn sites can register children when
        // the reaper is not in catch-all (PID 1) mode.
        *self.tracked_child_pids.lock() = Some(tracked);

        let daemon_clone = self.clone();
        tokio::spawn(async move {
            let mut scheduler_rx = daemon_clone.scheduler_tx.subscribe();
            loop {
                let deadline = daemon_clone.next_service_deadline();
                tokio::select! {
                    Some((pid, exit_code)) = rx.recv() => {
                        daemon_clone.handle_child_exit(pid, exit_code);
                    }
                    changed = scheduler_rx.changed() => {
                        if changed.is_err() {
                            break;
                        }
                    }
                    _ = async {
                        match deadline {
                            Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                            None => std::future::pending::<()>().await,
                        }
                    } => {}
                }
                daemon_clone.check_restarts();
                // Idle policy needs an Arc for its async handshake tasks.
                let policy_daemon = daemon_clone.clone();
                tokio::spawn(async move {
                    policy_daemon.apply_idle_policy().await;
                });
            }
        });
    }

    /// Handle a control protocol request.
    pub async fn handle_request(&self, request: Request, peer_uid: u32, peer_gid: u32) -> Response {
        match request {
            Request::Start {
                name,
                args,
                env,
                context,
            } => {
                self.handle_start(&name, args, env, context, peer_uid, peer_gid)
                    .await
            }
            Request::PrepareActivation { name, context } => {
                self.prepare_activation_context(name, context)
            }
            Request::StartTerminal { .. } => {
                Response::err("start_terminal requires a passed file descriptor")
            }
            Request::RegisterNamespace { .. } => {
                Response::err("register_namespace requires a passed file descriptor")
            }
            Request::TerminalResize {
                terminal_id,
                col_width,
                row_height,
                pix_width,
                pix_height,
            } => self.handle_terminal_resize(
                &terminal_id,
                col_width,
                row_height,
                pix_width,
                pix_height,
            ),
            Request::TerminalCommand {
                terminal_id,
                command,
                data,
            } => self.handle_terminal_command(&terminal_id, &command, data),
            Request::Stop { name, signal } => {
                self.handle_stop(&name, signal, peer_uid, peer_gid).await
            }
            Request::Freeze { name, reason } => {
                self.handle_freeze(&name, reason, peer_uid, peer_gid).await
            }
            Request::Unfreeze { name } => self.handle_unfreeze(&name, peer_uid, peer_gid).await,
            Request::Reconcile => self.handle_reconcile(peer_uid).await,
            Request::Status { name } => self.handle_status(name.as_deref()),
            Request::Shutdown => self.handle_shutdown().await,
            Request::Reload => self.handle_reload(),
            Request::Processes => self.handle_observer_processes(),
            Request::Process { pid } => self.handle_observer_process(pid),
            Request::ProcessOnly { pid } => self.handle_observer_process_only(pid),
            Request::Cgroups => self.handle_observer_cgroups(),
            Request::Cgroup { path } => self.handle_observer_cgroup(&path),
            Request::Pressure => self.handle_observer_pressure(),
            Request::CgroupHigh {
                path,
                percentage,
                interval,
            } => self.handle_observer_cgroup_high(path, percentage, interval, peer_uid),
            Request::CgroupProcs { path } => self.handle_observer_cgroup_procs(&path),
            Request::MoveProcess { pid, cgroup_name } => {
                self.handle_observer_move_process(pid, cgroup_name, peer_uid)
            }
            Request::ClearRefs { pid, value } => {
                self.handle_observer_clear_refs(pid, &value, peer_uid)
            }
            Request::FreezeProcess { pid, freeze } => {
                self.handle_observer_freeze_process(pid, freeze, peer_uid)
            }
            Request::FreezeCgroup { path, freeze } => {
                self.handle_observer_freeze_cgroup(&path, freeze, peer_uid)
            }
            // Job scheduling requests are handled by the JobScheduler, not the main Daemon service manager
            Request::ScheduleJob { .. }
            | Request::CancelJob { .. }
            | Request::EnqueueWork { .. }
            | Request::ListJobs
            | Request::JobFinished { .. }
            | Request::Event { .. } => Response::err(
                "Job scheduling requests are not handled directly by the daemon socket yet.",
            ),
        }
    }

    /// Handle a control request that carries one or more Unix file descriptors.
    pub async fn handle_request_with_fds(
        &self,
        request: Request,
        fds: Vec<OwnedFd>,
        peer_uid: u32,
        peer_gid: u32,
    ) -> Response {
        if fds.is_empty() {
            return Response::err("request is missing passed file descriptors");
        }

        match request {
            Request::StartTerminal {
                name,
                home,
                uid,
                gid,
                pty,
                env,
                context,
                command,
                ..
            } => self.handle_start_terminal(
                &name, &home, uid, gid, pty, env, context, command, fds, peer_uid, peer_gid,
            ),
            Request::RegisterNamespace {
                name,
                kind,
                target_pid,
            } => {
                if fds.len() != 1 {
                    return Response::err(format!(
                        "register_namespace expected 1 fd, got {}",
                        fds.len()
                    ));
                }
                let fd = fds.into_iter().next().expect("one fd");
                self.handle_register_namespace(&name, kind, target_pid, fd, peer_uid, peer_gid)
            }
            _ => Response::err("request does not accept passed file descriptors"),
        }
    }

    /// Handle a control request that carries one Unix file descriptor.
    pub async fn handle_request_with_fd(
        &self,
        request: Request,
        fd: OwnedFd,
        peer_uid: u32,
        peer_gid: u32,
    ) -> Response {
        self.handle_request_with_fds(request, vec![fd], peer_uid, peer_gid)
            .await
    }

    // ========================================================================
    // Request Handlers
    // ========================================================================

    fn handle_register_namespace(
        &self,
        name: &str,
        kind: NamespaceKind,
        target_pid: Option<u32>,
        fd: OwnedFd,
        peer_uid: u32,
        peer_gid: u32,
    ) -> Response {
        if let Err(reason) = crate::config::validate_cgroup_name(name) {
            return Response::err(format!("invalid service name: {reason}"));
        }

        let attach = {
            let mut services = self.services.lock();
            let Some(proc) = services.get_mut(name) else {
                return Response::err(format!("service '{}' not found", name));
            };
            if proc.pid.is_none() {
                return Response::err(format!("service '{}' is not running", name));
            }
            if let Err(resp) = check_impersonation(
                peer_uid,
                peer_gid,
                proc.config.uid.unwrap_or(peer_uid),
                proc.config.gid,
                name,
            ) {
                return resp;
            }

            let fd_num = fd.as_raw_fd();
            match kind {
                NamespaceKind::Net => {
                    proc.netns_fd = Some(fd);
                    proc.namespace_pid = target_pid.or(proc.namespace_pid);
                    proc.mesh_tun_attached = false;
                    info!(
                        fd = fd_num,
                        service = %name,
                        peer_uid,
                        "netns_registered"
                    );
                }
                NamespaceKind::User => {
                    proc.userns_fd = Some(fd);
                    proc.namespace_pid = target_pid.or(proc.namespace_pid);
                    proc.mesh_tun_attached = false;
                    info!(
                        fd = fd_num,
                        service = %name,
                        peer_uid,
                        "userns_registered"
                    );
                }
            }

            if proc.config.network.backend == mesh::config::NetworkBackend::MeshTun
                && proc.netns_fd.is_some()
                && !proc.mesh_tun_attached
            {
                let service_pid = proc.namespace_pid.or(proc.pid).expect("checked running");
                let userns_path = proc
                    .userns_fd
                    .as_ref()
                    .map(|_| format!("/proc/{service_pid}/ns/user"));
                Some((
                    proc.config.name.clone(),
                    proc.config.network.clone(),
                    format!("/proc/{service_pid}/ns/net"),
                    userns_path,
                ))
            } else {
                None
            }
        };

        if let Some((service_name, network, netns_path, userns_path)) = attach {
            if let Err(error) = crate::network::attach_mesh_tun(
                &service_name,
                &network,
                &netns_path,
                userns_path.as_deref(),
            ) {
                return Response::err(error.to_string());
            }
            if let Some(proc) = self.services.lock().get_mut(name) {
                proc.mesh_tun_attached = true;
            }
        }

        Response::ok_with_data(serde_json::json!({
            "name": name,
            "kind": kind,
            "registered": true
        }))
    }

    async fn handle_start(
        &self,
        name: &str,
        extra_args: Vec<String>,
        extra_env: HashMap<String, String>,
        context: Option<ActivationContext>,
        peer_uid: u32,
        peer_gid: u32,
    ) -> Response {
        self.start_request_impl(name, extra_args, extra_env, context, peer_uid, peer_gid)
            .await
    }

    async fn start_request_impl(
        &self,
        name: &str,
        extra_args: Vec<String>,
        mut extra_env: HashMap<String, String>,
        context: Option<ActivationContext>,
        peer_uid: u32,
        peer_gid: u32,
    ) -> Response {
        // Reject names that could escape the config/cgroup directories.
        if let Err(reason) = crate::config::validate_cgroup_name(name) {
            return Response::err(format!("invalid service name: {reason}"));
        }
        // Authorization: a non-privileged peer may only start services whose
        // config uid matches its own. Privileged UIDs may start any service.
        {
            let configs = self.configs.lock();
            if let Some(cfg) = configs.get(name) {
                if let Err(resp) = check_impersonation(
                    peer_uid,
                    peer_gid,
                    cfg.uid.unwrap_or(peer_uid),
                    cfg.gid,
                    name,
                ) {
                    return resp;
                }
            }
        }
        // Attempt to reload the config from disk before checking state
        let mut config = {
            let mut configs = self.configs.lock();
            // If we have a source path, reload it
            if let Some(cfg) = configs.get(name) {
                if let Some(path) = &cfg.source_path {
                    let source_path = std::path::PathBuf::from(path);
                    let on_demand_candidates = config::on_demand_config_candidates(name);
                    let is_on_demand = on_demand_candidates.contains(&source_path);
                    let reload_path = if is_on_demand {
                        config::select_on_demand_config(name).unwrap_or(source_path)
                    } else {
                        source_path
                    };
                    match config::load_app_config(&reload_path) {
                        Ok(mut new_cfg) => {
                            if is_on_demand && unsafe { libc::getuid() } == 0 {
                                match config::resolve_or_create_app_identity(name) {
                                    Ok(identity) => {
                                        new_cfg.uid = Some(identity.uid);
                                        new_cfg.gid = Some(identity.gid);
                                    }
                                    Err(e) => {
                                        return Response::err(format!(
                                            "failed to resolve app identity for '{}': {}",
                                            name, e
                                        ));
                                    }
                                }
                                new_cfg.user = None;
                                new_cfg.group = None;
                            }
                            debug!(
                                service = %name,
                                path = %reload_path.display(),
                                "config_reloaded"
                            );
                            configs.insert(name.to_string(), new_cfg.clone());
                            new_cfg
                        }
                        Err(e) => {
                            warn!(service = %name, error = %e, "reload_config_failed_using_cached");
                            cfg.clone()
                        }
                    }
                } else {
                    cfg.clone()
                }
            } else {
                if let Some(service_path) = config::select_on_demand_config(name) {
                    match config::load_app_config(&service_path) {
                        Ok(mut new_cfg) => {
                            // In root mode, app identity is owned by /home/<service>
                            // and persisted in /home/system/etc/uidmap when needed.
                            if unsafe { libc::getuid() } == 0 {
                                match config::resolve_or_create_app_identity(name) {
                                    Ok(identity) => {
                                        new_cfg.uid = Some(identity.uid);
                                        new_cfg.gid = Some(identity.gid);
                                    }
                                    Err(e) => {
                                        return Response::err(format!(
                                            "failed to resolve app identity for '{}': {}",
                                            name, e
                                        ));
                                    }
                                }
                                new_cfg.user = None;
                                new_cfg.group = None;
                            }

                            info!(
                                service = %name,
                                path = %service_path.display(),
                                "on_demand_config_loaded"
                            );
                            configs.insert(name.to_string(), new_cfg.clone());
                            new_cfg
                        }
                        Err(e) => {
                            return Response::err(format!(
                                "failed to load user config for '{}': {}",
                                name, e
                            ));
                        }
                    }
                } else {
                    return Response::err(format!("no config found for service '{}'", name));
                }
            }
        };

        // A5: Re-check authorization against the freshly loaded/reloaded config.
        // The config was just reloaded from disk (or loaded for the first time
        // from USER_INIT). Its `uid` may differ from the cached copy used for
        // the initial auth check above. A non-privileged peer must not benefit
        // from a config that resolves to a different UID.
        if let Err(resp) = check_impersonation(
            peer_uid,
            peer_gid,
            config.uid.unwrap_or(peer_uid),
            config.gid,
            name,
        ) {
            return resp;
        }

        // Determine if already running and if config changed
        let mut should_restart = false;
        {
            let services = self.services.lock();
            if let Some(proc) = services.get(name)
                && proc.protocol_state() == ServiceState::Running
            {
                if proc.config != config {
                    info!(service = %name, "config_changed_will_restart");
                    should_restart = true;
                } else {
                    return Response::ok_with_data(
                        serde_json::json!({"pid": proc.pid, "already_running": true}),
                    );
                }
            }
        }

        // If running but config changed, restart it by updating the config in place,
        // sending SIGTERM, and letting the restart loop bring it back with the new config.
        if should_restart {
            let maybe_pid = {
                let mut services = self.services.lock();
                if let Some(proc) = services.get_mut(name) {
                    proc.config = config.clone();
                    let _ = states::transition(
                        proc,
                        states::LifecycleEvent::StopRequested {
                            initiator: states::StopInitiator::Requested,
                        },
                    );
                    // Config change restart: keep the service wanted Running.
                    proc.target_state = states::ServiceState::Running;
                    proc.stop_reason = None;
                    // Don't change target_state so it restarts
                    proc.consecutive_failures = 0;
                    proc.next_restart_at = None;
                    proc.pid
                } else {
                    None
                }
            };
            if let Some(pid) = maybe_pid {
                let _ = process::send_signal(pid, libc::SIGTERM);
                return Response::ok_with_data(serde_json::json!({"restarting": true}));
            }
        }

        // Merge extra args and caller env.
        config.args.extend(extra_args);
        scrub_dangerous_env(&mut extra_env, &config);
        config.env.extend(extra_env);
        apply_activation_context_env(&mut config, context);

        // Phase 1: a frozen or freezing service is woken, never respawned.
        let state_probe = {
            let services = self.services.lock();
            services.get(name).map(|p| p.state)
        };
        if matches!(
            state_probe,
            Some(states::ServiceState::Frozen { .. }) | Some(states::ServiceState::Freezing { .. })
        ) {
            return match self.ensure_running(name, Some(config), None).await {
                Ok(outcome) => Response::ok_with_data(serde_json::json!({
                    "pid": ensure_outcome_pid(&outcome),
                    "outcome": ensure_outcome_label(&outcome),
                })),
                Err(e) => Response::err(e.to_string()),
            };
        }

        // Check resource availability
        if let Some(ref rm) = self.resource_manager
            && !rm.can_start(&config)
        {
            return Response::err("insufficient resources to start service");
        }

        {
            let mut services = self.services.lock();
            if let Some(proc) = services.get_mut(name) {
                proc.consecutive_failures = 0;
            }
        }

        match self.start_service_with_config(config, None) {
            Ok(pid) => Response::ok_with_data(serde_json::json!({"pid": pid})),
            Err(e) => Response::err(e.to_string()),
        }
    }

    fn handle_start_terminal(
        &self,
        name: &str,
        home: &str,
        uid: u32,
        gid: Option<u32>,
        pty: bool,
        mut extra_env: HashMap<String, String>,
        context: Option<ActivationContext>,
        command: Option<String>,
        mut fds: Vec<OwnedFd>,
        peer_uid: u32,
        peer_gid: u32,
    ) -> Response {
        if let Err(reason) = crate::config::validate_cgroup_name(name) {
            return Response::err(format!("invalid service name: {reason}"));
        }
        // Authorization: a non-privileged peer may only spawn processes as
        // itself. Privileged UIDs (root, system, sshd — see `privileged_uids`)
        // may target any UID. This prevents privilege escalation where an
        // authorized non-privileged peer requests uid=0.
        if let Err(resp) = check_impersonation(peer_uid, peer_gid, uid, gid, name) {
            return resp;
        }
        let home_path = std::path::Path::new(home);
        if !home_path.is_dir() {
            return Response::err(format!("home directory '{}' does not exist", home));
        }
        // A16: Validate that the home directory is owned by the target
        // UID. Otherwise a privileged ssh-mesh peer could set HOME
        // to any directory, influencing the child's startup scripts.
        if let Ok(metadata) = std::fs::metadata(home_path) {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != uid {
                return Response::err(format!(
                    "home directory '{}' is owned by UID {}, not the target UID {}",
                    home,
                    metadata.uid(),
                    uid
                ));
            }
        }

        let mut config = {
            let configs = self.configs.lock();
            configs.get(name).cloned()
        }
        .unwrap_or_else(|| {
            let current_uid = unsafe { libc::getuid() };
            let current_gid = unsafe { libc::getgid() };
            let run_as_uid = if current_uid == 0 { uid } else { current_uid };
            let run_as_gid = if current_uid == 0 {
                gid.unwrap_or(uid)
            } else {
                current_gid
            };

            let mut env = HashMap::new();
            env.insert("HOME".to_string(), home.to_string());
            env.insert("USER".to_string(), name.to_string());
            env.insert("LOGNAME".to_string(), name.to_string());
            let shell = preferred_shell();
            env.insert("SHELL".to_string(), shell.to_string());
            env.insert("TERM".to_string(), "xterm-256color".to_string());

            AppConfig {
                name: name.to_string(),
                command: shell.to_string(),
                args: vec!["-l".to_string()],
                uid: Some(run_as_uid),
                gid: Some(run_as_gid),
                user: None,
                group: None,
                env,
                oneshot: true,
                ..Default::default()
            }
        });

        if config.uid.is_none() {
            config.uid = Some(if unsafe { libc::getuid() } == 0 {
                uid
            } else {
                unsafe { libc::getuid() }
            });
        }
        if config.gid.is_none() {
            config.gid = Some(if unsafe { libc::getuid() } == 0 {
                gid.unwrap_or(uid)
            } else {
                unsafe { libc::getgid() }
            });
        }
        config
            .env
            .entry("HOME".to_string())
            .or_insert_with(|| home.to_string());
        config
            .env
            .entry("USER".to_string())
            .or_insert_with(|| name.to_string());
        config
            .env
            .entry("LOGNAME".to_string())
            .or_insert_with(|| name.to_string());
        scrub_dangerous_env(&mut extra_env, &config);
        config.env.extend(extra_env);
        apply_activation_context_env(&mut config, context);

        if let Some(command) = command {
            config.command = preferred_shell().to_string();
            config.args = vec!["-c".to_string(), command];
            config.oneshot = true;
        }

        // Final authorization guard on the resolved config. The config file
        // may have specified a uid different from the request; a non-privileged
        // peer must not benefit from that.
        if let Err(resp) = check_impersonation(
            peer_uid,
            peer_gid,
            config.uid.unwrap_or(peer_uid),
            config.gid,
            name,
        ) {
            return resp;
        }

        let cg =
            crate::cgroup::create_cgroup(name).unwrap_or_else(|_| "/sys/fs/cgroup".to_string());
        let (retained_pty, activation_fd) = if pty {
            if fds.len() != 1 {
                return Response::err(format!("pty terminal expected 1 fd, got {}", fds.len()));
            }
            let fd = fds.pop().expect("one fd");
            let retained_pty = match fd.try_clone() {
                Ok(fd) => Some(fd),
                Err(e) => return Response::err(format!("failed to retain PTY fd: {}", e)),
            };
            (retained_pty, process::ActivationFd::Pty(fd))
        } else if fds.len() == 1 {
            (
                None,
                process::ActivationFd::Stdio(fds.pop().expect("one fd")),
            )
        } else if fds.len() == 3 {
            let stderr = fds.pop().expect("stderr fd");
            let stdout = fds.pop().expect("stdout fd");
            let stdin = fds.pop().expect("stdin fd");
            (
                None,
                process::ActivationFd::StdioPipes {
                    stdin,
                    stdout,
                    stderr,
                },
            )
        } else {
            return Response::err(format!(
                "stdio terminal expected 1 or 3 fds, got {}",
                fds.len()
            ));
        };

        match process::spawn_process(&config, &cg, Some(activation_fd)) {
            Ok((pid, _)) => {
                if let Some(ref tracked) = *self.tracked_child_pids.lock() {
                    tracked.lock().insert(pid);
                }
                let terminal_id = format!(
                    "term-{}",
                    self.next_terminal_id.fetch_add(1, Ordering::Relaxed)
                );
                self.terminal_sessions.lock().insert(
                    terminal_id.clone(),
                    TerminalSession {
                        name: name.to_string(),
                        pid,
                        pty_fd: retained_pty,
                        pidfd: process::open_pidfd(pid).ok(),
                    },
                );
                Response::ok_with_data(serde_json::json!({
                    "pid": pid,
                    "terminal_id": terminal_id
                }))
            }
            Err(e) => Response::err(e.to_string()),
        }
    }

    fn handle_terminal_resize(
        &self,
        terminal_id: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    ) -> Response {
        let terminals = self.terminal_sessions.lock();
        let Some(session) = terminals.get(terminal_id) else {
            return Response::err(format!("terminal session '{}' not found", terminal_id));
        };
        let Some(fd) = session.pty_fd.as_ref() else {
            return Response::err(format!("terminal session '{}' has no PTY", terminal_id));
        };

        let mut winsize = libc::winsize {
            ws_row: row_height as u16,
            ws_col: col_width as u16,
            ws_xpixel: pix_width as u16,
            ws_ypixel: pix_height as u16,
        };
        let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &mut winsize) };
        if rc < 0 {
            return Response::err(format!(
                "failed to resize terminal '{}': {}",
                terminal_id,
                std::io::Error::last_os_error()
            ));
        }

        Response::ok_with_data(serde_json::json!({"terminal_id": terminal_id}))
    }

    fn handle_terminal_command(
        &self,
        terminal_id: &str,
        command: &str,
        data: serde_json::Value,
    ) -> Response {
        let signal = match command {
            "close" | "hup" => Some(libc::SIGHUP),
            "signal" => data
                .get("signal")
                .and_then(serde_json::Value::as_i64)
                .map(|signal| signal as i32),
            _ => {
                return Response::err(format!(
                    "unsupported terminal command '{}' for '{}'",
                    command, terminal_id
                ));
            }
        };

        let Some(signal) = signal else {
            return Response::err(format!(
                "terminal command '{}' for '{}' requires a signal",
                command, terminal_id
            ));
        };

        let (pid, pidfd) = {
            let mut terminals = self.terminal_sessions.lock();
            let Some(session) = terminals.get_mut(terminal_id) else {
                return Response::err(format!("terminal session '{}' not found", terminal_id));
            };
            (session.pid, session.pidfd.take())
        };

        match process::send_signal_pidfd(pidfd.as_ref(), pid, signal) {
            Ok(()) => Response::ok_with_data(serde_json::json!({
                "terminal_id": terminal_id,
                "pid": pid,
                "signal": signal
            })),
            Err(e) => Response::err(e.to_string()),
        }
    }

    fn prepare_activation_context(&self, name: String, context: ActivationContext) -> Response {
        let mut pending = self.pending_activation_contexts.lock();
        // Enforce a global cap across all services to prevent unbounded
        // HashMap growth from a peer creating contexts under many distinct
        // service names.
        const MAX_TOTAL_PENDING_CONTEXTS: usize = 1024;
        let total: usize = pending.values().map(|q| q.len()).sum();
        if total >= MAX_TOTAL_PENDING_CONTEXTS {
            warn!(
                service = %name,
                cap = MAX_TOTAL_PENDING_CONTEXTS,
                "activation_context_refused_at_cap"
            );
            return Response::err(format!(
                "pending activation context cap of {MAX_TOTAL_PENDING_CONTEXTS} reached"
            ));
        }
        let queue = pending.entry(name).or_default();
        queue.push_back(context);
        while queue.len() > 32 {
            queue.pop_front();
        }
        Response::ok()
    }

    pub fn take_activation_context(&self, name: &str) -> Option<ActivationContext> {
        let mut pending = self.pending_activation_contexts.lock();
        let context = pending.get_mut(name).and_then(VecDeque::pop_front);
        if pending.get(name).is_some_and(VecDeque::is_empty) {
            pending.remove(name);
        }
        context
    }

    /// Run the prepare-freeze handshake (phase 2c) and freeze on `ready`.
    ///
    /// Returns the freeze epoch when the service is now Frozen{Idle}.
    async fn freeze_for_idle(&self, name: &str) -> Result<Option<u64>> {
        self.freeze_for_idle_with(name, CONFIRM_FREEZE_TIMEOUT)
            .await
    }

    /// Test-tunable variant of [`Self::freeze_for_idle`].
    async fn freeze_for_idle_with(&self, name: &str, timeout: Duration) -> Result<Option<u64>> {
        let epoch_and_config = {
            let mut services = self.services.lock();
            let Some(proc) = services.get_mut(name) else {
                anyhow::bail!("service '{}' not found", name);
            };
            let epoch = states::next_epoch(proc.freeze_ack);
            let effects = states::transition(
                proc,
                states::LifecycleEvent::Freeze {
                    reason: FreezeReason::Idle,
                    epoch,
                },
            );
            if !states::is_freezing(proc) {
                return Err(anyhow::anyhow!(
                    "service '{}' is not freezable in state {:?}",
                    name,
                    proc.protocol_state()
                ));
            }
            let _ = effects;
            (epoch, proc.config.clone())
        };

        let socket = lifecycle_socket(&epoch_and_config.1);
        let handshake = match socket {
            Some(socket) => {
                mesh::lifecycle::notify(
                    &socket,
                    &mesh::lifecycle::LifecycleEvent {
                        action: mesh::lifecycle::LifecycleAction::PrepareFreeze {
                            epoch: epoch_and_config.0,
                        },
                        cause: mesh::lifecycle::LifecycleCause::Idle,
                        observed: false,
                    },
                )
                .await
            }
            None => Err(anyhow::anyhow!("no mesh lifecycle socket")),
        };

        match handshake {
            Ok(reply)
                if reply.success
                    && reply.reply == Some(mesh::lifecycle::FreezeRequestReply::Ready) =>
            {
                let confirmed = {
                    let mut services = self.services.lock();
                    let Some(proc) = services.get_mut(name) else {
                        anyhow::bail!("service '{}' vanished during handshake", name);
                    };
                    let Some(cg) = proc.cgroup_path.clone() else {
                        states::transition(proc, states::LifecycleEvent::FreezeCancelled);
                        return Ok(None);
                    };
                    // Guard: the service is still the one we prepared.
                    if !states::is_freezing(proc) {
                        return Ok(None);
                    }
                    match process::freeze_cgroup_confirmed(&cg, timeout) {
                        Ok(()) => {
                            proc.freeze_ack = Some(epoch_and_config.0);
                            states::transition(proc, states::LifecycleEvent::FrozenConfirmed);
                            true
                        }
                        Err(e) => {
                            states::transition(proc, states::LifecycleEvent::FreezeCancelled);
                            return Err(anyhow::anyhow!("freeze failed: {e}"));
                        }
                    }
                };
                if confirmed {
                    info!(service = %name, epoch = epoch_and_config.0, "service_frozen_idle");
                    Ok(Some(epoch_and_config.0))
                } else {
                    Ok(None)
                }
            }
            Ok(reply) => {
                // busy, or a service without handshake support: cancel.
                debug!(
                    service = %name,
                    reply = ?reply.reply,
                    error = ?reply.error,
                    "idle_freeze_cancelled"
                );
                let mut services = self.services.lock();
                if let Some(proc) = services.get_mut(name) {
                    states::transition(
                        proc,
                        states::LifecycleEvent::Unfreeze {
                            cause: states::UnfreezeCause::Activity,
                        },
                    );
                }
                Ok(None)
            }
            Err(error) => {
                debug!(
                    service = %name,
                    error = %error,
                    "idle_freeze_handshake_failed"
                );
                let mut services = self.services.lock();
                if let Some(proc) = services.get_mut(name) {
                    states::transition(
                        proc,
                        states::LifecycleEvent::Unfreeze {
                            cause: states::UnfreezeCause::Activity,
                        },
                    );
                }
                Ok(None)
            }
        }
    }

    /// Thaw a frozen service and notify it (phase 2c wake path).
    async fn thaw_service(&self, name: &str, cause: states::UnfreezeCause) {
        let (config, cg) = {
            let mut services = self.services.lock();
            let Some(proc) = services.get_mut(name) else {
                return;
            };
            let effects = states::transition(proc, states::LifecycleEvent::Unfreeze { cause });
            if effects.is_empty() {
                return;
            }
            let cg = proc.cgroup_path.clone();
            // Frozen time is not service execution time.
            let now = Instant::now();
            proc.last_watchdog_ping = Some(now);
            proc.last_stderr_at = Some(now);
            proc.idle_since = None;
            (proc.config.clone(), cg)
        };
        if let Some(cg) = cg {
            let _ = process::unfreeze_cgroup(&cg);
        }
        self.wake_scheduler();
        if let Some(socket) = lifecycle_socket(&config) {
            let _ = mesh::lifecycle::notify(
                &socket,
                &mesh::lifecycle::LifecycleEvent {
                    action: mesh::lifecycle::LifecycleAction::Unfreeze,
                    cause: match cause {
                        states::UnfreezeCause::Requested => {
                            mesh::lifecycle::LifecycleCause::Requested
                        }
                        states::UnfreezeCause::Activity => {
                            mesh::lifecycle::LifecycleCause::Activity
                        }
                        states::UnfreezeCause::PressureCleared => {
                            mesh::lifecycle::LifecycleCause::Pressure
                        }
                    },
                    observed: false,
                },
            )
            .await;
        }
        info!(service = %name, "service_unfrozen");
    }

    /// Internal stop used by idle and pressure policies (no peer auth).
    async fn stop_service_internal(&self, name: &str, initiator: states::StopInitiator) {
        let (pid, pidfd, config, cg) = {
            let mut services = self.services.lock();
            let Some(proc) = services.get_mut(name) else {
                return;
            };
            let _ = states::transition(proc, states::LifecycleEvent::StopRequested { initiator });
            proc.netns_fd = None;
            proc.userns_fd = None;
            proc.namespace_pid = None;
            proc.mesh_tun_attached = false;
            proc.stopping_since = proc.stopping_deadline();
            let mutate_pid = proc.pid;
            let mutate_pidfd = proc.pidfd.take();
            let cg = if proc.protocol_state() == ServiceState::Frozen {
                proc.cgroup_path.clone()
            } else {
                None
            };
            (mutate_pid, mutate_pidfd, proc.config.clone(), cg)
        };
        // Thaw first when frozen.
        if let Some(cg) = cg {
            let _ = process::unfreeze_cgroup(&cg);
        }
        if let Some(socket) = lifecycle_socket(&config) {
            let _ = mesh::lifecycle::notify(
                &socket,
                &mesh::lifecycle::LifecycleEvent {
                    action: mesh::lifecycle::LifecycleAction::Stop,
                    cause: match initiator {
                        states::StopInitiator::Requested => {
                            mesh::lifecycle::LifecycleCause::Requested
                        }
                        states::StopInitiator::Idle => mesh::lifecycle::LifecycleCause::Idle,
                        states::StopInitiator::Evicted => mesh::lifecycle::LifecycleCause::Pressure,
                    },
                    observed: false,
                },
            )
            .await;
        }
        if let Some(pid) = pid {
            let _ = process::stop_process(
                pid,
                pidfd.as_ref(),
                Some(config.kill_signal),
                config.timeout_stop_sec,
                config.send_sigkill,
            )
            .await;
        }
        {
            let mut services = self.services.lock();
            if let Some(proc) = services.get_mut(name) {
                states::transition(proc, states::LifecycleEvent::Exited { intentional: true });
                proc.state = states::ServiceState::Stopped;
                proc.network_pid = None;
            }
        }
        self.notify_service_exit(name);
    }

    async fn handle_stop(
        &self,
        name: &str,
        signal: Option<i32>,
        peer_uid: u32,
        peer_gid: u32,
    ) -> Response {
        if let Err(reason) = crate::config::validate_cgroup_name(name) {
            return Response::err(format!("invalid service name: {reason}"));
        }
        let (pid, network_pid, pidfd, config) = {
            let mut services = self.services.lock();
            match services.get_mut(name) {
                Some(proc)
                    if matches!(
                        proc.protocol_state(),
                        ServiceState::Running | ServiceState::Frozen
                    ) =>
                {
                    // Authorization: a non-privileged peer may only stop
                    // services running as its own UID.
                    let svc_uid = proc.config.uid.unwrap_or(peer_uid);
                    let svc_gid = proc.config.gid;
                    if let Err(resp) =
                        check_impersonation(peer_uid, peer_gid, svc_uid, svc_gid, name)
                    {
                        return resp;
                    }
                    // Thaw first: stopping a frozen cgroup needs a live child.
                    let mut effects = vec![];
                    if matches!(proc.protocol_state(), ServiceState::Frozen) {
                        effects = states::transition(
                            proc,
                            states::LifecycleEvent::Unfreeze {
                                cause: states::UnfreezeCause::Requested,
                            },
                        );
                        for effect in &effects {
                            if matches!(effect, states::Effect::UnfreezeCgroup)
                                && let Some(cg) = proc.cgroup_path.clone()
                            {
                                let _ = process::unfreeze_cgroup(&cg);
                            }
                        }
                    }
                    let _ = states::transition(
                        proc,
                        states::LifecycleEvent::StopRequested {
                            initiator: states::StopInitiator::Requested,
                        },
                    );
                    proc.netns_fd = None;
                    proc.userns_fd = None;
                    proc.namespace_pid = None;
                    proc.mesh_tun_attached = false;
                    proc.stopping_since = proc.stopping_deadline();
                    let pidfd = proc.pidfd.take();
                    (proc.pid, proc.network_pid, pidfd, proc.config.clone())
                }
                Some(_) => return Response::err(format!("service '{}' is not running", name)),
                None => return Response::err(format!("service '{}' not found", name)),
            }
        };

        if let Err(e) = run_service_commands(
            &config,
            &config.exec_stop,
            "ExecStop",
            config.timeout_stop_sec,
        ) {
            error!(service = %name, error = %e, "exec_stop_failed");
            return Response::err(e.to_string());
        }

        if let Some(network_pid) = network_pid {
            let _ = process::send_signal(network_pid, libc::SIGTERM);
        }
        if let Some(pid) = pid
            && config.kill_mode != crate::config::KillMode::None
            && let Err(e) = process::stop_process(
                pid,
                pidfd.as_ref(),
                signal.or(Some(config.kill_signal)),
                config.timeout_stop_sec,
                config.send_sigkill,
            )
            .await
        {
            error!(service = %name, error = %e, "stop_service_failed");
            return Response::err(e.to_string());
        }

        // Update state
        {
            let mut services = self.services.lock();
            if let Some(proc) = services.get_mut(name) {
                states::transition(proc, states::LifecycleEvent::Exited { intentional: true });
                proc.state = states::ServiceState::Stopped;
                proc.network_pid = None;
                proc.netns_fd = None;
                proc.userns_fd = None;
                proc.namespace_pid = None;
                proc.mesh_tun_attached = false;
            }
        }
        self.notify_service_exit(name);

        info!(service = %name, "service_stopped");
        Response::ok()
    }

    async fn handle_freeze(
        &self,
        name: &str,
        requested_reason: Option<String>,
        peer_uid: u32,
        peer_gid: u32,
    ) -> Response {
        if let Err(reason) = crate::config::validate_cgroup_name(name) {
            return Response::err(format!("invalid service name: {reason}"));
        }
        let config = {
            let services = self.services.lock();
            let proc = match services.get(name) {
                Some(p) if p.protocol_state() == ServiceState::Running => p,
                Some(_) => return Response::err(format!("service '{}' is not running", name)),
                None => return Response::err(format!("service '{}' not found", name)),
            };
            // Authorization: a non-privileged peer may only freeze services
            // running as its own UID.
            let svc_uid = proc.config.uid.unwrap_or(peer_uid);
            let svc_gid = proc.config.gid;
            if let Err(resp) = check_impersonation(peer_uid, peer_gid, svc_uid, svc_gid, name) {
                return resp;
            }
            // Phase 1: freezing without a cgroup is refused; there is no
            // SIGSTOP fallback because a stopped process breaks the socket
            // wake-up guarantees the rest of the lifecycle relies on.
            if proc.cgroup_path.is_none() {
                return Response::err(format!(
                    "service '{}' has no cgroup; freeze is refused",
                    name
                ));
            }
            proc.config.clone()
        };

        let epoch = {
            let mut services = self.services.lock();
            let Some(proc) = services.get_mut(name) else {
                return Response::err(format!("service '{}' not found", name));
            };
            let epoch = states::next_epoch(proc.freeze_ack);
            let effects = states::transition(
                proc,
                states::LifecycleEvent::Freeze {
                    reason: freeze_reason(requested_reason),
                    epoch,
                },
            );
            if effects.is_empty() && states::is_freezing(proc) {
                epoch
            } else if proc.protocol_state() == ServiceState::Running {
                // Freeze rejected by the state model.
                0
            } else {
                epoch
            }
        };

        let _ = notify_lifecycle(
            &config,
            mesh::lifecycle::LifecycleEvent {
                action: mesh::lifecycle::LifecycleAction::Freeze,
                cause: mesh::lifecycle::LifecycleCause::Requested,
                observed: false,
            },
        )
        .await;

        let freeze_result: Result<(), String> = {
            let mut services = self.services.lock();
            match services.get_mut(name) {
                Some(proc) if states::is_freezing(proc) && proc.cgroup_path.is_some() => {
                    let cg = proc.cgroup_path.clone().expect("cgroup checked");
                    match process::freeze_cgroup_confirmed(&cg, CONFIRM_FREEZE_TIMEOUT) {
                        Ok(()) => {
                            states::transition(proc, states::LifecycleEvent::FrozenConfirmed);
                            info!(service = %name, "service_frozen");
                            Ok(())
                        }
                        Err(e) => {
                            states::transition(proc, states::LifecycleEvent::FreezeCancelled);
                            Err(e.to_string())
                        }
                    }
                }
                Some(_) => Err(format!("service '{}' is no longer freezing", name)),
                None => Err(format!("service '{}' not found", name)),
            }
        };

        if let Err(e) = freeze_result {
            // The application already prepared for a freeze. Pair that event
            // even when the process exits in the race window or freezing the
            // cgroup fails, so it can undo its preparation.
            let _ = notify_lifecycle(
                &config,
                mesh::lifecycle::LifecycleEvent {
                    action: mesh::lifecycle::LifecycleAction::Unfreeze,
                    cause: mesh::lifecycle::LifecycleCause::Requested,
                    observed: false,
                },
            )
            .await;
            return Response::err(e.to_string());
        }

        let _ = epoch;
        Response::ok()
    }

    async fn handle_unfreeze(&self, name: &str, peer_uid: u32, peer_gid: u32) -> Response {
        if let Err(reason) = crate::config::validate_cgroup_name(name) {
            return Response::err(format!("invalid service name: {reason}"));
        }
        let config = {
            let mut services = self.services.lock();
            let proc = match services.get_mut(name) {
                // A pending freeze can be cancelled by unfreeze.
                Some(p) if states::is_freezing(p) || p.protocol_state() == ServiceState::Frozen => {
                    if states::is_freezing(p) {
                        states::transition(p, states::LifecycleEvent::FreezeCancelled);
                    }
                    p
                }
                Some(_) => return Response::err(format!("service '{}' is not frozen", name)),
                None => return Response::err(format!("service '{}' not found", name)),
            };
            // Authorization: a non-privileged peer may only unfreeze services
            // running as its own UID.
            let svc_uid = proc.config.uid.unwrap_or(peer_uid);
            let svc_gid = proc.config.gid;
            if let Err(resp) = check_impersonation(peer_uid, peer_gid, svc_uid, svc_gid, name) {
                return resp;
            }

            let config = proc.config.clone();
            if proc.pid.is_some() {
                if let Some(cg) = proc.cgroup_path.clone() {
                    if let Err(e) = process::unfreeze_cgroup(&cg) {
                        return Response::err(e.to_string());
                    }
                }
                states::transition(
                    proc,
                    states::LifecycleEvent::Unfreeze {
                        cause: states::UnfreezeCause::Requested,
                    },
                );
                // Frozen time is not service execution time. Give watchdog
                // and idle policies a fresh interval for application resume
                // work instead of immediately expiring an old deadline.
                let now = std::time::Instant::now();
                proc.last_watchdog_ping = Some(now);
                proc.last_stderr_at = Some(now);
                proc.idle_since = None;
                info!(service = %name, "service_unfrozen");
            }
            config
        };
        self.wake_scheduler();

        let _ = notify_lifecycle(
            &config,
            mesh::lifecycle::LifecycleEvent {
                action: mesh::lifecycle::LifecycleAction::Unfreeze,
                cause: mesh::lifecycle::LifecycleCause::Requested,
                observed: false,
            },
        )
        .await;

        Response::ok()
    }

    fn handle_status(&self, name: Option<&str>) -> Response {
        let services = self.services.lock();

        match name {
            Some(name) => match services.get(name) {
                Some(proc) => {
                    let status = proc.status();
                    Response::ok_with_data(serde_json::to_value(status).unwrap_or_default())
                }
                None => Response::err(format!("service '{}' not found", name)),
            },
            None => {
                // All services
                let statuses: Vec<ServiceStatus> = services.values().map(|p| p.status()).collect();
                Response::ok_with_data(serde_json::to_value(statuses).unwrap_or_default())
            }
        }
    }

    fn handle_observer_processes(&self) -> Response {
        let processes = self.observer.get_all_processes(1);
        Response::ok_with_data(serde_json::json!(
            processes.into_values().collect::<Vec<_>>()
        ))
    }

    fn handle_observer_process(&self, pid: u32) -> Response {
        match self.observer.get_process(pid) {
            Some(process) => {
                let cgroup = process
                    .cgroup_path
                    .as_ref()
                    .and_then(|p| observer::read_cgroup_detailed(p));
                let parent_cgroups = process
                    .cgroup_path
                    .as_ref()
                    .map(|p| observer::get_parent_cgroups(p))
                    .unwrap_or_default();
                Response::ok_with_data(serde_json::json!(ProcessDetailedInfo {
                    process,
                    cgroup,
                    parent_cgroups,
                }))
            }
            None => Response::err(format!("process {pid} not found")),
        }
    }

    fn handle_observer_process_only(&self, pid: u32) -> Response {
        match self.observer.get_process(pid) {
            Some(process) => Response::ok_with_data(serde_json::json!(process)),
            None => Response::err(format!("process {pid} not found")),
        }
    }

    fn handle_observer_cgroups(&self) -> Response {
        Response::ok_with_data(serde_json::json!(self.observer.get_all_cgroups()))
    }

    fn handle_observer_cgroup(&self, path: &str) -> Response {
        match observer::read_cgroup_detailed(path) {
            Some(cgroup) => Response::ok_with_data(serde_json::json!(cgroup)),
            None => Response::err(format!("cgroup {path} not found")),
        }
    }

    fn handle_observer_pressure(&self) -> Response {
        Response::ok_with_data(serde_json::json!(self.observer.get_psi_watches()))
    }

    fn handle_observer_cgroup_high(
        &self,
        path: String,
        percentage: f64,
        interval: u64,
        peer_uid: u32,
    ) -> Response {
        if let Err(resp) = require_system_or_root(peer_uid) {
            return resp;
        }
        match self
            .observer
            .adjust_cgroup_memory_high(path, percentage, interval)
        {
            Ok(()) => Response::ok(),
            Err(e) => Response::err(e.to_string()),
        }
    }

    fn handle_observer_cgroup_procs(&self, path: &str) -> Response {
        Response::ok_with_data(serde_json::json!(
            self.observer.get_processes_in_cgroup(path)
        ))
    }

    fn handle_observer_move_process(
        &self,
        pid: u32,
        cgroup_name: Option<String>,
        peer_uid: u32,
    ) -> Response {
        if let Err(resp) = require_system_or_root(peer_uid) {
            return resp;
        }
        match self.observer.move_process_to_cgroup(pid, cgroup_name) {
            Ok(()) => Response::ok(),
            Err(e) => Response::err(e.to_string()),
        }
    }

    fn handle_observer_clear_refs(&self, pid: u32, value: &str, peer_uid: u32) -> Response {
        if let Err(resp) = require_system_or_root(peer_uid) {
            return resp;
        }
        match self.observer.clear_refs(pid, value) {
            Ok(()) => Response::ok_with_data(serde_json::json!({
                "message": format!("cleared refs for process {pid} with value {value}")
            })),
            Err(e) => Response::err(e.to_string()),
        }
    }

    fn handle_observer_freeze_process(&self, pid: u32, freeze: bool, peer_uid: u32) -> Response {
        if let Err(resp) = require_system_or_root(peer_uid) {
            return resp;
        }
        match self.observer.freeze_process(pid, freeze) {
            Ok(()) => Response::ok(),
            Err(e) => Response::err(e.to_string()),
        }
    }

    fn handle_observer_freeze_cgroup(&self, path: &str, freeze: bool, peer_uid: u32) -> Response {
        if let Err(resp) = require_system_or_root(peer_uid) {
            return resp;
        }
        match self.observer.freeze_cgroup(path, freeze) {
            Ok(()) => Response::ok(),
            Err(e) => Response::err(e.to_string()),
        }
    }

    async fn handle_shutdown(&self) -> Response {
        info!("shutdown_requested");
        self.shutdown().await;
        // Exit the process since the accept loop has no clean break mechanism
        std::process::exit(0);
    }

    fn handle_reload(&self) -> Response {
        info!("reloading_configurations");

        // Reload from disk
        let dirs: Vec<&str> = self.config.config_dirs.iter().map(|s| s.as_str()).collect();
        let loaded_configs = config::load_system_configs(&dirs);

        let mut changed = 0;
        let mut configs = self.configs.lock();
        let mut services = self.services.lock();
        let mut reload_commands = Vec::new();

        for new_cfg in loaded_configs {
            let name = new_cfg.name.clone();
            let is_changed = match configs.get(&name) {
                Some(old_cfg) => {
                    if *old_cfg == new_cfg {
                        if services
                            .get(&name)
                            .is_some_and(|proc| proc.protocol_state() == ServiceState::Running)
                        {
                            reload_commands.push(new_cfg.clone());
                        }
                        false
                    } else {
                        true
                    }
                }
                None => true,
            };

            if is_changed {
                info!(service = %name, "config_changed_or_new_during_reload");
                configs.insert(name.clone(), new_cfg.clone());
                changed += 1;

                // Stop active process so it restarts with new config
                if let Some(proc) = services.get_mut(&name)
                    && proc.protocol_state() == ServiceState::Running
                {
                    proc.config = new_cfg.clone();
                    let _ = states::transition(
                        proc,
                        states::LifecycleEvent::StopRequested {
                            initiator: states::StopInitiator::Requested,
                        },
                    );
                    // Keep target_state running so it gets restarted!
                    proc.target_state = states::ServiceState::Running;
                    proc.stop_reason = None;
                    proc.consecutive_failures = 0;
                    proc.next_restart_at = None;
                    if let Some(pid) = proc.pid {
                        let _ = process::send_signal(pid, libc::SIGTERM);
                    }
                }
            }
        }
        drop(services);
        drop(configs);

        for config in reload_commands {
            if let Err(e) = run_service_commands(
                &config,
                &config.exec_reload,
                "ExecReload",
                config.timeout_start_sec,
            ) {
                warn!(service = %config.name, error = %e, "exec_reload_failed");
            }
        }

        Response::ok_with_data(serde_json::json!({"reloaded": true, "changed": changed}))
    }

    // ========================================================================
    // Internal Helpers
    // ========================================================================

    fn handle_child_exit(&self, pid: u32, exit_code: i32) {
        crate::activation::reclaim_inetd_permit(pid);
        // A service that exits releases its notify channel.
        if let Some(name) = {
            let services = self.services.lock();
            services
                .iter()
                .find(|(_, p)| p.pid == Some(pid))
                .map(|(name, _)| name.clone())
        } {
            self.stop_notify_receiver(&name);
        }
        let removed_terminals: Vec<String> = {
            let mut terminals = self.terminal_sessions.lock();
            let ids: Vec<String> = terminals
                .iter()
                .filter_map(|(id, session)| {
                    if session.pid == pid {
                        Some(id.clone())
                    } else {
                        None
                    }
                })
                .collect();
            for id in &ids {
                if let Some(session) = terminals.remove(id) {
                    debug!(
                        session_id = %id,
                        service = %session.name,
                        pid,
                        "terminal_session_exited"
                    );
                }
            }
            ids
        };
        if !removed_terminals.is_empty() {
            debug!(
                pid,
                removed_sessions = ?removed_terminals,
                "removed_terminal_sessions"
            );
        }

        let mut services = self.services.lock();
        for (name, proc) in services.iter_mut() {
            if proc.network_pid == Some(pid) {
                info!(
                    service = %name,
                    pid,
                    exit_code,
                    "network_sidecar_exited"
                );
                proc.network_pid = None;
                if proc.pid.is_none() {
                    if let Some(ref cg) = proc.cgroup_path.take() {
                        let _ = crate::cgroup::remove_cgroup(cg);
                    }
                }
                return;
            }

            if proc.pid == Some(pid) {
                let intentionally_stopped = proc.target_state == states::ServiceState::Stopped;
                info!(
                    service = %name,
                    pid,
                    exit_code,
                    intentional = intentionally_stopped,
                    "service_exited"
                );

                states::transition(
                    proc,
                    states::LifecycleEvent::Exited {
                        intentional: intentionally_stopped,
                    },
                );
                proc.pid = None;
                proc.stopping_since = None;
                proc.netns_fd = None;
                proc.userns_fd = None;
                proc.namespace_pid = None;
                proc.mesh_tun_attached = false;
                if let Some(network_pid) = proc.network_pid {
                    let _ = process::send_signal(network_pid, libc::SIGTERM);
                }

                if proc.network_pid.is_none() {
                    if let Some(ref cg) = proc.cgroup_path.take() {
                        let _ = crate::cgroup::remove_cgroup(cg);
                    }
                }

                self.notify_service_exit(name);

                let should_restart = if intentionally_stopped {
                    false
                } else if proc.config.oneshot {
                    // For oneshot, only restart if specifically configured to do so
                    should_restart_for_policy(proc.config.restart, exit_code)
                } else {
                    should_restart_for_policy(proc.config.restart, exit_code)
                };

                if should_restart {
                    // crashed or was killed for restart!
                    let running_duration = proc.started_at.map(|t| t.elapsed()).unwrap_or_default();
                    if running_duration >= std::time::Duration::from_secs(10) {
                        proc.consecutive_failures = 1;
                    } else {
                        proc.consecutive_failures += 1;
                    }

                    if let Some(max_retries) = proc.config.backoff.max_retries {
                        if proc.consecutive_failures > max_retries {
                            warn!(
                                service = %name,
                                crashes = proc.consecutive_failures,
                                max_retries,
                                "service_crash_limit_reached"
                            );
                            proc.target_state = states::ServiceState::Stopped;
                            proc.stop_reason = Some(states::StopReason::CrashLimit);
                            if let Some(ref cg) = proc.cgroup_path.take() {
                                let _ = crate::cgroup::remove_cgroup(cg);
                            }
                            return;
                        }
                    }

                    let backoff_secs = calculate_backoff(&proc.config, proc.consecutive_failures);
                    let restart_delay_secs =
                        restart_delay_with_jitter(name, backoff_secs.max(proc.config.restart_sec));

                    info!(
                        service = %name,
                        crashes = proc.consecutive_failures,
                        delay_secs = restart_delay_secs,
                        "service_crash_scheduled_restart"
                    );

                    proc.next_restart_at = Some(
                        std::time::Instant::now()
                            + std::time::Duration::from_secs(restart_delay_secs),
                    );
                } else {
                    proc.target_state = states::ServiceState::Stopped;
                }

                return;
            }
        }
        debug!(pid, exit_code, "unmanaged_child_exited");
    }

    fn next_service_deadline(&self) -> Option<std::time::Instant> {
        let now = std::time::Instant::now();
        let services = self.services.lock();
        services
            .values()
            .filter_map(|proc| {
                if proc.state == states::ServiceState::Stopped
                    && proc.target_state == states::ServiceState::Running
                    && proc.pid.is_none()
                {
                    return Some(proc.next_restart_at.unwrap_or(now));
                }
                if let states::ServiceState::Stopping { .. } = proc.state {
                    // A Stopping service must not be parked forever if its
                    // signal did not take effect; wake up for the SIGKILL
                    // escalation.
                    return proc.stop_escalation_deadline(std::time::Duration::from_secs(
                        STOPPING_ESCALATION_SECS,
                    ));
                }
                if let states::ServiceState::Frozen { .. } = proc.state {
                    // Frozen idle services: wake the policy at the next wake
                    // timer or the stop deadline, whichever comes first.
                    let wake = proc
                        .wake_at
                        .and_then(crate::process::instant_from_monotonic_us);
                    let stop = proc
                        .frozen_since()
                        .zip(proc.config.idle_termination_sec)
                        .map(|(since, secs)| since + std::time::Duration::from_secs(secs));
                    return wake.into_iter().chain(stop).min();
                }
                if proc.protocol_state() != ServiceState::Running {
                    return None;
                }

                // Idle freeze deadline for running services with a window.
                let freeze_deadline = proc
                    .config
                    .idle_freeze_sec
                    .filter(|_| proc.config.idle_action == crate::config::IdleAction::Freeze)
                    .and_then(|window| {
                        proc.idle_since
                            .map(|idle_since| idle_since + std::time::Duration::from_secs(window))
                    });

                let watchdog_deadline = proc.config.watchdog_sec.and_then(|watchdog_sec| {
                    if proc.config.ready_match.is_some() && !proc.ready {
                        return None;
                    }
                    proc.last_watchdog_ping
                        .or(proc.started_at)
                        .map(|last_ping| last_ping + std::time::Duration::from_secs(watchdog_sec))
                });

                let idle_deadline = proc.config.idle_termination_sec.and_then(|idle_sec| {
                    let metrics_idle =
                        proc.last_active == Some(0) && proc.last_sess.unwrap_or(0) == 0;
                    if !metrics_idle {
                        return None;
                    }
                    let duration = std::time::Duration::from_secs(idle_sec);
                    proc.idle_since
                        .map(|idle_since| idle_since + duration)
                        .or_else(|| {
                            proc.last_stderr_at
                                .map(|last_stderr| last_stderr + duration)
                        })
                });

                freeze_deadline
                    .into_iter()
                    .chain(watchdog_deadline)
                    .chain(idle_deadline)
                    .min()
            })
            .min()
    }

    fn check_restarts(&self) {
        let now = std::time::Instant::now();
        let mut to_restart = Vec::new();

        {
            let mut services = self.services.lock();
            for (name, proc) in services.iter_mut() {
                if proc.stop_escalation_due(
                    now,
                    std::time::Duration::from_secs(STOPPING_ESCALATION_SECS),
                ) {
                    warn!(service = %name, pid = proc.pid, "stopping_escalation_sigkill");
                    if let Some(pid) = proc.pid {
                        let _ = process::send_signal(pid, libc::SIGKILL);
                    }
                    // Keep `stopping_since` so a still-living process is
                    // escalated again on every scheduler pass until exit.
                }
            }
            for (_name, proc) in services.iter_mut() {
                if proc.state == states::ServiceState::Stopped
                    && proc.target_state == states::ServiceState::Running
                    && proc.pid.is_none()
                {
                    if let Some(next_at) = proc.next_restart_at {
                        if now >= next_at {
                            to_restart.push(proc.config.clone());
                            proc.next_restart_at = None;
                        }
                    } else {
                        // Immediate restart (should only occur if just loaded without backoff)
                        to_restart.push(proc.config.clone());
                    }
                }
            }

            for (name, proc) in services.iter_mut() {
                if proc.protocol_state() == ServiceState::Running {
                    // --- Watchdog Check ---
                    if let Some(watchdog_sec) = proc.config.watchdog_sec {
                        let mut check_watchdog = true;
                        // Grace period: don't check watchdog until started_at + watchdog_sec has passed
                        if let Some(started) = proc.started_at {
                            if now.duration_since(started)
                                < std::time::Duration::from_secs(watchdog_sec)
                            {
                                check_watchdog = false;
                            }
                        }
                        // Skip watchdog if ReadyMatch is configured but the service isn't ready yet
                        if proc.config.ready_match.is_some() && !proc.ready {
                            check_watchdog = false;
                        }

                        if check_watchdog {
                            let last_ping = proc
                                .last_watchdog_ping
                                .unwrap_or(proc.started_at.unwrap_or(now));
                            if now.duration_since(last_ping)
                                >= std::time::Duration::from_secs(watchdog_sec)
                            {
                                warn!(
                                    service = %name,
                                    timeout_sec = watchdog_sec,
                                    pattern = %proc.config.watchdog_match.as_deref().unwrap_or("active"),
                                    "watchdog_timeout"
                                );
                                let _ = states::transition(
                                    proc,
                                    states::LifecycleEvent::StopRequested {
                                        initiator: states::StopInitiator::Requested,
                                    },
                                );
                                if let Some(pid) = proc.pid {
                                    let _ = process::send_signal(pid, libc::SIGKILL);
                                }
                            }
                        }
                    }

                    // --- Idle Termination Check ---
                    if let Some(idle_sec) = proc.config.idle_termination_sec {
                        let metrics_idle =
                            proc.last_active == Some(0) && proc.last_sess.unwrap_or(0) == 0;
                        let stderr_idle = proc
                            .last_stderr_at
                            .map(|t| {
                                now.duration_since(t) >= std::time::Duration::from_secs(idle_sec)
                            })
                            .unwrap_or(false);

                        if metrics_idle && stderr_idle {
                            if proc.idle_since.is_none() {
                                proc.idle_since = Some(now);
                            }
                            if let Some(idle_start) = proc.idle_since {
                                if now.duration_since(idle_start)
                                    >= std::time::Duration::from_secs(idle_sec)
                                {
                                    info!(
                                        service = %name,
                                        idle_sec,
                                        "idle_termination_triggered"
                                    );
                                    let _ = states::transition(
                                        proc,
                                        states::LifecycleEvent::StopRequested {
                                            initiator: states::StopInitiator::Idle,
                                        },
                                    );
                                    if let Some(pid) = proc.pid {
                                        let _ = process::send_signal(pid, proc.config.kill_signal);
                                    }
                                }
                            }
                        } else {
                            proc.idle_since = None;
                        }
                    }
                }
            }
        }

        for config in to_restart {
            info!(service = %config.name, "restarting_service");
            if let Some(ref rm) = self.resource_manager
                && !rm.can_start(&config)
            {
                warn!(service = %config.name, "insufficient_resources_for_restart");
                let mut s = self.services.lock();
                if let Some(proc) = s.get_mut(&config.name) {
                    proc.state = states::ServiceState::Stopped;
                    proc.next_restart_at = Some(now + std::time::Duration::from_secs(10));
                }
                continue;
            }

            match self.start_service_with_config(config.clone(), None) {
                Ok(_) => {
                    let mut s = self.services.lock();
                    if let Some(proc) = s.get_mut(&config.name) {
                        proc.restarts += 1;
                    }
                }
                Err(e) => {
                    error!(service = %config.name, error = %e, "restart_service_failed");
                    let mut s = self.services.lock();
                    if let Some(proc) = s.get_mut(&config.name) {
                        proc.state = states::ServiceState::Stopped;
                        // Increase failure count
                        proc.consecutive_failures += 1;
                        let backoff_secs =
                            calculate_backoff(&proc.config, proc.consecutive_failures);
                        let restart_delay_secs =
                            restart_delay_with_jitter(&config.name, backoff_secs);
                        proc.next_restart_at = Some(
                            std::time::Instant::now()
                                + std::time::Duration::from_secs(restart_delay_secs),
                        );
                    }
                }
            }
        }
    }

    /// Thaw children that should be running after mesh-init itself resumes.

    ///
    /// A cgroup-v2 freezer has no provenance: systemd, a user, and mesh-init
    /// all leave the same `frozen 1` state.  The daemon's lifecycle state is
    /// therefore authoritative.  Services explicitly frozen through
    /// mesh-init are `Frozen` and are intentionally left alone; only a child
    /// still recorded as both current and desired `Running` is repaired.
    /// Apply the idle lifecycle policy (phases 1 and 2c): freeze idle
    /// services after their window, wake frozen services at `X_MESH_WAKE_AT`
    /// timers, and stop frozen idle services after IdleTerminationSec.
    ///
    /// Steps stay ordered so a service never freeze-races a stop. Called by
    /// the scheduler after `check_restarts`.
    async fn apply_idle_policy(self: Arc<Self>) {
        enum IdleStep {
            Freeze(String),
            Wake(String, states::UnfreezeCause),
            Stop(String, states::StopInitiator),
        }

        loop {
            let now = Instant::now();
            let step = {
                let mut steps: Vec<IdleStep> = Vec::new();
                let services = self.services.lock();
                for (name, proc) in services.iter() {
                    match proc.state {
                        states::ServiceState::Frozen { .. } => {
                            let wake_due = proc
                                .wake_at
                                .and_then(crate::process::instant_from_monotonic_us)
                                .is_some_and(|deadline| deadline <= now);
                            let thawable = proc.freeze_reason == Some(FreezeReason::Idle)
                                || proc.freeze_reason == Some(FreezeReason::Pressure);
                            if wake_due && thawable {
                                steps.push(IdleStep::Wake(
                                    name.clone(),
                                    states::UnfreezeCause::Activity,
                                ));
                            }
                            let stop_due = proc
                                .frozen_since()
                                .zip(proc.config.idle_termination_sec)
                                .map(|(since, secs)| since + std::time::Duration::from_secs(secs))
                                .is_some_and(|deadline| deadline <= now);
                            if stop_due {
                                steps.push(IdleStep::Stop(
                                    name.clone(),
                                    states::StopInitiator::Idle,
                                ));
                            }
                        }
                        states::ServiceState::Running => {
                            let freeze_window = proc.config.idle_freeze_sec.unwrap_or(0);
                            let wants_freeze = proc.config.idle_action
                                == crate::config::IdleAction::Freeze
                                && freeze_window > 0
                                && proc.idle_since.is_some_and(|idle_since| {
                                    now.duration_since(idle_since)
                                        >= std::time::Duration::from_secs(freeze_window)
                                });
                            let metrics_idle =
                                proc.last_active == Some(0) && proc.last_sess.unwrap_or(0) == 0;
                            let stderr_idle = proc
                                .last_stderr_at
                                .map(|t| {
                                    now.duration_since(t)
                                        >= std::time::Duration::from_secs(freeze_window)
                                })
                                .unwrap_or(false);
                            // A service with no self-report yet counts idle
                            // only via the legacy stderr metrics.
                            let idle_ok = wants_freeze
                                && (proc.notify_activity.is_some()
                                    || (metrics_idle && stderr_idle));
                            if idle_ok {
                                steps.push(IdleStep::Freeze(name.clone()));
                            }
                        }
                        states::ServiceState::Freezing { .. }
                        | states::ServiceState::Stopping { .. }
                        | states::ServiceState::Starting
                        | states::ServiceState::Stopped => {}
                    }
                }
                steps
            };
            let Some(step) = step.into_iter().next() else {
                return;
            };
            match step {
                IdleStep::Wake(name, cause) => self.thaw_service(&name, cause).await,
                IdleStep::Stop(name, initiator) => {
                    self.stop_service_internal(&name, initiator).await
                }
                IdleStep::Freeze(name) => {
                    let _ = self.freeze_for_idle(&name).await;
                }
            }
        }
    }

    /// Spawn the event-driven pressure policy task (phase 3).
    ///
    /// On each pass the pure `plan` function produces at most one action;
    /// the executor applies it, then sleeps for a cooldown window before
    /// re-evaluating, so an action's effect is observable.
    fn spawn_pressure_policy_task(daemon: Arc<Daemon>) {
        tokio::spawn(async move {
            let policy = crate::pressure::PressurePolicy::default().from_env();
            let mut history = crate::pressure::PressureHistory::default();
            info!("pressure_policy_started");
            loop {
                let now = Instant::now();
                let snapshot = daemon.pressure_snapshot(&policy);
                let previous_level = crate::pressure::classify(&snapshot, &policy);
                let actions = crate::pressure::plan(&snapshot, &policy, &history, now);
                match actions.into_iter().next() {
                    Some(crate::pressure::Action::Noop) => {
                        // Pressure cleared: thaw pressure-frozen services in
                        // priority order, one per cooldown.
                        if let Some(name) = daemon.next_pressure_thaw_candidate(&policy) {
                            daemon
                                .thaw_service(&name, states::UnfreezeCause::PressureCleared)
                                .await;
                            history.last_action = Some("thaw_pressure");
                            history.last_action_at = Some(now);
                        } else if history.previous_level != crate::pressure::PressureLevel::None {
                            history.previous_level = crate::pressure::PressureLevel::None;
                            history.level_since = Some(now);
                        }
                    }
                    Some(action) => {
                        daemon.execute_pressure_action(&action).await;
                        history.last_action = Some(action.name());
                        history.last_action_at = Some(now);
                    }
                    None => {
                        // No memory action this pass; CPU pressure is
                        // handled on its own branch (memory not involved).
                        if snapshot.cpu_avg10 >= policy.cpu_freeze_avg10
                            && let Some(name) = daemon.next_cpu_pressure_freeze_candidate()
                        {
                            let _ = daemon.freeze_for_pressure(&name).await;
                            history.last_action = Some("cpu_freeze");
                            history.last_action_at = Some(now);
                        }
                    }
                }
                // Track level entry for hysteresis.
                if history.previous_level != previous_level {
                    history.level_since = Some(Instant::now());
                    history.previous_level = previous_level;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    }

    /// Build one full snapshot from cgroup state and PSI files.
    fn pressure_snapshot(
        &self,
        _policy: &crate::pressure::PressurePolicy,
    ) -> crate::pressure::PressureSnapshot {
        let memory = crate::resource::read_memory_pressure();
        let cpu = crate::resource::read_cpu_pressure();
        let mem_total = crate::resource::read_mem_total().unwrap_or(0);
        let mem_available = crate::resource::read_available_memory().unwrap_or(0);

        let services = {
            let locked = self.services.lock();
            locked
                .values()
                .filter(|proc| {
                    matches!(
                        proc.protocol_state(),
                        ServiceState::Running | ServiceState::Frozen
                    )
                })
                .map(|proc| {
                    let idle = proc.notify_activity.is_some_and(|counts| counts.is_idle())
                        || proc.idle_since.is_some();
                    crate::pressure::ServicePressure {
                        name: proc.config.name.clone(),
                        state: proc.state,
                        priority: proc.config.priority,
                        idle,
                        self_reports: proc.notify_activity.is_some(),
                        freeze_reason: proc.freeze_reason,
                        cgroup_path: proc.cgroup_path.clone().unwrap_or_default(),
                        memory_current: proc.cgroup_memory_current().unwrap_or(0),
                        memory_low: proc.config.resources.memory_low.unwrap_or(0),
                        protected: proc.config.evictable == Some(false),
                        freezable: proc.cgroup_path.is_some(),
                    }
                })
                .collect()
        };
        crate::pressure::PressureSnapshot {
            memory_avg10: memory.as_ref().map(|p| p.some_avg10).unwrap_or(0.0),
            memory_avg60: memory.as_ref().map(|p| p.some_avg60).unwrap_or(0.0),
            cpu_avg10: cpu.as_ref().map(|p| p.some_avg10).unwrap_or(0.0),
            mem_total,
            mem_available,
            swap_exists: crate::resource::swap_exists(),
            services,
        }
    }

    /// Priority-ordered candidate to thaw once pressure clears.
    fn next_pressure_thaw_candidate(
        &self,
        _policy: &crate::pressure::PressurePolicy,
    ) -> Option<String> {
        let locked = self.services.lock();
        let mut frozen: Vec<(u32, String)> = locked
            .values()
            .filter(|proc| {
                proc.freeze_reason == Some(FreezeReason::Pressure)
                    || proc.freeze_reason == Some(FreezeReason::Idle)
            })
            .map(|proc| (proc.config.priority, proc.config.name.clone()))
            .collect();
        frozen.sort_by_key(|(priority, _)| *priority);
        frozen.first().map(|(_, name)| name.clone())
    }

    /// Busy background services that should give up CPU: lowest priority
    /// first, protected services skipped.
    fn next_cpu_pressure_freeze_candidate(&self) -> Option<String> {
        let locked = self.services.lock();
        let mut candidates: Vec<(u32, String)> = locked
            .values()
            .filter(|proc| {
                proc.protocol_state() == ServiceState::Running
                    && proc.freeze_reason.is_none()
                    && proc.config.evictable != Some(false)
                    && proc.cgroup_path.is_some()
            })
            .map(|proc| (proc.config.priority, proc.config.name.clone()))
            .collect();
        candidates.sort_by_key(|(priority, _)| std::cmp::Reverse(*priority));
        candidates.first().map(|(_, name)| name.clone())
    }

    /// Freeze a busy service under CPU pressure without a handshake.
    async fn freeze_for_pressure(&self, name: &str) -> Result<u64> {
        let epoch = {
            let mut services = self.services.lock();
            let Some(proc) = services.get_mut(name) else {
                anyhow::bail!("service '{}' not found", name);
            };
            let epoch = states::next_epoch(proc.freeze_ack);
            states::transition(
                proc,
                states::LifecycleEvent::Freeze {
                    reason: FreezeReason::Pressure,
                    epoch,
                },
            );
            epoch
        };
        let frozen = {
            let mut services = self.services.lock();
            let Some(proc) = services.get_mut(name) else {
                anyhow::bail!("service '{}' not found", name);
            };
            let Some(cg) = proc.cgroup_path.clone() else {
                return Err(anyhow::anyhow!("service '{}' has no cgroup", name));
            };
            match process::freeze_cgroup_confirmed(&cg, CONFIRM_FREEZE_TIMEOUT) {
                Ok(()) => {
                    proc.freeze_ack = Some(epoch);
                    states::transition(proc, states::LifecycleEvent::FrozenConfirmed);
                    true
                }
                Err(_) => {
                    states::transition(proc, states::LifecycleEvent::FreezeCancelled);
                    false
                }
            }
        };
        if frozen {
            info!(service = %name, "service_frozen_pressure");
            Ok(epoch)
        } else {
            Err(anyhow::anyhow!("freeze of {} did not confirm", name))
        }
    }

    /// Phase 3 executor: exactly one action per pass.
    async fn execute_pressure_action(&self, action: &crate::pressure::Action) {
        use crate::pressure::Action as A;
        match action {
            A::Trim { level } => {
                self.trim_services(Self::map_trim_round(*level)).await;
            }
            A::Reclaim { path } => {
                if let Err(error) = crate::cgroup::reclaim_memory(path, 128 << 20) {
                    warn!(path, error = %error, "memory_reclaim_failed");
                }
            }
            A::Freeze { name } => {
                let _ = self.freeze_for_idle(name).await;
            }
            A::StopEvict { name } => {
                info!(service = %name, "pressure_stop_evict");
                self.stop_service_internal(name, states::StopInitiator::Evicted)
                    .await;
            }
            A::CgroupKill { path } => {
                if let Err(error) = crate::cgroup::kill_scope(path) {
                    warn!(path, error = %error, "cgroup_kill_failed");
                }
            }
            A::Noop => {}
        }
    }

    /// Map a policy trim round onto the wire protocol level.
    fn map_trim_round(round: crate::pressure::TrimRound) -> mesh::lifecycle::TrimLevel {
        match round {
            crate::pressure::TrimRound::Background => mesh::lifecycle::TrimLevel::Background,
            crate::pressure::TrimRound::Ui => mesh::lifecycle::TrimLevel::Ui,
            crate::pressure::TrimRound::Complete => mesh::lifecycle::TrimLevel::Complete,
        }
    }

    /// `mesh.lifecycle trim {level}` to all running services that expose a
    /// mesh socket; best-effort and fire-and-forget.
    async fn trim_services(&self, level: mesh::lifecycle::TrimLevel) {
        let targets: Vec<AppConfig> = {
            let locked = self.services.lock();
            locked
                .values()
                .filter(|proc| proc.protocol_state() == ServiceState::Running)
                .map(|proc| proc.config.clone())
                .collect()
        };
        let mut tasks = tokio::task::JoinSet::new();
        for config in targets {
            if let Some(socket) = lifecycle_socket(&config) {
                tasks.spawn(async move {
                    mesh::lifecycle::notify(
                        &socket,
                        &mesh::lifecycle::LifecycleEvent {
                            action: mesh::lifecycle::LifecycleAction::Trim { level },
                            cause: mesh::lifecycle::LifecycleCause::Pressure,
                            observed: false,
                        },
                    )
                    .await
                    .is_ok()
                });
            }
        }
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(_) => {}
                Err(error) => warn!(error = %error, "trim_notification_task_failed"),
            }
        }
    }

    async fn reconcile_unexpected_frozen_services(&self) -> (usize, usize, usize) {
        let candidates: Vec<(String, Option<String>, AppConfig)> = {
            let services = self.services.lock();
            services
                .iter()
                .filter_map(|(name, proc)| {
                    (proc.protocol_state() == ServiceState::Running
                        && proc.target_state == states::ServiceState::Running)
                        .then(|| (name.clone(), proc.cgroup_path.clone(), proc.config.clone()))
                })
                .collect()
        };

        let checked = candidates.len();
        let mut reconciled = 0;
        let mut failed = 0;
        let mut notifications = tokio::task::JoinSet::new();
        for (name, cgroup_path, config) in candidates {
            match cgroup_path
                .as_deref()
                .map(crate::cgroup::cgroup_is_frozen)
                .transpose()
            {
                Ok(Some(true)) => match crate::cgroup::freeze_cgroup(
                    cgroup_path.as_deref().expect("checked cgroup path"),
                    false,
                ) {
                    Ok(()) => {
                        reconciled += 1;
                        info!(
                            service = %name,
                            path = %cgroup_path.as_deref().unwrap_or_default(),
                            "unexpected_frozen_service_reconciled"
                        );
                    }
                    Err(error) => {
                        failed += 1;
                        warn!(
                            service = %name,
                            path = %cgroup_path.as_deref().unwrap_or_default(),
                            error = %error,
                            "unexpected_frozen_service_unfreeze_failed"
                        );
                    }
                },
                Ok(Some(false) | None) => {}
                Err(error) => {
                    failed += 1;
                    debug!(
                        service = %name,
                        path = %cgroup_path.as_deref().unwrap_or_default(),
                        error = %error,
                        "service_cgroup_freeze_state_unavailable"
                    );
                }
            }
            // A reconcile request is also the platform-neutral resume event.
            // Notify every service that should be running, including services
            // whose cgroup was already thawed correctly by the host.
            notifications.spawn(async move {
                // Preserve event order per service while allowing different
                // services to be notified concurrently.
                let mut notification_failures = 0;
                if !notify_lifecycle(
                    &config,
                    mesh::lifecycle::LifecycleEvent {
                        action: mesh::lifecycle::LifecycleAction::Freeze,
                        cause: mesh::lifecycle::LifecycleCause::External,
                        observed: true,
                    },
                )
                .await
                {
                    notification_failures += 1;
                }
                if !notify_lifecycle(
                    &config,
                    mesh::lifecycle::LifecycleEvent {
                        action: mesh::lifecycle::LifecycleAction::Unfreeze,
                        cause: mesh::lifecycle::LifecycleCause::External,
                        observed: false,
                    },
                )
                .await
                {
                    notification_failures += 1;
                }
                notification_failures
            });
        }
        while let Some(result) = notifications.join_next().await {
            match result {
                Ok(notification_failures) => failed += notification_failures,
                Err(error) => {
                    // A task represents both ordered notifications.
                    failed += 2;
                    warn!(error = %error, "service_lifecycle_notification_task_failed");
                }
            }
        }
        (checked, reconciled, failed)
    }

    async fn handle_reconcile(&self, peer_uid: u32) -> Response {
        if let Err(response) = require_system_or_root(peer_uid) {
            return response;
        }
        let (checked, reconciled, failed) = self.reconcile_unexpected_frozen_services().await;
        Response::ok_with_data(serde_json::json!({
            "checked": checked,
            "reconciled": reconciled,
            "failed": failed,
        }))
    }

    /// Start a service by name using the pre-loaded config.
    fn start_service_internal(&self, name: &str) -> Result<u32> {
        let config = self
            .configs
            .lock()
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no config for '{}'", name))?;

        self.start_service_with_config(config, None)
    }

    /// The single entry point for making a service run (phase 1).
    ///
    /// Used by activation, hybrid forwarding, start requests and ssh-mesh
    /// on-demand starts. Semantics per lifecycle state:
    ///
    /// - `Stopped` → spawn a new child, taking `config` when provided.
    /// - `Frozen` → thaw; the live child keeps serving.
    /// - `Freezing` → cancel the pending freeze; the freeze never happened.
    /// - `Stopping` → report queued; the restart loop spawns after exit.
    /// - `Starting`/`Running` → no-op; return the current pid.
    ///
    /// `passed_fd` is only consumed when a fresh spawn actually happens.
    pub async fn ensure_running(
        &self,
        name: &str,
        config: Option<AppConfig>,
        passed_fd: Option<crate::process::ActivationFd>,
    ) -> Result<EnsureRunningOutcome> {
        loop {
            let (state, pid) = {
                let services = self.services.lock();
                match services.get(name) {
                    Some(proc) => (Some(proc.state), proc.pid),
                    None => (None, None),
                }
            };
            match state {
                None | Some(states::ServiceState::Stopped) => {
                    let config = match config.clone() {
                        Some(config) => config,
                        None => self
                            .configs
                            .lock()
                            .get(name)
                            .cloned()
                            .ok_or_else(|| anyhow::anyhow!("no config for '{}'", name))?,
                    };
                    {
                        let mut services = self.services.lock();
                        let Some(proc) = services.get_mut(name) else {
                            return Err(anyhow::anyhow!(
                                "service '{}' is not loaded; start it via start_service_with_config",
                                name
                            ));
                        };
                        states::transition(proc, states::LifecycleEvent::StartRequested);
                        proc.target_state = states::ServiceState::Running;
                    }
                    return self
                        .start_service_with_config(config, passed_fd)
                        .map(EnsureRunningOutcome::Started);
                }
                Some(states::ServiceState::Frozen { .. }) => {
                    let mut services = self.services.lock();
                    let Some(proc) = services.get_mut(name) else {
                        continue;
                    };
                    let effects = states::transition(
                        proc,
                        states::LifecycleEvent::Unfreeze {
                            cause: states::UnfreezeCause::Activity,
                        },
                    );
                    if let Some(cg) = proc.cgroup_path.clone() {
                        for effect in &effects {
                            if matches!(effect, states::Effect::UnfreezeCgroup) {
                                process::unfreeze_cgroup(&cg)?;
                            }
                        }
                    }
                    if !effects.is_empty() {
                        self.wake_scheduler();
                        return Ok(EnsureRunningOutcome::Thawed { pid: proc.pid });
                    }
                    // An explicit user freeze keeps it frozen; report it.
                    return Ok(EnsureRunningOutcome::ThawedRefused);
                }
                Some(states::ServiceState::Freezing { .. }) => {
                    let mut services = self.services.lock();
                    let Some(proc) = services.get_mut(name) else {
                        continue;
                    };
                    states::transition(proc, states::LifecycleEvent::FreezeCancelled);
                    self.wake_scheduler();
                    return Ok(EnsureRunningOutcome::FreezeCancelled);
                }
                Some(states::ServiceState::Stopping { .. }) => {
                    return Ok(EnsureRunningOutcome::QueuedWhileStopping);
                }
                Some(states::ServiceState::Starting) | Some(states::ServiceState::Running) => {
                    if pid.is_some() {
                        return Ok(EnsureRunningOutcome::AlreadyRunning { pid });
                    }
                    // Starting without a pid: spawn registration is midway;
                    // wait briefly for it to resolve.
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    continue;
                }
            }
        }
    }

    /// Start a service from a config.
    pub fn start_service_with_config(
        &self,
        mut config: AppConfig,
        passed_fd: Option<crate::process::ActivationFd>,
    ) -> Result<u32> {
        let name = config.name.clone();

        // Phase 2b: bind the per-service notify channel and publish
        // NOTIFY_SOCKET into the child environment. A "none" value disables
        // the channel deliberately.
        let notify_env = config.env.get("NOTIFY_SOCKET").cloned();
        if notify_env.as_deref() != Some("none") {
            if let Err(error) = self.start_notify_receiver(&name) {
                warn!(
                    service = %name,
                    error = %error,
                    "notify_receiver_bind_failed"
                );
            } else {
                crate::notify::apply_notify_env(&name, &mut config.env);
            }
        } else {
            // Explicitly disabled; keep whatever the caller asked for.
            config
                .env
                .insert("NOTIFY_SOCKET".to_string(), "none".to_string());
        }

        run_service_commands(
            &config,
            &config.exec_start_pre,
            "ExecStartPre",
            config.timeout_start_sec,
        )?;

        // Create cgroup
        let cgroup_path = match crate::cgroup::create_cgroup(&name) {
            Ok(path) => {
                // Set limits
                if let Err(e) = crate::cgroup::set_limits(&path, &config.resources) {
                    warn!(service = %name, error = %e, "set_cgroup_limits_failed");
                }
                Some(path)
            }
            Err(e) => {
                warn!(
                    service = %name,
                    error = %e,
                    "create_cgroup_failed"
                );
                None
            }
        };

        let cg = cgroup_path.as_deref().unwrap_or("/sys/fs/cgroup");

        // B9: Guard against double-spawn. If another caller (e.g. check_restarts)
        // already transitioned this service to `Starting`, refuse to spawn again
        // to avoid two processes for the same service.
        {
            let services = self.services.lock();
            if let Some(proc) = services.get(&name) {
                if proc.state == states::ServiceState::Starting && proc.pid.is_none() {
                    return Err(anyhow::anyhow!(
                        "service '{}' is already starting (double-spawn prevented)",
                        name
                    ));
                }
                if proc.protocol_state() == ServiceState::Running && proc.pid.is_some() {
                    // Already running; let the caller decide via handle_start's
                    // restart logic. Return the existing pid.
                    if let Some(pid) = proc.pid {
                        return Ok(pid);
                    }
                }
            }
        }

        // B5: Register the service in `Starting` state BEFORE spawning, so
        // that the SIGCHLD reaper can match a fast-exiting child's PID. If the
        // child exits before we insert, the exit event is lost and the daemon
        // believes a dead service is Running.
        {
            let mut services = self.services.lock();
            if let Some(proc) = services.get_mut(&name) {
                states::transition(proc, states::LifecycleEvent::StartRequested);
                proc.target_state = states::ServiceState::Running;
                proc.pid = None;
                proc.network_pid = None;
                proc.netns_fd = None;
                proc.userns_fd = None;
                proc.namespace_pid = None;
                proc.mesh_tun_attached = false;
            } else {
                let mut proc = ManagedProcess::new(config.clone());
                states::transition(&mut proc, states::LifecycleEvent::StartRequested);
                proc.target_state = states::ServiceState::Running;
                services.insert(name.clone(), proc);
            }
        }

        // Spawn process
        let (pid, stderr) = match process::spawn_process(&config, cg, passed_fd) {
            Ok(pair) => pair,
            Err(e) => {
                // Spawn failed: mark the service Stopped so it can be restarted.
                let mut services = self.services.lock();
                if let Some(proc) = services.get_mut(&name) {
                    states::transition(proc, states::LifecycleEvent::SpawnFailed);
                    proc.pid = None;
                    if !should_restart_for_policy(proc.config.restart, -1) {
                        proc.target_state = states::ServiceState::Stopped;
                    }
                }
                return Err(e.into());
            }
        };

        let network_sidecar = match crate::network::start_network_sidecar(&config, pid, cg) {
            Ok(sidecar) => sidecar,
            Err(error) => {
                let _ = process::send_signal(pid, libc::SIGTERM);
                let mut services = self.services.lock();
                if let Some(proc) = services.get_mut(&name) {
                    states::transition(proc, states::LifecycleEvent::SpawnFailed);
                    proc.pid = None;
                    proc.network_pid = None;
                    proc.netns_fd = None;
                    proc.userns_fd = None;
                    proc.namespace_pid = None;
                    proc.mesh_tun_attached = false;
                    if !should_restart_for_policy(proc.config.restart, -1) {
                        proc.target_state = states::ServiceState::Stopped;
                    }
                }
                return Err(error);
            }
        };

        // Register the spawned PID with the reaper (when not in catch-all mode)
        // and update the service state to Running.
        {
            if let Some(ref tracked) = *self.tracked_child_pids.lock() {
                tracked.lock().insert(pid);
                if let Some(sidecar) = &network_sidecar {
                    tracked.lock().insert(sidecar.pid);
                }
            }
            let mut services = self.services.lock();
            if let Some(proc) = services.get_mut(&name) {
                states::transition(proc, states::LifecycleEvent::Spawned);
                proc.target_state = states::ServiceState::Running;
                proc.pid = Some(pid);
                proc.network_pid = network_sidecar.as_ref().map(|sidecar| sidecar.pid);
                proc.started_at = Some(std::time::Instant::now());
                proc.cgroup_path = cgroup_path;
                proc.config = config.clone();
                proc.ready = config.ready_match.is_none();
                proc.last_watchdog_ping = None;
                proc.last_stderr_at = None;
                proc.last_active = None;
                proc.last_sess = None;
                proc.notify_activity = None;
                proc.idle_since = None;
                // A10: open a pidfd for PID-safe signaling. On failure
                // (extremely unlikely after spawn succeeded), leave pidfd
                // None; send_signal_pidfd will fall back to kill(2).
                match process::open_pidfd(pid) {
                    Ok(fd) => proc.pidfd = Some(fd),
                    Err(e) => warn!(
                        pid,
                        error = %e,
                        "open_pidfd_failed_using_kill"
                    ),
                }
            }
        }
        info!(service = %name, pid, "service_started");
        self.wake_scheduler();

        if let Some(stderr_pipe) = stderr {
            let services_clone = self.services.clone();
            spawn_stderr_reader(
                name.clone(),
                stderr_pipe,
                services_clone,
                self.scheduler_tx.clone(),
            );
        }

        if let Err(error) = run_service_commands(
            &config,
            &config.exec_start_post,
            "ExecStartPost",
            config.timeout_start_sec,
        ) {
            let _ = process::send_signal(pid, config.kill_signal);
            return Err(error);
        }

        Ok(pid)
    }

    /// Gracefully shut down all services.
    pub async fn shutdown(&self) {
        info!("shutting_down_all_services");

        let names: Vec<String> = self.services.lock().keys().cloned().collect();

        for name in names {
            let pid = {
                let services = self.services.lock();
                services.get(&name).and_then(|p| {
                    if matches!(
                        p.protocol_state(),
                        ServiceState::Running | ServiceState::Frozen
                    ) {
                        p.pid
                    } else {
                        None
                    }
                })
            };

            if let Some(pid) = pid {
                debug!(service = %name, pid, "stopping_service");
                let (kill_signal, timeout_stop, send_sigkill, pidfd) = {
                    let mut services = self.services.lock();
                    match services.get_mut(&name) {
                        Some(p) => (
                            p.config.kill_signal,
                            p.config.timeout_stop_sec,
                            p.config.send_sigkill,
                            p.pidfd.take(),
                        ),
                        None => (libc::SIGTERM, None, true, None),
                    }
                };
                let _ = process::stop_process(
                    pid,
                    pidfd.as_ref(),
                    Some(kill_signal),
                    timeout_stop,
                    send_sigkill,
                )
                .await;
            }

            let network_pid = {
                let services = self.services.lock();
                services.get(&name).and_then(|p| p.network_pid)
            };
            if let Some(pid) = network_pid {
                debug!(service = %name, pid, "stopping_network_sidecar");
                let _ = process::send_signal(pid, libc::SIGTERM);
            }

            // Clean up cgroup
            let cgroup_path = {
                let services = self.services.lock();
                services.get(&name).and_then(|p| p.cgroup_path.clone())
            };
            if let Some(ref cg) = cgroup_path {
                let _ = crate::cgroup::remove_cgroup(cg);
            }
        }

        // Clean up socket
        let _ = std::fs::remove_file(&self.config.socket_path);
        let _ = self.shutdown_tx.send(true);
        info!("daemon_shutdown_complete");
    }
}

fn lifecycle_socket(config: &AppConfig) -> Option<std::path::PathBuf> {
    match config
        .mesh
        .as_ref()
        .and_then(|mesh| mesh.address.as_deref())
    {
        Some(address) if address.starts_with("unix://") => {
            Some(std::path::PathBuf::from(&address[7..]))
        }
        Some(address) if address.starts_with('/') => Some(std::path::PathBuf::from(address)),
        Some(address) => {
            debug!(
                service = %config.name,
                address,
                "lifecycle_notification_non_unix_endpoint_unsupported"
            );
            None
        }
        None => Some(
            mesh::paths::AppPaths::for_app(&config.name)
                .mesh_socket()
                .clone(),
        ),
    }
}

async fn notify_lifecycle(config: &AppConfig, event: mesh::lifecycle::LifecycleEvent) -> bool {
    let Some(socket) = lifecycle_socket(config) else {
        return false;
    };
    if let Err(error) = mesh::lifecycle::notify(&socket, &event).await {
        debug!(
            service = %config.name,
            path = %socket.display(),
            action = ?event.action,
            cause = ?event.cause,
            error = %error,
            "service_lifecycle_notification_failed"
        );
        return false;
    }
    true
}

fn restart_delay_with_jitter(service_name: &str, base_secs: u64) -> u64 {
    if base_secs <= 1 {
        return base_secs;
    }

    let jitter_window = (base_secs / 10).clamp(1, 30);
    let mut hasher = DefaultHasher::new();
    service_name.hash(&mut hasher);
    base_secs.saturating_add(hasher.finish() % (jitter_window + 1))
}

fn calculate_backoff(config: &AppConfig, consecutive_failures: u32) -> u64 {
    if consecutive_failures == 0 {
        return 0;
    }
    let initial = config.backoff.initial_secs.max(config.restart_sec);
    let mut backoff_secs = match config.backoff.policy {
        crate::config::BackoffPolicy::Linear => initial.saturating_mul(consecutive_failures as u64),
        crate::config::BackoffPolicy::Exponential => {
            let multiplier = 1_u64
                .checked_shl(consecutive_failures - 1)
                .unwrap_or(u64::MAX);
            initial.saturating_mul(multiplier)
        }
    };

    if config.backoff.max_retries.is_none() {
        backoff_secs = backoff_secs.min(24 * 3600);
    }
    backoff_secs
}

fn spawn_stderr_reader(
    name: String,
    stderr: std::process::ChildStderr,
    services: Arc<Mutex<HashMap<String, ManagedProcess>>>,
    scheduler_tx: tokio::sync::watch::Sender<u64>,
) {
    std::thread::spawn(move || {
        use std::io::BufRead;
        let reader = std::io::BufReader::new(stderr);
        for line_result in reader.lines() {
            let line = match line_result {
                Ok(l) => l,
                Err(_) => break,
            };

            // 1. Forward the line to mesh-init's own stderr
            eprintln!("{}: {}", name, line);

            if line.trim().is_empty() {
                continue;
            }

            let now = std::time::Instant::now();
            let mut services_guard = services.lock();
            let Some(proc) = services_guard.get_mut(&name) else {
                break;
            };

            proc.last_stderr_at = Some(now);

            // Only wake the scheduler for state that moves a deadline earlier
            // or creates one. `last_stderr_at` alone pushes idle deadlines
            // later, which the scheduler reconciles on its next scheduled
            // wake, so chatty output does not spin the scheduler per line.
            let mut wake = false;

            // 3. Detect format
            let is_json = line.trim_start().starts_with('{');

            // 4. Check ReadyMatch
            if let Some(ref ready_match) = proc.config.ready_match {
                if !proc.ready && line.contains(ready_match) {
                    proc.ready = true;
                    wake = true;
                    info!(service = %name, pattern = %ready_match, "service_ready");
                }
            }

            // 5. Check WatchdogMatch
            if let Some(ref watchdog_match) = proc.config.watchdog_match {
                if line.contains(watchdog_match) {
                    proc.last_watchdog_ping = Some(now);
                    wake = true;
                }
            }

            // 6. Extract metrics
            let mut active = None;
            let mut sess = None;
            if is_json {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                    if let Some(obj) = v.as_object() {
                        if let Some(a) = obj.get("active").and_then(|a| a.as_u64()) {
                            active = Some(a);
                        }
                        if let Some(s) = obj.get("sess").and_then(|s| s.as_u64()) {
                            sess = Some(s);
                        }
                    }
                }
            } else {
                // logfmt-like token scanning (active=N sess=N)
                // Find active=N
                if let Some(pos) = line.find("active=") {
                    let s = &line[pos + 7..];
                    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if !digits.is_empty() {
                        if let Ok(val) = digits.parse::<u64>() {
                            active = Some(val);
                        }
                    }
                }
                // Find sess=N
                if let Some(pos) = line.find("sess=") {
                    let s = &line[pos + 5..];
                    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if !digits.is_empty() {
                        if let Ok(val) = digits.parse::<u64>() {
                            sess = Some(val);
                        }
                    }
                }
            }

            if active.is_some() {
                wake |= proc.last_active != active;
                proc.last_active = active;
            }
            if sess.is_some() {
                wake |= proc.last_sess != sess;
                proc.last_sess = sess;
            }
            drop(services_guard);
            if wake {
                scheduler_tx.send_modify(|revision| {
                    *revision = revision.wrapping_add(1);
                });
            }
        }
    });
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::io::Read;
    use std::os::fd::OwnedFd;
    use std::sync::Arc;

    fn env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    /// Create a fake cgroup tree that flips to `frozen 1` one millisecond
    /// after `cgroup.freeze=1` is written, like the kernel would.
    fn fake_cgroup(root: &std::path::Path, name: &str) -> String {
        let cg = root.join(format!("{name}.scope"));
        std::fs::create_dir_all(&cg).unwrap();
        std::fs::write(cg.join("cgroup.events"), "populated 1\nfrozen 0\n").unwrap();
        std::fs::write(cg.join("cgroup.freeze"), "0").unwrap();
        let freeze_file = cg.join("cgroup.freeze");
        let events_file = cg.join("cgroup.events");
        std::thread::spawn(move || {
            let mut last = String::new();
            loop {
                let current = std::fs::read_to_string(&freeze_file).unwrap_or_default();
                if current.trim() == "1" && last != "1" {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    std::fs::write(&events_file, "populated 1\nfrozen 1\n").unwrap();
                    return;
                }
                last = current;
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        });
        cg.display().to_string()
    }

    fn idle_service(
        name: &str,
        cgroup_path: String,
        socket: Option<std::path::PathBuf>,
    ) -> ManagedProcess {
        let mut proc = ManagedProcess::new(AppConfig {
            name: name.to_string(),
            command: "/bin/true".to_string(),
            mesh: socket.map(|path| mesh::config::MeshSection {
                address: Some(format!("unix://{}", path.display())),
                ..Default::default()
            }),
            ..Default::default()
        });
        proc.state = states::ServiceState::Running;
        proc.target_state = states::ServiceState::Running;
        proc.pid = Some(12345);
        proc.cgroup_path = Some(cgroup_path);
        proc
    }

    #[tokio::test]
    async fn idle_freeze_handshake_freezes_on_ready_reply() {
        let dir = tempfile::tempdir().unwrap();
        let cg_path = fake_cgroup(dir.path(), "echo");
        let socket_path = dir.path().join("echo.mesh.sock");

        std::thread::spawn(move || {
            let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
            if let Ok((stream, _)) = listener.accept() {
                use std::io::{BufRead, BufReader, Write};
                let mut write_half = stream.try_clone().unwrap();
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let request: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
                assert_eq!(request["method"], "mesh.lifecycle");
                assert_eq!(request["params"]["action"]["prepare_freeze"]["epoch"], 1);
                write_half
                    .write_all(
                        br#"{"jsonrpc":"2.0","id":"mesh-init-lifecycle","result":{"freeze":"ready","epoch":1}}"#,
                    )
                    .unwrap();
            }
        });

        let daemon = Daemon::new(DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test-handshake-ready.sock".to_string(),
        });
        daemon.services.lock().insert(
            "echo".to_string(),
            idle_service("echo", cg_path, Some(dir.path().join("echo.mesh.sock"))),
        );

        let outcome = daemon
            .freeze_for_idle_with("echo", Duration::from_millis(300))
            .await;
        assert!(matches!(outcome, Ok(Some(1))), "{outcome:?}");
        let services = daemon.services.lock();
        let proc = services.get("echo").unwrap();
        assert!(matches!(proc.state, states::ServiceState::Frozen { .. }));
        assert_eq!(proc.freeze_reason, Some(states::FreezeReason::Idle));
        assert_eq!(proc.freeze_ack, Some(1));
    }

    #[tokio::test]
    async fn idle_freeze_handshake_cancels_on_busy_reply() {
        let dir = tempfile::tempdir().unwrap();
        let cg_path = fake_cgroup(dir.path(), "echo");
        let socket_path = dir.path().join("echo.mesh.sock");

        std::thread::spawn(move || {
            let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
            if let Ok((stream, _)) = listener.accept() {
                use std::io::{BufRead, BufReader, Write};
                let mut write_half = stream.try_clone().unwrap();
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let _request: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
                write_half
                    .write_all(
                        br#"{"jsonrpc":"2.0","id":"mesh-init-lifecycle","result":{"freeze":"busy","epoch":1}}"#,
                    )
                    .unwrap();
            }
        });

        let daemon = Daemon::new(DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test-handshake-busy.sock".to_string(),
        });
        daemon.services.lock().insert(
            "echo".to_string(),
            idle_service("echo", cg_path, Some(dir.path().join("echo.mesh.sock"))),
        );

        let outcome = daemon
            .freeze_for_idle_with("echo", Duration::from_millis(300))
            .await;
        assert!(matches!(outcome, Ok(None)), "busy cancels: {outcome:?}");
        assert_eq!(
            daemon.services.lock().get("echo").unwrap().protocol_state(),
            ServiceState::Running
        );
    }

    #[tokio::test]
    async fn idle_freeze_handshake_cancels_without_service_socket() {
        let dir = tempfile::tempdir().unwrap();
        let cg_path = fake_cgroup(dir.path(), "echo");

        let daemon = Daemon::new(DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test-handshake-missing.sock".to_string(),
        });
        daemon
            .services
            .lock()
            .insert("echo".to_string(), idle_service("echo", cg_path, None));

        // No mesh socket: the handshake times out at the notify layer and
        // the freeze cancels in-state.
        let outcome = daemon
            .freeze_for_idle_with("echo", Duration::from_millis(100))
            .await;
        assert!(matches!(outcome, Ok(None)), "{outcome:?}");
        assert_eq!(
            daemon.services.lock().get("echo").unwrap().protocol_state(),
            ServiceState::Running
        );
    }

    #[tokio::test]
    async fn resume_reconciliation_thaws_running_service_only() {
        let root = std::env::temp_dir().join(format!(
            "mesh-init-reconcile-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();

        for name in ["running", "intentional"] {
            let path = root.join(name);
            std::fs::create_dir(&path).unwrap();
            std::fs::write(path.join("cgroup.events"), "populated 1\nfrozen 1\n").unwrap();
            std::fs::write(path.join("cgroup.freeze"), "1").unwrap();
        }

        let daemon = Daemon::new(DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test-reconcile.sock".to_string(),
        });
        let mut running = ManagedProcess::new(AppConfig::default());
        running.state = states::ServiceState::Running;
        running.target_state = states::ServiceState::Running;
        running.cgroup_path = Some(root.join("running").display().to_string());

        let mut intentional = ManagedProcess::new(AppConfig::default());
        intentional.state = states::ServiceState::Frozen {
            reason: states::FreezeReason::User,
            since: std::time::Instant::now(),
        };
        intentional.explicit_freeze = true;
        intentional.target_state = states::ServiceState::Running;
        intentional.cgroup_path = Some(root.join("intentional").display().to_string());

        {
            let mut services = daemon.services.lock();
            services.insert("running".to_string(), running);
            services.insert("intentional".to_string(), intentional);
        }

        let counts = daemon.reconcile_unexpected_frozen_services().await;
        // No mesh sockets are listening, so both ordered lifecycle
        // notifications are reported as delivery failures.
        assert_eq!(counts, (1, 1, 2));

        assert_eq!(
            std::fs::read_to_string(root.join("running/cgroup.freeze")).unwrap(),
            "0"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("intentional/cgroup.freeze")).unwrap(),
            "1"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn reconcile_rejects_unprivileged_peer() {
        let daemon = Daemon::new(DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test-reconcile-auth.sock".to_string(),
        });
        let response = daemon.handle_reconcile(424_242).await;
        assert!(!response.success);
        assert!(
            response
                .error
                .is_some_and(|error| error.contains("permission denied"))
        );
    }

    #[test]
    fn test_dangerous_env_filter_drops_default_blocked_names() {
        let _guard = env_lock().lock().unwrap();
        unsafe { std::env::remove_var("MESH_DANGEROUS_ENV") };
        let config = AppConfig::default();
        let mut env = HashMap::from([
            ("APP_MODE".to_string(), "prod".to_string()),
            ("PATH".to_string(), "/tmp/bin".to_string()),
            ("LD_PRELOAD".to_string(), "/tmp/libhack.so".to_string()),
            ("BASH_FUNC_demo%%".to_string(), "() { :; }".to_string()),
        ]);

        scrub_dangerous_env(&mut env, &config);

        assert_eq!(env.get("APP_MODE").map(String::as_str), Some("prod"));
        assert!(!env.contains_key("PATH"));
        assert!(!env.contains_key("LD_PRELOAD"));
        assert!(!env.contains_key("BASH_FUNC_demo%%"));
    }

    #[test]
    fn test_dangerous_env_filter_honors_service_allowlist() {
        let _guard = env_lock().lock().unwrap();
        unsafe { std::env::remove_var("MESH_DANGEROUS_ENV") };
        let config = AppConfig {
            allow_dangerous_env: vec!["PATH".to_string(), "BASH_FUNC_*".to_string()],
            ..Default::default()
        };
        let mut env = HashMap::from([
            ("PATH".to_string(), "/opt/app/bin".to_string()),
            ("LD_PRELOAD".to_string(), "/tmp/libhack.so".to_string()),
            ("BASH_FUNC_demo%%".to_string(), "() { :; }".to_string()),
        ]);

        scrub_dangerous_env(&mut env, &config);

        assert!(env.contains_key("PATH"));
        assert!(env.contains_key("BASH_FUNC_demo%%"));
        assert!(!env.contains_key("LD_PRELOAD"));
    }

    #[test]
    fn test_dangerous_env_filter_uses_global_override() {
        let _guard = env_lock().lock().unwrap();
        unsafe { std::env::set_var("MESH_DANGEROUS_ENV", "SECRET_*,APP_MODE") };
        let config = AppConfig::default();
        let mut env = HashMap::from([
            ("PATH".to_string(), "/tmp/bin".to_string()),
            ("APP_MODE".to_string(), "prod".to_string()),
            ("SECRET_TOKEN".to_string(), "s3cr3t".to_string()),
        ]);

        scrub_dangerous_env(&mut env, &config);

        unsafe { std::env::remove_var("MESH_DANGEROUS_ENV") };
        assert!(env.contains_key("PATH"));
        assert!(!env.contains_key("APP_MODE"));
        assert!(!env.contains_key("SECRET_TOKEN"));
    }

    #[test]
    fn test_activation_context_overrides_caller_metadata_env() {
        let _guard = env_lock().lock().unwrap();
        unsafe { std::env::remove_var("MESH_DANGEROUS_ENV") };
        let mut config = AppConfig {
            env: HashMap::from([("SSH_MESH_ROUTE_USER".to_string(), "spoofed".to_string())]),
            ..Default::default()
        };
        let context = ActivationContext {
            kind: "ssh".to_string(),
            user: "alice".to_string(),
            command: None,
            certificate_user: None,
            peer_key_sha: None,
            client_id: None,
            env: HashMap::new(),
        };

        apply_activation_context_env(&mut config, Some(context));

        assert_eq!(
            config.env.get("SSH_MESH_ROUTE_USER").map(String::as_str),
            Some("alice")
        );
    }

    #[test]
    fn test_daemon_config_loading() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("sleep.toml");
        std::fs::write(
            &config_path,
            r#"
[Service]
ExecStart = "/bin/sleep 10"
OOMScoreAdjust = -700
"#,
        )
        .unwrap();

        let configs = config::load_system_configs(&[dir.path().to_str().unwrap()]);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].name, "sleep");
        assert_eq!(configs[0].priority, 300);
        assert_eq!(configs[0].command, "/bin/sleep");
    }

    #[test]
    fn test_daemon_creation() {
        let cfg = DaemonConfig {
            config_dirs: vec!["/nonexistent".to_string()],
            socket_path: "/tmp/mesh-init-test.sock".to_string(),
        };
        let daemon = Daemon::new(cfg);
        assert!(daemon.services.lock().is_empty());
    }

    #[tokio::test]
    async fn test_start_terminal_uses_named_config_and_passed_fd() {
        let cfg = DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test.sock".to_string(),
        };
        let daemon = Daemon::new(cfg);
        let tracked = Arc::new(parking_lot::Mutex::new(HashSet::new()));
        *daemon.tracked_child_pids.lock() = Some(tracked.clone());
        let current_uid = unsafe { libc::getuid() };
        let current_gid = unsafe { libc::getgid() };
        let home = tempfile::tempdir().unwrap();

        daemon.configs.lock().insert(
            "alice".to_string(),
            AppConfig {
                name: "alice".to_string(),
                command: "/bin/sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "printf 'uid=%s home=%s user=%s\\n' \"$(id -u)\" \"$HOME\" \"$USER\""
                        .to_string(),
                ],
                uid: Some(current_uid),
                gid: Some(current_gid),
                oneshot: true,
                ..Default::default()
            },
        );

        let (child_end, mut parent_end) = std::os::unix::net::UnixStream::pair().unwrap();
        let request = Request::StartTerminal {
            name: "alice".to_string(),
            home: home.path().to_string_lossy().into_owned(),
            uid: current_uid,
            gid: Some(current_gid),
            pty: false,
            env: HashMap::from([
                (
                    "HOME".to_string(),
                    home.path().to_string_lossy().into_owned(),
                ),
                ("USER".to_string(), "alice".to_string()),
            ]),
            context: None,
            command: None,
            fd_count: None,
        };

        let response = daemon
            .handle_request_with_fd(request, OwnedFd::from(child_end), 0, 0)
            .await;
        assert!(response.success, "{:?}", response.error);
        let pid = response
            .data
            .as_ref()
            .and_then(|data| data.get("pid"))
            .and_then(serde_json::Value::as_u64)
            .expect("terminal response includes pid") as u32;
        assert!(
            tracked.lock().contains(&pid),
            "terminal pid {pid} should be tracked for SIGCHLD reaping"
        );

        let mut output = String::new();
        parent_end.read_to_string(&mut output).unwrap();
        assert!(output.contains(&format!("uid={}", current_uid)), "{output}");
        assert!(
            output.contains(&format!("home={}", home.path().display())),
            "{output}"
        );
        assert!(output.contains("user=alice"), "{output}");
    }

    #[tokio::test]
    async fn test_start_terminal_maps_three_stdio_fds() {
        let cfg = DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test.sock".to_string(),
        };
        let daemon = Daemon::new(cfg);
        let current_uid = unsafe { libc::getuid() };
        let current_gid = unsafe { libc::getgid() };
        let home = tempfile::tempdir().unwrap();

        daemon.configs.lock().insert(
            "alice".to_string(),
            AppConfig {
                name: "alice".to_string(),
                command: "/bin/sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "printf 'out\\n'; printf 'err\\n' >&2".to_string(),
                ],
                uid: Some(current_uid),
                gid: Some(current_gid),
                oneshot: true,
                ..Default::default()
            },
        );

        let (stdin_child, stdin_parent) = std::os::unix::net::UnixStream::pair().unwrap();
        let (stdout_child, mut stdout_parent) = std::os::unix::net::UnixStream::pair().unwrap();
        let (stderr_child, mut stderr_parent) = std::os::unix::net::UnixStream::pair().unwrap();
        let request = Request::StartTerminal {
            name: "alice".to_string(),
            home: home.path().to_string_lossy().into_owned(),
            uid: current_uid,
            gid: Some(current_gid),
            pty: false,
            env: HashMap::new(),
            context: None,
            command: None,
            fd_count: Some(3),
        };

        let response = daemon
            .handle_request_with_fds(
                request,
                vec![
                    OwnedFd::from(stdin_child),
                    OwnedFd::from(stdout_child),
                    OwnedFd::from(stderr_child),
                ],
                0,
                0,
            )
            .await;
        assert!(response.success, "{:?}", response.error);
        drop(stdin_parent);

        let mut stdout = String::new();
        let mut stderr = String::new();
        stdout_parent.read_to_string(&mut stdout).unwrap();
        stderr_parent.read_to_string(&mut stderr).unwrap();

        assert_eq!(stdout, "out\n");
        assert_eq!(stderr, "err\n");
    }

    #[tokio::test]
    async fn test_start_terminal_rejects_uid_mismatch_for_non_root_peer() {
        let cfg = DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test.sock".to_string(),
        };
        let daemon = Daemon::new(cfg);
        let current_uid = unsafe { libc::getuid() };
        let current_gid = unsafe { libc::getgid() };
        let home = tempfile::tempdir().unwrap();

        let (child_end, _parent_end) = std::os::unix::net::UnixStream::pair().unwrap();
        // Request a uid different from the peer's (current_uid).
        let requested_uid = if current_uid == 0 {
            // root peer is allowed to spawn as any uid; nothing to test here.
            return;
        } else if privileged_uids().contains(&current_uid) {
            // Privileged mesh-init peers, such as the default system uid 1000,
            // are also allowed to spawn as another uid.
            return;
        } else {
            current_uid.saturating_add(1)
        };
        let request = Request::StartTerminal {
            name: "dynamic-user".to_string(),
            home: home.path().to_string_lossy().into_owned(),
            uid: requested_uid,
            gid: Some(current_gid.saturating_add(1)),
            env: HashMap::new(),
            pty: false,
            context: None,
            command: None,
            fd_count: None,
        };

        // Pass peer_uid = current_uid (the actual non-root user).
        let response = daemon
            .handle_request_with_fd(request, OwnedFd::from(child_end), current_uid, current_gid)
            .await;
        assert!(
            !response.success,
            "non-root peer must not be able to spawn as a different uid; got success: {:?}",
            response.data
        );
        assert!(
            response
                .error
                .as_deref()
                .is_some_and(|e| e.contains("permission denied")),
            "expected permission-denied error, got: {:?}",
            response.error
        );
    }

    #[tokio::test]
    async fn test_register_namespace_stores_netns_fd() {
        let cfg = DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test.sock".to_string(),
        };
        let daemon = Daemon::new(cfg);
        let current_uid = unsafe { libc::getuid() };
        let mut proc = ManagedProcess::new(AppConfig {
            name: "net-svc".to_string(),
            command: "/bin/sleep".to_string(),
            args: vec!["60".to_string()],
            uid: Some(current_uid),
            ..Default::default()
        });
        proc.state = states::ServiceState::Running;
        proc.target_state = states::ServiceState::Running;
        proc.pid = Some(1234);
        daemon.services.lock().insert("net-svc".to_string(), proc);

        let (child_end, _parent_end) = std::os::unix::net::UnixStream::pair().unwrap();
        let response = daemon
            .handle_request_with_fd(
                Request::RegisterNamespace {
                    name: "net-svc".to_string(),
                    kind: NamespaceKind::Net,
                    target_pid: None,
                },
                OwnedFd::from(child_end),
                current_uid,
                unsafe { libc::getgid() },
            )
            .await;

        assert!(response.success, "{:?}", response.error);
        let status = daemon
            .services
            .lock()
            .get("net-svc")
            .expect("service")
            .status();
        assert!(status.netns_registered);
    }

    #[tokio::test]
    async fn test_register_namespace_rejects_unknown_service() {
        let cfg = DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test.sock".to_string(),
        };
        let daemon = Daemon::new(cfg);
        let current_uid = unsafe { libc::getuid() };
        let (child_end, _parent_end) = std::os::unix::net::UnixStream::pair().unwrap();

        let response = daemon
            .handle_request_with_fd(
                Request::RegisterNamespace {
                    name: "missing".to_string(),
                    kind: NamespaceKind::Net,
                    target_pid: None,
                },
                OwnedFd::from(child_end),
                current_uid,
                unsafe { libc::getgid() },
            )
            .await;

        assert!(!response.success);
        assert!(
            response
                .error
                .as_deref()
                .is_some_and(|e| e.contains("not found")),
            "expected not-found error, got: {:?}",
            response.error
        );
    }

    #[tokio::test]
    async fn test_privileged_uids_default_includes_root_system_and_mesh() {
        let _guard = ENV_MUTEX.lock();
        // Ensure no override env var leaks from another test.
        unsafe { std::env::remove_var("MESH_INIT_PRIVILEGED_UIDS") };
        let uids = privileged_uids();
        assert!(uids.contains(&0), "root must be privileged");
        assert!(uids.contains(&1000), "system (1000) must be privileged");
        assert!(
            uids.contains(&150),
            "default ssh-mesh uid (150) must be privileged"
        );
    }

    static ENV_MUTEX: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[tokio::test]
    async fn test_privileged_uids_env_override() {
        let _guard = ENV_MUTEX.lock();
        unsafe { std::env::set_var("MESH_INIT_PRIVILEGED_UIDS", "0,42") };
        let uids = privileged_uids();
        unsafe { std::env::remove_var("MESH_INIT_PRIVILEGED_UIDS") };
        assert_eq!(uids, vec![0, 42]);
    }

    #[tokio::test]
    async fn test_check_impersonation_allows_privileged_for_any_target() {
        let _guard = ENV_MUTEX.lock();
        // A privileged UID (1000) may target any UID.
        assert!(check_impersonation(1000, 1000, 0, None, "svc").is_ok());
        assert!(check_impersonation(1000, 1000, 9999, Some(9999), "svc").is_ok());
    }

    #[tokio::test]
    async fn test_check_impersonation_rejects_unprivileged_mismatch() {
        // A non-privileged UID may only target itself.
        assert!(check_impersonation(5000, 5000, 5000, None, "svc").is_ok());
        assert!(check_impersonation(5000, 5000, 0, None, "svc").is_err());
        assert!(check_impersonation(5000, 5000, 5000, Some(6000), "svc").is_err());
        assert!(check_impersonation(5000, 6000, 5000, Some(6000), "svc").is_ok());
    }

    #[test]
    fn restart_delay_jitter_keeps_one_second_delay_exact() {
        assert_eq!(restart_delay_with_jitter("svc-a", 1), 1);
    }

    #[test]
    fn restart_delay_jitter_is_bounded_and_deterministic() {
        let first = restart_delay_with_jitter("svc-a", 100);
        let second = restart_delay_with_jitter("svc-a", 100);
        assert_eq!(first, second);
        assert!((100..=110).contains(&first));
    }

    #[test]
    fn scheduler_selects_the_nearest_service_deadline() {
        let daemon = Daemon::new(DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test-scheduler-deadline.sock".to_string(),
        });
        let now = std::time::Instant::now();

        let mut restart = ManagedProcess::new(AppConfig::default());
        restart.state = states::ServiceState::Stopped;
        restart.target_state = states::ServiceState::Running;
        restart.next_restart_at = Some(now + std::time::Duration::from_secs(30));

        let watchdog_config = AppConfig {
            watchdog_sec: Some(5),
            ..AppConfig::default()
        };
        let mut watchdog = ManagedProcess::new(watchdog_config);
        watchdog.state = states::ServiceState::Running;
        watchdog.target_state = states::ServiceState::Running;
        watchdog.started_at = Some(now);

        daemon.services.lock().extend([
            ("restart".to_string(), restart),
            ("watchdog".to_string(), watchdog),
        ]);

        assert_eq!(
            daemon.next_service_deadline(),
            Some(now + std::time::Duration::from_secs(5))
        );
    }

    #[test]
    fn scheduler_waits_for_ready_match_before_arming_watchdog() {
        let daemon = Daemon::new(DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test-scheduler-ready.sock".to_string(),
        });
        let config = AppConfig {
            watchdog_sec: Some(5),
            ready_match: Some("ready".to_string()),
            ..AppConfig::default()
        };
        let mut proc = ManagedProcess::new(config);
        proc.state = states::ServiceState::Running;
        proc.target_state = states::ServiceState::Running;
        proc.started_at = Some(std::time::Instant::now());
        proc.ready = false;
        daemon.services.lock().insert("service".to_string(), proc);

        assert_eq!(daemon.next_service_deadline(), None);
    }

    #[tokio::test]
    async fn test_oneshot_restart_behavior() {
        let daemon = Daemon::new(DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test-oneshot.sock".to_string(),
        });

        let mut config = AppConfig::default();
        config.name = "oneshot-svc".to_string();
        config.oneshot = true;
        config.restart = RestartPolicy::No;

        // 1. Exit with 0, Restart=No
        {
            let mut proc = ManagedProcess::new(config.clone());
            proc.state = states::ServiceState::Running;
            proc.target_state = states::ServiceState::Running;
            proc.pid = Some(9999);
            daemon
                .services
                .lock()
                .insert("oneshot-svc".to_string(), proc);
            daemon
                .configs
                .lock()
                .insert("oneshot-svc".to_string(), config.clone());

            daemon.handle_child_exit(9999, 0);

            let services = daemon.services.lock();
            let proc = services.get("oneshot-svc").unwrap();
            assert_eq!(proc.target_state, states::ServiceState::Stopped);
            assert_eq!(proc.state, states::ServiceState::Stopped);
            assert!(proc.pid.is_none());
        }

        // 2. Exit with 1, Restart=No
        {
            let mut proc = ManagedProcess::new(config.clone());
            proc.state = states::ServiceState::Running;
            proc.target_state = states::ServiceState::Running;
            proc.pid = Some(9998);
            daemon
                .services
                .lock()
                .insert("oneshot-svc".to_string(), proc);

            daemon.handle_child_exit(9998, 1);

            let services = daemon.services.lock();
            let proc = services.get("oneshot-svc").unwrap();
            assert_eq!(proc.target_state, states::ServiceState::Stopped);
        }

        // 3. Exit with 1, Restart=OnFailure
        {
            let mut config_fail = config.clone();
            config_fail.restart = RestartPolicy::OnFailure;
            let mut proc = ManagedProcess::new(config_fail.clone());
            proc.state = states::ServiceState::Running;
            proc.target_state = states::ServiceState::Running;
            proc.pid = Some(9997);
            daemon
                .services
                .lock()
                .insert("oneshot-svc".to_string(), proc);
            daemon
                .configs
                .lock()
                .insert("oneshot-svc".to_string(), config_fail);

            daemon.handle_child_exit(9997, 1);

            let services = daemon.services.lock();
            let proc = services.get("oneshot-svc").unwrap();
            // Should restart! So target_state is still Running
            assert_eq!(proc.target_state, states::ServiceState::Running);
        }
    }

    #[tokio::test]
    async fn test_restart_sec_backoff_behavior() {
        let daemon = Daemon::new(DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test-restart-sec.sock".to_string(),
        });

        let mut config = AppConfig::default();
        config.name = "restart-sec-svc".to_string();
        config.restart = RestartPolicy::Always;
        config.restart_sec = 5; // 5 seconds restart delay

        // consecutive_failures should accumulate and use exponential backoff starting at 5s
        let mut proc = ManagedProcess::new(config.clone());
        proc.state = states::ServiceState::Running;
        proc.target_state = states::ServiceState::Running;
        proc.pid = Some(9999);
        daemon
            .services
            .lock()
            .insert("restart-sec-svc".to_string(), proc);
        daemon
            .configs
            .lock()
            .insert("restart-sec-svc".to_string(), config.clone());

        // First crash (ran for < 10s)
        daemon.handle_child_exit(9999, 1);
        {
            let services = daemon.services.lock();
            let proc = services.get("restart-sec-svc").unwrap();
            assert_eq!(proc.consecutive_failures, 1);
            let delay_dur = proc
                .next_restart_at
                .unwrap()
                .duration_since(std::time::Instant::now());
            assert!(
                delay_dur >= std::time::Duration::from_millis(4500)
                    && delay_dur <= std::time::Duration::from_millis(6500)
            );
        }

        // Simulate restarting (updating state/pid, keep consecutive_failures=1)
        {
            let mut services = daemon.services.lock();
            let proc = services.get_mut("restart-sec-svc").unwrap();
            proc.state = states::ServiceState::Running;
            proc.pid = Some(9998);
            proc.started_at = Some(std::time::Instant::now());
        }

        // Second crash (ran for < 10s)
        daemon.handle_child_exit(9998, 1);
        {
            let services = daemon.services.lock();
            let proc = services.get("restart-sec-svc").unwrap();
            assert_eq!(proc.consecutive_failures, 2);
            let delay_dur = proc
                .next_restart_at
                .unwrap()
                .duration_since(std::time::Instant::now());
            assert!(
                delay_dur >= std::time::Duration::from_millis(9500)
                    && delay_dur <= std::time::Duration::from_millis(11500)
            );
        }

        // Simulate restarting, running for > 10s (successful run)
        {
            let mut services = daemon.services.lock();
            let proc = services.get_mut("restart-sec-svc").unwrap();
            proc.state = states::ServiceState::Running;
            proc.pid = Some(9997);
            proc.started_at = Some(std::time::Instant::now() - std::time::Duration::from_secs(12));
        }

        // Third crash (after running successfully for > 10s)
        daemon.handle_child_exit(9997, 1);
        {
            let services = daemon.services.lock();
            let proc = services.get("restart-sec-svc").unwrap();
            // consecutive_failures should be reset to 1
            assert_eq!(proc.consecutive_failures, 1);
            let delay_dur = proc
                .next_restart_at
                .unwrap()
                .duration_since(std::time::Instant::now());
            assert!(
                delay_dur >= std::time::Duration::from_millis(4500)
                    && delay_dur <= std::time::Duration::from_millis(6500)
            );
        }
    }

    #[tokio::test]
    async fn test_watchdog_timeout_behavior() {
        let daemon = Daemon::new(DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test-watchdog.sock".to_string(),
        });

        let mut config = AppConfig::default();
        config.name = "watchdog-svc".to_string();
        config.watchdog_sec = Some(2); // 2 seconds watchdog
        config.watchdog_match = Some("active".to_string());

        let mut proc = ManagedProcess::new(config.clone());
        proc.state = states::ServiceState::Running;
        proc.target_state = states::ServiceState::Running;
        proc.pid = Some(9999);
        proc.started_at = Some(std::time::Instant::now() - std::time::Duration::from_secs(3)); // already past startup grace period
        proc.last_watchdog_ping =
            Some(std::time::Instant::now() - std::time::Duration::from_secs(3)); // watchdog expired!

        daemon
            .services
            .lock()
            .insert("watchdog-svc".to_string(), proc);

        // Run check_restarts. This should detect the watchdog timeout and kill the process.
        daemon.check_restarts();

        // In check_restarts, we kill via process::send_signal. Since PID 9999 doesn't exist, it won't crash the test.
        // Let's verify that last_watchdog_ping hasn't changed, but let's check that if we update last_watchdog_ping, check_restarts doesn't kill it.
        {
            let mut services = daemon.services.lock();
            let proc = services.get_mut("watchdog-svc").unwrap();
            proc.last_watchdog_ping = Some(std::time::Instant::now());
        }
        // This time it shouldn't trigger watchdog (last_watchdog_ping is recent).
        daemon.check_restarts();
    }

    #[tokio::test]
    async fn test_idle_termination_behavior() {
        let daemon = Daemon::new(DaemonConfig {
            config_dirs: vec![],
            socket_path: "/tmp/mesh-init-test-idle.sock".to_string(),
        });

        let mut config = AppConfig::default();
        config.name = "idle-svc".to_string();
        config.idle_termination_sec = Some(2);

        let mut proc = ManagedProcess::new(config.clone());
        proc.state = states::ServiceState::Running;
        proc.target_state = states::ServiceState::Running;
        proc.pid = Some(9999);
        proc.last_active = Some(0);
        proc.last_sess = Some(0);
        proc.last_stderr_at = Some(std::time::Instant::now() - std::time::Duration::from_secs(3)); // no stderr for 3 seconds

        daemon.services.lock().insert("idle-svc".to_string(), proc);

        // First check_restarts tick: sets idle_since
        daemon.check_restarts();

        {
            let services = daemon.services.lock();
            let proc = services.get("idle-svc").unwrap();
            assert!(proc.idle_since.is_some());
        }

        // Simulate time passing (move idle_since back in time)
        {
            let mut services = daemon.services.lock();
            let proc = services.get_mut("idle-svc").unwrap();
            proc.idle_since = Some(std::time::Instant::now() - std::time::Duration::from_secs(3));
        }

        // Second check_restarts tick: triggers idle termination
        daemon.check_restarts();

        {
            let services = daemon.services.lock();
            let proc = services.get("idle-svc").unwrap();
            assert_eq!(proc.target_state, states::ServiceState::Stopped);
        }
    }
}
