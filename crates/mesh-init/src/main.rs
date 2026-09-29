//! mesh-init — minimal init/supervisor daemon with mesh and resource awareness.
//!
//! When run without a command, starts the supervisor daemon.
//!
//! With a command, mesh-init acts as a container supervisor: it starts configured
//! and on-demand secondary services, runs the command as its main child, and
//! shuts down when that main child exits.
//!
//! Running as root will create /run/mesh/mesh-init/mesh.sock as control socket and
//! default to /home/system/etc/mesh-init for configs.
//!
//! As a regular user it can't grant permissions or use `/run/mesh`, but will still
//! start additional services, using `$HOME/etc/mesh-init` for configuration and
//! `$HOME/.local/run/<service>/mesh.sock` for service sockets.

use anyhow::Result;
use clap::Parser;
use std::path::Path;
use tracing::info;

use mesh_init::daemon::{Daemon, DaemonConfig};

/// Wait for the termination signals used by service managers and interactive
/// supervisors. Keeping this separate lets both daemon and command mode stop
/// their managed children through `Daemon::shutdown`.
async fn termination_signal() -> Result<&'static str> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = signal(SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => Ok("SIGINT"),
            _ = sigterm.recv() => Ok("SIGTERM"),
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        Ok("SIGINT")
    }
}

#[derive(Parser, Debug)]
#[clap(name = "mesh-init", version = "0.1.0", trailing_var_arg = true)]
struct Args {
    /// Command to execute immediately. If omitted, runs as a daemon.
    command: Vec<String>,
}

// Note: this implements a narrow subset of systemd - using sockets instead of dbus,
// toml files with a subset of the fields for config, and with special adaptation for
// containers. It is far more tolerant - can run as any PID, fallbacks if it can't
// handle cgroups, etc. It is also using /home

#[tokio::main]
async fn main() -> Result<()> {
    let (_log_buffer, _trace_guard) = mesh::local_trace::init("mesh-init");

    let args = Args::parse();
    let socket_path = get_socket_path();
    let config_dirs = get_config_dirs();

    let command = if args.command.is_empty() {
        None
    } else {
        Some(args.command)
    };

    if let Some(command) = &command
        && command[0] == "seed"
    {
        return seed_command(&command[1..], &config_dirs);
    }

    run(config_dirs, socket_path, command).await
}

/// Operator command: preview or copy newly shipped default configuration.
///
/// Startup seeding only runs on first start; this command is how operators
/// merge defaults from a newer package without touching existing files.
fn seed_command(args: &[String], config_dirs: &[String]) -> Result<()> {
    let preview = args.iter().any(|arg| arg == "--preview");
    let Some(dest) = config_dirs.first() else {
        anyhow::bail!("no mesh-init configuration directory configured");
    };
    let Some(defaults) = mesh_init::seed::defaults_dir() else {
        anyhow::bail!("no packaged mesh-init defaults found; set MESH_INIT_DEFAULTS_DIR");
    };

    if preview {
        let missing = mesh_init::seed::preview_seed(Path::new(dest), &defaults)?;
        if missing.is_empty() {
            println!("up to date: all default files present in {}", dest);
        } else {
            println!("{} default file(s) missing in {}:", missing.len(), dest);
            for path in &missing {
                println!("  {}", path.display());
            }
        }
        return Ok(());
    }

    let result = mesh_init::seed::seed_operator(Path::new(dest), &defaults)?;
    println!(
        "seeded {} file(s), kept {} existing file(s) in {}",
        result.seeded.len(),
        result.skipped.len(),
        dest
    );
    for path in &result.seeded {
        println!("  copied {}", path.display());
    }
    for path in &result.skipped {
        println!("  kept {}", path.display());
    }
    Ok(())
}

/// Common startup: create the supervisor and optionally run its main child.
async fn run(
    config_dirs: Vec<String>,
    socket_path: String,
    command: Option<Vec<String>>,
) -> Result<()> {
    // Collect systemd socket activation file descriptors before the daemon
    // creates its own listeners. This must happen before start_background_tasks.
    mesh_init::activation::collect_systemd_fds();

    // Seed first-start default configuration before any config is loaded, so
    // the seeded services participate in the normal startup sequence.
    mesh_init::seed::seed_on_startup(&config_dirs);

    let config = DaemonConfig {
        config_dirs,
        socket_path: socket_path.clone(),
    };

    info!(
        pid = std::process::id(),
        uid = unsafe { libc::getuid() },
        mode = if command.is_some() { "exec" } else { "daemon" },
        "starting_mesh_init"
    );

    let daemon = Daemon::new(config);

    if let Some(command) = command {
        // Container mode remains a full supervisor. Configured services and
        // activation listeners are available while the main child runs, and
        // callers can start further on-demand services through mesh.sock.
        daemon.start_background_tasks();

        // Preserve the setup sequencing guarantee: oneshot `init-*` services
        // are setup work (mounts, network, env) that must complete before the
        // main child starts. Long-running `init-*` services are dependencies
        // that stay up, so they do not block startup.
        wait_for_init_services(&daemon).await;

        let app_name = "cmd";
        let cmd = command[0].clone();
        let args = command[1..].to_vec();

        // Apply defaults from default.toml if present. Execution mode is used
        // by VM/container init scripts as a small "run this command under the
        // default service policy" entrypoint, so hardening/identity/resource
        // fields from default.toml should apply to the command too.
        let default_cfg = daemon.configs.lock().get("default").cloned();

        let mut cfg = default_cfg.unwrap_or_default();
        cfg.name = app_name.to_string();
        cfg.command = cmd;
        cfg.args = args;
        cfg.exec_start_pre.clear();
        cfg.exec_start_post.clear();
        cfg.exec_stop.clear();
        cfg.exec_reload.clear();
        cfg.restart = mesh_init::config::RestartPolicy::No;
        cfg.oneshot = true;
        cfg.activation.clear();
        cfg.source_path = None;

        info!(command = %cfg.command, args = ?cfg.args, "executing_command");
        let _pid = daemon.start_service_with_config(cfg, None)?;

        let server = mesh_init::server::ControlServer::new(
            daemon.config.socket_path.clone(),
            daemon.clone(),
        );
        let server_run = server.run();
        tokio::pin!(server_run);
        let main_exit = wait_for_service_exit(&daemon, app_name);
        tokio::pin!(main_exit);

        tokio::select! {
            () = &mut main_exit => {
                daemon.shutdown().await;
                server_run.await?;
            }
            result = &mut server_run => {
                result?;
                // A requested daemon shutdown also terminates the main child.
                daemon.shutdown().await;
                wait_for_service_exit(&daemon, app_name).await;
            }
            signal = termination_signal() => {
                info!(signal = %signal?, "termination_signal_received");
                daemon.shutdown().await;
                server_run.await?;
            }
        }
    } else {
        // Start all background tasks: load configs, start init-* services,
        // start regular services/activation listeners, resource manager, child reaper.
        daemon.start_background_tasks();

        // Start job scheduler
        let jobs_dir = mesh::paths::AppPaths::for_app("system")
            .etc
            .join("mesh-init/jobs")
            .to_string_lossy()
            .into_owned();
        let executor =
            std::sync::Arc::new(mesh::jobs::executor::MeshInitExecutor::new(socket_path));
        let scheduler =
            std::sync::Arc::new(mesh::jobs::scheduler::JobScheduler::new(jobs_dir, executor));

        let sched_clone = scheduler.clone();
        tokio::spawn(async move {
            if let Err(e) = sched_clone.check_jobs().await {
                tracing::error!(error = %e, "jobscheduler_failed_checking_jobs");
            }
        });

        // Daemon mode: the control server runs in the foreground until a
        // control-plane shutdown or a service-manager termination signal.
        let server = mesh_init::server::ControlServer::new(
            daemon.config.socket_path.clone(),
            daemon.clone(),
        );
        let server_run = server.run();
        tokio::pin!(server_run);
        tokio::select! {
            result = &mut server_run => result?,
            signal = termination_signal() => {
                info!(signal = %signal?, "termination_signal_received");
                daemon.shutdown().await;
                server_run.await?;
            }
        }
    }

    Ok(())
}

/// Wait until configured oneshot `init-*` services have exited.
///
/// `start_background_tasks` starts services concurrently, so oneshot setup
/// services (`init-*` with `Type = "oneshot"`) can race the main child. This
/// waits for them to reach the `Stopped` state before the caller proceeds.
/// A bounded deadline keeps a wedged setup service from hanging container
/// startup forever; the timeout is logged and startup continues.
async fn wait_for_init_services(daemon: &std::sync::Arc<Daemon>) {
    const INIT_SEQUENCE_TIMEOUT_SECS: u64 = 120;

    let init_names: Vec<String> = {
        let configs = daemon.configs.lock();
        let mut names: Vec<String> = configs
            .values()
            .filter(|cfg| cfg.name.starts_with("init-") && cfg.oneshot)
            .map(|cfg| cfg.name.clone())
            .collect();
        names.sort();
        names
    };
    if init_names.is_empty() {
        return;
    }

    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(INIT_SEQUENCE_TIMEOUT_SECS);
    let mut rx = daemon.service_exit_tx.subscribe();

    loop {
        let pending: Vec<String> = {
            let services = daemon.services.lock();
            init_names
                .iter()
                .filter(|name| match services.get(*name) {
                    Some(proc) => {
                        !(proc.state == mesh_init::states::ServiceState::Stopped
                            && proc.pid.is_none())
                    }
                    None => false,
                })
                .cloned()
                .collect()
        };
        if pending.is_empty() {
            return;
        }

        let now = tokio::time::Instant::now();
        if now >= deadline {
            tracing::warn!(
                services = ?pending,
                timeout_secs = INIT_SEQUENCE_TIMEOUT_SECS,
                "init_services_timeout_continuing"
            );
            return;
        }

        // Service exits are announced on the broadcast channel; wake on any
        // exit and re-check. A timeout just loops until the deadline.
        let _ = tokio::time::timeout(deadline - now, rx.recv()).await;
    }
}

/// Wait until a service transitions to Stopped state.
async fn wait_for_service_exit(daemon: &std::sync::Arc<Daemon>, name: &str) {
    let mut rx = daemon.service_exit_tx.subscribe();

    // Check initial state first to avoid missing an exit that happened before we subscribed
    {
        let services = daemon.services.lock();
        if let Some(proc) = services.get(name) {
            if proc.state == mesh_init::states::ServiceState::Stopped && proc.pid.is_none() {
                return;
            }
        } else {
            return;
        }
    }

    while let Ok(exited_name) = rx.recv().await {
        if exited_name == name {
            let services = daemon.services.lock();
            if let Some(proc) = services.get(name) {
                if proc.state == mesh_init::states::ServiceState::Stopped && proc.pid.is_none() {
                    break;
                }
            } else {
                break;
            }
        }
    }
}

fn get_config_dirs() -> Vec<String> {
    mesh_init::config::core_config_dirs()
        .into_iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect()
}

fn get_socket_path() -> String {
    if let Ok(path) = std::env::var("MESH_INIT_SOCK") {
        return path;
    }
    if let Ok(dir) = std::env::var("MESH_INIT_RUN") {
        return std::path::PathBuf::from(dir)
            .join("control.sock")
            .to_string_lossy()
            .into_owned();
    }
    mesh::paths::AppPaths::for_app("mesh-init")
        .mesh_socket()
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_paths_use_system_app_home() {
        assert_eq!(
            get_config_dirs(),
            mesh_init::config::core_config_dirs()
                .into_iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            get_socket_path(),
            mesh::paths::AppPaths::for_app("mesh-init")
                .mesh_socket()
                .to_string_lossy()
        );
    }
}
