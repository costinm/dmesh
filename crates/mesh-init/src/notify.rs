//! sd_notify-compatible notify channel (phase 2b).
//!
//! mesh-init sets `NOTIFY_SOCKET` for every service it spawns, like systemd.
//! The socket is a datagram socket the daemon owns. The sender is identified
//! by `SCM_CREDENTIALS`: the PID must belong to the service's cgroup, so no
//! service can speak for another.
//!
//! Recognized messages (newline separated `KEY=VALUE`):
//!
//! | Message                | Origin  | Meaning                                    |
//! |------------------------|---------|--------------------------------------------|
//! | `READY=1`              | systemd | Started; supports `Type=notify`            |
//! | `WATCHDOG=1`           | systemd | Watchdog ping                              |
//! | `STOPPING=1`           | systemd | Shown in status                            |
//! | `STATUS=…`             | systemd | Human readable status line                 |
//! | `FDSTORE=1`+`FDNAME=`  | systemd | Hand sockets to mesh-init to watch frozen  |
//! | `X_MESH_IDLE=1`        | mesh    | Idle, with `X_MESH_ACTIVE=`/`X_MESH_CONNS=`|
//! | `X_MESH_BUSY=1`        | mesh    | Busy again                                 |
//! | `X_MESH_WAKE_AT=`      | mesh    | CLOCK_MONOTONIC µs of the next timer       |

use std::collections::HashMap;
use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use nix::cmsg_space;
use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrLike, UnixAddr, recvmsg};
use parking_lot::Mutex;
use tracing::{debug, info, warn};

use crate::process::{ActivityCounts, ManagedProcess};

/// Deterministic datagram endpoint for a service.
pub fn notify_socket_path(service_name: &str) -> String {
    mesh::paths::AppPaths::for_app(service_name)
        .run_dir(service_name)
        .join("notify.sock")
        .to_string_lossy()
        .into_owned()
}

/// Set `NOTIFY_SOCKET` on a service environment unless the config already
/// chose one explicitly.
pub fn apply_notify_env(name: &str, env: &mut HashMap<String, String>) {
    env.entry("NOTIFY_SOCKET".to_string())
        .or_insert_with(|| notify_socket_path(name));
}

/// One parsed notify datagram.
#[derive(Debug)]
pub enum NotifyMessage {
    Ready,
    Watchdog,
    Stopping,
    Status(String),
    /// FDSTORE with `SCM_RIGHTS` payloads; the daemon watches its copies and
    /// drops them after each thaw.
    FdStore(Vec<OwnedFd>, Option<String>),
    /// Service self-reported state; wake_at_us mirrors X_MESH_WAKE_AT.
    State {
        idle: bool,
        counts: ActivityCounts,
        wake_at_us: Option<u64>,
    },
    Ignored,
}

/// Parse one notify datagram body.
///
/// The fds received in the ancillary data join the message when `FDSTORE`
/// appears in the body.
pub fn parse_notify(body: &[u8], fds: Vec<OwnedFd>) -> anyhow::Result<NotifyMessage> {
    anyhow::ensure!(
        fds.is_empty() || text_mentions_fdstore(body),
        "fds received without FDSTORE message"
    );
    let text = std::str::from_utf8(body)?;
    let mut keys: HashMap<&str, &str> = HashMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        keys.insert(key, value);
    }

    if keys.contains_key("FDSTORE") {
        let name = keys.get("FDNAME").map(|s| s.trim().to_string());
        return Ok(NotifyMessage::FdStore(fds, name));
    }
    if keys.contains_key("READY") {
        return Ok(NotifyMessage::Ready);
    }
    if keys.contains_key("WATCHDOG") {
        return Ok(NotifyMessage::Watchdog);
    }
    if keys.contains_key("STOPPING") {
        return Ok(NotifyMessage::Stopping);
    }
    if let Some(status) = keys.get("STATUS") {
        return Ok(NotifyMessage::Status(status.to_string()));
    }
    for key in ["X_MESH_IDLE", "X_MESH_BUSY"] {
        if keys.contains_key(key) {
            let wake_at_us = keys
                .get("X_MESH_WAKE_AT")
                .and_then(|v| v.trim().parse::<u64>().ok())
                .filter(|v| *v > 0);
            let counts = ActivityCounts {
                connections: keys
                    .get("X_MESH_CONNS")
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0),
                requests: keys
                    .get("X_MESH_REQS")
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0),
                holds: keys
                    .get("X_MESH_ACTIVE")
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0),
            };
            return Ok(NotifyMessage::State {
                idle: key == "X_MESH_IDLE",
                counts,
                wake_at_us,
            });
        }
    }
    Ok(NotifyMessage::Ignored)
}

fn text_mentions_fdstore(body: &[u8]) -> bool {
    String::from_utf8_lossy(body).contains("FDSTORE")
}

/// Whether a sender PID belongs to a service scope, checked via
/// `cgroup.procs` — the durable proxy for `[proc/PID/cgroup.txt] membership.
pub fn pid_in_cgroup(pid: u32, cgroup_path: &str) -> bool {
    let Ok(procs) = std::fs::read_to_string(format!("{cgroup_path}/cgroup.procs")) else {
        return false;
    };
    procs.lines().any(|line| line.trim() == pid.to_string())
}

/// A receiver for one service.
pub struct NotifyReceiver {
    pub service_name: String,
    pub cgroup_path: Option<String>,
    /// Shared service registry used to apply notifications under the lock.
    pub services: Arc<Mutex<HashMap<String, ManagedProcess>>>,
    /// Scheduler wake channel so idle/wake changes re-arm timers.
    pub scheduler_tx: Option<tokio::sync::watch::Sender<u64>>,
    socket_path: String,
    raw_fd: std::os::fd::RawFd,
    /// Socket-owned fds handed to the daemon, keyed by FDNAME.
    pub stored_fds: Mutex<Vec<(Option<String>, OwnedFd)>>,
}

/// One raw datagram read with ancillary data.
struct Datagram {
    sender_pid: Option<u32>,
    body: Vec<u8>,
    fds: Vec<OwnedFd>,
}

fn recv_datagram(fd: i32) -> Result<Datagram, std::io::Error> {
    const BUFFER_SIZE: usize = 8192;
    let mut body = vec![0_u8; BUFFER_SIZE];
    let (bytes, fds, sender_pid) = {
        let mut iov = [std::io::IoSliceMut::new(&mut body)];
        let mut space = cmsg_space!([libc::c_int; 16], libc::ucred);
        let message = recvmsg::<UnixAddr>(fd, &mut iov, Some(&mut space), MsgFlags::MSG_DONTWAIT)
            .map_err(std::io::Error::from)?;
        if message.flags.contains(MsgFlags::MSG_CTRUNC) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "notify ancillary data truncated; descriptors lost",
            ));
        }
        let mut fds = Vec::new();
        let mut sender_pid = None;
        for cmsg in message.cmsgs().map_err(std::io::Error::from)? {
            match cmsg {
                ControlMessageOwned::ScmRights(rights) => {
                    for raw in rights {
                        fds.push(unsafe { OwnedFd::from_raw_fd(raw) });
                    }
                }
                ControlMessageOwned::ScmCredentials(cred) => {
                    sender_pid = Some(cred.pid() as u32);
                }
                _ => {}
            }
        }
        (message.bytes, fds, sender_pid)
    };
    body.truncate(bytes);
    Ok(Datagram {
        sender_pid,
        body,
        fds,
    })
}

impl NotifyReceiver {
    /// Bind the notify socket for a service. The path is removed on drop.
    pub fn bind(service_name: &str, cgroup_path: Option<String>) -> anyhow::Result<Self> {
        let socket_path = notify_socket_path(service_name);
        if let Some(parent) = std::path::Path::new(&socket_path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _ = std::fs::remove_file(&socket_path);
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            anyhow::bail!(
                "socket(AF_UNIX, SOCK_DGRAM): {}",
                std::io::Error::last_os_error()
            );
        }
        let addr = UnixAddr::new(socket_path.as_str())
            .map_err(std::io::Error::from)
            .map_err(anyhow::Error::from)?;
        let rc = unsafe { libc::bind(fd, addr.as_ptr().cast(), addr.len()) };
        if rc != 0 {
            unsafe { libc::close(fd) };
            anyhow::bail!("bind {}: {}", socket_path, std::io::Error::last_os_error());
        }
        // Any local uid may notify; PID membership is the guard.
        if let Ok(metadata) = std::fs::metadata(&socket_path) {
            let mut perms = metadata.permissions();
            std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o666);
            let _ = std::fs::set_permissions(&socket_path, perms);
        }
        Ok(Self {
            service_name: service_name.to_string(),
            cgroup_path,
            services: Arc::new(Mutex::new(HashMap::new())),
            scheduler_tx: None,
            socket_path,
            raw_fd: fd,
            stored_fds: Mutex::new(Vec::new()),
        })
    }

    /// Bind with explicit shared handles (used by the daemon).
    pub fn bind_with(
        service_name: &str,
        cgroup_path: Option<String>,
        services: Arc<Mutex<HashMap<String, ManagedProcess>>>,
        scheduler_tx: tokio::sync::watch::Sender<u64>,
    ) -> anyhow::Result<Self> {
        let mut receiver = Self::bind(service_name, cgroup_path)?;
        receiver.services = services;
        receiver.scheduler_tx = Some(scheduler_tx);
        Ok(receiver)
    }

    /// Apply one mutation to the owning service under the registry lock.
    fn apply<F: FnOnce(&mut ManagedProcess)>(&self, mutate: F) {
        let mut services = self.services.lock();
        if let Some(proc) = services.get_mut(&self.service_name) {
            mutate(proc);
        }
        drop(services);
        if let Some(scheduler_tx) = &self.scheduler_tx
            && scheduler_tx.receiver_count() > 0
        {
            scheduler_tx.send_modify(|revision| {
                *revision = revision.wrapping_add(1);
            });
        }
    }

    /// Reader loop; returns when `stop` is set.
    pub fn run_with_stop(&self, stop: &AtomicBool) {
        let flags = unsafe { libc::fcntl(self.raw_fd, libc::F_GETFL) };
        if flags >= 0 {
            unsafe { libc::fcntl(self.raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        }
        loop {
            if stop.load(Ordering::Acquire) {
                break;
            }
            match recv_datagram(self.raw_fd) {
                Ok(datagram) => {
                    if let Err(error) = self.handle(datagram) {
                        debug!(error = %error, "notify_datagram_failed");
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    // Poll-free sleep keeps CPU usage negligible while the
                    // service is quiet; notify datagrams are rare.
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(_) => {
                    // The kernel dropped a datagram or a transient error
                    // occurred; keep watching.
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
    }

    fn handle(&self, datagram: Datagram) -> anyhow::Result<()> {
        let service = self.service_name.as_str();
        // Guard: the sender PID must belong to the service's cgroup.
        if let (Some(cg), Some(pid)) = (self.cgroup_path.as_ref(), datagram.sender_pid)
            && !pid_in_cgroup(pid, cg)
        {
            warn!(service, pid, "notify_sender_not_in_service_cgroup");
            anyhow::bail!("sender pid {pid} is not in {cg}");
        }
        let message = parse_notify(&datagram.body, datagram.fds)?;
        match message {
            NotifyMessage::FdStore(fds, name) => {
                info!(service, count = fds.len(), "notify_fdstore_received");
                // FDSTORE hands sockets to mesh-init to watch while frozen
                // and to pass back after a restart via LISTEN_FDS.
                let mut stored = self.stored_fds.lock();
                for (order, fd) in (stored.len()..).zip(fds.into_iter()) {
                    crate::activation::register_service_listener_fd(
                        service,
                        order,
                        &fd,
                        name.clone(),
                    );
                    stored.push((name.clone(), fd));
                }
            }
            NotifyMessage::Ready => {
                self.apply(|proc| {
                    proc.ready = true;
                });
            }
            NotifyMessage::Watchdog => {
                self.apply(|proc| {
                    proc.last_watchdog_ping = Some(std::time::Instant::now());
                });
            }
            NotifyMessage::Stopping => {
                info!(service, "service_reported_stopping");
            }
            NotifyMessage::Status(status) => {
                debug!(service, status, "service_status_update");
            }
            NotifyMessage::State {
                idle,
                counts,
                wake_at_us,
            } => {
                self.apply(move |proc| {
                    proc.notify_activity = Some(counts);
                    if idle {
                        if proc.idle_since.is_none() {
                            proc.idle_since = Some(std::time::Instant::now());
                        }
                    } else {
                        proc.idle_since = None;
                    }
                    proc.wake_at = wake_at_us;
                });
            }
            NotifyMessage::Ignored => {}
        }
        Ok(())
    }
}

impl Drop for NotifyReceiver {
    fn drop(&mut self) {
        unsafe { libc::close(self.raw_fd) };
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mesh_state_messages() {
        let message =
            parse_notify(b"X_MESH_IDLE=1\nX_MESH_ACTIVE=0\nX_MESH_CONNS=0\n", vec![]).unwrap();
        match message {
            NotifyMessage::State {
                idle,
                counts,
                wake_at_us,
            } => {
                assert!(idle);
                assert_eq!(counts.connections, 0);
                assert!(counts.is_idle());
                assert!(wake_at_us.is_none());
            }
            other => panic!("expected state, got {other:?}"),
        }

        let message = parse_notify(b"X_MESH_IDLE=1\nX_MESH_CONNS=2\n", vec![]).unwrap();
        match message {
            NotifyMessage::State { idle, counts, .. } => {
                assert!(idle);
                assert_eq!(counts.connections, 2);
                assert!(!counts.is_idle());
            }
            other => panic!("expected state, got {other:?}"),
        }

        let message = parse_notify(
            b"X_MESH_BUSY=1\nX_MESH_ACTIVE=3\nX_MESH_WAKE_AT=12345\n",
            vec![],
        )
        .unwrap();
        match message {
            NotifyMessage::State {
                idle,
                counts,
                wake_at_us,
            } => {
                assert!(!idle);
                assert_eq!(counts.holds, 3);
                assert_eq!(wake_at_us, Some(12345));
            }
            other => panic!("expected state, got {other:?}"),
        }
    }

    #[test]
    fn parses_systemd_standard_messages() {
        assert!(matches!(
            parse_notify(b"READY=1\n", vec![]).unwrap(),
            NotifyMessage::Ready
        ));
        assert!(matches!(
            parse_notify(b"WATCHDOG=1\n", vec![]).unwrap(),
            NotifyMessage::Watchdog
        ));
        assert!(matches!(
            parse_notify(b"STOPPING=1\n", vec![]).unwrap(),
            NotifyMessage::Stopping
        ));
        assert!(matches!(
            parse_notify(b"STATUS=loading\n", vec![]).unwrap(),
            NotifyMessage::Status(_)
        ));
        assert!(matches!(
            parse_notify(b"OTHER=1\n", vec![]).unwrap(),
            NotifyMessage::Ignored
        ));
    }

    #[test]
    fn fdstore_names_carry_fds() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let fd: OwnedFd = a.into();
        let message = parse_notify(b"FDSTORE=1\nFDNAME=http\n", vec![fd]).unwrap();
        match message {
            NotifyMessage::FdStore(fds, name) => {
                assert_eq!(fds.len(), 1);
                assert_eq!(name, Some("http".to_string()));
            }
            other => panic!("expected fdstore, got {other:?}"),
        }
    }
}
