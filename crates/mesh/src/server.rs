use crate::auth::{AuthConfig, DelegationEnvelope};
use crate::paths::AppPaths;
use std::collections::HashSet;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::pin::Pin;
use std::sync::{Mutex, OnceLock};
use std::task::{Context, Poll};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufStream, ReadBuf};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info, warn};

/// Set `FD_CLOEXEC` on an existing file descriptor.
///
/// Best-effort: logs a warning on failure. This prevents the FD from being
/// inherited by child processes spawned via `execve()`.
fn set_cloexec(fd: i32) {
    // SAFETY: fd is a valid open file descriptor. F_GETFD/F_SETFD do not
    // have undefined behavior on valid fds.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return;
    }
    if flags & libc::FD_CLOEXEC == 0 {
        // SAFETY: as above.
        let _ = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    }
}

pub enum MeshStream {
    /// A UDS stream plus the activity connection guard held for its lifetime.
    Uds(UnixStream, Option<crate::activity::ConnectionGuard>),
    /// A UDS stream that has had its read side buffered (e.g. after consuming a
    /// leading delegation envelope line). Buffered bytes are preserved for
    /// subsequent reads.
    UdsBuf(
        BufStream<UnixStream>,
        Option<crate::activity::ConnectionGuard>,
    ),
    Stdio {
        stdin: tokio::io::Stdin,
        stdout: tokio::io::Stdout,
        /// Activity held for the lifetime of a stdio-activated instance.
        _guard: Option<crate::activity::ConnectionGuard>,
    },
}

impl AsyncRead for MeshStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            MeshStream::Uds(s, _) => Pin::new(s).poll_read(cx, buf),
            MeshStream::UdsBuf(s, _) => Pin::new(s).poll_read(cx, buf),
            MeshStream::Stdio { stdin, .. } => Pin::new(stdin).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MeshStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            MeshStream::Uds(s, _) => Pin::new(s).poll_write(cx, buf),
            MeshStream::UdsBuf(s, _) => Pin::new(s).poll_write(cx, buf),
            MeshStream::Stdio { stdout, .. } => Pin::new(stdout).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            MeshStream::Uds(s, _) => Pin::new(s).poll_flush(cx),
            MeshStream::UdsBuf(s, _) => Pin::new(s).poll_flush(cx),
            MeshStream::Stdio { stdout, .. } => Pin::new(stdout).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            MeshStream::Uds(s, _) => Pin::new(s).poll_shutdown(cx),
            MeshStream::UdsBuf(s, _) => Pin::new(s).poll_shutdown(cx),
            MeshStream::Stdio { stdout, .. } => Pin::new(stdout).poll_shutdown(cx),
        }
    }
}

enum ListenerMode {
    Uds(UnixListener),
    Stdio(bool), // bool is `has_yielded`
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivatedFdKind {
    Tcp,
    Unix,
    Vsock,
    Other(i32),
}

static TAKEN_ACTIVATED_FDS: OnceLock<Mutex<HashSet<i32>>> = OnceLock::new();

fn taken_activated_fds() -> &'static Mutex<HashSet<i32>> {
    TAKEN_ACTIVATED_FDS.get_or_init(|| Mutex::new(HashSet::new()))
}

pub struct MeshListener {
    mode: ListenerMode,
    auth: Option<AuthConfig>,
    current_uid: u32,
    /// When true, peer UIDs configured as delegates must send a validated
    /// `DelegationEnvelope` as the first line of the connection. Opt-in via the
    /// `MESH_ENFORCE_DELEGATION` env var. Defaults to `false` for backward
    /// compatibility.
    enforce_delegation: bool,
}

impl MeshListener {
    pub fn new(
        app_name: &str,
        listen_path: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let auth = AuthConfig::load_for_app(app_name);
        let current_uid = unsafe { libc::getuid() };
        let enforce_delegation = std::env::var("MESH_ENFORCE_DELEGATION")
            .map(|v| {
                let v = v.trim();
                v.eq_ignore_ascii_case("1") || v.eq_ignore_ascii_case("true") || v == "yes"
            })
            .unwrap_or(false);

        let mode = if let Some(listener) = take_activated_unix_listener()? {
            ListenerMode::Uds(listener)
        } else if let Some(path_str) = listen_path {
            Self::bind_uds(app_name, path_str)?
        } else {
            info!("MeshListener: Serving over stdin/stdout");
            ListenerMode::Stdio(false)
        };

        Ok(Self {
            mode,
            auth,
            current_uid,
            enforce_delegation,
        })
    }

    fn bind_uds(
        app_name: &str,
        path_str: &str,
    ) -> Result<ListenerMode, Box<dyn std::error::Error>> {
        let actual_path = if path_str.starts_with('_') {
            path_str.replacen('_', "\0", 1)
        } else if path_str.starts_with('/') {
            path_str.to_string()
        } else {
            let dir = AppPaths::for_app(app_name).run_dir(app_name);
            let _ = std::fs::create_dir_all(&dir);
            dir.join(path_str).to_string_lossy().into_owned()
        };

        if !actual_path.starts_with('\0') {
            let path = std::path::Path::new(&actual_path);
            if path.exists() {
                let _ = std::fs::remove_file(path);
            }
        }
        let listener = UnixListener::bind(&actual_path)?;
        info!("MeshListener: Listening on UDS {:?}", actual_path);

        if !actual_path.starts_with('\0') {
            // Public mesh IPC is connectable by local clients; handlers
            // authenticate requests at the protocol layer.
            let mut perms = std::fs::metadata(&actual_path)?.permissions();
            perms.set_mode(0o666);
            std::fs::set_permissions(&actual_path, perms)?;
        }

        Ok(ListenerMode::Uds(listener))
    }

    pub async fn accept(&mut self) -> Result<Option<MeshStream>, Box<dyn std::error::Error>> {
        match &mut self.mode {
            ListenerMode::Uds(listener) => loop {
                let (stream, _) = listener.accept().await?;
                let peer_uid = stream.peer_cred()?.uid();

                let auth = self.auth.as_ref();
                let is_authorized = match auth {
                    Some(a) => a.is_uid_authorized(peer_uid, self.current_uid),
                    None => crate::auth::AuthConfig::is_builtin_uid_authorized(
                        peer_uid,
                        self.current_uid,
                    ),
                };

                if !is_authorized {
                    error!(
                        "MeshListener: Unauthorized UDS connection from UID {}",
                        peer_uid
                    );
                    continue;
                }

                // Activity tracking (phase 2a): long-lived sessions keep the
                // service busy for mesh-init's idle policy.
                let guard = Some(crate::activity::connection());

                // Delegation enforcement: if the peer UID is configured as a
                // trusted delegate, require a DelegationEnvelope as the first
                // line and validate it before serving any HTTP. This prevents a
                // delegate (e.g. sshd) from asserting arbitrary identities.
                if self.enforce_delegation
                    && let Some(a) = auth
                    && a.get_delegate(peer_uid).is_some()
                {
                    match Self::read_and_validate_delegation(stream, a, peer_uid).await {
                        Ok(buf_stream) => return Ok(Some(MeshStream::UdsBuf(buf_stream, guard))),
                        Err(reason) => {
                            warn!(
                                "MeshListener: rejecting delegated connection from UID {}: {}",
                                peer_uid, reason
                            );
                            continue;
                        }
                    }
                }

                return Ok(Some(MeshStream::Uds(stream, guard)));
            },
            ListenerMode::Stdio(yielded) => {
                if *yielded {
                    return Ok(None);
                }
                *yielded = true;

                // For stdio mode, mesh-init handles auth checking prior to activation
                // No need to check X_PEER_UID here.
                Ok(Some(MeshStream::Stdio {
                    stdin: tokio::io::stdin(),
                    stdout: tokio::io::stdout(),
                    _guard: Some(crate::activity::connection()),
                }))
            }
        }
    }

    /// Read the leading `DelegationEnvelope` line from a delegate connection
    /// and validate it against the auth config. On success returns the
    /// buffered stream (preserving any HTTP bytes already read).
    async fn read_and_validate_delegation(
        stream: UnixStream,
        auth: &AuthConfig,
        delegate_uid: u32,
    ) -> Result<BufStream<UnixStream>, String> {
        let mut buf_stream = BufStream::new(stream);
        // Cap the envelope line at 8 KiB to prevent unbounded reads.
        const MAX_ENVELOPE_LEN: usize = 8 * 1024;
        let mut line = Vec::with_capacity(256);
        loop {
            let buffered = buf_stream
                .fill_buf()
                .await
                .map_err(|e| format!("read error: {e}"))?;
            if buffered.is_empty() {
                return Err("connection closed before delegation envelope".to_string());
            }
            if let Some(pos) = buffered.iter().position(|&b| b == b'\n') {
                line.extend_from_slice(&buffered[..pos]);
                // Consume only up to and including the newline; bytes after it
                // remain in BufStream's buffer for subsequent HTTP reads.
                buf_stream.consume(pos + 1);
                break;
            }
            // No newline yet: accumulate the whole buffer and keep filling.
            line.extend_from_slice(buffered);
            let n = buffered.len();
            buf_stream.consume(n);
            if line.len() > MAX_ENVELOPE_LEN {
                return Err("delegation envelope exceeds 8 KiB".to_string());
            }
        }

        let envelope: DelegationEnvelope = serde_json::from_slice(&line)
            .map_err(|e| format!("invalid delegation envelope JSON: {e}"))?;

        auth.validate_delegation(delegate_uid, &envelope.peer)
            .map_err(|e| format!("delegation rejected: {e}"))?;

        if !auth.is_peer_allowed(&envelope.peer) {
            return Err(format!(
                "delegated identity {:?} not permitted by peer allowlist",
                envelope.peer
            ));
        }

        Ok(buf_stream)
    }
}

pub fn activated_listener_fds() -> Result<Vec<i32>, Box<dyn std::error::Error>> {
    if let Ok(fd_str) = std::env::var("LISTEN_FD") {
        let fd = fd_str.parse::<i32>()?;
        return Ok(vec![fd]);
    }

    if let Ok(fds_str) = std::env::var("LISTEN_FDS") {
        let fds = fds_str.parse::<i32>()?;
        if fds > 0 {
            // systemd socket activation always starts passing descriptors at
            // fd 3. mesh-init uses the same convention for Accept=false services.
            return Ok((3..3 + fds).collect());
        }
    }

    Ok(Vec::new())
}

pub fn activated_fd_kind(fd: i32) -> Result<ActivatedFdKind, Box<dyn std::error::Error>> {
    let mut socket_type: libc::c_int = 0;
    let mut socket_type_len = std::mem::size_of_val(&socket_type) as libc::socklen_t;
    // SAFETY: socket_type points to writable memory of socket_type_len bytes.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut socket_type_len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if socket_type != libc::SOCK_STREAM {
        return Ok(ActivatedFdKind::Other(socket_type));
    }

    // SAFETY: sockaddr_storage is a plain old data buffer initialized by getsockname.
    let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut addr_len = std::mem::size_of_val(&addr) as libc::socklen_t;
    // SAFETY: addr points to writable storage large enough for addr_len bytes.
    let rc = unsafe {
        libc::getsockname(
            fd,
            (&mut addr as *mut libc::sockaddr_storage).cast(),
            &mut addr_len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let family = addr.ss_family as libc::c_int;
    if family == libc::AF_UNIX {
        Ok(ActivatedFdKind::Unix)
    } else if family == libc::AF_INET || family == libc::AF_INET6 {
        Ok(ActivatedFdKind::Tcp)
    } else if family == libc::AF_VSOCK {
        Ok(ActivatedFdKind::Vsock)
    } else {
        Ok(ActivatedFdKind::Other(family))
    }
}

pub fn first_activated_listener_fd(
    kind: ActivatedFdKind,
) -> Result<Option<i32>, Box<dyn std::error::Error>> {
    for fd in activated_listener_fds()? {
        if taken_activated_fds()
            .lock()
            .map(|taken| taken.contains(&fd))
            .unwrap_or(false)
        {
            debug!(fd, "skipping already claimed activated listener fd");
            continue;
        }

        match activated_fd_kind(fd) {
            Ok(fd_kind) if fd_kind == kind => return Ok(Some(fd)),
            Ok(fd_kind) => debug!(
                fd,
                ?fd_kind,
                wanted = ?kind,
                "skipping activated listener fd"
            ),
            Err(e) => debug!(fd, error = %e, "skipping unusable activated listener fd"),
        }
    }
    Ok(None)
}

fn mark_activated_listener_fd_taken(fd: i32) {
    if let Ok(mut taken) = taken_activated_fds().lock() {
        taken.insert(fd);
    }
}

pub fn take_activated_unix_listener() -> Result<Option<UnixListener>, Box<dyn std::error::Error>> {
    let Some(fd) = first_activated_listener_fd(ActivatedFdKind::Unix)? else {
        return Ok(None);
    };
    mark_activated_listener_fd_taken(fd);
    info!("MeshListener: Using activated Unix listener FD {}", fd);
    // SAFETY: activated_fd_kind verifies that fd is an open Unix stream socket.
    // from_raw_fd takes ownership exactly once in this activation path.
    let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    std_listener.set_nonblocking(true)?;
    set_cloexec(std_listener.as_raw_fd());
    Ok(Some(UnixListener::from_std(std_listener)?))
}

pub fn take_activated_tcp_listener()
-> Result<Option<std::net::TcpListener>, Box<dyn std::error::Error>> {
    let Some(fd) = first_activated_listener_fd(ActivatedFdKind::Tcp)? else {
        return Ok(None);
    };
    mark_activated_listener_fd_taken(fd);
    info!("Using activated TCP listener FD {}", fd);
    // SAFETY: activated_fd_kind verifies that fd is an open TCP stream socket.
    // from_raw_fd takes ownership exactly once in this activation path.
    let listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
    listener.set_nonblocking(true)?;
    set_cloexec(listener.as_raw_fd());
    Ok(Some(listener))
}

pub fn activated_listener_names() -> Vec<String> {
    std::env::var("LISTEN_FDNAMES")
        .ok()
        .map(|names| parse_activated_listener_names(&names))
        .unwrap_or_default()
}

fn parse_activated_listener_names(names: &str) -> Vec<String> {
    names
        .split(|c: char| c == ':' || c.is_ascii_whitespace())
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

pub fn activated_listener_fd_by_name(
    name: &str,
) -> Result<Option<i32>, Box<dyn std::error::Error>> {
    let names = activated_listener_names();
    if names.is_empty() {
        return Ok(None);
    }
    let fds = activated_listener_fds()?;
    for (idx, fd_name) in names.iter().enumerate() {
        if fd_name == name {
            return Ok(fds.get(idx).copied());
        }
    }
    Ok(None)
}

pub fn first_activated_listener_fd_by_name(
    name: &str,
    kind: ActivatedFdKind,
) -> Result<Option<i32>, Box<dyn std::error::Error>> {
    let names = activated_listener_names();
    if names.is_empty() {
        return Ok(None);
    }
    let fds = activated_listener_fds()?;
    for (idx, fd_name) in names.iter().enumerate() {
        if fd_name != name {
            continue;
        }
        let Some(fd) = fds.get(idx).copied() else {
            continue;
        };
        if taken_activated_fds()
            .lock()
            .map(|taken| taken.contains(&fd))
            .unwrap_or(false)
        {
            debug!(
                fd,
                name, "skipping already claimed named activated listener fd"
            );
            continue;
        }
        match activated_fd_kind(fd) {
            Ok(fd_kind) if fd_kind == kind => return Ok(Some(fd)),
            Ok(fd_kind) => debug!(
                fd,
                name,
                ?fd_kind,
                wanted = ?kind,
                "skipping named activated listener fd"
            ),
            Err(e) => {
                debug!(fd, name, error = %e, "skipping unusable named activated listener fd");
            }
        }
    }
    Ok(None)
}

pub fn take_activated_unix_listener_by_name(
    name: &str,
) -> Result<Option<UnixListener>, Box<dyn std::error::Error>> {
    let Some(fd) = first_activated_listener_fd_by_name(name, ActivatedFdKind::Unix)? else {
        return Ok(None);
    };
    mark_activated_listener_fd_taken(fd);
    info!(
        "MeshListener: Using activated Unix listener FD {} ({})",
        fd, name
    );
    // SAFETY: activated_fd_kind verifies that fd is an open Unix stream socket.
    // from_raw_fd takes ownership exactly once in this activation path.
    let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    std_listener.set_nonblocking(true)?;
    set_cloexec(std_listener.as_raw_fd());
    Ok(Some(UnixListener::from_std(std_listener)?))
}

pub fn take_activated_tcp_listener_by_name(
    name: &str,
) -> Result<Option<std::net::TcpListener>, Box<dyn std::error::Error>> {
    let Some(fd) = first_activated_listener_fd_by_name(name, ActivatedFdKind::Tcp)? else {
        return Ok(None);
    };
    mark_activated_listener_fd_taken(fd);
    info!("Using activated TCP listener FD {} ({})", fd, name);
    // SAFETY: activated_fd_kind verifies that fd is an open TCP stream socket.
    // from_raw_fd takes ownership exactly once in this activation path.
    let listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
    listener.set_nonblocking(true)?;
    set_cloexec(listener.as_raw_fd());
    Ok(Some(listener))
}

pub fn take_activated_vsock_listener_by_name(
    name: &str,
) -> Result<Option<OwnedFd>, Box<dyn std::error::Error>> {
    let Some(fd) = first_activated_listener_fd_by_name(name, ActivatedFdKind::Vsock)? else {
        return Ok(None);
    };
    mark_activated_listener_fd_taken(fd);
    info!("Using activated AF_VSOCK listener FD {} ({})", fd, name);
    // SAFETY: activated_fd_kind verifies that fd is an open AF_VSOCK stream socket.
    // from_raw_fd takes ownership exactly once in this activation path.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    set_cloexec(fd.as_raw_fd());
    Ok(Some(fd))
}

pub fn take_activated_vsock_listener() -> Result<Option<OwnedFd>, Box<dyn std::error::Error>> {
    let Some(fd) = first_activated_listener_fd(ActivatedFdKind::Vsock)? else {
        return Ok(None);
    };
    mark_activated_listener_fd_taken(fd);
    info!("Using activated AF_VSOCK listener FD {}", fd);
    // SAFETY: activated_fd_kind verifies that fd is an open AF_VSOCK stream socket.
    // from_raw_fd takes ownership exactly once in this activation path.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    set_cloexec(fd.as_raw_fd());
    Ok(Some(fd))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_activated_listener_names_accepts_colons_and_spaces() {
        assert_eq!(
            parse_activated_listener_names("ssh:http admin:jsonl ssh-uds"),
            vec!["ssh", "http", "admin", "jsonl", "ssh-uds"]
        );
    }
}
