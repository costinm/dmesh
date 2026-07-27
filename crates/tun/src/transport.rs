use crate::policy::FlowContext;
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional};
use tokio::net::TcpStream;

pub trait TunByteStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T> TunByteStream for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

pub type BoxTunByteStream = Box<dyn TunByteStream>;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TcpFlowControlSnapshot {
    pub send_capacity_bytes: u64,
    pub unacked_packets: u32,
    pub notsent_bytes: u32,
    pub send_cwnd_packets: u32,
    pub send_mss: u32,
}

pub trait TcpFlowControl: Send + Sync + 'static {
    fn snapshot(&self) -> Option<TcpFlowControlSnapshot>;
}

pub struct ConnectedTcpStream {
    pub stream: BoxTunByteStream,
    pub flow_control: Option<Arc<dyn TcpFlowControl>>,
}

impl ConnectedTcpStream {
    pub fn generic(stream: BoxTunByteStream) -> Self {
        Self {
            stream,
            flow_control: None,
        }
    }

    pub fn with_flow_control(
        stream: BoxTunByteStream,
        flow_control: Arc<dyn TcpFlowControl>,
    ) -> Self {
        Self {
            stream,
            flow_control: Some(flow_control),
        }
    }
}

/// Bridge an already-accepted byte stream into a guest TCP listener.
///
/// The source tuple is the original peer address that should be visible to the
/// guest. The stream may be a native TCP accept, SSH channel, HBONE stream, or
/// any other bidirectional transport.
pub async fn bridge_accepted_tcp_to_guest<S>(
    injector: Arc<dyn mesh::tun::TunInjector>,
    src: SocketAddr,
    dst: SocketAddr,
    mut stream: S,
) -> Result<(u64, u64), anyhow::Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut guest = injector
        .connect_tcp(src.ip(), src.port(), dst.ip(), dst.port())
        .await?;
    Ok(copy_bidirectional(&mut stream, &mut guest).await?)
}

#[async_trait::async_trait]
pub trait TcpConnector: Send + Sync + 'static {
    async fn connect(&self, ctx: &FlowContext) -> Result<ConnectedTcpStream, anyhow::Error>;
}

#[derive(Debug, Default)]
pub struct NativeTcpConnector;

#[async_trait::async_trait]
impl TcpConnector for NativeTcpConnector {
    async fn connect(&self, ctx: &FlowContext) -> Result<ConnectedTcpStream, anyhow::Error> {
        let stream = TcpStream::connect(ctx.dst).await?;
        stream.set_nodelay(true)?;
        tune_backend_socket(&stream);
        #[cfg(target_os = "linux")]
        let flow_control =
            native_tcp_flow_control(&stream).map(|flow| Arc::new(flow) as Arc<dyn TcpFlowControl>);
        #[cfg(not(target_os = "linux"))]
        let flow_control: Option<Arc<dyn TcpFlowControl>> = None;
        let stream: BoxTunByteStream = Box::new(stream);
        match flow_control {
            Some(flow_control) => Ok(ConnectedTcpStream::with_flow_control(stream, flow_control)),
            None => Ok(ConnectedTcpStream::generic(stream)),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct NativeTcpFlowControl {
    fd: OwnedFd,
}

#[cfg(target_os = "linux")]
impl TcpFlowControl for NativeTcpFlowControl {
    fn snapshot(&self) -> Option<TcpFlowControlSnapshot> {
        let mut info = std::mem::MaybeUninit::<libc::tcp_info>::zeroed();
        let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_INFO,
                info.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return None;
        }
        let info = unsafe { info.assume_init() };
        let cwnd_bytes = u64::from(info.tcpi_snd_cwnd) * u64::from(info.tcpi_snd_mss);
        let unacked_bytes = u64::from(info.tcpi_unacked) * u64::from(info.tcpi_snd_mss);
        let notsent_bytes = tcp_info_notsent_bytes(&info);
        let queued_bytes = unacked_bytes.saturating_add(u64::from(notsent_bytes));
        Some(TcpFlowControlSnapshot {
            send_capacity_bytes: cwnd_bytes.saturating_sub(queued_bytes),
            unacked_packets: info.tcpi_unacked,
            notsent_bytes,
            send_cwnd_packets: info.tcpi_snd_cwnd,
            send_mss: info.tcpi_snd_mss,
        })
    }
}

#[cfg(all(target_os = "linux", target_env = "musl"))]
fn tcp_info_notsent_bytes(info: &libc::tcp_info) -> u32 {
    info.tcpi_notsent_bytes
}

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
fn tcp_info_notsent_bytes(_info: &libc::tcp_info) -> u32 {
    0
}

#[cfg(target_os = "linux")]
fn native_tcp_flow_control(stream: &TcpStream) -> Option<NativeTcpFlowControl> {
    let fd = unsafe { libc::dup(stream.as_raw_fd()) };
    if fd < 0 {
        tracing::debug!(
            error = %std::io::Error::last_os_error(),
            "failed to duplicate native TCP socket for flow-control metadata"
        );
        return None;
    }
    Some(NativeTcpFlowControl {
        fd: unsafe { OwnedFd::from_raw_fd(fd) },
    })
}

#[cfg(target_os = "linux")]
fn tune_backend_socket(stream: &TcpStream) {
    // Bulk proxy traffic benefits from kernel buffers that match the synthetic
    // TCP window, while TCP_NOTSENT_LOWAT reduces wakeups when the kernel send
    // queue is already full. All knobs are best-effort: policy-selected streams
    // may not always be ordinary Linux TCP sockets.
    set_sockopt_int(
        stream,
        libc::IPPROTO_TCP,
        libc::TCP_QUICKACK,
        1,
        "TCP_QUICKACK",
    );
    set_sockopt_int(
        stream,
        libc::IPPROTO_TCP,
        libc::TCP_NOTSENT_LOWAT,
        16 * 1024,
        "TCP_NOTSENT_LOWAT",
    );
    set_sockopt_int(
        stream,
        libc::SOL_SOCKET,
        libc::SO_SNDBUF,
        4 * 1024 * 1024,
        "SO_SNDBUF",
    );
    set_sockopt_int(
        stream,
        libc::SOL_SOCKET,
        libc::SO_RCVBUF,
        4 * 1024 * 1024,
        "SO_RCVBUF",
    );
}

#[cfg(target_os = "linux")]
fn set_sockopt_int(
    stream: &TcpStream,
    level: libc::c_int,
    optname: libc::c_int,
    value: libc::c_int,
    label: &'static str,
) {
    // Best-effort: TCP_QUICKACK is Linux-specific and advisory. Failure should
    // not break non-performance-critical connectors or unusual socket types.
    let rc = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            level,
            optname,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if rc != 0 {
        tracing::debug!(
            error = %std::io::Error::last_os_error(),
            "failed to set {label} on mesh-tun backend socket"
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn tune_backend_socket(_stream: &TcpStream) {}

pub struct FixedTcpConnectorPolicy {
    connector: Arc<dyn TcpConnector>,
}

impl FixedTcpConnectorPolicy {
    pub fn new(connector: Arc<dyn TcpConnector>) -> Self {
        Self { connector }
    }
}

#[async_trait::async_trait]
impl crate::policy::MeshTunPolicy for FixedTcpConnectorPolicy {
    async fn check(&self, _ctx: &FlowContext) -> crate::policy::PolicyDecision {
        crate::policy::PolicyDecision::Allow
    }

    async fn route_tcp(&self, _ctx: &FlowContext) -> crate::policy::TcpRouteDecision {
        crate::policy::TcpRouteDecision::Connect {
            connector: self.connector.clone(),
        }
    }
}
