//! UDP implementation of the QUIC-lite bearer contract.
//!
//! This is low-level packet transport code. It must not expose or depend on
//! application streams, stream IDs, stream offsets, or application framing.
//! It only moves complete opaque QUIC packets through the interfaces in
//! [`crate::bearer`].
//!
//! This module owns Tokio socket I/O and host socket policy only. The fixed
//! peer-to-`PeerL2Address` mapping is runtime-independent core code. Linux
//! callers may use [`TokioUdpBearer::bind`]. Android or another platform may
//! bind an fd to the required network, convert it to a [`std::net::UdpSocket`],
//! and pass it to [`TokioUdpBearer::from_std`]. Both paths apply the same host
//! socket-buffer policy; configured DSCP is applied as IPv4 `IP_TOS` or IPv6
//! `IPV6_TCLASS`. Platform network selection and permissions remain outside
//! `quic-lite`.

use std::{
    format, io,
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
};

use tokio::{net::UdpSocket, sync::Notify};

use crate::bearer::{
    BearerContext, BearerId, BearerInfo, BearerName, PacketBearer, PacketEgress, PacketIngress,
    PacketMeta, PacketPool, PacketSubmitError, PacketWriter, PeerL2Address,
};
use crate::peer_table::{PeerL2Table, PeerL2TableFull};

/// Host kernel queue request used by the default UDP bearer configuration.
///
/// Kernels may clamp or account for this value differently. Failure to apply
/// it is still reported: silently using a small queue recreates the loss mode
/// that the old host UDP listener worked around.
pub const HOST_UDP_SOCKET_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// Parse a bearer endpoint using `default_port` when the name omits a port.
///
/// Accepted forms include `udp://192.0.2.1:4433`, `192.0.2.1`,
/// `[2001:db8::1]`, and the link-local forms `[fe80::1%wlan0]:4433` and
/// `[fe80::1%3]`. Interface names are resolved from the normal Linux sysfs
/// network-interface index; numeric scope IDs work on every host.
pub fn parse_peer(name: &str, default_port: u16) -> io::Result<SocketAddr> {
    let name = name.strip_prefix("udp://").unwrap_or(name);
    if let Ok(address) = name.parse::<SocketAddr>() {
        return Ok(address);
    }
    if let Ok(address) = name.parse::<IpAddr>() {
        return Ok(SocketAddr::new(address, default_port));
    }
    if let Some(address) = name
        .strip_prefix('[')
        .and_then(|name| name.strip_suffix(']'))
        .and_then(|address| address.parse::<Ipv6Addr>().ok())
    {
        return Ok(SocketAddr::new(IpAddr::V6(address), default_port));
    }
    let (address_scope, port) = name
        .strip_prefix('[')
        .and_then(|name| {
            name.rsplit_once("]:")
                .map(|(address, port)| (address, Some(port)))
                .or_else(|| name.strip_suffix(']').map(|address| (address, None)))
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid UDP peer"))?;
    let (address, scope) = address_scope.rsplit_once('%').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "scoped IPv6 peer needs %INTERFACE",
        )
    })?;
    let address = address
        .parse::<Ipv6Addr>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let port = port
        .map(str::parse::<u16>)
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
        .unwrap_or(default_port);
    let scope_id = scope.parse::<u32>().ok().or_else(|| {
        std::fs::read_to_string(format!("/sys/class/net/{scope}/ifindex"))
            .ok()
            .and_then(|index| index.trim().parse::<u32>().ok())
    });
    let scope_id = scope_id.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown IPv6 scope interface {scope:?}"),
        )
    })?;
    Ok(SocketAddr::V6(SocketAddrV6::new(
        address, port, 0, scope_id,
    )))
}

/// Wildcard bind address in the peer's address family.
pub const fn wildcard_bind(peer: SocketAddr, port: u16) -> SocketAddr {
    match peer {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), port),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
    }
}

/// Socket policy shared by newly bound and platform-adopted UDP sockets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpSocketConfig {
    /// Six-bit Differentiated Services Code Point. ECN bits are left clear.
    pub dscp: Option<u8>,
    /// Requested kernel receive queue size in bytes, or platform default.
    pub receive_buffer_bytes: Option<usize>,
    /// Requested kernel send queue size in bytes, or platform default.
    pub send_buffer_bytes: Option<usize>,
}

impl Default for UdpSocketConfig {
    fn default() -> Self {
        Self {
            dscp: None,
            receive_buffer_bytes: Some(HOST_UDP_SOCKET_BUFFER_BYTES),
            send_buffer_bytes: Some(HOST_UDP_SOCKET_BUFFER_BYTES),
        }
    }
}

impl UdpSocketConfig {
    fn validate(self) -> io::Result<Self> {
        if self.dscp.is_some_and(|dscp| dscp > 63) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP DSCP must fit in six bits",
            ));
        }
        for bytes in [self.receive_buffer_bytes, self.send_buffer_bytes]
            .into_iter()
            .flatten()
        {
            if bytes == 0 || i32::try_from(bytes).is_err() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UDP socket buffer size must be in 1..=i32::MAX",
                ));
            }
        }
        Ok(self)
    }
}

#[cfg(unix)]
fn set_socket_option(
    socket: &impl std::os::fd::AsRawFd,
    level: libc::c_int,
    option: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&value as *const libc::c_int).cast(),
            core::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn configure_socket(
    socket: &impl std::os::fd::AsRawFd,
    address: SocketAddr,
    config: UdpSocketConfig,
) -> io::Result<()> {
    let config = config.validate()?;
    if let Some(bytes) = config.receive_buffer_bytes {
        set_socket_option(
            socket,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            bytes as libc::c_int,
        )?;
    }
    if let Some(bytes) = config.send_buffer_bytes {
        set_socket_option(
            socket,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            bytes as libc::c_int,
        )?;
    }
    if let Some(dscp) = config.dscp {
        let traffic_class = libc::c_int::from(dscp << 2);
        match address {
            SocketAddr::V4(_) => {
                set_socket_option(socket, libc::IPPROTO_IP, libc::IP_TOS, traffic_class)?;
            }
            SocketAddr::V6(_) => {
                set_socket_option(socket, libc::IPPROTO_IPV6, libc::IPV6_TCLASS, traffic_class)?;
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn configure_socket(
    _socket: &std::net::UdpSocket,
    _address: SocketAddr,
    config: UdpSocketConfig,
) -> io::Result<()> {
    let config = config.validate()?;
    if config.dscp.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "UDP DSCP configuration is unsupported on this platform",
        ));
    }
    Ok(())
}

#[derive(Debug)]
/// Peer-address-table failure from [`TokioUdpBearer`].
///
/// Socket receive failures are private bearer-task state. This type is public
/// only because applications explicitly register and remove peer addresses.
pub enum UdpBearerError {
    /// The fixed-capacity UDP peer table has no free entry.
    PeerTableFull,
}

enum UdpReceiveError {
    Io(io::Error),
    PoolUnavailable,
    InvalidPayloadOffset,
    PeerTableFull,
}

struct TokioUdpShared<const PEERS: usize> {
    socket: UdpSocket,
    peers: Mutex<PeerL2Table<SocketAddr, PEERS>>,
    write_blocked: AtomicBool,
    write_blocked_notify: Notify,
}

/// Cloneable handle to one Tokio UDP socket and bearer-scoped peer table.
///
/// Clones share only host I/O state. One clone may wait for receive readiness
/// while another is registered for synchronous egress; neither runs an
/// internal loop or owns QUIC state. The reusable address table itself remains
/// in the runtime-independent core.
#[derive(Clone)]
pub struct TokioUdpBearer<const PEERS: usize> {
    shared: Arc<TokioUdpShared<PEERS>>,
    info: BearerInfo,
}

impl<const PEERS: usize> TokioUdpBearer<PEERS> {
    fn new(socket: UdpSocket) -> Self {
        Self {
            shared: Arc::new(TokioUdpShared {
                socket,
                peers: Mutex::new(PeerL2Table::new()),
                write_blocked: AtomicBool::new(false),
                write_blocked_notify: Notify::new(),
            }),
            info: BearerInfo {
                name: BearerName::new("udp").unwrap(),
                max_packet_size: crate::DEFAULT_MAX_PACKET_SIZE,
                prefix_required: 0,
                suffix_required: 0,
                requires_packet_encryption: true,
                secure_link: false,
                nominal_bitrate_bps: 0,
                local_mac: None,
            },
        }
    }

    /// Change the registration name before adding the bearer to a node.
    pub fn set_name(&mut self, name: BearerName) {
        self.info.name = name;
    }

    fn peers(&self) -> MutexGuard<'_, PeerL2Table<SocketAddr, PEERS>> {
        // Every operation while holding this lock preserves the table's
        // invariants before it can panic. Recovering a poisoned host mutex is
        // therefore safer than permanently disabling the bearer.
        self.shared
            .peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Bind a normal Linux/host UDP socket without another networking crate.
    pub async fn bind(address: SocketAddr) -> io::Result<Self> {
        Self::bind_with_config(address, UdpSocketConfig::default()).await
    }

    /// Apply the bearer socket policy to an existing shared Tokio socket.
    ///
    /// This supports process listeners which must keep their `Arc<UdpSocket>`
    /// because discovery, incoming associations, and outgoing associations all
    /// share one local port. It configures only kernel socket policy and does
    /// not create a second reader or another peer table.
    pub fn configure_existing(socket: &UdpSocket, config: UdpSocketConfig) -> io::Result<()> {
        configure_socket(socket, socket.local_addr()?, config)
    }

    /// Bind and configure a normal Linux/host UDP socket.
    pub async fn bind_with_config(
        address: SocketAddr,
        config: UdpSocketConfig,
    ) -> io::Result<Self> {
        config.validate()?;
        let socket = std::net::UdpSocket::bind(address)?;
        configure_socket(&socket, socket.local_addr()?, config)?;
        Self::from_configured_std(socket)
    }

    /// Adopt a socket created and configured by the platform.
    ///
    /// Constructing it from a raw file descriptor and setting Android network
    /// binding, permissions, or interface scope remains the platform adapter's
    /// responsibility. Common kernel queue sizes are applied here.
    pub fn from_std(socket: std::net::UdpSocket) -> io::Result<Self> {
        Self::from_std_with_config(socket, UdpSocketConfig::default())
    }

    /// Adopt a platform-created socket and apply the common host policy.
    pub fn from_std_with_config(
        socket: std::net::UdpSocket,
        config: UdpSocketConfig,
    ) -> io::Result<Self> {
        config.validate()?;
        configure_socket(&socket, socket.local_addr()?, config)?;
        Self::from_configured_std(socket)
    }

    fn from_configured_std(socket: std::net::UdpSocket) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        Ok(Self::new(UdpSocket::from_std(socket)?))
    }

    /// Return the socket's effective local address after binding.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.shared.socket.local_addr()
    }

    /// Borrow the shared UDP socket for platform-specific read-only setup.
    pub fn socket(&self) -> &UdpSocket {
        &self.shared.socket
    }

    /// Return the existing handle for a peer or allocate one fixed table slot.
    pub fn register_peer(&self, peer: SocketAddr) -> Result<PeerL2Address, UdpBearerError> {
        self.peers()
            .get_or_insert(peer)
            .map_err(|PeerL2TableFull| UdpBearerError::PeerTableFull)
    }

    /// Resolve a live bearer-local peer handle to its socket address.
    pub fn peer(&self, address: PeerL2Address) -> Option<SocketAddr> {
        self.peers().peer(address).copied()
    }

    /// Find the existing bearer-local handle for a socket address.
    pub fn peer_l2_address(&self, peer: SocketAddr) -> Option<PeerL2Address> {
        self.peers().address(&peer)
    }

    /// Retire one peer mapping after the QUIC owner has released every route
    /// which uses it. A later occupant of the table slot receives a new
    /// generation-tagged handle, so a retained stale handle cannot redirect a
    /// packet to that peer.
    pub fn remove_peer(&self, peer_l2_address: PeerL2Address) -> Option<SocketAddr> {
        self.peers().remove(peer_l2_address)
    }

    /// Receive one UDP packet directly into a QUIC-owned packet-pool slot.
    ///
    /// This is the normal host receive path. The pool chooses the common
    /// prefix and suffix layout, the socket fills only the payload region, and
    /// ownership of the committed lease moves to ingress without an
    /// intermediate allocation or copy.
    async fn receive_from_pool<P, I>(
        &self,
        bearer: BearerId,
        pool: &'static P,
        payload_offset: usize,
        received_at_us: u64,
        ingress: &I,
    ) -> Result<(), UdpReceiveError>
    where
        P: PacketPool,
        I: PacketIngress<P::Buffer>,
    {
        let mut writer = pool
            .acquire_writer(payload_offset, 0)
            .ok_or(UdpReceiveError::PoolUnavailable)?;
        let output = writer.payload_mut();
        let payload_capacity = output
            .len()
            .saturating_sub(crate::PACKET_SUFFIX_RESERVE)
            .min(crate::DEFAULT_MAX_PACKET_SIZE);
        if payload_capacity == 0 {
            return Err(UdpReceiveError::InvalidPayloadOffset);
        }
        let (len, peer) = self
            .shared
            .socket
            .recv_from(&mut output[..payload_capacity])
            .await
            .map_err(UdpReceiveError::Io)?;
        let peer_l2_address = self
            .register_peer(peer)
            .map_err(|_| UdpReceiveError::PeerTableFull)?;
        let packet = writer
            .commit(len)
            .ok_or(UdpReceiveError::InvalidPayloadOffset)?;
        ingress.enqueue_packet(
            PacketMeta {
                bearer,
                peer_l2_address,
                received_at_us,
            },
            packet,
        );
        Ok(())
    }
}

impl<B: AsRef<[u8]>, const PEERS: usize> PacketEgress<B> for TokioUdpBearer<PEERS> {
    fn submit(
        &mut self,
        peer_l2_address: PeerL2Address,
        submission: crate::bearer::EgressSubmission<B>,
    ) -> Result<(), PacketSubmitError<B>> {
        let Some(peer) = self.peer(peer_l2_address) else {
            submission.complete(crate::bearer::PacketSendOutcome::Failed, 0);
            return Ok(());
        };
        let expected = submission.packet().bytes().len();
        match self
            .shared
            .socket
            .try_send_to(submission.packet().bytes(), peer)
        {
            Ok(sent) if sent == expected => {
                submission.complete(crate::bearer::PacketSendOutcome::Sent, 0);
                Ok(())
            }
            Ok(_sent) => {
                submission.complete(crate::bearer::PacketSendOutcome::Failed, 0);
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                self.shared.write_blocked.store(true, Ordering::Release);
                self.shared.write_blocked_notify.notify_one();
                Err(PacketSubmitError::WouldBlock(submission))
            }
            Err(_error) => {
                submission.complete(crate::bearer::PacketSendOutcome::Failed, 0);
                Ok(())
            }
        }
    }
}

impl<P, const PEERS: usize> PacketBearer<P> for TokioUdpBearer<PEERS>
where
    P: PacketPool + Sync + 'static,
    P::Buffer: Send + 'static,
    P::Writer: Send + 'static,
{
    type AttachError = core::convert::Infallible;

    fn info(&self) -> BearerInfo {
        self.info
    }

    fn attach(&mut self, context: BearerContext<P>) -> Result<(), Self::AttachError> {
        let receiver = self.clone();
        let receive_context = context.clone();
        tokio::spawn(async move {
            loop {
                match receiver
                    .receive_from_pool(
                        receive_context.bearer(),
                        receive_context.pool(),
                        crate::PACKET_PREFIX_RESERVE,
                        0,
                        &receive_context,
                    )
                    .await
                {
                    Ok(()) => {}
                    Err(UdpReceiveError::PoolUnavailable) => tokio::task::yield_now().await,
                    Err(_) => break,
                }
            }
        });

        let readiness = self.clone();
        tokio::spawn(async move {
            loop {
                readiness.shared.write_blocked_notify.notified().await;
                if readiness.shared.socket.writable().await.is_err() {
                    break;
                }
                if readiness.shared.write_blocked.swap(false, Ordering::AcqRel) {
                    context.send_ready();
                }
            }
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_names_apply_defaults_and_scopes() {
        assert_eq!(
            parse_peer("udp://127.0.0.1", 3339).unwrap(),
            "127.0.0.1:3339".parse().unwrap()
        );
        assert_eq!(
            parse_peer("[2001:db8::1]", 3339).unwrap(),
            "[2001:db8::1]:3339".parse().unwrap()
        );
        assert_eq!(
            parse_peer("[fe80::1%7]:4444", 3339).unwrap(),
            "[fe80::1%7]:4444".parse().unwrap()
        );
    }

    #[test]
    fn wildcard_bind_follows_peer_family() {
        assert_eq!(
            wildcard_bind("127.0.0.1:1".parse().unwrap(), 9),
            "0.0.0.0:9".parse().unwrap()
        );
        assert_eq!(
            wildcard_bind("[::1]:1".parse().unwrap(), 9),
            "[::]:9".parse().unwrap()
        );
    }

    #[cfg(unix)]
    fn socket_option(
        socket: &impl std::os::fd::AsRawFd,
        level: libc::c_int,
        option: libc::c_int,
    ) -> io::Result<libc::c_int> {
        let mut value = 0;
        let mut length = core::mem::size_of_val(&value) as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                level,
                option,
                (&mut value as *mut libc::c_int).cast(),
                &mut length,
            )
        };
        if result == 0 {
            Ok(value)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(unix)]
    fn assert_ipv4_socket_policy(socket: &UdpSocket, dscp: u8, buffer_bytes: usize) {
        assert_eq!(
            socket_option(socket, libc::IPPROTO_IP, libc::IP_TOS).unwrap() & 0xfc,
            libc::c_int::from(dscp << 2)
        );
        assert!(
            socket_option(socket, libc::SOL_SOCKET, libc::SO_RCVBUF).unwrap()
                >= buffer_bytes as libc::c_int
        );
        assert!(
            socket_option(socket, libc::SOL_SOCKET, libc::SO_SNDBUF).unwrap()
                >= buffer_bytes as libc::c_int
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_applies_dscp_and_kernel_buffers() {
        let config = UdpSocketConfig {
            dscp: Some(10),
            receive_buffer_bytes: Some(64 * 1024),
            send_buffer_bytes: Some(64 * 1024),
        };
        let bearer = TokioUdpBearer::<1>::bind_with_config("127.0.0.1:0".parse().unwrap(), config)
            .await
            .unwrap();
        assert_ipv4_socket_policy(bearer.socket(), 10, 64 * 1024);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn adopted_socket_applies_the_same_policy() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let local = socket.local_addr().unwrap();
        let config = UdpSocketConfig {
            dscp: Some(46),
            receive_buffer_bytes: Some(96 * 1024),
            send_buffer_bytes: Some(96 * 1024),
        };
        let bearer = TokioUdpBearer::<1>::from_std_with_config(socket, config).unwrap();
        assert_eq!(bearer.local_addr().unwrap(), local);
        assert_ipv4_socket_policy(bearer.socket(), 46, 96 * 1024);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ipv6_bind_applies_dscp_as_traffic_class() {
        let bearer = match TokioUdpBearer::<1>::bind_with_config(
            "[::1]:0".parse().unwrap(),
            UdpSocketConfig {
                dscp: Some(18),
                receive_buffer_bytes: None,
                send_buffer_bytes: None,
            },
        )
        .await
        {
            Ok(bearer) => bearer,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::AddrNotAvailable | io::ErrorKind::Unsupported
                ) =>
            {
                return;
            }
            Err(error) => panic!("IPv6 UDP bind/configuration failed: {error}"),
        };
        assert_eq!(
            socket_option(bearer.socket(), libc::IPPROTO_IPV6, libc::IPV6_TCLASS).unwrap() & 0xfc,
            libc::c_int::from(18 << 2)
        );
    }

    #[tokio::test]
    async fn rejects_out_of_range_dscp_before_binding() {
        let error = TokioUdpBearer::<1>::bind_with_config(
            "127.0.0.1:0".parse().unwrap(),
            UdpSocketConfig {
                dscp: Some(64),
                ..UdpSocketConfig::default()
            },
        )
        .await
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
