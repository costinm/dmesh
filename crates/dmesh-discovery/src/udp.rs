//! The UDP discovery transport: multicast announces and solicitation,
//! directed discovery, and the receive loop. Enabled by the `tokio` feature.
//!
//! Discovery on UDP is a raw tagged-CBOR datagram; QUIC is not involved. A
//! platform that already owns the socket (the QUIC listener on Linux, a
//! descriptor handed over by Android) passes it in, and a datagram that
//! arrives on a socket someone else reads goes to [`UdpDiscovery::on_datagram`].

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::oneshot;

use crate::engine::{Carrier, Engine, Received};
use crate::inventory::Device;

/// The shared multicast discovery port.
pub const MULTICAST_PORT: u16 = 5227;
/// Best-effort IPv4 compatibility group.
pub const MULTICAST_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 250);
/// The IPv6 link-local group, joined and sent on per interface.
pub const MULTICAST_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x5227);

/// Where announces and solicitations go.
#[derive(Clone, Debug)]
pub enum Destinations {
    /// The multicast groups on every live IPv6 interface (and IPv4, for older peers).
    Multicast { ipv4: bool },
    /// These addresses only: tests, and a node that is told whom to ask.
    Fixed(Vec<SocketAddr>),
}

/// The multicast destinations for the given IPv6 interface indices.
pub fn multicast_destinations(ipv4: bool, indices: &[u32]) -> Vec<SocketAddr> {
    let mut destinations = Vec::new();
    if ipv4 {
        destinations.push(SocketAddr::new(MULTICAST_V4.into(), MULTICAST_PORT));
    }
    for index in indices {
        destinations.push(SocketAddr::V6(SocketAddrV6::new(
            MULTICAST_V6,
            MULTICAST_PORT,
            0,
            *index,
        )));
    }
    destinations
}

#[derive(Debug)]
pub enum DirectedError {
    Io(io::Error),
    /// No reply within the time allowed.
    Timeout,
    /// The receive loop stopped.
    Stopped,
    /// The reply carried no verifiable identity.
    Unsigned,
}

impl std::fmt::Display for DirectedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "directed discovery: {error}"),
            Self::Timeout => f.write_str("directed discovery response timed out"),
            Self::Stopped => f.write_str("directed discovery listener stopped"),
            Self::Unsigned => {
                f.write_str("discovery response is not signed by its announced identity")
            }
        }
    }
}

impl std::error::Error for DirectedError {}

type Waiters = Mutex<HashMap<u64, oneshot::Sender<Device>>>;

/// Called for every UDP datagram after the engine has processed it: the
/// sender, the bytes, and what the engine made of them.
pub type Observer = Arc<dyn Fn(SocketAddr, &[u8], &Received) + Send + Sync>;

/// The UDP side of discovery for one [`Engine`].
pub struct UdpDiscovery {
    engine: Arc<Engine>,
    /// Sockets the receive loops read.
    listeners: Vec<Arc<UdpSocket>>,
    /// The socket announces, requests and replies leave from. On Linux it is
    /// the normal service socket, so a reply returns to the fixed service port.
    sender: Arc<UdpSocket>,
    destinations: Destinations,
    waiters: Waiters,
    /// IPv6 interface indices whose multicast group the listeners have joined.
    joined: Mutex<BTreeSet<u32>>,
    observer: RwLock<Option<Observer>>,
}

impl UdpDiscovery {
    pub fn new(
        engine: Arc<Engine>,
        listeners: Vec<Arc<UdpSocket>>,
        sender: Arc<UdpSocket>,
        destinations: Destinations,
    ) -> Arc<Self> {
        Arc::new(Self {
            engine,
            listeners,
            sender,
            destinations,
            waiters: Mutex::new(HashMap::new()),
            joined: Mutex::new(BTreeSet::new()),
            observer: RwLock::new(None),
        })
    }

    /// One socket that both receives and sends: a descriptor an Android
    /// service adopts, or a bound socket in a test.
    pub fn from_socket(engine: Arc<Engine>, socket: UdpSocket, destinations: Destinations) -> Arc<Self> {
        let socket = Arc::new(socket);
        Self::new(engine, vec![socket.clone()], socket, destinations)
    }

    /// Adopt an already bound UDP descriptor (Android binds it to the selected
    /// network before handing it over). Takes ownership of `fd`.
    pub fn from_fd(engine: Arc<Engine>, fd: i32, destinations: Destinations) -> io::Result<Arc<Self>> {
        // SAFETY: the caller transfers ownership of an open UDP socket.
        let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
        socket.set_nonblocking(true)?;
        Ok(Self::from_socket(engine, UdpSocket::from_std(socket)?, destinations))
    }

    /// Bind the shared multicast listeners (IPv6 on every live link, and IPv4
    /// for older peers) and send from the IPv6 socket.
    pub async fn bind_multicast(engine: Arc<Engine>) -> io::Result<Arc<Self>> {
        let mut listeners = Vec::new();
        match bind_v4() {
            Ok(socket) => listeners.push(Arc::new(socket)),
            Err(error) => tracing::warn!(%error, "mcast_v4_listener_unavailable"),
        }
        let v6 = Arc::new(bind_v6()?);
        listeners.push(v6.clone());
        Ok(Self::new(
            engine,
            listeners,
            v6,
            Destinations::Multicast { ipv4: true },
        ))
    }

    /// Install a hook that sees every processed UDP datagram (a platform that
    /// keeps its own view of discovered devices updates it here).
    pub fn set_observer(&self, observer: Observer) {
        if let Ok(mut slot) = self.observer.write() {
            *slot = Some(observer);
        }
    }

    pub fn engine(&self) -> &Arc<Engine> {
        &self.engine
    }

    /// Start one receive task per listener.
    pub fn spawn(self: &Arc<Self>) -> Vec<tokio::task::JoinHandle<()>> {
        self.listeners
            .iter()
            .map(|socket| {
                let this = self.clone();
                let socket = socket.clone();
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 2048];
                    loop {
                        match socket.recv_from(&mut buffer).await {
                            Ok((len, sender)) => this.on_datagram(sender, &buffer[..len]).await,
                            Err(error) => {
                                tracing::error!(%error, "discovery receive failed");
                                break;
                            }
                        }
                    }
                })
            })
            .collect()
    }

    /// Process a datagram a receive loop, or the owner of a shared socket,
    /// read from `sender`: record an announce, answer a request, or complete
    /// a directed discovery.
    pub async fn on_datagram(&self, sender: SocketAddr, bytes: &[u8]) {
        let peer = sender.to_string();
        let received = self.engine.on_datagram(&Carrier::udp(&peer, sender), bytes);
        if let Some(observer) = self.observer.read().ok().and_then(|observer| observer.clone()) {
            observer(sender, bytes, &received);
        }
        match received {
            Received::Request { reply, .. } => {
                if let Err(error) = self.sender.send_to(&reply, sender).await {
                    tracing::warn!(%error, %sender, "discovery reply failed");
                }
            }
            Received::Response { id, device } => {
                let waiter = self.waiters.lock().ok().and_then(|mut waiters| waiters.remove(&id));
                if let Some(waiter) = waiter {
                    let _ = waiter.send(*device);
                }
            }
            Received::Rejected => tracing::warn!(%sender, "dropping announce with invalid identity"),
            Received::Announce { .. } | Received::Own | Received::Ignored => {}
        }
    }

    fn destinations(&self) -> Vec<SocketAddr> {
        match &self.destinations {
            Destinations::Fixed(addresses) => addresses.clone(),
            Destinations::Multicast { ipv4 } => {
                multicast_destinations(*ipv4, &crate::interfaces::multicast_v6_indices())
            }
        }
    }

    /// Join the IPv6 multicast group on every interface that has appeared
    /// since the last call (a P2P group can come up long after start), on each
    /// listener. Called before every multicast send; it is cheap when nothing changed.
    pub fn join_new_interfaces(&self) {
        if !matches!(self.destinations, Destinations::Multicast { .. }) {
            return;
        }
        let Ok(mut joined) = self.joined.lock() else {
            return;
        };
        for index in crate::interfaces::multicast_v6_indices() {
            if joined.contains(&index) {
                continue;
            }
            let mut any = false;
            for socket in &self.listeners {
                // An IPv4 listener cannot join an IPv6 group; that is expected.
                if socket.join_multicast_v6(&MULTICAST_V6, index).is_ok() {
                    any = true;
                }
            }
            if any {
                joined.insert(index);
            } else {
                tracing::warn!(index, "discovery multicast join failed");
            }
        }
    }

    async fn send_all(&self, wire: &[u8]) -> usize {
        self.join_new_interfaces();
        let mut sent = 0;
        for destination in self.destinations() {
            // An interface can vanish between listing and sending (a transient
            // P2P group); discovery is soft state, so one stale scope is skipped.
            match self.sender.send_to(wire, destination).await {
                Ok(_) => sent += 1,
                Err(error) => tracing::warn!(%error, %destination, "discovery send skipped"),
            }
        }
        sent
    }

    /// Announce ourselves to every destination. Returns how many the socket accepted.
    pub async fn announce(&self) -> io::Result<usize> {
        let wire = self.engine.announce_wire().map_err(io::Error::other)?;
        Ok(self.send_all(&wire).await)
    }

    /// Active discovery: ask every peer in reach to send its announce now.
    /// Returns how many destinations accepted the request.
    pub async fn solicit(&self) -> usize {
        self.send_all(&Engine::request_wire(Engine::new_request_id())).await
    }

    /// Ask one explicit UDP address for its announce and wait for the signed
    /// reply. The address is the path under test; there is no node lookup and
    /// no fallback.
    pub async fn directed(&self, peer: SocketAddr, wait: Duration) -> Result<Device, DirectedError> {
        let id = Engine::new_request_id();
        let (sender, receiver) = oneshot::channel();
        self.waiters.lock().map_err(|_| DirectedError::Stopped)?.insert(id, sender);
        if let Err(error) = self.sender.send_to(&Engine::request_wire(id), peer).await {
            self.forget(id);
            return Err(DirectedError::Io(error));
        }
        let device = match tokio::time::timeout(wait, receiver).await {
            Ok(Ok(device)) => device,
            Ok(Err(_)) => return Err(DirectedError::Stopped),
            Err(_) => {
                self.forget(id);
                return Err(DirectedError::Timeout);
            }
        };
        if !device.authenticated {
            return Err(DirectedError::Unsigned);
        }
        Ok(device)
    }

    fn forget(&self, id: u64) {
        if let Ok(mut waiters) = self.waiters.lock() {
            waiters.remove(&id);
        }
    }
}

/// A shareable socket option set to `1`.
fn enable(socket: &std::net::UdpSocket, level: libc::c_int, option: libc::c_int) -> io::Result<()> {
    let enabled: libc::c_int = 1;
    // SAFETY: a valid descriptor and a correctly sized option value.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if result == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

/// Create a datagram socket of `family`, shareable (`SO_REUSEADDR`) so
/// independently supervised services each receive every multicast datagram.
fn shared_socket(family: libc::c_int) -> io::Result<std::net::UdpSocket> {
    // SAFETY: plain socket creation; ownership passes to the UdpSocket below.
    let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    enable(&socket, libc::SOL_SOCKET, libc::SO_REUSEADDR)?;
    Ok(socket)
}

fn bind_v4() -> io::Result<UdpSocket> {
    let socket = shared_socket(libc::AF_INET)?;
    let address = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: MULTICAST_PORT.to_be(),
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    // SAFETY: a valid descriptor and a correctly sized address.
    let result = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_in).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    socket.set_nonblocking(true)?;
    let socket = UdpSocket::from_std(socket)?;
    socket.join_multicast_v4(MULTICAST_V4, Ipv4Addr::UNSPECIFIED)?;
    Ok(socket)
}

fn bind_v6() -> io::Result<UdpSocket> {
    let socket = shared_socket(libc::AF_INET6)?;
    // IPv6-only before bind: otherwise the IPv4 listener on this port wins and
    // IPv6 multicast is silently unavailable.
    enable(&socket, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY)?;
    let address = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: MULTICAST_PORT.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: Ipv6Addr::UNSPECIFIED.octets(),
        },
        sin6_scope_id: 0,
    };
    // SAFETY: a valid descriptor and a correctly sized address.
    let result = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_in6).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    socket.set_nonblocking(true)?;
    let socket = UdpSocket::from_std(socket)?;
    let indices = crate::interfaces::multicast_v6_indices();
    if indices.is_empty() {
        return Err(io::Error::other("no active IPv6 multicast interface"));
    }
    for index in indices {
        socket.join_multicast_v6(&MULTICAST_V6, index)?;
    }
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::NoFacts;
    use crate::identity::P256Identity;

    async fn node() -> (Arc<UdpDiscovery>, SocketAddr) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let engine = Arc::new(Engine::new(Arc::new(P256Identity::generate()), Arc::new(NoFacts)));
        (UdpDiscovery::from_socket(engine, socket, Destinations::Fixed(Vec::new())), address)
    }

    /// Two nodes that announce to each other on loopback.
    async fn pair() -> ((Arc<UdpDiscovery>, SocketAddr), (Arc<UdpDiscovery>, SocketAddr)) {
        let (mut a, a_addr) = node().await;
        let (mut b, b_addr) = node().await;
        // Re-point each at the other (fixed destinations are set at construction).
        let rebuild = |discovery: Arc<UdpDiscovery>, peer: SocketAddr| {
            let socket = discovery.sender.clone();
            UdpDiscovery::new(
                discovery.engine.clone(),
                vec![socket.clone()],
                socket,
                Destinations::Fixed(vec![peer]),
            )
        };
        a = rebuild(a, b_addr);
        b = rebuild(b, a_addr);
        a.spawn();
        b.spawn();
        ((a, a_addr), (b, b_addr))
    }

    async fn eventually(mut check: impl FnMut() -> bool) -> bool {
        for _ in 0..100 {
            if check() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    #[tokio::test]
    async fn an_announce_over_udp_reaches_the_peer_inventory() {
        let ((a, _), (b, _)) = pair().await;
        assert_eq!(a.announce().await.unwrap(), 1);
        let a_id = a.engine().device_id();
        assert!(eventually(|| b.engine().devices().iter().any(|d| d.key() == crate::inventory::hex(&a_id))).await);
        let device = &b.engine().devices()[0];
        assert!(device.authenticated);
        assert!(device.udp_sender.is_some());
    }

    #[tokio::test]
    async fn solicitation_makes_the_peer_reply_and_the_reply_is_recorded() {
        let ((a, _), (b, _)) = pair().await;
        assert_eq!(a.solicit().await, 1);
        // B answers the request; A records B from the reply.
        let b_id = b.engine().device_id();
        assert!(eventually(|| a.engine().devices().iter().any(|d| d.key() == crate::inventory::hex(&b_id))).await);
    }

    #[tokio::test]
    async fn directed_discovery_returns_the_signed_device() {
        let ((a, a_addr), (b, _)) = pair().await;
        let device = b.directed(a_addr, Duration::from_secs(2)).await.unwrap();
        assert_eq!(device.key(), crate::inventory::hex(&a.engine().device_id()));
        assert!(device.authenticated);
    }

    #[tokio::test]
    async fn directed_discovery_to_a_silent_address_times_out() {
        let ((_, _), (b, _)) = pair().await;
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let error = b
            .directed(silent.local_addr().unwrap(), Duration::from_millis(150))
            .await
            .unwrap_err();
        assert!(matches!(error, DirectedError::Timeout), "{error}");
    }

    #[test]
    fn multicast_destinations_cover_each_scope_and_optionally_ipv4() {
        let destinations = multicast_destinations(true, &[2, 7]);
        assert_eq!(destinations.len(), 3);
        assert_eq!(destinations[0], "224.0.0.250:5227".parse().unwrap());
        assert_eq!(destinations[2].to_string(), "[ff02::5227%7]:5227");
        assert_eq!(multicast_destinations(false, &[]).len(), 0);
    }
}
