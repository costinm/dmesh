use crate::packet::{
    build_ethernet_ipv4_tcp_frame_with_options_into, ethernet_payload_to_ip, ip_packet_destination,
    ip_packet_source, ip_to_ethernet_frame_into, ipv4_checksum_valid, ipv4_tcp_checksum_valid,
};

use bytes::Bytes;
use mesh::config::DEFAULT_MESH_TUN_MTU;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use tokio::net::UnixListener;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct BwrapInfoServerConfig {
    pub if_name: String,
    pub network: Ipv4Addr,
    pub prefix_len: u8,
    pub first_host: u32,
    pub gateway: String,
    pub vm_id: String,
    pub egress_redirect: Option<EgressRedirectConfig>,
}

struct BwrapInfoServerState {
    config: BwrapInfoServerConfig,
    next_host: AtomicU32,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TapCaptureSpec {
    pub vm_id: String,
    pub netns_path: PathBuf,
    pub userns_path: Option<PathBuf>,
    pub if_name: Option<String>,
    pub setup: Option<NetnsSetup>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NetnsSetup {
    pub address: Option<String>,
    pub gateway: Option<String>,
    pub mtu: Option<u32>,
    pub default_route: bool,
    pub egress_redirect: Option<EgressRedirectConfig>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EgressRedirectConfig {
    pub listen_port: u16,
    pub proxy_uid: Option<u32>,
}

pub async fn run_control_server(
    listener: UnixListener,
    tun_tx: mpsc::Sender<Vec<u8>>,
) -> Result<(), anyhow::Error> {
    tracing::info!(addr = ?listener.local_addr(), "mesh-tun control socket started");

    loop {
        let (stream, _) = listener.accept().await?;
        let tun_tx = tun_tx.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_control_client(stream, tun_tx).await {
                tracing::warn!(%error, "mesh-tun control client disconnected");
            }
        });
    }
}

pub async fn run_bwrap_info_server(
    listener: UnixListener,
    config: BwrapInfoServerConfig,
    tun_tx: mpsc::Sender<Vec<u8>>,
) -> Result<(), anyhow::Error> {
    tracing::info!(addr = ?listener.local_addr(), "mesh-tun bwrap info socket started");
    let state = Arc::new(BwrapInfoServerState {
        next_host: AtomicU32::new(config.first_host),
        config,
    });

    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        let tun_tx = tun_tx.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_bwrap_info_client(stream, state, tun_tx).await {
                tracing::warn!(%error, "mesh-tun bwrap info client disconnected");
            }
        });
    }
}

async fn handle_control_client(
    stream: tokio::net::UnixStream,
    tun_tx: mpsc::Sender<Vec<u8>>,
) -> Result<(), anyhow::Error> {
    let std_stream = stream.into_std()?;
    std_stream.set_nonblocking(false)?;
    tokio::task::spawn_blocking(move || {
        let reader_stream = std_stream.try_clone()?;
        let mut reader = BufReader::new(reader_stream);
        let mut writer = std_stream;
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                return Ok::<(), anyhow::Error>(());
            }
            let request = line.trim();
            if request.is_empty() {
                continue;
            }
            match parse_control_request(request) {
                Ok(ControlRequest::CaptureTap(spec)) => {
                    let egress_redirect = spec
                        .setup
                        .as_ref()
                        .and_then(|setup| setup.egress_redirect.clone());
                    let netns_path = spec.netns_path.clone();
                    let userns_path = spec.userns_path.clone();
                    let result = start_tap_capture(spec, tun_tx.clone()).and_then(|()| {
                        if let Some(egress) = egress_redirect {
                            // The listener has to be bound after nft is installed and from
                            // inside the service netns, so redirected TCP connects land in
                            // mesh-tun without requiring NET_ADMIN in the container.
                            start_egress_listener(netns_path, userns_path, egress)?;
                        }
                        Ok(())
                    });
                    match result {
                        Ok(()) => {
                            crate::stats::stats()
                                .control_capture_ok
                                .fetch_add(1, Ordering::Relaxed);
                            writeln!(writer, "ok")?
                        }
                        Err(error) => {
                            crate::stats::stats()
                                .control_capture_err
                                .fetch_add(1, Ordering::Relaxed);
                            writeln!(writer, "error {error}")?
                        }
                    }
                }
                Ok(ControlRequest::Ping) => {
                    writeln!(writer, "ok pong")?;
                }
                Ok(ControlRequest::Stats) => {
                    writeln!(
                        writer,
                        "ok {}",
                        crate::stats::stats().snapshot_lines().join(" ")
                    )?;
                }
                Ok(ControlRequest::ResetStats) => {
                    crate::stats::stats().reset();
                    writeln!(writer, "ok")?;
                }
                Err(error) => {
                    writeln!(writer, "error {error}")?;
                }
            }
            writer.flush()?;
        }
    })
    .await?
}

async fn handle_bwrap_info_client(
    stream: tokio::net::UnixStream,
    state: Arc<BwrapInfoServerState>,
    tun_tx: mpsc::Sender<Vec<u8>>,
) -> Result<(), anyhow::Error> {
    let mut stream = stream.into_std()?;
    stream.set_nonblocking(false)?;
    tokio::task::spawn_blocking(move || {
        let info = read_bwrap_info(&mut stream)?;
        let child_pid = parse_bwrap_child_pid(&info)
            .ok_or_else(|| anyhow::anyhow!("bwrap info did not include child-pid: {info}"))?;
        let guest_ip = state.allocate_guest_ip()?;
        let config = &state.config;
        let spec = TapCaptureSpec {
            vm_id: config.vm_id.clone(),
            netns_path: PathBuf::from(format!("/proc/{child_pid}/ns/net")),
            userns_path: Some(PathBuf::from(format!("/proc/{child_pid}/ns/user"))),
            if_name: Some(config.if_name.clone()),
            setup: Some(NetnsSetup {
                address: Some(format!("{guest_ip}/{}", config.prefix_len)),
                gateway: Some(config.gateway.clone()),
                // Keep the guest TAP MTU aligned with the MSS advertised by
                // the synthetic TCP stack. A 1500-byte guest MTU paired with a
                // ~64 KiB advertised MSS causes oversized guest-bound frames
                // and can look like random iperf stalls.
                mtu: Some(DEFAULT_MESH_TUN_MTU),
                default_route: true,
                egress_redirect: config.egress_redirect.clone(),
            }),
        };

        start_tap_capture(spec, tun_tx)?;
        if let Some(egress) = &config.egress_redirect {
            start_egress_listener(
                PathBuf::from(format!("/proc/{child_pid}/ns/net")),
                Some(PathBuf::from(format!("/proc/{child_pid}/ns/user"))),
                egress.clone(),
            )?;
        }
        crate::stats::stats()
            .control_capture_ok
            .fetch_add(1, Ordering::Relaxed);
        stream.write_all(b"x")?;
        stream.flush()?;
        Ok::<(), anyhow::Error>(())
    })
    .await?
}

impl BwrapInfoServerState {
    fn allocate_guest_ip(&self) -> Result<Ipv4Addr, anyhow::Error> {
        let host = self.next_host.fetch_add(1, Ordering::Relaxed);
        let prefix_len = self.config.prefix_len;
        let host_bits = 32u8.saturating_sub(prefix_len);
        if host_bits < 32 && host >= (1u32 << host_bits).saturating_sub(1) {
            anyhow::bail!("bwrap IPv4 pool exhausted");
        }

        let mask = if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_len)
        };
        let network = u32::from(self.config.network) & mask;
        Ok(Ipv4Addr::from(network | host))
    }
}

fn read_bwrap_info(stream: &mut std::os::unix::net::UnixStream) -> Result<String, anyhow::Error> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut info = String::new();
    let mut buf = [0u8; 512];
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        info.push_str(&String::from_utf8_lossy(&buf[..n]));
        if parse_bwrap_child_pid(&info).is_some() {
            return Ok(info);
        }
    }
    Ok(info)
}

fn parse_bwrap_child_pid(info: &str) -> Option<u32> {
    let marker = "\"child-pid\"";
    let after_marker = info.split(marker).nth(1)?;
    let after_colon = after_marker.split(':').nth(1)?;
    let digits: String = after_colon
        .chars()
        .skip_while(|ch| ch.is_whitespace())
        .take_while(|ch| ch.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

enum ControlRequest {
    Ping,
    Stats,
    ResetStats,
    CaptureTap(TapCaptureSpec),
}

fn parse_control_request(request: &str) -> Result<ControlRequest, anyhow::Error> {
    let mut fields = request.split_whitespace();
    match fields.next() {
        Some("ping") => Ok(ControlRequest::Ping),
        Some("stats") => Ok(ControlRequest::Stats),
        Some("reset-stats") => Ok(ControlRequest::ResetStats),
        Some("capture-tap") => {
            let mut vm_id = None;
            let mut netns_path = None;
            let mut userns_path = None;
            let mut if_name = None;
            let mut setup = None;
            let mut address = None;
            let mut gateway = None;
            let mut mtu = None;
            let mut default_route = false;
            let mut egress_redirect_port = None;
            let mut egress_redirect_uid = None;
            for field in fields {
                let Some((key, value)) = field.split_once('=') else {
                    anyhow::bail!("expected key=value field, got {field}");
                };
                match key {
                    "vm_id" => vm_id = Some(value.to_string()),
                    "netns" => netns_path = Some(PathBuf::from(value)),
                    "userns" => userns_path = Some(PathBuf::from(value)),
                    "if" => if_name = Some(value.to_string()),
                    "gw" => gateway = Some(value.to_string()),
                    "mtu" => mtu = Some(value.parse()?),
                    "egress_port" => egress_redirect_port = Some(value.parse()?),
                    "egress_uid" => egress_redirect_uid = Some(value.parse()?),
                    "setup" => match value {
                        "tap" => setup = Some(()),
                        other => anyhow::bail!("unsupported setup={other}"),
                    },
                    "addr" => address = Some(value.to_string()),
                    "route" => {
                        default_route = match value {
                            "default" => true,
                            "none" => false,
                            other => anyhow::bail!("unsupported route={other}"),
                        };
                    }
                    other => anyhow::bail!("unknown capture-tap field {other}"),
                }
            }
            let setup = setup.map(|()| NetnsSetup {
                address,
                gateway,
                mtu,
                default_route,
                egress_redirect: egress_redirect_port.map(|listen_port| EgressRedirectConfig {
                    listen_port,
                    proxy_uid: egress_redirect_uid,
                }),
            });
            Ok(ControlRequest::CaptureTap(TapCaptureSpec {
                vm_id: vm_id.unwrap_or_else(|| "netns".to_string()),
                netns_path: netns_path
                    .ok_or_else(|| anyhow::anyhow!("capture-tap requires netns=/path"))?,
                userns_path,
                if_name,
                setup,
            }))
        }
        Some(other) => anyhow::bail!("unknown control command {other}"),
        None => anyhow::bail!("empty control command"),
    }
}

static GUEST_ROUTER: std::sync::OnceLock<
    std::sync::RwLock<std::collections::HashMap<std::net::IpAddr, TapInjectSender>>,
> = std::sync::OnceLock::new();

// Host-to-guest TCP can enqueue 65 KiB frames. Keep each inject drain small
// enough that the TAP worker returns to TAP input frequently and does not
// delay ACK processing behind a multi-megabyte burst.
const TAP_INJECT_DRAIN_BUDGET: usize = 16;
const INJECT_DIAGNOSTIC_SAMPLE_MASK: u64 = 1023;
const MAC_VALID_FLAG: u64 = 1 << 63;

#[derive(Debug)]
pub enum TapInject {
    Ip(Vec<u8>),
    Tcp4 {
        src_addr: Ipv4Addr,
        src_port: u16,
        dst_addr: Ipv4Addr,
        dst_port: u16,
        flags: u8,
        seq: u32,
        ack: u32,
        options: Vec<u8>,
        payload: Bytes,
    },
}

#[derive(Clone)]
pub struct TapInjectSender {
    tx: mpsc::Sender<TapInject>,
    wake_fd: Arc<OwnedFd>,
}

impl TapInjectSender {
    fn new(tx: mpsc::Sender<TapInject>, wake_fd: Arc<OwnedFd>) -> Self {
        Self { tx, wake_fd }
    }

    pub async fn send(&self, packet: TapInject) -> Result<(), mpsc::error::SendError<TapInject>> {
        self.tx.send(packet).await?;
        self.wake();
        Ok(())
    }

    fn try_send(&self, packet: TapInject) -> Result<(), mpsc::error::TrySendError<TapInject>> {
        self.tx.try_send(packet)?;
        self.wake();
        Ok(())
    }

    fn wake(&self) {
        let value = 1u64.to_ne_bytes();
        // The TAP worker polls this eventfd along with the TAP fd. Waking it
        // removes the previous 10ms worst-case latency for guest-bound ACK/data
        // frames emitted by flow tasks.
        let rc =
            unsafe { libc::write(self.wake_fd.as_raw_fd(), value.as_ptr().cast(), value.len()) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EAGAIN) {
                tracing::debug!(%err, "failed to wake TAP inject thread");
            }
        }
    }
}

pub fn register_destination(ip: std::net::IpAddr, sender: TapInjectSender) {
    let registry =
        GUEST_ROUTER.get_or_init(|| std::sync::RwLock::new(std::collections::HashMap::new()));
    let mut destinations = registry
        .write()
        .unwrap_or_else(|poison| poison.into_inner());
    destinations.insert(ip, sender);
}

pub fn unregister_destination(ip: &std::net::IpAddr) {
    if let Some(registry) = GUEST_ROUTER.get() {
        registry
            .write()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(ip);
    }
}

pub fn destination_sender(ip: &std::net::IpAddr) -> Option<TapInjectSender> {
    let registry = GUEST_ROUTER.get()?;
    let destinations = registry.read().unwrap_or_else(|poison| poison.into_inner());
    destinations.get(ip).cloned()
}

pub fn route_outgoing_packet(packet: &[u8]) -> bool {
    let dst_ip = match ip_packet_destination(packet) {
        Some(ip) => ip,
        None => return false,
    };
    if let Some(registry) = GUEST_ROUTER.get() {
        let destinations = registry.read().unwrap_or_else(|poison| poison.into_inner());
        if let Some(sender) = destinations.get(&dst_ip) {
            match sender.try_send(TapInject::Ip(packet.to_vec())) {
                Ok(()) => {
                    crate::stats::stats()
                        .route_hit
                        .fetch_add(1, Ordering::Relaxed);
                    return true;
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    crate::stats::stats()
                        .route_send_full
                        .fetch_add(1, Ordering::Relaxed);
                    return true;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {}
            }
        }
    }
    crate::stats::stats()
        .route_miss
        .fetch_add(1, Ordering::Relaxed);
    false
}

fn start_tap_capture(
    spec: TapCaptureSpec,
    tun_tx: mpsc::Sender<Vec<u8>>,
) -> Result<(), anyhow::Error> {
    let spec = Arc::new(spec);
    let (inject_tx, inject_rx) = mpsc::channel::<TapInject>(1024);
    let inject_wake_fd = create_eventfd()?;
    let guest_mac = Arc::new(AtomicU64::new(0));

    let socket = fork_and_create_tap(&spec)?;
    let socket_arc = Arc::new(socket);

    std::thread::Builder::new()
        .name(format!("mesh-tun-tap-{}", spec.vm_id))
        .spawn(move || {
            if let Err(error) = packet_capture_thread_loop(
                &spec,
                socket_arc,
                tun_tx,
                guest_mac,
                inject_tx,
                inject_rx,
                inject_wake_fd,
            ) {
                tracing::warn!(vm_id = %spec.vm_id, %error, "TAP capture loop stopped");
            }
        })?;

    Ok(())
}

fn create_eventfd() -> Result<Arc<OwnedFd>, anyhow::Error> {
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(Arc::new(unsafe { OwnedFd::from_raw_fd(fd) }))
}

fn inject_ip_packet(
    socket: &OwnedFd,
    guest_mac: Arc<AtomicU64>,
    ip_packet: &[u8],
    frame: &mut Vec<u8>,
) -> Result<(), anyhow::Error> {
    let (src_mac, dst_mac) = tap_frame_macs(&guest_mac);
    ip_to_ethernet_frame_into(frame, ip_packet, src_mac, dst_mac, 60)?;
    write_tap_frame(socket, frame)
}

fn tap_frame_macs(guest_mac: &AtomicU64) -> ([u8; 6], [u8; 6]) {
    let gateway_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    // The TAP worker learns the guest MAC from inbound frames. Keep it in an
    // atomic so every injected packet avoids a mutex lock on the hot path.
    let dst_mac = decode_cached_mac(guest_mac.load(Ordering::Relaxed))
        .unwrap_or([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    let src_mac = if dst_mac == [0, 0, 0, 0, 0, 0] {
        dst_mac
    } else {
        gateway_mac
    };
    (src_mac, dst_mac)
}

fn write_tap_frame(socket: &OwnedFd, frame: &[u8]) -> Result<(), anyhow::Error> {
    let inject_count = crate::stats::record_tap_inject(frame.len());

    // Full frame diagnostics re-parse and re-checksum the packet we just
    // built. Packet/byte counters are batched in thread-local storage; sample
    // this debug path so iperf-style runs avoid checksum validation per frame.
    if inject_count & INJECT_DIAGNOSTIC_SAMPLE_MASK == 0 {
        record_inject_frame(&frame);
    }
    // SAFETY: frame points to valid memory for frame.len() bytes and socket is
    // an owned TAP file descriptor kept alive for the duration of this call.
    let rc = unsafe { libc::write(socket.as_raw_fd(), frame.as_ptr().cast(), frame.len()) };
    crate::stats::stats()
        .tap_last_inject_write_rc
        .store(rc.max(0) as u64, Ordering::Relaxed);
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EBADF) {
            crate::stats::stats()
                .tap_inject_error
                .fetch_add(1, Ordering::Relaxed);
            tracing::error!("TAP inject failed: {}", err);
        }
        return Err(err.into());
    }
    Ok(())
}

fn inject_tap_packet(
    socket: &OwnedFd,
    guest_mac: Arc<AtomicU64>,
    packet: TapInject,
    frame: &mut Vec<u8>,
) -> Result<(), anyhow::Error> {
    match packet {
        TapInject::Ip(packet) => inject_ip_packet(socket, guest_mac, &packet, frame),
        TapInject::Tcp4 {
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            flags,
            seq,
            ack,
            options,
            payload,
        } => {
            let (src_mac, dst_mac) = tap_frame_macs(&guest_mac);
            build_ethernet_ipv4_tcp_frame_with_options_into(
                frame, src_mac, dst_mac, 60, src_addr, src_port, dst_addr, dst_port, flags, seq,
                ack, &options, &payload,
            )?;
            write_tap_frame(socket, frame)
        }
    }
}

fn record_inject_frame(frame: &[u8]) {
    if frame.len() < 14 {
        return;
    }
    let stats = crate::stats::stats();
    stats
        .tap_last_inject_dst_mac_hi
        .store(mac_hi(&frame[0..6]), Ordering::Relaxed);
    stats
        .tap_last_inject_dst_mac_lo
        .store(mac_lo(&frame[0..6]), Ordering::Relaxed);
    stats
        .tap_last_inject_src_mac_hi
        .store(mac_hi(&frame[6..12]), Ordering::Relaxed);
    stats
        .tap_last_inject_src_mac_lo
        .store(mac_lo(&frame[6..12]), Ordering::Relaxed);
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    stats
        .tap_last_inject_ethertype
        .store(u64::from(ethertype), Ordering::Relaxed);
    stats
        .tap_last_inject_len
        .store(frame.len() as u64, Ordering::Relaxed);

    if ethertype == 0x0800 && frame.len() >= 54 {
        let ip = &frame[14..];
        let ihl = usize::from(ip[0] & 0x0f) * 4;
        stats
            .tap_last_inject_ip_checksum_ok
            .store(u64::from(ipv4_checksum_valid(ip)), Ordering::Relaxed);
        if ihl >= 20 && ip.len() >= ihl + 20 && ip[9] == 6 {
            stats.tap_last_inject_ipv4_src.store(
                u64::from(u32::from_be_bytes([ip[12], ip[13], ip[14], ip[15]])),
                Ordering::Relaxed,
            );
            stats.tap_last_inject_ipv4_dst.store(
                u64::from(u32::from_be_bytes([ip[16], ip[17], ip[18], ip[19]])),
                Ordering::Relaxed,
            );
            stats
                .tap_last_inject_tcp_flags
                .store(u64::from(ip[ihl + 13]), Ordering::Relaxed);
            stats
                .tap_last_inject_tcp_checksum_ok
                .store(u64::from(ipv4_tcp_checksum_valid(ip)), Ordering::Relaxed);
        }
    }
}

fn mac_hi(mac: &[u8]) -> u64 {
    (u64::from(mac[0]) << 16) | (u64::from(mac[1]) << 8) | u64::from(mac[2])
}

fn mac_lo(mac: &[u8]) -> u64 {
    (u64::from(mac[3]) << 16) | (u64::from(mac[4]) << 8) | u64::from(mac[5])
}

fn encode_cached_mac(mac: [u8; 6]) -> u64 {
    MAC_VALID_FLAG
        | (u64::from(mac[0]) << 40)
        | (u64::from(mac[1]) << 32)
        | (u64::from(mac[2]) << 24)
        | (u64::from(mac[3]) << 16)
        | (u64::from(mac[4]) << 8)
        | u64::from(mac[5])
}

fn decode_cached_mac(encoded: u64) -> Option<[u8; 6]> {
    if encoded & MAC_VALID_FLAG == 0 {
        return None;
    }
    Some([
        ((encoded >> 40) & 0xff) as u8,
        ((encoded >> 32) & 0xff) as u8,
        ((encoded >> 24) & 0xff) as u8,
        ((encoded >> 16) & 0xff) as u8,
        ((encoded >> 8) & 0xff) as u8,
        (encoded & 0xff) as u8,
    ])
}

fn packet_capture_thread_loop(
    _spec: &TapCaptureSpec,
    socket_arc: Arc<OwnedFd>,
    tun_tx: mpsc::Sender<Vec<u8>>,
    guest_mac: Arc<AtomicU64>,
    inject_tx: mpsc::Sender<TapInject>,
    mut inject_rx: mpsc::Receiver<TapInject>,
    inject_wake_fd: Arc<OwnedFd>,
) -> Result<(), anyhow::Error> {
    let mut buf = vec![0u8; 65535];
    let mut registered_ips = std::collections::HashSet::new();
    let mut inject_frame = Vec::with_capacity(65536);

    loop {
        let drained = drain_inject_queue(
            &socket_arc,
            guest_mac.clone(),
            &mut inject_rx,
            &mut inject_frame,
            TAP_INJECT_DRAIN_BUDGET,
        )?;

        let mut poll_fds = [
            libc::pollfd {
                fd: socket_arc.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: inject_wake_fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // If the inject queue is empty, block on both TAP input and eventfd
        // producer wakeups. This removes the old 10ms poll timeout that delayed
        // guest-bound ACK/data frames under reverse iperf.
        let timeout_ms = if drained == 0 { -1 } else { 0 };
        let ready = unsafe { libc::poll(poll_fds.as_mut_ptr(), poll_fds.len() as _, timeout_ms) };
        if ready < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err.into());
        }
        if ready == 0 {
            continue;
        }
        if poll_fds[1].revents & libc::POLLIN != 0 {
            drain_eventfd(&inject_wake_fd)?;
        }
        if poll_fds[0].revents & libc::POLLIN == 0 {
            continue;
        }

        // SAFETY: buf is writable for buf.len() bytes and socket_arc is a live
        // TAP fd owned by this capture thread.
        let n = unsafe { libc::read(socket_arc.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EBADF) {
                break;
            }
            return Err(err.into());
        }
        let n = n as usize;
        crate::stats::record_tap_frame_rx(n);
        if n < 14 {
            continue;
        }

        let mut src_mac = [0u8; 6];
        src_mac.copy_from_slice(&buf[6..12]);
        guest_mac.store(encode_cached_mac(src_mac), Ordering::Relaxed);

        if let Some(reply) = arp_reply(&buf[..n]) {
            crate::stats::stats()
                .arp_request_rx
                .fetch_add(1, Ordering::Relaxed);
            // SAFETY: reply points to valid memory for reply.len() bytes and
            // socket_arc is the live TAP fd for this capture thread.
            let rc =
                unsafe { libc::write(socket_arc.as_raw_fd(), reply.as_ptr().cast(), reply.len()) };
            if rc >= 0 {
                crate::stats::stats()
                    .arp_reply_tx
                    .fetch_add(1, Ordering::Relaxed);
            }
            continue;
        }

        if let Some((ip_packet, _src_mac)) = ethernet_payload_to_ip(&buf[..n]) {
            crate::stats::record_tap_ip_rx(ip_packet.len());
            if let Some(src_ip) = ip_packet_source(&ip_packet) {
                if registered_ips.insert(src_ip) {
                    register_destination(
                        src_ip,
                        TapInjectSender::new(inject_tx.clone(), inject_wake_fd.clone()),
                    );
                }
            }

            match tun_tx.try_send(ip_packet) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    crate::stats::stats()
                        .tun_input_queue_full
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(anyhow::anyhow!("TUN input queue closed"));
                }
            }
        }
    }

    for ip in registered_ips {
        unregister_destination(&ip);
    }
    crate::stats::flush_hot_counters();

    Ok(())
}

fn drain_eventfd(fd: &OwnedFd) -> Result<(), std::io::Error> {
    let mut value = [0u8; 8];
    loop {
        let rc = unsafe { libc::read(fd.as_raw_fd(), value.as_mut_ptr().cast(), value.len()) };
        if rc == 8 {
            continue;
        }
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAGAIN) {
                return Ok(());
            }
            return Err(err);
        }
        return Ok(());
    }
}

fn drain_inject_queue(
    socket: &OwnedFd,
    guest_mac: Arc<AtomicU64>,
    inject_rx: &mut mpsc::Receiver<TapInject>,
    frame: &mut Vec<u8>,
    budget: usize,
) -> Result<usize, anyhow::Error> {
    let mut drained = 0usize;
    while drained < budget {
        match inject_rx.try_recv() {
            Ok(packet) => {
                crate::stats::stats()
                    .tap_inject_queue_rx
                    .fetch_add(1, Ordering::Relaxed);
                inject_tap_packet(socket, guest_mac.clone(), packet, frame)?;
                drained += 1;
            }
            Err(mpsc::error::TryRecvError::Empty) => return Ok(drained),
            Err(mpsc::error::TryRecvError::Disconnected) => return Ok(drained),
        }
    }
    Ok(drained)
}

fn fork_and_create_tap(spec: &TapCaptureSpec) -> Result<OwnedFd, anyhow::Error> {
    use std::os::fd::FromRawFd;

    // Create a socketpair for passing the file descriptor
    let mut fds = [0i32; 2];
    // SAFETY: fds points to two writable i32 slots for socketpair to fill.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: socketpair succeeded and initialized both fds. Each fd is moved
    // into exactly one OwnedFd here.
    let parent_sock = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    // SAFETY: see parent_sock above.
    let child_sock = unsafe { OwnedFd::from_raw_fd(fds[1]) };

    let self_userns = std::fs::metadata("/proc/self/ns/user");
    let target_userns = spec
        .userns_path
        .as_ref()
        .and_then(|path| std::fs::metadata(path).ok());
    let should_enter_userns = match (self_userns, target_userns) {
        (Ok(s), Some(t)) => {
            use std::os::unix::fs::MetadataExt;
            s.ino() != t.ino()
        }
        _ => false,
    };

    // SAFETY: fork is called to enter the target namespaces and create a TAP fd
    // in the child, then the child exits via _exit. The child avoids returning
    // into Rust async runtime state.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    if pid == 0 {
        // In the child process:
        // Note: The child process is single-threaded, so it can safely call setns(..., CLONE_NEWUSER)
        drop(parent_sock);

        let run_child = || -> Result<(), std::io::Error> {
            // Unshare filesystem state to avoid sharing context with parent threads
            // SAFETY: unshare is called in the forked child before starting any
            // child threads; CLONE_FS has no Rust aliasing implications.
            let rc = unsafe { libc::unshare(libc::CLONE_FS) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }

            // First, enter the user namespace of the target process if it is different
            // This is crucial because it gives us capabilities (like CAP_NET_ADMIN/CAP_SYS_ADMIN) inside that namespace
            if should_enter_userns && let Some(userns_path) = &spec.userns_path {
                let userns_file = std::fs::File::open(&userns_path)?;
                // SAFETY: userns_file is an open namespace fd and setns only
                // mutates the child process namespace membership.
                let rc = unsafe { libc::setns(userns_file.as_raw_fd(), libc::CLONE_NEWUSER) };
                if rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }

            // Enter the network namespace
            let netns_file = std::fs::File::open(&spec.netns_path)?;
            // SAFETY: netns_file is an open namespace fd and setns only mutates
            // the child process namespace membership.
            let rc = unsafe { libc::setns(netns_file.as_raw_fd(), libc::CLONE_NEWNET) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }

            let if_name = spec.if_name.as_deref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "capture-tap requires if=NAME",
                )
            })?;
            let tap_fd = open_tap_device(if_name)?;

            if let Some(setup) = &spec.setup {
                configure_netns_interface(if_name, setup)?;
            } else {
                run_ip(&["link", "set", "dev", "lo", "up"], true)?;
                run_ip(&["link", "set", "dev", if_name, "up"], false)?;
            }

            send_fd(child_sock.as_raw_fd(), tap_fd.as_raw_fd())?;
            Ok(())
        };

        match run_child() {
            // SAFETY: this is the forked child; _exit terminates without running
            // parent-runtime destructors.
            Ok(()) => unsafe { libc::_exit(0) },
            Err(e) => {
                let code = e.raw_os_error().unwrap_or(255);
                // SAFETY: see successful _exit path above.
                unsafe { libc::_exit(code) }
            }
        }
    }

    // In the parent process:
    drop(child_sock);

    // Wait for the child to exit
    let mut status = 0i32;
    // SAFETY: pid is the child returned by fork and status points to writable
    // storage for waitpid to fill.
    let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    if libc::WIFEXITED(status) {
        let exit_code = libc::WEXITSTATUS(status);
        if exit_code != 0 {
            return Err(std::io::Error::from_raw_os_error(exit_code).into());
        }
    } else {
        anyhow::bail!("child process terminated abnormally");
    }

    // Receive FD
    let fd = recv_fd(parent_sock.as_raw_fd())?;
    Ok(fd)
}

fn configure_netns_interface(if_name: &str, setup: &NetnsSetup) -> Result<(), std::io::Error> {
    run_ip(&["link", "set", "dev", "lo", "up"], true)?;

    if let Some(address) = &setup.address {
        run_ip(&["addr", "add", address, "dev", if_name], true)?;
    }

    if let Some(mtu) = setup.mtu {
        run_ip(
            &["link", "set", "dev", if_name, "mtu", &mtu.to_string()],
            true,
        )?;
    }

    run_ip(&["link", "set", "dev", if_name, "up"], false)?;

    if setup.default_route {
        if let Some(gateway) = &setup.gateway {
            run_ip(
                &["route", "add", "default", "via", gateway, "dev", if_name],
                true,
            )?;
        } else {
            run_ip(&["route", "add", "default", "dev", if_name], true)?;
        }
    }

    if let Some(egress) = &setup.egress_redirect {
        configure_egress_redirect(egress)?;
    }

    Ok(())
}

fn configure_egress_redirect(config: &EgressRedirectConfig) -> Result<(), std::io::Error> {
    let exclude_uid = config
        .proxy_uid
        .map(|uid| format!("meta skuid {uid} return\n"))
        .unwrap_or_default();
    let rules = format!(
        "table ip mesh_tun {{\n  chain output {{\n    type nat hook output priority dstnat; policy accept;\n    oifname \"lo\" tcp dport {port} return\n    {exclude_uid}    ip protocol tcp redirect to :{port}\n  }}\n}}\n",
        port = config.listen_port,
        exclude_uid = exclude_uid
    );
    run_nft(&["delete", "table", "ip", "mesh_tun"], true)?;
    run_nft_stdin(&rules)
}

fn start_egress_listener(
    netns_path: PathBuf,
    userns_path: Option<PathBuf>,
    config: EgressRedirectConfig,
) -> Result<(), anyhow::Error> {
    let listener_fd =
        bind_tcp_listener_in_netns(&netns_path, userns_path.as_ref(), config.listen_port)?;
    let listener = TcpListener::from(listener_fd);
    listener.set_nonblocking(false)?;
    crate::stats::stats()
        .egress_listener_start
        .fetch_add(1, Ordering::Relaxed);
    std::thread::Builder::new()
        .name(format!("mesh-tun-egress-{}", config.listen_port))
        .spawn(move || {
            if let Err(error) = egress_accept_loop(listener) {
                tracing::error!(%error, "mesh-tun egress listener stopped");
            }
        })?;
    Ok(())
}

fn egress_accept_loop(listener: TcpListener) -> Result<(), anyhow::Error> {
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) => {
                crate::stats::stats()
                    .egress_accept_error
                    .fetch_add(1, Ordering::Relaxed);
                return Err(error.into());
            }
        };
        crate::stats::stats()
            .egress_accept
            .fetch_add(1, Ordering::Relaxed);
        std::thread::Builder::new()
            .name("mesh-tun-egress-flow".to_string())
            .spawn(move || {
                if let Err(error) = handle_egress_stream(stream) {
                    tracing::debug!(%peer, %error, "egress stream closed");
                }
            })?;
    }
}

fn handle_egress_stream(mut inbound: TcpStream) -> Result<(), anyhow::Error> {
    let original_dst = match original_dst(&inbound) {
        Ok(original_dst) => original_dst,
        Err(error) => {
            crate::stats::stats()
                .egress_original_dst_error
                .fetch_add(1, Ordering::Relaxed);
            return Err(error);
        }
    };
    let mut upstream = match TcpStream::connect(original_dst) {
        Ok(upstream) => upstream,
        Err(error) => {
            crate::stats::stats()
                .egress_connect_error
                .fetch_add(1, Ordering::Relaxed);
            return Err(error.into());
        }
    };
    inbound.set_nodelay(true)?;
    upstream.set_nodelay(true)?;

    let mut inbound_read = inbound.try_clone()?;
    let mut upstream_write = upstream.try_clone()?;
    let upstream_shutdown = upstream.try_clone()?;
    let inbound_shutdown = inbound.try_clone()?;
    let tx = std::thread::spawn(move || {
        let copied = copy_egress_counted(
            &mut inbound_read,
            &mut upstream_write,
            &crate::stats::stats().egress_bytes_to_upstream,
        );
        let _ = upstream_shutdown.shutdown(Shutdown::Write);
        copied
    });
    let rx = copy_egress_counted(
        &mut upstream,
        &mut inbound,
        &crate::stats::stats().egress_bytes_to_guest,
    )?;
    let _ = inbound_shutdown.shutdown(Shutdown::Write);
    let tx = tx
        .join()
        .map_err(|_| anyhow::anyhow!("egress copy thread panicked"))??;
    tracing::trace!(to_upstream = tx, to_inbound = rx, dst = %original_dst, "egress stream proxied");
    Ok(())
}

fn copy_egress_counted(
    reader: &mut TcpStream,
    writer: &mut TcpStream,
    counter: &AtomicU64,
) -> Result<u64, std::io::Error> {
    let mut total = 0u64;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            return Ok(total);
        }
        writer.write_all(&buf[..n])?;
        let n = n as u64;
        total += n;
        counter.fetch_add(n, Ordering::Relaxed);
    }
}

fn original_dst(stream: &TcpStream) -> Result<SocketAddr, anyhow::Error> {
    const SO_ORIGINAL_DST: libc::c_int = 80;
    let mut addr = std::mem::MaybeUninit::<libc::sockaddr_in>::zeroed();
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            addr.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let addr = unsafe { addr.assume_init() };
    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    Ok(SocketAddr::from((ip, port)))
}

fn bind_tcp_listener_in_netns(
    netns_path: &PathBuf,
    userns_path: Option<&PathBuf>,
    port: u16,
) -> Result<OwnedFd, anyhow::Error> {
    let mut fds = [0i32; 2];
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let parent_sock = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let child_sock = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if pid == 0 {
        drop(parent_sock);
        let result = bind_tcp_listener_in_netns_child(&child_sock, netns_path, userns_path, port);
        match result {
            Ok(()) => unsafe { libc::_exit(0) },
            Err(error) => {
                let code = error.raw_os_error().unwrap_or(255);
                unsafe { libc::_exit(code) }
            }
        }
    }
    drop(child_sock);

    let mut status = 0i32;
    let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if libc::WIFEXITED(status) {
        let exit_code = libc::WEXITSTATUS(status);
        if exit_code != 0 {
            return Err(std::io::Error::from_raw_os_error(exit_code).into());
        }
    } else {
        anyhow::bail!("egress listener child terminated abnormally");
    }
    Ok(recv_fd(parent_sock.as_raw_fd())?)
}

fn bind_tcp_listener_in_netns_child(
    child_sock: &OwnedFd,
    netns_path: &PathBuf,
    userns_path: Option<&PathBuf>,
    port: u16,
) -> Result<(), std::io::Error> {
    let rc = unsafe { libc::unshare(libc::CLONE_FS) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if let Some(userns_path) = userns_path {
        let userns_file = std::fs::File::open(userns_path)?;
        let rc = unsafe { libc::setns(userns_file.as_raw_fd(), libc::CLONE_NEWUSER) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    let netns_file = std::fs::File::open(netns_path)?;
    let rc = unsafe { libc::setns(netns_file.as_raw_fd(), libc::CLONE_NEWNET) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
    listener.set_nonblocking(false)?;
    let fd = listener.into_raw_fd();
    let send_result = send_fd(child_sock.as_raw_fd(), fd);
    unsafe {
        libc::close(fd);
    }
    send_result
}

fn open_tap_device(if_name: &str) -> Result<OwnedFd, std::io::Error> {
    use std::os::fd::FromRawFd;

    let name = std::ffi::CString::new(if_name)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid if name"))?;
    if name.as_bytes_with_nul().len() > libc::IFNAMSIZ {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }

    // SAFETY: the path is a static NUL-terminated C string and flags/mode are valid.
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: open succeeded and returned an owned fd, moved into OwnedFd once.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    // SAFETY: ifreq is a plain C struct that is fully initialized below before
    // it is passed to ioctl.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    // SAFETY: ifr_name has at least IFNAMSIZ bytes, checked above, and ifru_flags
    // is the active union field expected by TUNSETIFF.
    unsafe {
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            req.ifr_name.as_mut_ptr(),
            name.as_bytes_with_nul().len(),
        );
        req.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short;
    }

    // SAFETY: fd is a live /dev/net/tun fd and req points to an initialized ifreq.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &mut req) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(fd)
}

fn run_ip(args: &[&str], allow_existing: bool) -> Result<(), std::io::Error> {
    let output = std::process::Command::new("ip").args(args).output()?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if allow_existing
        && (stderr.contains("File exists") || stderr.contains("RTNETLINK answers: File exists"))
    {
        return Ok(());
    }

    Err(std::io::Error::other(format!(
        "ip {} failed: {}",
        args.join(" "),
        stderr.trim()
    )))
}

fn run_nft(args: &[&str], allow_missing: bool) -> Result<(), std::io::Error> {
    let output = std::process::Command::new("nft").args(args).output()?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if allow_missing
        && (stderr.contains("No such file or directory")
            || stderr.contains("No such table")
            || stderr.contains("Could not process rule"))
    {
        return Ok(());
    }
    Err(std::io::Error::other(format!(
        "nft {} failed: {}",
        args.join(" "),
        stderr.trim()
    )))
}

fn run_nft_stdin(rules: &str) -> Result<(), std::io::Error> {
    let mut child = std::process::Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| std::io::Error::other("nft stdin unavailable"))?
        .write_all(rules.as_bytes())?;
    let output = child.wait_with_output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(std::io::Error::other(format!(
        "nft -f - failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

fn send_fd(sock: RawFd, fd: RawFd) -> Result<(), std::io::Error> {
    // SAFETY: msghdr is a plain C struct; all relevant fields are initialized
    // before sendmsg is called.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };

    // We must send at least one dummy byte of data for sendmsg to succeed on many platforms
    let mut dummy: u8 = 0;
    let mut iov = libc::iovec {
        iov_base: (&mut dummy as *mut u8).cast(),
        iov_len: 1,
    };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;

    // Allocate control message buffer for the file descriptor
    // SAFETY: CMSG_SPACE only computes the buffer size for one RawFd.
    let mut control_buf =
        [0u8; unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize }];
    msg.msg_control = control_buf.as_mut_ptr().cast();
    msg.msg_controllen = control_buf.len() as _;

    // SAFETY: msg points to an initialized msghdr with a control buffer.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(std::io::Error::other("CMSG_FIRSTHDR failed"));
    }
    // SAFETY: cmsg points into control_buf and has enough space for one RawFd
    // because control_buf was sized with CMSG_SPACE.
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        let data_ptr = libc::CMSG_DATA(cmsg);
        std::ptr::write(data_ptr.cast::<RawFd>(), fd);
    }

    // SAFETY: msg references stack buffers that remain alive for the duration
    // of sendmsg; sock is expected to be a connected Unix socket fd.
    let rc = unsafe { libc::sendmsg(sock, &msg, 0) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn recv_fd(sock: RawFd) -> Result<OwnedFd, std::io::Error> {
    // SAFETY: msghdr is a plain C struct; all relevant fields are initialized
    // before recvmsg is called.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };

    let mut dummy: u8 = 0;
    let mut iov = libc::iovec {
        iov_base: (&mut dummy as *mut u8).cast(),
        iov_len: 1,
    };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;

    // SAFETY: CMSG_SPACE only computes the buffer size for one RawFd.
    let mut control_buf =
        [0u8; unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize }];
    msg.msg_control = control_buf.as_mut_ptr().cast();
    msg.msg_controllen = control_buf.len() as _;

    // SAFETY: msg references stack buffers that remain alive for the duration
    // of recvmsg; sock is expected to be a connected Unix socket fd.
    let rc = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: msg was filled by recvmsg and still owns the control buffer.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(std::io::Error::other("no control message received"));
    }

    // SAFETY: cmsg was checked non-null and points into the received control
    // buffer. read_unaligned avoids layout-alignment assumptions.
    let cmsg_level = unsafe { std::ptr::addr_of!((*cmsg).cmsg_level).read_unaligned() };
    // SAFETY: see cmsg_level above.
    let cmsg_type = unsafe { std::ptr::addr_of!((*cmsg).cmsg_type).read_unaligned() };
    let is_scm_rights = cmsg_level == libc::SOL_SOCKET && cmsg_type == libc::SCM_RIGHTS;
    if !is_scm_rights {
        return Err(std::io::Error::other("expected SCM_RIGHTS"));
    }

    // SAFETY: the SCM_RIGHTS control message contains at least one RawFd.
    let fd = unsafe { libc::CMSG_DATA(cmsg).cast::<RawFd>().read_unaligned() };
    if fd < 0 {
        return Err(std::io::Error::other("invalid file descriptor received"));
    }

    use std::os::fd::FromRawFd;
    // SAFETY: fd was received via SCM_RIGHTS and is now owned by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn arp_reply(frame: &[u8]) -> Option<Vec<u8>> {
    if frame.len() < 42 || u16::from_be_bytes([frame[12], frame[13]]) != 0x0806 {
        return None;
    }
    let arp = &frame[14..42];
    let htype = u16::from_be_bytes([arp[0], arp[1]]);
    let ptype = u16::from_be_bytes([arp[2], arp[3]]);
    let hlen = arp[4];
    let plen = arp[5];
    let op = u16::from_be_bytes([arp[6], arp[7]]);
    if htype != 1 || ptype != 0x0800 || hlen != 6 || plen != 4 || op != 1 {
        return None;
    }

    let gateway_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let sender_mac = &arp[8..14];
    let sender_ip = &arp[14..18];
    let target_ip = &arp[24..28];

    let mut reply = vec![0u8; 42];
    reply[0..6].copy_from_slice(sender_mac);
    reply[6..12].copy_from_slice(&gateway_mac);
    reply[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    reply[14..16].copy_from_slice(&1u16.to_be_bytes());
    reply[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
    reply[18] = 6;
    reply[19] = 4;
    reply[20..22].copy_from_slice(&2u16.to_be_bytes());
    reply[22..28].copy_from_slice(&gateway_mac);
    reply[28..32].copy_from_slice(target_ip);
    reply[32..38].copy_from_slice(sender_mac);
    reply[38..42].copy_from_slice(sender_ip);
    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tap_capture_command() {
        let ControlRequest::CaptureTap(spec) = parse_control_request(
            "capture-tap vm_id=app5 netns=/proc/791/ns/net userns=/proc/791/ns/user if=tap0 setup=tap addr=10.5.0.2/24 gw=10.5.0.1 route=default",
        )
        .unwrap()
        else {
            panic!("expected capture-tap");
        };
        assert_eq!(spec.vm_id, "app5");
        assert_eq!(spec.netns_path, PathBuf::from("/proc/791/ns/net"));
        assert_eq!(spec.userns_path, Some(PathBuf::from("/proc/791/ns/user")));
        assert_eq!(spec.if_name.as_deref(), Some("tap0"));
        assert_eq!(
            spec.setup,
            Some(NetnsSetup {
                address: Some("10.5.0.2/24".to_string()),
                gateway: Some("10.5.0.1".to_string()),
                mtu: None,
                default_route: true,
                egress_redirect: None,
            })
        );
    }

    #[test]
    fn route_outgoing_packet_counts_full_destination_queue() {
        crate::stats::stats().reset();
        let dst = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 250, 0, 2));
        let (tx, mut rx) = mpsc::channel::<TapInject>(1);
        let wake_fd = create_eventfd().unwrap();
        register_destination(dst, TapInjectSender::new(tx, wake_fd));

        let first = crate::packet::build_ipv4_udp_packet(
            std::net::Ipv4Addr::new(192, 0, 2, 10),
            1234,
            std::net::Ipv4Addr::new(10, 250, 0, 2),
            5678,
            b"first",
        )
        .unwrap();
        let second = crate::packet::build_ipv4_udp_packet(
            std::net::Ipv4Addr::new(192, 0, 2, 10),
            1234,
            std::net::Ipv4Addr::new(10, 250, 0, 2),
            5678,
            b"second",
        )
        .unwrap();

        assert!(route_outgoing_packet(&first));
        assert!(route_outgoing_packet(&second));
        assert_eq!(
            crate::stats::stats()
                .route_send_full
                .load(Ordering::Relaxed),
            1
        );

        unregister_destination(&dst);
        let _ = rx.try_recv();
    }
}
