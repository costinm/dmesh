use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use mesh::config::DEFAULT_MESH_TUN_MTU;
use mesh::tun::{TunDnsHandler, TunUdpHandler};
use policy::MeshTunPolicy;
use tcp_proxy::TcpProxyConfig;
use tokio::sync::mpsc;

pub mod control;
pub mod flow;
pub mod injector;
pub mod packet;
pub mod policy;
pub mod stats;
pub mod tcp_proxy;
pub mod telemetry;
pub mod transport;
pub mod uds;
pub mod vhost_user;

/// Configuration for MeshTun.
#[derive(Debug, Clone)]
pub struct MeshTunConfig {
    /// TUN interface name. Ignored if `fd` is set.
    pub name: Option<String>,
    /// Pre-opened TUN file descriptor, used by Android VPN integration.
    pub fd: Option<i32>,
    /// Local IP address reserved for this capture endpoint.
    pub address: IpAddr,
    /// Network prefix length.
    pub prefix_len: u8,
    /// MTU for packet buffers and created TUN devices.
    pub mtu: usize,
    /// Packet queue capacity for TUN ingress, egress, and capture fanout.
    pub packet_queue_capacity: usize,
    /// Workload identity attached to flows from this capture instance.
    pub vm_id: String,
    /// TCP proxy flow-control settings for the mesh/policy path.
    pub tcp_proxy_config: TcpProxyConfig,
}

impl Default for MeshTunConfig {
    fn default() -> Self {
        Self {
            name: None,
            fd: None,
            address: IpAddr::V4(Ipv4Addr::new(10, 5, 0, 1)),
            prefix_len: 16,
            mtu: DEFAULT_MESH_TUN_MTU as usize,
            packet_queue_capacity: 4096,
            vm_id: "default".to_string(),
            tcp_proxy_config: TcpProxyConfig::default(),
        }
    }
}

pub struct MeshTun {
    config: MeshTunConfig,
}

impl MeshTun {
    pub fn new(config: MeshTunConfig) -> Result<Self, anyhow::Error> {
        Ok(Self { config })
    }

    /// Create a MeshTun from an Android VPN/TUN file descriptor.
    ///
    /// The caller remains responsible for passing a valid TUN fd. The fd is
    /// handed to `tun-rs` when [`MeshTun::run_with_policy`] is called.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `fd` is a valid file descriptor for a TUN/VPN device.
    pub unsafe fn from_fd(fd: i32) -> Result<Self, anyhow::Error> {
        if fd < 0 {
            anyhow::bail!("invalid TUN file descriptor: {fd}");
        }
        let config = MeshTunConfig {
            fd: Some(fd),
            ..MeshTunConfig::default()
        };
        Ok(Self { config })
    }

    /// Start packet routing over a real TUN device with a TCP routing policy.
    ///
    /// The policy is called once for each new TCP SYN before the guest
    /// connection is accepted.
    pub async fn run_with_policy(
        self,
        tcp_policy: Arc<dyn MeshTunPolicy>,
        udp_handler: Arc<dyn TunUdpHandler>,
        dns_handler: Arc<dyn TunDnsHandler>,
    ) -> Result<Arc<dyn mesh::tun::TunInjector>, anyhow::Error> {
        let queue_capacity = self.config.packet_queue_capacity;
        let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>(queue_capacity);
        let (device_tx, mut device_rx) = mpsc::channel::<Vec<u8>>(queue_capacity);
        let tcp_proxy = tcp_proxy::TcpProxyManager::new(
            self.config.vm_id.clone(),
            device_tx.clone(),
            tcp_policy,
            self.config.tcp_proxy_config.clone(),
        );
        let injector = Arc::new(injector::MeshTunInjector::with_tcp_proxy(
            device_tx.clone(),
            tcp_proxy.clone(),
        ));

        let tun = self.open_tun_device()?;
        let tun_arc = Arc::new(tun);
        let tun_read = tun_arc.clone();
        let tun_write = tun_arc;
        let mtu = self.config.mtu.max(1500);

        tokio::spawn(async move {
            let mut buf = vec![0u8; mtu.max(65535)];
            loop {
                match tun_read.recv(&mut buf).await {
                    Ok(n) => {
                        if tun_tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        tracing::error!(%error, "TUN read stopped");
                        break;
                    }
                }
            }
        });

        tokio::spawn(async move {
            while let Some(packet) = device_rx.recv().await {
                if let Err(error) = tun_write.send(&packet).await {
                    tracing::error!(%error, "TUN write stopped");
                    break;
                }
            }
        });

        spawn_packet_router_with_policy(tcp_proxy, udp_handler, dns_handler, tun_rx);
        Ok(injector)
    }

    /// Start packet routing over caller-provided channels with a TCP routing policy.
    ///
    /// The policy is called once for each new TCP SYN before the guest
    /// connection is accepted. It can deny the flow or select a connector
    /// backed by a native socket, SSH channel, H2 stream, or another
    /// socket-like transport.
    pub async fn run_with_channels_and_policy(
        self,
        tcp_policy: Arc<dyn MeshTunPolicy>,
        udp_handler: Arc<dyn TunUdpHandler>,
        dns_handler: Arc<dyn TunDnsHandler>,
    ) -> Result<
        (
            Arc<dyn mesh::tun::TunInjector>,
            mpsc::Sender<Vec<u8>>,
            mpsc::Receiver<Vec<u8>>,
        ),
        anyhow::Error,
    > {
        let (incoming_tx, incoming_rx) =
            mpsc::channel::<Vec<u8>>(self.config.packet_queue_capacity);
        let (outgoing_tx, outgoing_rx) =
            mpsc::channel::<Vec<u8>>(self.config.packet_queue_capacity);
        let tcp_proxy = tcp_proxy::TcpProxyManager::new(
            self.config.vm_id.clone(),
            outgoing_tx.clone(),
            tcp_policy,
            self.config.tcp_proxy_config.clone(),
        );
        let injector = Arc::new(injector::MeshTunInjector::with_tcp_proxy(
            outgoing_tx.clone(),
            tcp_proxy.clone(),
        ));
        spawn_packet_router_with_policy(tcp_proxy, udp_handler, dns_handler, incoming_rx);
        Ok((injector, incoming_tx, outgoing_rx))
    }

    fn open_tun_device(&self) -> Result<tun_rs::AsyncDevice, anyhow::Error> {
        if let Some(fd) = self.config.fd {
            if fd < 0 {
                anyhow::bail!("invalid TUN file descriptor: {fd}");
            }
            return unsafe { tun_rs::AsyncDevice::from_fd(fd) }
                .map_err(|error| anyhow::anyhow!("TUN FD error: {error}"));
        }

        #[cfg(target_os = "android")]
        {
            anyhow::bail!("Android TUN devices must be provided by VpnService fd")
        }

        #[cfg(not(target_os = "android"))]
        {
            let mut builder = tun_rs::DeviceBuilder::new();
            if let Some(name) = &self.config.name {
                builder = builder.name(name);
            }
            builder
                .mtu(self.config.mtu as u16)
                .build_async()
                .map_err(|error| anyhow::anyhow!("TUN create error: {error}"))
        }
    }
}

fn spawn_packet_router_with_policy(
    tcp_proxy: tcp_proxy::TcpProxyManager,
    udp_handler: Arc<dyn TunUdpHandler>,
    dns_handler: Arc<dyn TunDnsHandler>,
    mut incoming_rx: mpsc::Receiver<Vec<u8>>,
) {
    tokio::spawn(async move {
        while let Some(packet) = incoming_rx.recv().await {
            match packet::parse_ip_packet_owned(packet) {
                packet::TunPacket::Udp(packet)
                    if packet.src_port == 53 || packet.dst_port == 53 =>
                {
                    tracing::info!(
                        src = %std::net::SocketAddr::new(packet.src_addr, packet.src_port),
                        dst = %std::net::SocketAddr::new(packet.dst_addr, packet.dst_port),
                        bytes = packet.payload.len(),
                        "DNS packet observed from TUN"
                    );
                    let handler = dns_handler.clone();
                    tokio::spawn(async move {
                        handler.handle_dns(packet).await;
                    });
                }
                packet::TunPacket::Udp(packet) => {
                    tracing::info!(
                        src = %std::net::SocketAddr::new(packet.src_addr, packet.src_port),
                        dst = %std::net::SocketAddr::new(packet.dst_addr, packet.dst_port),
                        bytes = packet.payload.len(),
                        "UDP packet observed from TUN"
                    );
                    let handler = udp_handler.clone();
                    tokio::spawn(async move {
                        handler.handle_udp(packet).await;
                    });
                }
                packet::TunPacket::Tcp(tcp) => {
                    tracing::info!(
                        src = %std::net::SocketAddr::new(tcp.src_addr, tcp.src_port),
                        dst = %std::net::SocketAddr::new(tcp.dst_addr, tcp.dst_port),
                        syn = tcp.syn,
                        ack = tcp.ack,
                        "TCP packet observed; routing to TcpProxyManager"
                    );
                    tcp_proxy.handle_packet(tcp).await;
                }
                packet::TunPacket::Other => {}
            }
        }
    });
}
