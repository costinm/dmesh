use crate::packet::build_ipv4_udp_packet;
use crate::tcp_proxy::TcpProxyManager;
use mesh::tun::TunInjector;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use tokio::sync::mpsc;

pub struct MeshTunInjector {
    tx: mpsc::Sender<Vec<u8>>,
    tcp_proxy: Option<TcpProxyManager>,
}

impl MeshTunInjector {
    pub fn new(tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            tx,
            tcp_proxy: None,
        }
    }

    /// Create an injector that can also synthesize inbound TCP connections into a guest.
    ///
    /// `connect_tcp` uses the shared proxy manager so guest replies are routed
    /// through the same packet path as guest-originated flows.
    pub fn with_tcp_proxy(tx: mpsc::Sender<Vec<u8>>, tcp_proxy: TcpProxyManager) -> Self {
        Self {
            tx,
            tcp_proxy: Some(tcp_proxy),
        }
    }
}

#[async_trait::async_trait]
impl TunInjector for MeshTunInjector {
    async fn connect_tcp(
        &self,
        src_addr: IpAddr,
        src_port: u16,
        dst_addr: IpAddr,
        dst_port: u16,
    ) -> Result<tokio::io::DuplexStream, anyhow::Error> {
        let Some(tcp_proxy) = &self.tcp_proxy else {
            anyhow::bail!("TCP stream injection is not configured for this mesh-tun injector");
        };
        tcp_proxy
            .connect_inbound(
                SocketAddr::new(src_addr, src_port),
                SocketAddr::new(dst_addr, dst_port),
            )
            .await
    }

    async fn inject_udp(
        &self,
        src_addr: IpAddr,
        src_port: u16,
        dst_addr: IpAddr,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<(), anyhow::Error> {
        let packet = match (src_addr, dst_addr) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                build_ipv4_udp_packet(src, src_port, dst, dst_port, payload)?
            }
            (IpAddr::V6(_), IpAddr::V6(_)) => {
                anyhow::bail!("IPv6 UDP injection is not implemented yet")
            }
            _ => anyhow::bail!("source and destination IP versions differ"),
        };

        self.tx.send(packet).await.map_err(|_| {
            crate::stats::stats()
                .tun_output_queue_full
                .fetch_add(1, Ordering::Relaxed);
            anyhow::anyhow!("TUN output queue closed")
        })?;
        Ok(())
    }
}
