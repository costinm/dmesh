use crate::policy::{AllowAllPolicy, FlowContext, FlowProtocol, MeshTunPolicy, PolicyDecision};
use crate::telemetry::{MeshTunEvent, MeshTunTelemetry, NoopTelemetry};
use mesh::tun::{TunDnsHandler, TunInjector, TunUdpHandler, TunUdpPacket};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::net::UdpSocket;

#[derive(Clone)]
pub struct MeshPassthrough {
    vm_id: String,
    policy: Arc<dyn MeshTunPolicy>,
    telemetry: Arc<dyn MeshTunTelemetry>,
    injector: Arc<Mutex<Option<Arc<dyn TunInjector>>>>,
    udp_response_timeout: Duration,
}

impl MeshPassthrough {
    pub fn new(vm_id: impl Into<String>) -> Self {
        Self {
            vm_id: vm_id.into(),
            policy: Arc::new(AllowAllPolicy),
            telemetry: Arc::new(NoopTelemetry),
            injector: Arc::new(Mutex::new(None)),
            udp_response_timeout: Duration::from_millis(500),
        }
    }

    pub fn vm_id(&self) -> &str {
        &self.vm_id
    }

    pub fn with_policy(mut self, policy: Arc<dyn MeshTunPolicy>) -> Self {
        self.policy = policy;
        self
    }

    pub fn with_telemetry(mut self, telemetry: Arc<dyn MeshTunTelemetry>) -> Self {
        self.telemetry = telemetry;
        self
    }

    pub fn with_injector(self, injector: Arc<dyn TunInjector>) -> Self {
        *lock_or_recover(&self.injector) = Some(injector);
        self
    }

    pub fn set_injector(&self, injector: Arc<dyn TunInjector>) {
        *lock_or_recover(&self.injector) = Some(injector);
    }

    pub fn with_udp_response_timeout(mut self, timeout: Duration) -> Self {
        self.udp_response_timeout = timeout;
        self
    }

    fn udp_context(&self, packet: &TunUdpPacket, protocol: FlowProtocol) -> FlowContext {
        FlowContext {
            vm_id: self.vm_id.clone(),
            protocol,
            src: SocketAddr::new(packet.src_addr, packet.src_port),
            dst: SocketAddr::new(packet.dst_addr, packet.dst_port),
        }
    }

    async fn check_policy(&self, context: &FlowContext) -> bool {
        match self.policy.check(context).await {
            PolicyDecision::Allow => true,
            PolicyDecision::Deny { reason } => {
                self.telemetry
                    .record(MeshTunEvent::FlowDeny {
                        context: context.clone(),
                        reason,
                    })
                    .await;
                false
            }
        }
    }

    async fn handle_udp_packet(&self, packet: TunUdpPacket, protocol: FlowProtocol) {
        let context = self.udp_context(&packet, protocol);
        if !self.check_policy(&context).await {
            return;
        }

        self.telemetry
            .record(MeshTunEvent::FlowOpen(context.clone()))
            .await;

        let result = self.proxy_udp_packet(&packet).await;
        match result {
            Ok(bytes) => {
                self.telemetry
                    .record(MeshTunEvent::FlowBytes {
                        context: context.clone(),
                        guest_to_remote: packet.payload.len() as u64,
                        remote_to_guest: bytes,
                    })
                    .await;
                self.telemetry
                    .record(MeshTunEvent::FlowClose(context))
                    .await;
            }
            Err(error) => {
                self.telemetry
                    .record(MeshTunEvent::FlowError {
                        context,
                        error: error.to_string(),
                    })
                    .await;
            }
        }
    }

    async fn proxy_udp_packet(&self, packet: &TunUdpPacket) -> Result<u64, anyhow::Error> {
        let bind_addr = if packet.src_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        let dst = SocketAddr::new(packet.dst_addr, packet.dst_port);
        socket.send_to(&packet.payload, dst).await?;

        let mut buf = vec![0u8; 65535];
        let recv =
            tokio::time::timeout(self.udp_response_timeout, socket.recv_from(&mut buf)).await;
        let Ok(Ok((n, remote))) = recv else {
            return Ok(0);
        };

        let injector = lock_or_recover(&self.injector).clone();
        if let Some(injector) = injector {
            injector
                .inject_udp(
                    remote.ip(),
                    remote.port(),
                    packet.src_addr,
                    packet.src_port,
                    &buf[..n],
                )
                .await?;
        }

        Ok(n as u64)
    }
}

fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

#[async_trait::async_trait]
impl TunUdpHandler for MeshPassthrough {
    async fn handle_udp(&self, packet: TunUdpPacket) {
        self.handle_udp_packet(packet, FlowProtocol::Udp).await;
    }
}

#[async_trait::async_trait]
impl TunDnsHandler for MeshPassthrough {
    async fn handle_dns(&self, packet: TunUdpPacket) {
        self.handle_udp_packet(packet, FlowProtocol::Dns).await;
    }
}
