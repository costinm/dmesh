use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::transport::{NativeTcpConnector, TcpConnector};

pub type VmId = String;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum FlowProtocol {
    Tcp,
    Udp,
    Dns,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FlowContext {
    pub vm_id: VmId,
    pub protocol: FlowProtocol,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PolicyDecision {
    Allow,
    Deny { reason: String },
}

impl PolicyDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

#[derive(Clone)]
pub enum TcpRouteDecision {
    Connect { connector: Arc<dyn TcpConnector> },
    Deny { reason: String },
}

#[async_trait::async_trait]
pub trait MeshTunPolicy: Send + Sync + 'static {
    async fn check(&self, ctx: &FlowContext) -> PolicyDecision;

    async fn route_tcp(&self, ctx: &FlowContext) -> TcpRouteDecision {
        match self.check(ctx).await {
            PolicyDecision::Allow => TcpRouteDecision::Connect {
                connector: Arc::new(NativeTcpConnector),
            },
            PolicyDecision::Deny { reason } => TcpRouteDecision::Deny { reason },
        }
    }
}

#[derive(Debug, Default)]
pub struct AllowAllPolicy;

#[async_trait::async_trait]
impl MeshTunPolicy for AllowAllPolicy {
    async fn check(&self, _ctx: &FlowContext) -> PolicyDecision {
        PolicyDecision::Allow
    }
}

#[derive(Debug, Clone)]
pub struct DenyPortPolicy {
    pub dst_addr: Option<IpAddr>,
    pub dst_port: u16,
    pub reason: String,
}

#[async_trait::async_trait]
impl MeshTunPolicy for DenyPortPolicy {
    async fn check(&self, ctx: &FlowContext) -> PolicyDecision {
        if ctx.dst.port() == self.dst_port
            && self
                .dst_addr
                .map(|addr| addr == ctx.dst.ip())
                .unwrap_or(true)
        {
            return PolicyDecision::Deny {
                reason: self.reason.clone(),
            };
        }
        PolicyDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_allow_all_policy() {
        let policy = AllowAllPolicy;
        let ctx = FlowContext {
            vm_id: "test-vm".to_string(),
            protocol: FlowProtocol::Tcp,
            src: "10.0.0.1:12345".parse().unwrap(),
            dst: "1.1.1.1:80".parse().unwrap(),
        };
        assert!(policy.check(&ctx).await.is_allowed());
    }

    #[tokio::test]
    async fn test_deny_port_policy_match() {
        let policy = DenyPortPolicy {
            dst_addr: None,
            dst_port: 80,
            reason: "no web".to_string(),
        };
        let ctx = FlowContext {
            vm_id: "test-vm".to_string(),
            protocol: FlowProtocol::Tcp,
            src: "10.0.0.1:12345".parse().unwrap(),
            dst: "1.1.1.1:80".parse().unwrap(),
        };
        match policy.check(&ctx).await {
            PolicyDecision::Deny { reason } => assert_eq!(reason, "no web"),
            PolicyDecision::Allow => panic!("Expected deny"),
        }
    }

    #[tokio::test]
    async fn test_deny_port_policy_different_port() {
        let policy = DenyPortPolicy {
            dst_addr: None,
            dst_port: 80,
            reason: "no web".to_string(),
        };
        let ctx = FlowContext {
            vm_id: "test-vm".to_string(),
            protocol: FlowProtocol::Tcp,
            src: "10.0.0.1:12345".parse().unwrap(),
            dst: "1.1.1.1:443".parse().unwrap(),
        };
        assert!(policy.check(&ctx).await.is_allowed());
    }

    #[tokio::test]
    async fn test_deny_port_policy_with_addr_match() {
        let policy = DenyPortPolicy {
            dst_addr: Some("1.1.1.1".parse().unwrap()),
            dst_port: 80,
            reason: "no cf".to_string(),
        };
        let ctx = FlowContext {
            vm_id: "test-vm".to_string(),
            protocol: FlowProtocol::Tcp,
            src: "10.0.0.1:12345".parse().unwrap(),
            dst: "1.1.1.1:80".parse().unwrap(),
        };
        assert!(!policy.check(&ctx).await.is_allowed());
    }

    #[tokio::test]
    async fn test_deny_port_policy_with_addr_mismatch() {
        let policy = DenyPortPolicy {
            dst_addr: Some("1.1.1.1".parse().unwrap()),
            dst_port: 80,
            reason: "no cf".to_string(),
        };
        let ctx = FlowContext {
            vm_id: "test-vm".to_string(),
            protocol: FlowProtocol::Tcp,
            src: "10.0.0.1:12345".parse().unwrap(),
            dst: "8.8.8.8:80".parse().unwrap(),
        };
        assert!(policy.check(&ctx).await.is_allowed());
    }
}
