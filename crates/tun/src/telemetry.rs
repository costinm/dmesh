use crate::policy::{FlowContext, VmId};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MeshTunEvent {
    FlowOpen(FlowContext),
    FlowDeny {
        context: FlowContext,
        reason: String,
    },
    FlowBytes {
        context: FlowContext,
        guest_to_remote: u64,
        remote_to_guest: u64,
    },
    FlowClose(FlowContext),
    FlowError {
        context: FlowContext,
        error: String,
    },
    VmConnect {
        vm_id: VmId,
    },
    VmDisconnect {
        vm_id: VmId,
    },
}

#[async_trait::async_trait]
pub trait MeshTunTelemetry: Send + Sync + 'static {
    async fn record(&self, event: MeshTunEvent);
}

#[derive(Debug, Default)]
pub struct NoopTelemetry;

#[async_trait::async_trait]
impl MeshTunTelemetry for NoopTelemetry {
    async fn record(&self, _event: MeshTunEvent) {}
}
