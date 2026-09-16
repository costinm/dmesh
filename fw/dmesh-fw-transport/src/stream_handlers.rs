//! Firmware application-stream dispatch above the shared QUIC connection.
//!
//! `core_runtime` owns datagram ingress and bearer egress only. Application
//! handlers are composed here, so adding an update, probe, log, or future
//! CoAP-like service never adds a branch to a UART/UDP/NOW receive function.

type ConnectionService = dmesh_server::transport::ConnectionDispatcher<
    { crate::CONNECTION_HISTORY_CAPACITY },
    { crate::TRANSPORT_MTU },
    { crate::MAX_QUIC_ASSOCIATIONS },
>;

pub(crate) unsafe fn before_receive(service: &mut ConnectionService, now_ms: u64) {
    crate::flash::expire(service, now_ms);
}

pub(crate) unsafe fn after_receive(
    service: &mut ConnectionService,
    path: quic_lite::PathId,
    now_ms: u64,
    closed: bool,
) {
    crate::flash::after_receive(service, path, now_ms, closed)
}

pub(crate) unsafe fn before_poll(
    service: &mut ConnectionService,
    path: quic_lite::PathId,
    now_ms: u64,
) {
    crate::flash::expire(service, now_ms);
    crate::flash::before_poll(service, path, now_ms);
}
