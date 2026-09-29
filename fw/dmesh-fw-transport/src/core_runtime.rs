//! ESP scheduling glue retained during the `QuicNode` bearer cutover.
//!
//! Packet parsing and association state belong to `quic_node_esp`. These
//! lifecycle hooks deliberately do not emulate the removed dispatcher.

use core::sync::atomic::{AtomicUsize, Ordering};

static DEADLINE_WAKER: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn install_connection_deadline_waker(waker: Option<fn()>) {
    DEADLINE_WAKER.store(waker.map(|f| f as usize).unwrap_or(0), Ordering::Release);
}

pub(crate) fn request_connection_deadline_recheck() {
    let raw = DEADLINE_WAKER.load(Ordering::Acquire);
    if raw != 0 {
        let wake: fn() = unsafe { core::mem::transmute(raw) };
        wake();
    }
}

pub fn install_ble_coc_egress_pump(
    _pump: Option<fn(quic_lite::PeerL2Address, &mut [u8; crate::TRANSPORT_MTU], Option<usize>)>,
) {
}

pub(crate) fn transport_profile_snapshot() -> crate::TransportProfile {
    crate::profile_store::snapshot()
}

pub(crate) fn apply_uart_profile(enabled: bool) {
    if !crate::uart_esp::packetized_debug_selected() {
        crate::uart_esp::set_always_on(enabled);
    }
}

pub(crate) fn prepare_raw_association(_profile: &crate::TransportProfile) {}
pub(crate) fn prepare_espnow_association(_profile: &crate::TransportProfile) {}
pub(crate) fn replace_raw_association(_profile: &crate::TransportProfile) {}

pub const fn connection_path_id(transport_id: u8, peer: [u8; 6]) -> quic_lite::PeerL2Address {
    let value = ((transport_id as u64) << 48)
        | ((peer[0] as u64) << 40)
        | ((peer[1] as u64) << 32)
        | ((peer[2] as u64) << 24)
        | ((peer[3] as u64) << 16)
        | ((peer[4] as u64) << 8)
        | peer[5] as u64;
    match quic_lite::PeerL2Address::new(value) {
        Some(path) => path,
        None => panic!("transport path must be nonzero"),
    }
}

pub(crate) const fn connection_path_transport(path: quic_lite::PeerL2Address) -> u8 {
    (path.value() >> 48) as u8
}

pub(crate) const fn connection_path_peer(path: quic_lite::PeerL2Address) -> [u8; 6] {
    let value = path.value();
    [
        (value >> 40) as u8,
        (value >> 32) as u8,
        (value >> 24) as u8,
        (value >> 16) as u8,
        (value >> 8) as u8,
        value as u8,
    ]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionFrameIngress {
    pub accepted: bool,
    pub response: Option<usize>,
}

pub fn receive_connection_frame_ingress(
    _path: quic_lite::PeerL2Address,
    _packet: &[u8],
    _response: &mut [u8; crate::TRANSPORT_MTU],
) -> ConnectionFrameIngress {
    ConnectionFrameIngress {
        accepted: false,
        response: None,
    }
}

pub fn receive_connection_frame(
    path: quic_lite::PeerL2Address,
    packet: &[u8],
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    receive_connection_frame_ingress(path, packet, response).response
}

pub fn poll_connection(
    _path: quic_lite::PeerL2Address,
    _response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    None
}
pub(crate) fn connection_tx_burst_packets() -> usize {
    1
}
pub(crate) fn connection_delay_ms() -> Option<u32> {
    None
}
pub(crate) fn schedule_connection_timer() {}
pub(crate) fn schedule_uart_egress_ready() {
    // Send completion returns the retained pool lease and may unblock a stream
    // write which lost the race with an ACK. Wake the sole QUIC owner so it
    // drains that completion and retries the unchanged stream bytes.
    crate::main_runtime::request_quic_ingress();
}
pub(crate) fn connection_last_error() -> u32 {
    0
}
pub(crate) fn connection_reply_path() -> Option<quic_lite::PeerL2Address> {
    None
}
pub(crate) fn connection_has_path(_path: quic_lite::PeerL2Address) -> bool {
    false
}
pub(crate) fn take_terminal_response_delivered() -> bool {
    false
}

pub(crate) fn receive_raw_udp6(
    path: quic_lite::PeerL2Address,
    _peer: crate::wifi_raw_udp6_esp::RawUdp6Peer,
    packet: &[u8],
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    receive_connection_frame(path, packet, response)
}
pub(crate) fn receive_main_raw_udp6(
    path: quic_lite::PeerL2Address,
    peer: crate::wifi_raw_udp6_esp::RawUdp6Peer,
    packet: &[u8],
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    receive_raw_udp6(path, peer, packet, response)
}
pub(crate) fn poll_raw_udp6(
    path: quic_lite::PeerL2Address,
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    poll_connection(path, response)
}

pub(crate) fn receive_recovery_connectionless(
    _peer: crate::wifi_raw_udp6_esp::RawUdp6Peer,
    packet: &[u8],
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> crate::wifi_raw_udp6_esp::ConnectionlessUdp6Outcome {
    let Some(id) = dmesh_server::announce::discovery_request_id(packet) else {
        return crate::wifi_raw_udp6_esp::ConnectionlessUdp6Outcome::Rejected;
    };
    let Some((record, used)) = crate::main_runtime::recovery_discovery_record(0) else {
        return crate::wifi_raw_udp6_esp::ConnectionlessUdp6Outcome::Rejected;
    };
    let Some(announce) = dmesh_server::announce::decode_announce(&record[..used]) else {
        return crate::wifi_raw_udp6_esp::ConnectionlessUdp6Outcome::Rejected;
    };
    let Some(used) = dmesh_server::announce::encode_discovery_response(announce, id, response)
    else {
        return crate::wifi_raw_udp6_esp::ConnectionlessUdp6Outcome::Rejected;
    };
    crate::wifi_raw_udp6_esp::ConnectionlessUdp6Outcome::Response(used)
}
pub(crate) fn receive_udp6_connectionless(
    peer: crate::wifi_raw_udp6_esp::RawUdp6Peer,
    packet: &[u8],
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> crate::wifi_raw_udp6_esp::ConnectionlessUdp6Outcome {
    let Some(record) = dmesh_server::tagged::decode(packet) else {
        return crate::wifi_raw_udp6_esp::ConnectionlessUdp6Outcome::Rejected;
    };
    let Some(encoded) = crate::main_runtime::receive_tagged_discovery(record) else {
        return crate::wifi_raw_udp6_esp::ConnectionlessUdp6Outcome::Rejected;
    };
    if encoded.len() > response.len() {
        return crate::wifi_raw_udp6_esp::ConnectionlessUdp6Outcome::Rejected;
    }
    response[..encoded.len()].copy_from_slice(&encoded);
    crate::wifi_raw_udp6_esp::ConnectionlessUdp6Outcome::Response(encoded.len())
}
pub(crate) fn receive_main_espnow(
    _peer: crate::wifi_espnow_esp::EspNowPeer,
    _packet: &[u8],
    _response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    None
}
pub(crate) fn poll_espnow(
    _peer: crate::wifi_espnow_esp::EspNowPeer,
    _response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    None
}
