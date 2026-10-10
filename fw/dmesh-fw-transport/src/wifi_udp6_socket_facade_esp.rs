//! Compatibility façade for the firmware UDP6 bearer.
//!
//! ESP-IDF/lwIP owns Ethernet, IPv6, NDP, and UDP framing. QUIC payloads are
//! received into the node packet pool and transmitted directly from the pool
//! lease; this module owns only peer/path mapping and discovery observations.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicUsize, Ordering};

pub const RAW_UDP6_PORT: u16 = 3339;
pub const ANNOUNCE_UDP6_PORT: u16 = 5227;
pub const ANNOUNCE_PEER_CAPACITY: usize = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawUdp6Peer {
    pub link: crate::shared_ingress_esp::IngressLink,
    pub mac: [u8; 6],
    pub ip: [u8; 16],
    pub port: u16,
}

pub type RawUdp6Handler = fn(
    quic_lite::PeerL2Address,
    RawUdp6Peer,
    &[u8],
    &mut [u8; quic_lite::DEFAULT_MAX_PACKET_SIZE],
) -> Option<usize>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionlessUdp6Outcome {
    Rejected,
    Handled,
    Response(usize),
}

pub type ConnectionlessUdp6Handler = fn(
    RawUdp6Peer,
    &[u8],
    &mut [u8; quic_lite::DEFAULT_MAX_PACKET_SIZE],
) -> ConnectionlessUdp6Outcome;
pub type RawUdp6PollHandler =
    fn(quic_lite::PeerL2Address, &mut [u8; quic_lite::DEFAULT_MAX_PACKET_SIZE]) -> Option<usize>;

static STARTED: AtomicBool = AtomicBool::new(false);
static START_STATUS: AtomicU32 = AtomicU32::new(0);
static POLL_HANDLER: AtomicUsize = AtomicUsize::new(0);

type UdpPathBindings =
    dmesh_server::transport_path::PathBindingTable<RawUdp6Peer, { crate::MAX_QUIC_ASSOCIATIONS }>;
static mut UDP_PATH_BINDINGS: UdpPathBindings =
    UdpPathBindings::new(((dmesh_server::transport_path::TransportId::UDP6.0 as u64) << 48) | 1);
static UDP_PATH_LOCK: AtomicBool = AtomicBool::new(false);

fn with_udp_paths<R>(f: impl FnOnce(&mut UdpPathBindings) -> R) -> R {
    while UDP_PATH_LOCK.swap(true, Ordering::Acquire) {
        core::hint::spin_loop();
    }
    let result = unsafe { f(&mut *core::ptr::addr_of_mut!(UDP_PATH_BINDINGS)) };
    UDP_PATH_LOCK.store(false, Ordering::Release);
    result
}

struct AnnouncePeerSlot {
    device_id: [AtomicU32; 4],
    device_id_len: AtomicU8,
    source_ip: [AtomicU32; 4],
    source_mac_low: AtomicU32,
    source_mac_high: AtomicU32,
    uptime_secs: AtomicU32,
    kind: AtomicU32,
    last_seen_ms: AtomicU32,
}

impl AnnouncePeerSlot {
    const fn new() -> Self {
        Self {
            device_id: [const { AtomicU32::new(0) }; 4],
            device_id_len: AtomicU8::new(0),
            source_ip: [const { AtomicU32::new(0) }; 4],
            source_mac_low: AtomicU32::new(0),
            source_mac_high: AtomicU32::new(0),
            uptime_secs: AtomicU32::new(0),
            kind: AtomicU32::new(0),
            last_seen_ms: AtomicU32::new(0),
        }
    }
}

static ANNOUNCE_PEERS: [AnnouncePeerSlot; ANNOUNCE_PEER_CAPACITY] =
    [const { AnnouncePeerSlot::new() }; ANNOUNCE_PEER_CAPACITY];
static ANNOUNCE_NEXT: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnouncePeerSnapshot {
    pub device_id: [u8; 16],
    pub device_id_len: u8,
    pub source_ip: [u8; 16],
    pub source_mac: [u8; 6],
    pub uptime_secs: u32,
    pub kind: u8,
    pub last_seen_ms: u32,
}

pub fn announce_peers(out: &mut [Option<AnnouncePeerSnapshot>; ANNOUNCE_PEER_CAPACITY]) {
    for (index, slot) in ANNOUNCE_PEERS.iter().enumerate() {
        let last_seen_ms = slot.last_seen_ms.load(Ordering::Acquire);
        if last_seen_ms == 0 {
            out[index] = None;
            continue;
        }
        let mut device_id = [0; 16];
        let mut source_ip = [0; 16];
        for (index, word) in slot.device_id.iter().enumerate() {
            device_id[index * 4..index * 4 + 4]
                .copy_from_slice(&word.load(Ordering::Relaxed).to_be_bytes());
        }
        for (index, word) in slot.source_ip.iter().enumerate() {
            source_ip[index * 4..index * 4 + 4]
                .copy_from_slice(&word.load(Ordering::Relaxed).to_be_bytes());
        }
        let low = slot.source_mac_low.load(Ordering::Relaxed).to_le_bytes();
        let high = slot.source_mac_high.load(Ordering::Relaxed).to_le_bytes();
        out[index] = Some(AnnouncePeerSnapshot {
            device_id,
            device_id_len: slot.device_id_len.load(Ordering::Relaxed),
            source_ip,
            source_mac: [low[0], low[1], low[2], low[3], high[0], high[1]],
            uptime_secs: slot.uptime_secs.load(Ordering::Relaxed),
            kind: slot.kind.load(Ordering::Relaxed) as u8,
            last_seen_ms,
        });
    }
}

pub fn start(
    _local_mac: [u8; 6],
    _ap_bssid: [u8; 6],
    _handler: RawUdp6Handler,
    _connectionless_handler: ConnectionlessUdp6Handler,
) -> bool {
    start_sockets()
}

pub fn start_ap(
    _handler: RawUdp6Handler,
    _connectionless_handler: ConnectionlessUdp6Handler,
) -> bool {
    start_sockets()
}

fn start_sockets() -> bool {
    if !crate::wifi_udp6_socket_esp::start() {
        START_STATUS.store(2, Ordering::Release);
        STARTED.store(false, Ordering::Release);
        return false;
    }
    STARTED.store(true, Ordering::Release);
    crate::wifi_udp6_socket_esp::refresh_interfaces();
    START_STATUS.store(1, Ordering::Release);
    true
}

pub fn started() -> bool {
    STARTED.load(Ordering::Acquire)
}

pub fn start_status() -> u32 {
    START_STATUS.load(Ordering::Relaxed)
}

pub fn stop() {
    if STARTED.swap(false, Ordering::AcqRel) {
        crate::wifi_udp6_socket_esp::stop();
        START_STATUS.store(0, Ordering::Release);
    }
}

pub fn rebind_sta_after_wifi_restart() -> bool {
    crate::wifi_udp6_socket_esp::refresh_interfaces();
    true
}

pub fn ensure_ap_rx_callback() -> bool {
    crate::wifi_udp6_socket_esp::refresh_interfaces();
    true
}

pub fn update_ap_bssid(_ap_bssid: [u8; 6]) {}

pub fn set_sta_driver_tx(enabled: bool) {
    let _ = enabled; // Legacy profile knob; lwIP owns all UDP6 transmit policy.
}

pub fn sta_driver_tx_enabled() -> bool {
    true
}

pub fn set_poll_handler(handler: Option<RawUdp6PollHandler>) {
    POLL_HANDLER.store(
        handler.map_or(0, |handler| handler as usize),
        Ordering::Release,
    );
}

pub fn stats() -> (u32, u32, u32, u32, u32, u32) {
    crate::wifi_udp6_socket_esp::stats()
}

pub fn diagnostics() -> (u32, u32, u32, u32, u32, u32) {
    let (_, _, _, _, _, errors) = stats();
    (0, errors, 0, 0, 0, 0)
}

pub fn reset_diagnostics() {
    crate::wifi_udp6_socket_esp::reset_stats();
}

pub fn ndp_advertisements() -> u32 {
    0
}

pub fn ethernet_tx_done_diagnostics() -> [u32; 4] {
    [0; 4]
}

pub fn tx_submit_timing() -> (u32, u32, u32) {
    (0, 0, 0)
}

pub fn last_tx_result() -> u32 {
    0
}

pub(crate) fn tx_submit_failure_details() -> (u32, u32, u32) {
    (0, 0, 0)
}

pub(crate) fn tx_failure_memory() -> [u32; 4] {
    [0; 4]
}

pub(crate) fn bind_udp_peer_for_socket(peer: RawUdp6Peer) -> Option<quic_lite::PeerL2Address> {
    // The socket RX task has higher priority than the serialized owner. It
    // must not spin if it preempted that owner while the table is locked:
    // doing so prevents the owner from ever releasing the lock. Contention
    // takes the existing deferred-packet path, resolved by the owner later.
    if UDP_PATH_LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        return None;
    }
    let result = unsafe { (&mut *core::ptr::addr_of_mut!(UDP_PATH_BINDINGS)).bind(peer) };
    UDP_PATH_LOCK.store(false, Ordering::Release);
    result
}

pub(crate) fn peer_for_path(path: quic_lite::PeerL2Address) -> Option<RawUdp6Peer> {
    with_udp_paths(|bindings| bindings.get(path))
}

pub(crate) fn path_for_udp_address(address: &[u8]) -> Option<quic_lite::PeerL2Address> {
    let bytes: &[u8; 18] = address.try_into().ok()?;
    let port = u16::from_be_bytes([bytes[16], bytes[17]]);
    with_udp_paths(|bindings| bindings.find(|peer| peer.ip == bytes[..16] && peer.port == port))
}

pub(crate) fn transmit_udp6(
    link: crate::shared_ingress_esp::IngressLink,
    peer: RawUdp6Peer,
    source_port: u16,
    payload: &[u8],
) -> bool {
    source_port == RAW_UDP6_PORT
        && crate::wifi_udp6_socket_esp::send_data(RawUdp6Peer { link, ..peer }, payload)
            == crate::wifi_udp6_socket_esp::SendResult::Accepted
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum UdpTransmitResult {
    Accepted,
    Busy,
    Failed,
}

pub(crate) fn transmit_udp6_owned(
    peer: RawUdp6Peer,
    source_port: u16,
    packet: crate::quic_node_esp::FirmwarePacket,
) -> (crate::quic_node_esp::FirmwarePacket, UdpTransmitResult) {
    let result = if source_port == RAW_UDP6_PORT {
        crate::wifi_udp6_socket_esp::send_data(peer, packet.bytes())
    } else {
        crate::wifi_udp6_socket_esp::SendResult::Failed
    };
    let result = match result {
        crate::wifi_udp6_socket_esp::SendResult::Accepted => UdpTransmitResult::Accepted,
        crate::wifi_udp6_socket_esp::SendResult::Busy => UdpTransmitResult::Busy,
        crate::wifi_udp6_socket_esp::SendResult::Failed => UdpTransmitResult::Failed,
    };
    (packet, result)
}

pub fn broadcast_announce(payload: &[u8]) -> bool {
    if payload.is_empty() || payload.len() > crate::TRANSPORT_MTU {
        return false;
    }
    let mut sent = false;
    if crate::wifi_esp::sta_associated() {
        sent |= crate::wifi_udp6_socket_esp::send_announce(
            crate::shared_ingress_esp::IngressLink::WifiSta,
            payload,
        ) == crate::wifi_udp6_socket_esp::SendResult::Accepted;
    }
    if crate::wifi_esp::lab_open_ap_active() {
        sent |= crate::wifi_udp6_socket_esp::send_announce(
            crate::shared_ingress_esp::IngressLink::WifiAp,
            payload,
        ) == crate::wifi_udp6_socket_esp::SendResult::Accepted;
    }
    sent
}

pub(crate) fn poll_connection_timer() {
    let poll = POLL_HANDLER.load(Ordering::Acquire);
    if poll == 0 {
        return;
    }
    let Some(path) = crate::core_runtime::connection_reply_path() else {
        return;
    };
    let Some(peer) = peer_for_path(path) else {
        return;
    };
    let poll: RawUdp6PollHandler = unsafe { core::mem::transmute(poll) };
    let mut response = [0; quic_lite::DEFAULT_MAX_PACKET_SIZE];
    if let Some(used) = poll(path, &mut response).filter(|used| *used <= response.len()) {
        let _ = transmit_udp6(peer.link, peer, RAW_UDP6_PORT, &response[..used]);
    }
}

pub(crate) fn record_announce_peer(
    announce: dmesh_server::announce::Announce,
    source_mac: [u8; 6],
    source_ip: [u8; 16],
) {
    let mut selected = None;
    for (index, slot) in ANNOUNCE_PEERS.iter().enumerate() {
        let mut equal = slot.device_id_len.load(Ordering::Acquire) == announce.device_id_len;
        for (word, bytes) in slot
            .device_id
            .iter()
            .zip(announce.device_id.chunks_exact(4))
        {
            if word.load(Ordering::Acquire) != u32::from_be_bytes(bytes.try_into().unwrap()) {
                equal = false;
                break;
            }
        }
        if equal && slot.last_seen_ms.load(Ordering::Acquire) != 0 {
            selected = Some(index);
            break;
        }
    }
    let index = selected
        .unwrap_or_else(|| ANNOUNCE_NEXT.fetch_add(1, Ordering::Relaxed) % ANNOUNCE_PEER_CAPACITY);
    let slot = &ANNOUNCE_PEERS[index];
    for (word, bytes) in slot
        .device_id
        .iter()
        .zip(announce.device_id.chunks_exact(4))
    {
        word.store(
            u32::from_be_bytes(bytes.try_into().unwrap()),
            Ordering::Relaxed,
        );
    }
    slot.device_id_len
        .store(announce.device_id_len, Ordering::Relaxed);
    for (word, bytes) in slot.source_ip.iter().zip(source_ip.chunks_exact(4)) {
        word.store(
            u32::from_be_bytes(bytes.try_into().unwrap()),
            Ordering::Relaxed,
        );
    }
    slot.source_mac_low.store(
        u32::from_le_bytes([source_mac[0], source_mac[1], source_mac[2], source_mac[3]]),
        Ordering::Relaxed,
    );
    slot.source_mac_high.store(
        u32::from_le_bytes([source_mac[4], source_mac[5], 0, 0]),
        Ordering::Relaxed,
    );
    slot.uptime_secs
        .store(announce.uptime_secs, Ordering::Relaxed);
    slot.kind.store(announce.kind as u32, Ordering::Relaxed);
    let now_ms = (unsafe { esp_idf_sys::esp_timer_get_time() } / 1_000).max(1) as u32;
    slot.last_seen_ms.store(now_ms, Ordering::Release);
}

pub fn record_connectionless_announce(
    announce: dmesh_server::announce::Announce,
    source_mac: [u8; 6],
) {
    record_announce_peer(announce, source_mac, [0; 16]);
}
