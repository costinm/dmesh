//! ESP-IDF lwIP UDP6 adapter for Main/Recovery.
//!
//! The Wi-Fi driver and lwIP own Ethernet, IPv6, NDP, and UDP framing. This
//! adapter receives UDP payloads directly into the node packet pool and sends
//! QUIC payloads from the same pool lease; it does not build Ethernet or
//! 802.11 frames or retain a bearer-private packet buffer.

use core::{
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU32, Ordering},
};
use quic_lite::PacketWriter;

use crate::wifi_raw_udp6_esp::{
    RawUdp6Peer, ANNOUNCE_UDP6_PORT, RAW_UDP6_PORT,
};

static DATA_SOCKET: AtomicI32 = AtomicI32::new(-1);
static ANNOUNCE_SOCKET: AtomicI32 = AtomicI32::new(-1);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static RX_TASK: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static RX_DATAGRAMS: AtomicU32 = AtomicU32::new(0);
static RX_QUEUE_DROPS: AtomicU32 = AtomicU32::new(0);
static RX_INVALID: AtomicU32 = AtomicU32::new(0);
static RX_QUIC_ADMITTED: AtomicU32 = AtomicU32::new(0);
static TX_DATAGRAMS: AtomicU32 = AtomicU32::new(0);
static TX_ERRORS: AtomicU32 = AtomicU32::new(0);
static JOINED_STA_INDEX: AtomicU32 = AtomicU32::new(0);
static JOINED_AP_INDEX: AtomicU32 = AtomicU32::new(0);

// ESP-IDF's picolibc stores errno in thread-local storage. The generated
// esp-idf-sys binding exposes the C TLS variable as an ordinary static, which
// creates an invalid non-TLS relocation when referenced from Rust. The SDK's
// Newlib-compatibility setting exports this accessor for the current profiles.
unsafe extern "C" {
    fn __errno() -> *mut i32;
}

fn errno() -> i32 {
    unsafe { *__errno() }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SendResult {
    Accepted,
    Busy,
    Failed,
}

fn socket_address(ip: [u8; 16], port: u16, scope: u32) -> esp_idf_sys::sockaddr_in6 {
    let mut address = esp_idf_sys::sockaddr_in6::default();
    address.sin6_len = core::mem::size_of::<esp_idf_sys::sockaddr_in6>() as u8;
    address.sin6_family = esp_idf_sys::AF_INET6 as esp_idf_sys::sa_family_t;
    address.sin6_port = port.to_be();
    address.sin6_scope_id = scope;
    address.sin6_addr.un.u8_addr = ip;
    address
}

fn bind_udp6(port: u16) -> Option<i32> {
    let socket = unsafe {
        esp_idf_sys::lwip_socket(
            esp_idf_sys::AF_INET6 as i32,
            esp_idf_sys::SOCK_DGRAM as i32,
            esp_idf_sys::IPPROTO_UDP as i32,
        )
    };
    if socket < 0 {
        return None;
    }
    let reuse: i32 = 1;
    let option = unsafe {
        esp_idf_sys::lwip_setsockopt(
            socket,
            esp_idf_sys::SOL_SOCKET as i32,
            esp_idf_sys::SO_REUSEADDR as i32,
            (&reuse as *const i32).cast(),
            core::mem::size_of_val(&reuse) as esp_idf_sys::socklen_t,
        )
    };
    let local = socket_address([0; 16], port, 0);
    let bound = unsafe {
        esp_idf_sys::lwip_bind(
            socket,
            (&local as *const esp_idf_sys::sockaddr_in6).cast(),
            core::mem::size_of_val(&local) as esp_idf_sys::socklen_t,
        )
    };
    if option != 0 || bound != 0 {
        unsafe { esp_idf_sys::lwip_close(socket) };
        return None;
    }
    Some(socket)
}

fn ensure_sockets() -> bool {
    if DATA_SOCKET.load(Ordering::Acquire) >= 0
        && ANNOUNCE_SOCKET.load(Ordering::Acquire) >= 0
    {
        return true;
    }
    let Some(data) = bind_udp6(RAW_UDP6_PORT) else { return false };
    let Some(announce) = bind_udp6(ANNOUNCE_UDP6_PORT) else {
        unsafe { esp_idf_sys::lwip_close(data) };
        return false;
    };
    DATA_SOCKET.store(data, Ordering::Release);
    ANNOUNCE_SOCKET.store(announce, Ordering::Release);
    join_announce_group();
    true
}

/// Start the shared UDP6 listener sockets. STA and AP use the same bound
/// sockets; IPv6 scope selects the interface for link-local peers.
pub(crate) fn start() -> bool {
    if !ensure_sockets() {
        return false;
    }
    // The higher-priority RX task can run before xTaskCreate returns. Publish
    // readiness first so a queued datagram cannot trap startup in poll.
    ACTIVE.store(true, Ordering::Release);
    if !ensure_rx_task() {
        ACTIVE.store(false, Ordering::Release);
        return false;
    }
    true
}

/// AP netif/interface indices may become available after the initial STA
/// socket setup. Refresh multicast membership after each radio profile change.
pub(crate) fn refresh_interfaces() {
    join_announce_group();
}

pub(crate) fn stop() {
    // Keep the two lwIP sockets and the one blocking receiver task reusable
    // across STA/AP transitions. With no Wi-Fi netif up, lwIP poll sleeps and
    // this costs no packet buffer or periodic owner wake.
    ACTIVE.store(false, Ordering::Release);
}

fn join_announce_group() {
    let socket = ANNOUNCE_SOCKET.load(Ordering::Acquire);
    if socket < 0 { return; }
    const GROUP: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x52, 0x27];
    for link in [
        crate::shared_ingress_esp::IngressLink::WifiSta,
        crate::shared_ingress_esp::IngressLink::WifiAp,
    ] {
        let Some(index) = crate::wifi_esp::netif_index(link) else { continue };
        let joined_index = match link {
            crate::shared_ingress_esp::IngressLink::WifiSta => &JOINED_STA_INDEX,
            crate::shared_ingress_esp::IngressLink::WifiAp => &JOINED_AP_INDEX,
            crate::shared_ingress_esp::IngressLink::None => continue,
        };
        if joined_index.load(Ordering::Acquire) == index {
            continue;
        }
        let mut request = esp_idf_sys::ipv6_mreq::default();
        request.ipv6mr_multiaddr.un.u8_addr = GROUP;
        request.ipv6mr_interface = index;
        let result = unsafe {
            esp_idf_sys::lwip_setsockopt(
                socket,
                esp_idf_sys::IPPROTO_IPV6 as i32,
                esp_idf_sys::IPV6_JOIN_GROUP as i32,
                (&request as *const esp_idf_sys::ipv6_mreq).cast(),
                core::mem::size_of_val(&request) as esp_idf_sys::socklen_t,
            )
        };
        if result == 0 {
            joined_index.store(index, Ordering::Release);
        }
    }
}

fn link_index(link: crate::shared_ingress_esp::IngressLink) -> Option<u32> {
    crate::wifi_esp::netif_index(link)
}

fn send_fd(fd: i32, link: crate::shared_ingress_esp::IngressLink, ip: [u8; 16], port: u16, bytes: &[u8]) -> SendResult {
    if fd < 0 || bytes.is_empty() {
        return SendResult::Failed;
    }
    let Some(scope) = link_index(link) else { return SendResult::Failed };
    let address = socket_address(ip, port, scope);
    let sent = unsafe {
        esp_idf_sys::lwip_sendto(
            fd,
            bytes.as_ptr().cast(),
            bytes.len(),
            esp_idf_sys::MSG_DONTWAIT as i32,
            (&address as *const esp_idf_sys::sockaddr_in6).cast(),
            core::mem::size_of_val(&address) as esp_idf_sys::socklen_t,
        )
    };
    if sent == bytes.len() as isize {
        TX_DATAGRAMS.fetch_add(1, Ordering::Relaxed);
        SendResult::Accepted
    } else {
        TX_ERRORS.fetch_add(1, Ordering::Relaxed);
        let error = errno();
        if error == esp_idf_sys::EWOULDBLOCK as i32 || error == esp_idf_sys::EAGAIN as i32 {
            SendResult::Busy
        } else {
            SendResult::Failed
        }
    }
}

pub(crate) fn send_data(peer: RawUdp6Peer, bytes: &[u8]) -> SendResult {
    send_fd(DATA_SOCKET.load(Ordering::Acquire), peer.link, peer.ip, peer.port, bytes)
}

pub(crate) fn send_announce(link: crate::shared_ingress_esp::IngressLink, bytes: &[u8]) -> SendResult {
    const GROUP: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x52, 0x27];
    let Some(scope) = link_index(link) else { return SendResult::Failed };
    let address = socket_address(GROUP, ANNOUNCE_UDP6_PORT, scope);
    let fd = DATA_SOCKET.load(Ordering::Acquire);
    let sent = unsafe {
        esp_idf_sys::lwip_sendto(
            fd,
            bytes.as_ptr().cast(),
            bytes.len(),
            esp_idf_sys::MSG_DONTWAIT as i32,
            (&address as *const esp_idf_sys::sockaddr_in6).cast(),
            core::mem::size_of_val(&address) as esp_idf_sys::socklen_t,
        )
    };
    if sent == bytes.len() as isize {
        TX_DATAGRAMS.fetch_add(1, Ordering::Relaxed);
        SendResult::Accepted
    } else {
        TX_ERRORS.fetch_add(1, Ordering::Relaxed);
        SendResult::Failed
    }
}

fn peer_from_address(address: esp_idf_sys::sockaddr_in6) -> Option<RawUdp6Peer> {
    let link = crate::wifi_esp::link_for_netif_index(address.sin6_scope_id)?;
    let ip = unsafe { address.sin6_addr.un.u8_addr };
    Some(RawUdp6Peer {
        link,
        mac: mac_from_link_local(ip).unwrap_or([0; 6]),
        ip,
        port: u16::from_be(address.sin6_port),
    })
}

fn mac_from_link_local(ip: [u8; 16]) -> Option<[u8; 6]> {
    if ip[0] != 0xfe || ip[1] & 0xc0 != 0x80 || ip[11] != 0xff || ip[12] != 0xfe {
        return None;
    }
    Some([ip[8] ^ 0x02, ip[9], ip[10], ip[13], ip[14], ip[15]])
}

/// Poll a small batch on the serialized QUIC owner. Datagram payloads are
/// received directly into pool writers and handed to the endpoint without a
/// second copy. lwIP handles Ethernet, IPv6, checksums, and neighbor discovery.
pub(crate) fn poll() {
    let data = DATA_SOCKET.load(Ordering::Acquire);
    let announce = ANNOUNCE_SOCKET.load(Ordering::Acquire);
    if data < 0 || announce < 0 { return; }
    for _ in 0..4 {
        if !receive_one(announce, true) { break; }
    }
    for _ in 0..4 {
        if !receive_one(data, false) { break; }
    }
}

fn ensure_rx_task() -> bool {
    if !RX_TASK.load(Ordering::Acquire).is_null() {
        return true;
    }
    let mut task = core::ptr::null_mut();
    let created = unsafe {
        esp_idf_sys::xTaskCreatePinnedToCore(
            Some(rx_task_entry),
            b"dmesh_udp6_rx\0".as_ptr().cast(),
            3_072,
            core::ptr::null_mut(),
            4,
            &mut task,
            // IDF 6 uses INT_MAX, not -1, for an unpinned task. Passing -1
            // asserts on the single-core C6 before Main becomes reachable.
            esp_idf_sys::CONFIG_FREERTOS_NO_AFFINITY as i32,
        )
    } == 1 && !task.is_null();
    if created {
        RX_TASK.store(task.cast(), Ordering::Release);
    }
    created
}

unsafe extern "C" fn rx_task_entry(_argument: *mut c_void) {
    unsafe { esp_idf_sys::lwip_socket_thread_init() };
    loop {
        let data = DATA_SOCKET.load(Ordering::Acquire);
        let announce = ANNOUNCE_SOCKET.load(Ordering::Acquire);
        if data < 0 || announce < 0 {
            unsafe { esp_idf_sys::vTaskDelay(100) };
            continue;
        }
        let mut descriptors = [
            esp_idf_sys::pollfd { fd: announce, events: esp_idf_sys::POLLIN as i16, revents: 0 },
            esp_idf_sys::pollfd { fd: data, events: esp_idf_sys::POLLIN as i16, revents: 0 },
        ];
        let ready = unsafe { esp_idf_sys::lwip_poll(descriptors.as_mut_ptr(), descriptors.len() as u32, 1_000) };
        if ready <= 0 {
            continue;
        }
        if descriptors[0].revents & esp_idf_sys::POLLIN as i16 != 0 {
            while receive_one(announce, true) {}
        }
        if descriptors[1].revents & esp_idf_sys::POLLIN as i16 != 0 {
            while receive_one(data, false) {}
        }
    }
}

fn discard_one(fd: i32) -> bool {
    // UDP recv with a zero-length destination consumes and frees the whole
    // datagram in lwIP. A non-null address satisfies its pbuf argument check;
    // length zero means no payload is copied and no pool lease is needed.
    let mut unused = 0u8;
    let consumed = unsafe {
        esp_idf_sys::lwip_recvfrom(fd, (&mut unused as *mut u8).cast(), 0,
            esp_idf_sys::MSG_DONTWAIT as i32, core::ptr::null_mut(), core::ptr::null_mut())
    } >= 0;
    if consumed {
        RX_QUEUE_DROPS.fetch_add(1, Ordering::Relaxed);
    }
    consumed
}

fn receive_one(fd: i32, announcement_socket: bool) -> bool {
    if !ACTIVE.load(Ordering::Acquire) {
        return discard_one(fd);
    }
    let Some(mut writer) = crate::quic_node_esp::acquire_udp_receive_writer() else {
        // Leave no permanently-readable datagram behind: otherwise this
        // priority-4 task spins and the priority-1 owner cannot free leases.
        return discard_one(fd);
    };
    let mut source = esp_idf_sys::sockaddr_in6::default();
    let mut source_len = core::mem::size_of_val(&source) as esp_idf_sys::socklen_t;
    let capacity = writer.payload_mut().len();
    let received = unsafe {
        esp_idf_sys::lwip_recvfrom(
            fd,
            writer.payload_mut().as_mut_ptr().cast(),
            capacity,
            esp_idf_sys::MSG_DONTWAIT as i32,
            (&mut source as *mut esp_idf_sys::sockaddr_in6).cast(),
            &mut source_len,
        )
    };
    if received <= 0 {
        if received < 0 {
            let error = errno();
            if error != esp_idf_sys::EWOULDBLOCK as i32 && error != esp_idf_sys::EAGAIN as i32 {
                RX_INVALID.fetch_add(1, Ordering::Relaxed);
            }
        }
        return false;
    }
    let Some(packet) = writer.commit(received as usize) else {
        RX_QUEUE_DROPS.fetch_add(1, Ordering::Relaxed);
        return true;
    };
    let Some(peer) = peer_from_address(source) else {
        RX_INVALID.fetch_add(1, Ordering::Relaxed);
        return true;
    };
    RX_DATAGRAMS.fetch_add(1, Ordering::Relaxed);
    if announcement_socket || dmesh_server::announce::discovery_request_id(packet.bytes()).is_some() {
        if !crate::quic_node_esp::defer_control_packet(
            crate::quic_node_esp::ControlPeer::Udp(peer), packet,
        ) {
            RX_QUEUE_DROPS.fetch_add(1, Ordering::Relaxed);
        }
        return true;
    }
    if let Some(path) = crate::wifi_raw_udp6_esp::bind_udp_peer_for_socket(peer) {
        crate::quic_node_esp::receive_udp6_packet(path, packet);
        RX_QUIC_ADMITTED.fetch_add(1, Ordering::Relaxed);
    } else if !crate::quic_node_esp::defer_udp_packet(peer, packet) {
        RX_QUEUE_DROPS.fetch_add(1, Ordering::Relaxed);
    }
    true
}

pub(crate) fn stats() -> (u32, u32, u32, u32, u32, u32) {
    (
        RX_DATAGRAMS.load(Ordering::Relaxed),
        RX_QUEUE_DROPS.load(Ordering::Relaxed),
        RX_INVALID.load(Ordering::Relaxed),
        RX_QUIC_ADMITTED.load(Ordering::Relaxed),
        TX_DATAGRAMS.load(Ordering::Relaxed),
        TX_ERRORS.load(Ordering::Relaxed),
    )
}

pub(crate) fn reset_stats() {
    RX_DATAGRAMS.store(0, Ordering::Relaxed);
    RX_QUEUE_DROPS.store(0, Ordering::Relaxed);
    RX_INVALID.store(0, Ordering::Relaxed);
    RX_QUIC_ADMITTED.store(0, Ordering::Relaxed);
    TX_DATAGRAMS.store(0, Ordering::Relaxed);
    TX_ERRORS.store(0, Ordering::Relaxed);
}
