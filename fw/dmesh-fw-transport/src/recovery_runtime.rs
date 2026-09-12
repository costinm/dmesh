//! Minimal Recovery STA/UDP6 flash server.
//!
//! The host uses the same `ObjectUploadClient` two-stream operation that it
//! uses for Main. Recovery owns only STA setup, a normal lwIP UDP6 socket,
//! and the shared flash-stream server; it never starts UART packet framing,
//! NAN, NOW, raw UDP6, AP, or generic handlers.

use core::ffi::c_void;

type ConnectionService = dmesh_server::transport::ConnectionDispatcher<
    { crate::CONNECTION_HISTORY_CAPACITY },
    { crate::TRANSPORT_MTU },
    { crate::MAX_QUIC_ASSOCIATIONS },
>;

const RECOVERY_UDP_PORT: u16 = 3339;
const ANNOUNCE_UDP_PORT: u16 = 5227;
// A host AP may retain a previous association briefly after Recovery takes
// over.  This remains bounded and precedes any erase/write work.
const START_TIMEOUT_MS: u64 = 75_000;
const IDLE_TIMEOUT_MS: u64 = 180_000;

extern "C" {
    fn dmesh_boot_handoff_set(handoff: u8);
}

pub fn run() {
    esp_idf_sys::link_patches();
    let mut profile = crate::TransportProfile::new();
    if !crate::main_runtime::apply_sta_profile_from_nvs(&mut profile) {
        log(b"DMESH recovery: STA profile missing\n\0");
        return_to_main();
    }
    log(b"DMESH recovery: STA start\n\0");
    crate::wifi_esp::init_sta_configured(&profile);
    log(b"DMESH recovery: STA setup returned\n\0");
    // The configured STA association is asynchronous. Recovery does not
    // explicitly scan when NVS supplied the SSID and PSK.
    let started_us = now_us();
    let mut association_logged = false;
    let mut last_reconnect_ms = 0;
    while !crate::wifi_esp::sta_associated() || !crate::wifi_esp::sta_link_local_ready() {
        if crate::wifi_esp::sta_associated() && !association_logged {
            log(b"DMESH recovery: associated\n\0");
            association_logged = true;
        }
        if elapsed_ms(started_us) >= START_TIMEOUT_MS {
            log(b"DMESH recovery: STA timeout\n\0");
            return_to_main();
        }
        let elapsed = elapsed_ms(started_us);
        if elapsed.saturating_sub(last_reconnect_ms) >= 5_000 {
            let _ = crate::wifi_esp::reconnect_sta_once();
            log(b"DMESH recovery: STA reconnect\n\0");
            last_reconnect_ms = elapsed;
        }
        delay_ms(50);
    }
    log(b"DMESH recovery: IPv6 ready\n\0");
    let Some(mut socket) = Udp6Socket::bind(RECOVERY_UDP_PORT) else {
        log(b"DMESH recovery: UDP6 bind failed\n\0");
        return_to_main();
    };
    log(b"DMESH recovery: upload wait\n\0");
    serve_upload(&mut socket, started_us, &profile);
}

fn serve_upload(
    socket: &mut Udp6Socket,
    started_us: u64,
    profile: &crate::TransportProfile,
) -> ! {
    // Use Main's same bounded QUIC-lite association policy. The UDP socket is
    // only a datagram adapter; it does not own a separate ACK, window, or
    // retransmission policy.
    let association = crate::core_runtime::raw_association(profile);
    let mut service = ConnectionService::new(
        quic_lite::ConnectionId::new(1).expect("valid server CID"),
        quic_lite::recovery_connection_limits(false, 0),
        association,
    );
    let mut rx = [0u8; crate::TRANSPORT_MTU];
    let mut tx = [0u8; crate::TRANSPORT_MTU];
    let path = quic_lite::PathId::new(1).expect("valid socket path");
    let mut last_packet_ms = elapsed_ms(started_us);
    // Send a discovery record in the first loop turn, then periodically while
    // waiting for the host's existing ObjectUploadClient association.
    let mut last_announce_ms = elapsed_ms(started_us).saturating_sub(2_000);
    let mut complete_at_ms = None;
    let mut ingress_error_logged = false;
    loop {
        let now = now_us();
        let elapsed = elapsed_ms(started_us);
        if elapsed.saturating_sub(last_announce_ms) >= 2_000 {
            if let Some((record, used)) = crate::main_runtime::recovery_discovery_record(elapsed / 1_000) {
                let _ = socket.send_discovery(&record[..used]);
            }
            last_announce_ms = elapsed;
        }
        // QUIC-lite association timers (ACK delay and PTO) use the
        // millisecond domain advertised by AssociationProfile. Flash worker
        // expiry below deliberately remains in ESP microseconds.
        service.set_time(elapsed);
        unsafe { crate::stream_handlers::before_receive(&mut service, now) };
        // Drain the kernel's existing datagram queue before taking the idle
        // sleep.  This is deliberately not an application queue or an
        // alternate UDP protocol: each complete packet is immediately handed
        // to the one QUIC-lite association, which decides ACKs, MAX_* credit,
        // and any retransmission.  A one-packet/5 ms cadence discarded a
        // normal initial QUIC flight from lwIP before Recovery could emit its
        // ACKs, making loss recovery look like a flash failure.
        let mut received = false;
        while let Some((used, peer)) = socket.receive(&mut rx) {
            let packet_now = now_us();
            service.set_time(elapsed_ms(started_us));
            unsafe { crate::stream_handlers::before_receive(&mut service, packet_now) };
            last_packet_ms = elapsed_ms(started_us);
            let immediate = match service.receive(path, &rx[..used], &mut tx) {
                Ok(response) => {
                    ingress_error_logged = false;
                    response
                }
                Err(error) => {
                    // Console-only transition evidence. The socket adapter
                    // neither retries nor interprets the packet; QUIC-lite
                    // remains the owner of admission and loss behavior.
                    if !ingress_error_logged {
                        log(match error {
                            quic_lite::Error::WrongConnectionId => {
                                b"DMESH recovery: UDP wrong CID\n\0"
                            }
                            quic_lite::Error::FlowControl => {
                                b"DMESH recovery: UDP flow reject\n\0"
                            }
                            quic_lite::Error::Invalid => {
                                b"DMESH recovery: UDP invalid\n\0"
                            }
                            _ => b"DMESH recovery: UDP ingress reject\n\0",
                        });
                        ingress_error_logged = true;
                    }
                    None
                }
            };
            let response = unsafe {
                crate::stream_handlers::after_receive(
                    &mut service,
                    path,
                    packet_now,
                    false,
                    immediate,
                    &mut tx,
                )
            };
            if let Some(used) = response {
                let _ = socket.send_to(&tx[..used], peer);
            }
            received = true;
            if crate::flash::take_durable_flash_completion() {
                // `after_receive` has already produced the normal terminal
                // QUIC response.  Keep the socket alive briefly so it leaves
                // the device before selecting the newly durable Main image.
                complete_at_ms = Some(elapsed);
            }
        }
        // Flash workers release receive capacity asynchronously. Polling this
        // hook does not add a recovery protocol: it only lets QUIC-lite emit
        // its normal MAX_* update after durable storage becomes available.
        if let Ok(Some(reply_path)) = unsafe { crate::stream_handlers::storage_ready(&mut service, now) } {
            if reply_path == path {
                if let Ok(Some(used)) = service.poll_for(path, &mut tx) {
                    let _ = socket.send_last(&tx[..used]);
                }
            }
        }
        unsafe { crate::stream_handlers::before_poll(&mut service, path, now) };
        if let Ok(Some(used)) = service.poll_for(path, &mut tx) {
            let _ = socket.send_last(&tx[..used]);
        }
        if let Some(completed) = complete_at_ms {
            if elapsed.saturating_sub(completed) >= 250 {
                return_to_main();
            }
        }
        // No valid client reached the receiver. This is before destructive
        // work and is therefore safe to return to Main as requested.
        if elapsed >= START_TIMEOUT_MS && last_packet_ms == 0 {
            return_to_main();
        }
        // Once a client has started a stream, leave Recovery selected on a
        // timeout: a partially erased Main must not be selected.
        if elapsed.saturating_sub(last_packet_ms) >= IDLE_TIMEOUT_MS {
            unsafe { esp_idf_sys::esp_restart() };
        }
        if !received {
            delay_ms(5);
        }
    }
}

#[derive(Clone, Copy)]
struct Peer(esp_idf_sys::sockaddr_in6);

struct Udp6Socket {
    fd: i32,
    scope_id: u32,
    last_peer: Option<Peer>,
}

impl Udp6Socket {
    fn bind(port: u16) -> Option<Self> {
        let fd = unsafe {
            esp_idf_sys::lwip_socket(
                esp_idf_sys::AF_INET6 as i32,
                esp_idf_sys::SOCK_DGRAM as i32,
                esp_idf_sys::IPPROTO_UDP as i32,
            )
        };
        if fd < 0 {
            return None;
        }
        let mut address = esp_idf_sys::sockaddr_in6::default();
        address.sin6_family = esp_idf_sys::AF_INET6 as _;
        address.sin6_port = port.to_be();
        if unsafe {
            esp_idf_sys::lwip_bind(
                fd,
                (&address as *const esp_idf_sys::sockaddr_in6).cast(),
                core::mem::size_of::<esp_idf_sys::sockaddr_in6>() as _,
            )
        } != 0
        {
            unsafe { esp_idf_sys::lwip_close(fd) };
            return None;
        }
        let flags = unsafe { esp_idf_sys::lwip_fcntl(fd, esp_idf_sys::F_SETFL as _, esp_idf_sys::O_NONBLOCK as _) };
        if flags < 0 {
            unsafe { esp_idf_sys::lwip_close(fd) };
            return None;
        }
        Some(Self { fd, scope_id: crate::wifi_esp::sta_netif_index()?, last_peer: None })
    }

    fn receive(&mut self, output: &mut [u8]) -> Option<(usize, Peer)> {
        let mut peer = esp_idf_sys::sockaddr_in6::default();
        let mut peer_len = core::mem::size_of::<esp_idf_sys::sockaddr_in6>() as esp_idf_sys::socklen_t;
        let used = unsafe {
            esp_idf_sys::lwip_recvfrom(
                self.fd,
                output.as_mut_ptr().cast::<c_void>(),
                output.len(),
                0,
                (&mut peer as *mut esp_idf_sys::sockaddr_in6).cast(),
                &mut peer_len,
            )
        };
        if used <= 0 || peer_len as usize != core::mem::size_of::<esp_idf_sys::sockaddr_in6>() {
            return None;
        }
        let peer = Peer(peer);
        self.last_peer = Some(peer);
        Some((used as usize, peer))
    }

    fn send_to(&self, bytes: &[u8], peer: Peer) -> bool {
        // lwIP does not preserve a Linux-style interface scope in every
        // received link-local sockaddr.  Recovery has exactly one STA netif,
        // so make the reply route explicit just as `send_discovery` does.
        // This is socket routing only; the QUIC peer identity remains the
        // opaque address supplied by recvfrom.
        let mut address = peer.0;
        address.sin6_scope_id = self.scope_id;
        (unsafe {
            esp_idf_sys::lwip_sendto(
                self.fd,
                bytes.as_ptr().cast::<c_void>(),
                bytes.len(),
                0,
                (&address as *const esp_idf_sys::sockaddr_in6).cast(),
                core::mem::size_of::<esp_idf_sys::sockaddr_in6>() as _,
            )
        }) == bytes.len() as isize
    }

    fn send_last(&self, bytes: &[u8]) -> bool {
        self.last_peer.is_some_and(|peer| self.send_to(bytes, peer))
    }

    fn send_discovery(&self, bytes: &[u8]) -> bool {
        let mut group = esp_idf_sys::sockaddr_in6::default();
        group.sin6_family = esp_idf_sys::AF_INET6 as _;
        group.sin6_port = ANNOUNCE_UDP_PORT.to_be();
        group.sin6_scope_id = self.scope_id;
        group.sin6_addr = esp_idf_sys::in6_addr {
            un: esp_idf_sys::in6_addr__bindgen_ty_1 {
                u8_addr: [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x52, 0x27],
            },
        };
        (unsafe {
            esp_idf_sys::lwip_sendto(
                self.fd,
                bytes.as_ptr().cast::<c_void>(),
                bytes.len(),
                0,
                (&group as *const esp_idf_sys::sockaddr_in6).cast(),
                core::mem::size_of::<esp_idf_sys::sockaddr_in6>() as _,
            )
        }) == bytes.len() as isize
    }
}

impl Drop for Udp6Socket {
    fn drop(&mut self) {
        unsafe { esp_idf_sys::lwip_close(self.fd) };
    }
}

fn now_us() -> u64 {
    unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 }
}

fn elapsed_ms(started_us: u64) -> u64 {
    now_us().saturating_sub(started_us) / 1_000
}

fn delay_ms(ms: u32) {
    let ticks = (u64::from(ms) * u64::from(esp_idf_sys::configTICK_RATE_HZ)).div_ceil(1_000);
    unsafe { esp_idf_sys::vTaskDelay(ticks.max(1) as _) };
}

pub(crate) fn log(message: &'static [u8]) {
    unsafe { esp_idf_sys::esp_rom_printf(message.as_ptr().cast()) };
}


fn return_to_main() -> ! {
    unsafe {
        dmesh_boot_handoff_set(2);
        esp_idf_sys::esp_restart();
    }
}
