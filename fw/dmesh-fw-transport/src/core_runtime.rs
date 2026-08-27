// IMPORTANT: This is shared no-std ESP firmware code. Host-neutral protocol
// behavior remains in quic-lite/dmesh-server; this worker composes ESP UART,
// NVS, STA/UDP, and flash adapters for the shared firmware lanes.
//! Shared no-std transport worker used by Main and the frozen Recovery lane.
//!
//! The reusable pieces are split by bearer: `uart` handles the command/control
//! channel, `wifi` owns STA setup and the UDP transport adapter, and
//! `udp_flash` consumes ordered application stream bytes.
// This association and dispatcher are one shared bearer service.  They are
// private on purpose: Main selects *when* the profile takes effect, while this
// module performs the paired association/dispatcher mutation atomically from
// that single runtime task.
static mut RAW_ASSOCIATION: dmesh_server::raw_transport::RawAssociation =
    dmesh_server::raw_transport::RawAssociation::c6_default();

/// Copy the committed profile for a Main policy effect. Called only by the
/// Main event owner after it receives an explicit event; callbacks never keep
/// this credential-bearing value beyond the locked copy operation.
pub(crate) fn transport_profile_snapshot() -> crate::TransportProfile {
    crate::profile_store::snapshot()
}

/// Apply UART power policy only to real UART bridges. On ESP32-C6 USB-JTAG,
/// the USB/JTAG transport is also the debug and recovery path; sleepy mode
/// must leave it untouched even when the radio enters light sleep.
pub(crate) fn apply_uart_profile(enabled: bool) {
    #[cfg(target_arch = "riscv32")]
    {
        let _ = enabled;
    }
    #[cfg(not(target_arch = "riscv32"))]
    // Main's active personality promises a usable physical UART control
    // bearer. Keep its sole reader/writer enabled until an explicit
    // `transport.start uart=off` profile replaces it; a short debug window
    // would leave boot waiting for an event that only UART could deliver.
    // C6 USB-JTAG deliberately takes the no-op branch above: it is a packet
    // transport/debug facility, not a power-gated UART bridge.
    crate::uart_esp::set_always_on(enabled);
}

fn raw_association(
    profile: &crate::TransportProfile,
) -> dmesh_server::raw_transport::RawAssociation {
    let window = crate::RAW_SERVICE_HISTORY_CAPACITY;
    let tx_burst_packets = if profile.tx_burst_packets == 0 {
        window
    } else {
        usize::from(profile.tx_burst_packets)
    };
    dmesh_server::raw_transport::RawAssociation {
        history_packets: window,
        ack_frequency: if profile.ack_frequency == 0 {
            8
        } else {
            profile.ack_frequency
        },
        ack_delay_ms: if profile.ack_delay_ms == 0 {
            5
        } else {
            profile.ack_delay_ms
        },
        tx_burst_packets,
        // This governs transport admission/bootstrap, not the bounded
        // immediate raw-send turn. Keep the existing ledger window so a
        // paced egress setting cannot deadlock OPEN/ACK progress.
        initial_window_packets: window,
    }
    .clamp::<{ crate::RAW_SERVICE_HISTORY_CAPACITY }>()
}

/// Construct the association used by the packet-at-a-time action bearer.
///
/// ESP-NOW-compatible actions are a bounded datagram bearer. The endpoint
/// ledger, rather than a bearer-private queue, owns the initial bounded flight.
/// C6 delivers the peer response through the action transaction's callback,
/// so sending a complete small flight while that response coverage remains
/// open avoids requiring a new driver response window for every 64-byte
/// stream packet. It is an association admission limit, not a polling loop.
///
/// Main calls this only at explicit NAN/NOW epoch boundaries. It changes no
/// Wi-Fi callback or hardware state; it simply gives the shared raw service
/// the matching QUIC-lite contract before an action frame constructs it.
pub fn espnow_association(
    profile: &crate::TransportProfile,
) -> dmesh_server::raw_transport::RawAssociation {
    // Keep one immediate ACK per packet, but admit the complete bounded C6
    // initial flight. This is set only at an explicit NAN/NOW epoch boundary,
    // before a new association is admitted; it creates neither a timer tick
    // nor an adapter-private egress queue.
    let mut association = dmesh_server::raw_transport::RawAssociation::c6_default();
    association.ack_frequency = 1;
    if profile.ack_delay_ms != 0 {
        association.ack_delay_ms = profile.ack_delay_ms;
    }
    association.clamp::<{ crate::RAW_SERVICE_HISTORY_CAPACITY }>()
}

type RawServiceDispatcher = dmesh_server::raw_transport::RawServiceDispatcher<
    { crate::RAW_SERVICE_HISTORY_CAPACITY },
    { crate::TRANSPORT_MTU },
>;

// The service endpoint is shared by UART, raw UDP6, and ESP-NOW. Its
// dispatcher/server metadata is fixed-size, so reserve it statically instead
// of entering the ESP heap on the first received radio frame. The potentially
// large QUIC ledger remains allocated by the service only after a valid OPEN.
static mut RAW_SERVICE: core::mem::MaybeUninit<RawServiceDispatcher> =
    core::mem::MaybeUninit::uninit();
static RAW_SERVICE_READY: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
/// Last server-side raw-QUIC parsing error. Client errors are already exposed
/// by the action adapter; this scalar closes the diagnostic gap when a peer
/// receives OPEN_ACK but the server rejects its following stream request.
/// It stores the portable compact error code, not packet bytes or state.
static RAW_SERVICE_LAST_ERROR: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Read the bounded raw-service error diagnostic for the radio snapshot.
pub(crate) fn raw_service_last_error() -> u32 {
    RAW_SERVICE_LAST_ERROR.load(core::sync::atomic::Ordering::Acquire)
}

/// Return whether a NOW datagram belongs to the currently live shared server
/// association. The action adapter uses this only when a local one-shot
/// client is also draining against the same peer; routing by source MAC alone
/// would otherwise discard the peer's ACK for this server. The dispatcher
/// checks the ingress path and QUIC DCID without retaining the packet.
pub(crate) fn raw_service_owns_espnow_packet(
    peer: crate::wifi_espnow_esp::EspNowPeer,
    packet: &[u8],
) -> bool {
    unsafe {
        raw_service_if_ready().is_some_and(|service| {
            service.owns_packet_for_path(
                dmesh_server::raw_transport::IngressPath {
                    transport_id: dmesh_server::transport_path::TransportId::NOW.0,
                    peer: peer.mac,
                },
                packet,
            )
        })
    }
}

/// Derive the long-lived raw-service receive CID from the factory STA MAC.
///
/// The raw dispatcher is shared by UART, UDP6, and NOW, and a peer can see
/// the same device alternate between client and server roles. A fixed CID on
/// every board lets delayed action packets from one device select a different
/// board's newly opened association. The factory MAC is stable before Wi-Fi
/// starts, unique for the deployed ESP32 fleet, and does not require NVS,
/// allocation, or an extra radio operation.
fn raw_service_connection_id() -> quic_lite::ConnectionId {
    let mac_value = if let Some(mac) = crate::wifi_esp::factory_sta_mac() {
        mac.into_iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(byte))
    } else {
        // ESP-IDF normally exposes the eFuse MAC before Wi-Fi initialization.
        // Keep a nonzero fallback solely for a platform failure; action/UDP
        // start will surface that failure separately through its own status.
        1
    };
    quic_lite::ConnectionId::new(0x5241_0000_0000 | mac_value)
        .expect("factory-MAC raw service CID is nonzero")
}

unsafe fn raw_service_mut() -> &'static mut RawServiceDispatcher {
    if !RAW_SERVICE_READY.load(core::sync::atomic::Ordering::Acquire) {
        core::ptr::addr_of_mut!(RAW_SERVICE).write(core::mem::MaybeUninit::new(
            RawServiceDispatcher::new(
                raw_service_connection_id(),
                quic_lite::ConnectionLimits::default(),
                *core::ptr::addr_of!(RAW_ASSOCIATION),
            ),
        ));
        RAW_SERVICE_READY.store(true, core::sync::atomic::Ordering::Release);
    }
    &mut *core::ptr::addr_of_mut!(RAW_SERVICE).cast::<RawServiceDispatcher>()
}

unsafe fn raw_service_if_ready() -> Option<&'static mut RawServiceDispatcher> {
    RAW_SERVICE_READY
        .load(core::sync::atomic::Ordering::Acquire)
        .then(|| &mut *core::ptr::addr_of_mut!(RAW_SERVICE).cast::<RawServiceDispatcher>())
}

/// End the current raw-radio association before replacing its profile.
///
/// A UART control that changes raw pacing or pre-association receive policy
/// cannot leave a dispatcher carrying the old ACK/burst contract. The
/// hardware callback has already been stopped at this point, and the shared
/// ingress worker is its sole caller, so dropping here releases any old
/// connection ledger before the next STA association constructs a fresh one.
unsafe fn reset_raw_service_unchecked() {
    // A live NOW responder owns a bounded management-receive lease while it
    // waits for the peer's ACK. Profile replacement is an explicit terminal
    // transition, so release that lease before discarding the dispatcher; it
    // must never survive into UART, UDP6, or the next radio epoch.
    crate::wifi_nan_dw_capture_esp::end_now_service_receive_lease();
    if RAW_SERVICE_READY.swap(false, core::sync::atomic::Ordering::AcqRel) {
        unsafe {
            core::ptr::drop_in_place(
                core::ptr::addr_of_mut!(RAW_SERVICE).cast::<RawServiceDispatcher>(),
            );
        }
    }
}

/// Forget the bounded raw service before a radio epoch is replaced.
///
/// Called by Main only while handling a serialized profile/lifecycle event.
/// It is not a periodic operation and cannot race a radio callback: callers
/// stop the relevant bearer callback before invoking it.
pub(crate) fn reset_raw_service() {
    unsafe { reset_raw_service_unchecked() }
}

/// Install the association defaults that the next raw service will use.
///
/// Called once during a STA/raw-radio start transition, before the receive
/// callback can construct a dispatcher.  Returning the burst limit keeps the
/// radio adapter independent of this private static state.
pub(crate) fn prepare_raw_association(profile: &crate::TransportProfile) -> usize {
    unsafe {
        RAW_ASSOCIATION = raw_association(profile);
        RAW_ASSOCIATION.tx_burst_packets
    }
}

/// Install the action-bearer association at an explicit NAN/NOW epoch
/// boundary.  A previous raw service may have been reached over UART or
/// UDP6, so replace it rather than letting an old eight-packet association
/// survive into the packet-at-a-time action path. The physical bearer is not
/// touched here; callers have already serialized the radio transition.
pub(crate) fn prepare_espnow_association(profile: &crate::TransportProfile) -> usize {
    unsafe {
        RAW_ASSOCIATION = espnow_association(profile);
        let association = RAW_ASSOCIATION;
        // The raw-service dispatcher controls QUIC admission, whereas the
        // action adapter controls how many already-admitted datagrams one
        // callback turn submits. Keep the two values synchronized here at
        // the epoch boundary; otherwise a stale adapter default can create a
        // radio burst that contradicts the selected association profile.
        crate::wifi_espnow_esp::set_tx_burst_packets(association.tx_burst_packets);
        if let Some(service) = raw_service_if_ready() {
            service.replace_association(association);
        }
        association.tx_burst_packets
    }
}

/// Replace the live raw service's association defaults without changing radio
/// state.  Main calls this only for an explicit ACK/burst profile transition;
/// the raw callback never invokes it.  A not-yet-created dispatcher simply
/// picks up the prepared defaults on its first valid OPEN.
pub(crate) fn replace_raw_association(profile: &crate::TransportProfile) -> usize {
    unsafe {
        RAW_ASSOCIATION = raw_association(profile);
        let association = RAW_ASSOCIATION;
        if let Some(service) = raw_service_if_ready() {
            service.replace_association(association);
        }
        association.tx_burst_packets
    }
}
// Exactly one device-initiated object transfer may be active for the current
// one-association raw service. The state is allocated only after a validated
// `flash` request; it is not a bearer queue and owns no copy of object data.
static mut FLASH_DOWNLOAD: Option<(
    dmesh_server::raw_transport::IngressPath,
    alloc::boxed::Box<crate::flash::SignedObjectFlashDownload>,
)> = None;
// PPP needs a response buffer while its callback sends an immediate ACK. It
// is allocated only after the first valid UART service packet; this is bearer
// scratch, not a second QUIC ledger or egress queue.
static mut UART_SERVICE_RESPONSE: Option<alloc::boxed::Box<[u8; crate::TRANSPORT_MTU]>> = None;
/// Scratch for the typed raw-service deadline event. The shared ingress task
/// is its only user, exactly like normal raw ingress, so this adds neither a
/// bearer queue nor a second packet pool allocation.
static mut RAW_SERVICE_TIMER_RESPONSE: [u8; crate::TRANSPORT_MTU] = [0; crate::TRANSPORT_MTU];

pub fn receive_raw_service(
    path: dmesh_server::raw_transport::IngressPath,
    packet: &[u8],
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    unsafe {
        let download_slot = core::ptr::addr_of_mut!(FLASH_DOWNLOAD);
        if let Some((download_path, download)) = (*download_slot).as_mut() {
            if *download_path == path && download.accepts(packet) {
                let response = download.receive(packet, response).ok().flatten();
                finish_flash_download();
                return response;
            }
        }
        let service = raw_service_mut();
        service.set_time(esp_idf_sys::esp_timer_get_time().max(0) as u64);
        let result = match service.receive(path, packet, response) {
            Ok(value) => {
                match service.take_flash_request() {
                    Some(request) => begin_flash_download(service, path, request, response, value),
                    None => value,
                }
            }
            Err(error) => {
                RAW_SERVICE_LAST_ERROR.store(
                    dmesh_server::raw_transport::receive_error_code(error) as u32,
                    core::sync::atomic::Ordering::Release,
                );
                crate::commands::send_stat(
                    b"raw service error=",
                    dmesh_server::raw_transport::receive_error_code(error) as u64,
                );
                None
            }
        };
        if path.transport_id == dmesh_server::transport_path::TransportId::NOW.0 {
            if service.reply_path() == Some(path) {
                // The C6 continuous private action dispatcher sees the
                // bootstrap reliably but not every later ACK. Hold the
                // existing NAN receive owner for this *accepted* responder
                // association, not for arbitrary action noise. Its explicit
                // eight-second deadline is rearmed only by subsequent
                // accepted packets and is serviced by Main's blocking timer.
                let _ = crate::wifi_nan_dw_capture_esp::begin_now_service_receive_lease();
            } else {
                // A processed CLOSE clears reply_path in the dispatcher.
                // Return promptly to ordinary DW capture rather than waiting
                // for the stale-responder deadline.
                crate::wifi_nan_dw_capture_esp::end_now_service_receive_lease();
            }
        }
        // The packet worker may just have created or advanced a NOW server
        // association. Main could otherwise still be blocked with the old
        // (or no) deadline and miss the connection-owned PTO until an
        // unrelated NAN event occurs. This marker only wakes Main to
        // recompute its one-shot timer; it neither polls nor sends here.
        if path.transport_id == dmesh_server::transport_path::TransportId::NOW.0 {
            crate::main_runtime::request_raw_service_deadline_recheck();
        }
        result
    }
}

/// Flash setup is cold and may construct a large receiver. Keep it out of the
/// raw packet service frame so a normal UDP/NOW/UART IPERF packet does not
/// reserve the flash constructor's stack footprint.
#[inline(never)]
unsafe fn begin_flash_download(
    service: &mut RawServiceDispatcher,
    path: dmesh_server::raw_transport::IngressPath,
    request: alloc::vec::Vec<u8>,
    response: &mut [u8; crate::TRANSPORT_MTU],
    fallback: Option<usize>,
) -> Option<usize> {
    let download_slot = core::ptr::addr_of_mut!(FLASH_DOWNLOAD);
    let Some(request) = dmesh_server::protocol::decode_flash_request(&request) else {
        let _ = service.complete_flash(alloc::vec::Vec::from(&b"flash invalid"[..]));
        return fallback;
    };
    if (*download_slot).is_some() {
        let _ = service.complete_flash(alloc::vec::Vec::from(&b"flash busy"[..]));
        return fallback;
    }
    let cid = quic_lite::ConnectionId::new(0x464c_0001).expect("nonzero flash client CID");
    match crate::flash::SignedObjectFlashDownload::new(cid, request) {
        Ok(mut download) => match download.start(response) {
            Ok(used) => {
                *download_slot = Some((path, alloc::boxed::Box::new(download)));
                Some(used)
            }
            Err(_) => {
                let _ = service.complete_flash(alloc::vec::Vec::from(&b"flash start failed"[..]));
                fallback
            }
        },
        Err(_) => {
            let _ = service.complete_flash(alloc::vec::Vec::from(&b"flash rejected"[..]));
            fallback
        }
    }
}

/// Complete the original `flash` request only after the sink has committed
/// all accepted blocks. The next normal raw-service poll emits this response.
unsafe fn finish_flash_download() {
    let download_slot = core::ptr::addr_of_mut!(FLASH_DOWNLOAD);
    let complete = (*download_slot)
        .as_mut()
        .is_some_and(|(_, download)| download.is_complete_and_durable());
    if !complete {
        return;
    }
    *download_slot = None;
    if let Some(service) = raw_service_if_ready() {
        let _ = service.complete_flash(alloc::vec::Vec::from(&b"flash complete"[..]));
    }
}

pub fn poll_raw_service(
    path: dmesh_server::raw_transport::IngressPath,
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    unsafe {
        let download_slot = core::ptr::addr_of_mut!(FLASH_DOWNLOAD);
        if let Some((download_path, download)) = (*download_slot).as_mut() {
            if *download_path == path {
                let now_us = esp_idf_sys::esp_timer_get_time().max(0) as u64;
                let response = download
                    .poll_retransmit(now_us, 600_000, response)
                    .ok()
                    .flatten()
                    .or_else(|| download.poll_transmit(response).ok().flatten());
                finish_flash_download();
                if response.is_some() {
                    return response;
                }
            }
        }
        let service = raw_service_if_ready()?;
        let now_us = esp_idf_sys::esp_timer_get_time().max(0) as u64;
        service.set_time(now_us);
        // Prefer endpoint-owned loss recovery over a fresh ACK/control frame:
        // an action response can be accepted by the local driver yet lost on
        // air, and no bearer-local response queue is allowed to mask that.
        service
            .poll_retransmit_for(path, now_us, 600_000, response)
            .ok()
            .flatten()
            .or_else(|| service.poll_for(path, response).ok().flatten())
    }
}

/// Return the next transport-owned NOW server deadline in Main milliseconds.
///
/// The raw endpoint reports only a pending ACK or retained-packet PTO in its
/// microsecond clock.  Main converts that one value into a blocking queue
/// timeout; this does not create a periodic radio service tick and leaves
/// idle, UART, and UDP6 services entirely ingress-driven.
pub(crate) fn raw_service_now_delay_ms() -> Option<u32> {
    unsafe {
        let service = raw_service_if_ready()?;
        let path = service.reply_path()?;
        if path.transport_id != dmesh_server::transport_path::TransportId::NOW.0 {
            return None;
        }
        let now_us = esp_idf_sys::esp_timer_get_time().max(0) as u64;
        let deadline_us = service.next_service_deadline(600_000)?;
        Some(
            deadline_us
                .saturating_sub(now_us)
                .saturating_add(999)
                .div_euclid(1_000)
                .clamp(1, u64::from(u32::MAX)) as u32,
        )
    }
}

/// Ask the shared ingress owner to retransmit one due NOW server packet.
/// Called only after Main's one-shot deadline; it does not touch the service
/// directly because UART, UDP6, and NOW ingress all serialize that state on
/// the packet worker.
pub(crate) fn schedule_raw_service_now_timer() {
    let _ = crate::shared_ingress_esp::schedule_raw_service_timer(service_raw_service_timer);
}

/// Perform one server-side NOW PTO turn on the packet worker. The reply path
/// comes from the accepted raw service packet, not from an adapter-private
/// queue, so future multipath policy can replace this final transport match.
fn service_raw_service_timer() {
    unsafe {
        let Some(service) = raw_service_if_ready() else {
            return;
        };
        let Some(path) = service.reply_path() else {
            return;
        };
        if path.transport_id != dmesh_server::transport_path::TransportId::NOW.0 {
            return;
        }
        let response = &mut *core::ptr::addr_of_mut!(RAW_SERVICE_TIMER_RESPONSE);
        let Some(used) = poll_raw_service(path, response) else {
            return;
        };
        if used <= response.len() {
            let _ = crate::wifi_espnow_esp::transmit_from_worker(
                crate::wifi_espnow_esp::EspNowPeer { mac: path.peer },
                &response[..used],
            );
        }
    }
}

/// Recovery is only the first consumer of this generic raw bearer.  Its
/// handler contains no flash, Wi-Fi, or address policy: those stay outside
/// the host-tested raw service and ESP adapter respectively.
pub(crate) fn receive_raw_udp6(
    peer: crate::wifi_raw_udp6_esp::RawUdp6Peer,
    packet: &[u8],
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    receive_raw_service(
        dmesh_server::raw_transport::IngressPath {
            transport_id: dmesh_server::transport_path::TransportId::UDP6.0,
            peer: peer.mac,
        },
        packet,
        response,
    )
}

pub(crate) fn poll_raw_udp6(
    peer: crate::wifi_raw_udp6_esp::RawUdp6Peer,
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    poll_raw_service(
        dmesh_server::raw_transport::IngressPath {
            transport_id: dmesh_server::transport_path::TransportId::UDP6.0,
            peer: peer.mac,
        },
        response,
    )
}

/// The action bearer has its own bounded DCID table so an ESP-NOW test cannot
/// steal an active UDP6 diagnostic connection. The application protocol is
/// otherwise identical and stays in the host-tested raw service.
pub(crate) fn receive_espnow(
    peer: crate::wifi_espnow_esp::EspNowPeer,
    packet: &[u8],
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    // Presence is one-way shared CBOR, not a QUIC-lite datagram. Retain it
    // before the action bearer reaches connection dispatch so unassociated
    // NAN+NOW nodes keep the same bounded discovery view as STA/UDP6 nodes.
    if let Some(announce) = dmesh_server::announce::decode_announce(packet) {
        crate::wifi_raw_udp6_esp::record_connectionless_announce(announce, peer.mac);
        return None;
    }
    receive_raw_service(
        dmesh_server::raw_transport::IngressPath {
            transport_id: dmesh_server::transport_path::TransportId::NOW.0,
            peer: peer.mac,
        },
        packet,
        response,
    )
}

pub(crate) fn poll_espnow(
    peer: crate::wifi_espnow_esp::EspNowPeer,
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    poll_raw_service(
        dmesh_server::raw_transport::IngressPath {
            transport_id: dmesh_server::transport_path::TransportId::NOW.0,
            peer: peer.mac,
        },
        response,
    )
}

/// Shared-pool UART callback for the small Recovery regression profile.
/// `uart_esp` has already decoded PPP and placed the datagram in the common
/// packet pool; this function owns no UART queue or separate receive buffer.
pub(crate) fn receive_uart_ingress(
    _item: crate::shared_ingress_esp::IngressPacket,
    packet: &[u8],
) {
    // UART owns only its on-demand response scratch and PPP egress. The shared
    // service decides whether the packet advances a connection and remembers
    // UART as its reply path exactly like it does for radio bearers.
    unsafe {
        let slot = core::ptr::addr_of_mut!(UART_SERVICE_RESPONSE);
        if (*slot).is_none() {
            *slot = Some(alloc::boxed::Box::new([0; crate::TRANSPORT_MTU]));
        }
        let Some(response) = (*slot).as_mut() else {
            return;
        };
        let path = dmesh_server::raw_transport::IngressPath {
            transport_id: dmesh_server::transport_path::TransportId::UART.0,
            peer: [0; 6],
        };
        let immediate = receive_raw_service(path, packet, response);
        pump_uart_egress(path, response, immediate);
    }
}

/// Queue one UART-writable edge from the dedicated physical writer.
///
/// The writer has just freed a record slot; it does not inspect QUIC state or
/// manufacture a packet. The typed shared-worker event keeps packet creation
/// serialized with UART/NOW/UDP ingress and avoids turning this into a timer
/// tick or a second UART egress queue.
pub(crate) fn schedule_uart_egress_ready() {
    let _ = crate::shared_ingress_esp::schedule_uart_egress_ready(service_uart_egress_ready);
}

/// Continue a UART service only after its physical writer reports capacity.
///
/// Called once for each coalesced dequeue edge, not periodically. It respects
/// the actual queue vacancy before calling `poll_raw_service`: polling an
/// endpoint that cannot submit would otherwise consume a ledger packet and
/// leave it waiting for a retransmission that no UART timer owns.
fn service_uart_egress_ready() {
    unsafe {
        let Some(response) = (*core::ptr::addr_of_mut!(UART_SERVICE_RESPONSE)).as_mut() else {
            return;
        };
        let path = dmesh_server::raw_transport::IngressPath {
            transport_id: dmesh_server::transport_path::TransportId::UART.0,
            peer: [0; 6],
        };
        pump_uart_egress(path, response, None);
    }
}

/// Pump only as many UART packets as the physical writer can accept now.
///
/// A classic ESP32 deliberately has one MTU-sized egress slot to preserve
/// internal RAM. Unlike a socket, `poll_transmit` advances the QUIC ledger as
/// it produces a datagram, so capacity must be checked before polling rather
/// than treating a failed enqueue as ordinary packet loss.
fn pump_uart_egress(
    path: dmesh_server::raw_transport::IngressPath,
    response: &mut [u8; crate::TRANSPORT_MTU],
    immediate: Option<usize>,
) {
    let (queued, capacity) = crate::uart_esp::transport_egress_capacity();
    let credit = capacity.saturating_sub(queued);
    if credit == 0 {
        return;
    }
    let _ = dmesh_server::raw_transport::pump_egress(
        response,
        credit,
        immediate,
        |response| poll_raw_service(path, response),
        crate::uart_esp::send_transport_packet,
    );
}
