// IMPORTANT: This is shared no-std ESP firmware code. Host-neutral protocol
// behavior remains in quic-lite/dmesh-server; this worker composes ESP UART,
// NVS, STA/UDP, and flash adapters for Recovery and later Main reuse.
//! Shared no-std Recovery/Main transport worker.
//!
//! The reusable pieces are split by bearer: `uart` handles the command/control
//! channel, `wifi` owns STA setup and the UDP transport adapter, and
//! `udp_flash` consumes ordered application stream bytes.
static mut TRANSPORT_PROFILE: crate::TransportProfile = crate::TransportProfile::new();
static mut RAW_ASSOCIATION: dmesh_server::raw_transport::RawAssociation =
    dmesh_server::raw_transport::RawAssociation::c6_default();
static mut ESPNOW_ASSOCIATION: dmesh_server::raw_transport::RawAssociation =
    dmesh_server::raw_transport::RawAssociation::conservative();

extern "C" {
    fn nvs_open(namespace: *const i8, mode: i32, handle: *mut u32) -> i32;
    fn nvs_get_u32(handle: u32, key: *const i8, value: *mut u32) -> i32;
    fn nvs_close(handle: u32);
}

/// Stage2 owns this boot-control word. It is intentionally separate from
/// ordinary DMesh settings, which are accessed through the NVS handler.
unsafe fn command_mode_from_stage2_nvs() -> bool {
    let mut handle = 0_u32;
    if unsafe { nvs_open(b"stg2\0".as_ptr().cast(), 0, &mut handle) } != 0 {
        return false;
    }
    let mut target = 0_u32;
    let command_mode = unsafe {
        nvs_get_u32(handle, b"boot_target\0".as_ptr().cast(), &mut target) == 0 && target == 2
    };
    unsafe { nvs_close(handle) };
    command_mode
}

/// Temporary e6 lab run: prove raw NOW receive after STA disconnect while
/// retaining the channel-6 radio. This is volatile and does not alter NVS.
const LAB_FORCE_UNASSOCIATED_NOW: bool = false;

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

/// Use the same C6 association defaults as the established raw-UDP6 path.
/// The action bearer changes frame I/O only: it must not silently shrink the
/// QUIC-lite ACK ratio, transmit burst, or loss/reordering ledger. A nonzero
/// runtime field below is an explicit measurement/association choice.
/// Construct the shared action-bearer association from the live profile.
///
/// Main calls this too: its transport runtime only decides when the radio is
/// active, while Recovery/Main must use identical credits and egress bounds.
pub fn espnow_association(
    profile: &crate::TransportProfile,
) -> dmesh_server::raw_transport::RawAssociation {
    let mut association = dmesh_server::raw_transport::RawAssociation::c6_default();
    // A nonzero runtime field is an explicit lab/association choice.
    if profile.ack_frequency != 0 {
        association.ack_frequency = profile.ack_frequency;
    }
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

unsafe fn raw_service_mut() -> &'static mut RawServiceDispatcher {
    if !RAW_SERVICE_READY.load(core::sync::atomic::Ordering::Acquire) {
        core::ptr::addr_of_mut!(RAW_SERVICE).write(core::mem::MaybeUninit::new(
            RawServiceDispatcher::new(
                quic_lite::ConnectionId::new(0x5241_5753).expect("nonzero raw service CID"),
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
unsafe fn reset_raw_service() {
    if RAW_SERVICE_READY.swap(false, core::sync::atomic::Ordering::AcqRel) {
        unsafe {
            core::ptr::drop_in_place(core::ptr::addr_of_mut!(RAW_SERVICE).cast::<RawServiceDispatcher>());
        }
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
        match service.receive(path, packet, response) {
            Ok(value) => {
                let Some(request) = service.take_flash_request() else {
                    return value;
                };
                begin_flash_download(service, path, request, response, value)
            }
            Err(error) => {
                crate::commands::send_stat(
                    b"raw service error=",
                    dmesh_server::raw_transport::receive_error_code(error) as u64,
                );
                None
            }
        }
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

/// Recovery is only the first consumer of this generic raw bearer.  Its
/// handler contains no flash, Wi-Fi, or address policy: those stay outside
/// the host-tested raw service and ESP adapter respectively.
fn receive_raw_udp6(
    peer: crate::wifi_raw_udp6_esp::RawUdp6Peer,
    packet: &[u8],
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    receive_raw_service(
        dmesh_server::raw_transport::IngressPath {
            transport_id: 1,
            peer: peer.mac,
        },
        packet,
        response,
    )
}

fn poll_raw_udp6(
    peer: crate::wifi_raw_udp6_esp::RawUdp6Peer,
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    poll_raw_service(
        dmesh_server::raw_transport::IngressPath {
            transport_id: 1,
            peer: peer.mac,
        },
        response,
    )
}

/// The action bearer has its own bounded DCID table so an ESP-NOW test cannot
/// steal an active UDP6 diagnostic connection. The application protocol is
/// otherwise identical and stays in the host-tested raw service.
fn receive_espnow(
    peer: crate::wifi_espnow_esp::EspNowPeer,
    packet: &[u8],
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    receive_raw_service(
        dmesh_server::raw_transport::IngressPath {
            transport_id: 2,
            peer: peer.mac,
        },
        packet,
        response,
    )
}

fn poll_espnow(
    peer: crate::wifi_espnow_esp::EspNowPeer,
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    poll_raw_service(
        dmesh_server::raw_transport::IngressPath {
            transport_id: 2,
            peer: peer.mac,
        },
        response,
    )
}

/// Shared-pool UART callback for the small Recovery regression profile.
/// `uart_esp` has already decoded PPP and placed the datagram in the common
/// packet pool; this function owns no UART queue or separate receive buffer.
fn receive_uart_ingress(_item: crate::shared_ingress_esp::IngressPacket, packet: &[u8]) {
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
            transport_id: 3,
            peer: [0; 6],
        };
        let immediate = receive_raw_service(path, packet, response);
        // UART is a physical L2 path, not a second transport scheduler. Use
        // the same bounded response pump as raw UDP6 and ESP-NOW so an ACK
        // that has no immediate response can still release delayed control or
        // the next stream packet.
        let _ = dmesh_server::raw_transport::pump_egress(
            response,
            crate::RAW_SERVICE_HISTORY_CAPACITY,
            immediate,
            |response| poll_raw_service(path, response),
            crate::uart_esp::send_transport_packet,
        );
    }
}

/// Raw PPP records deliberately bypass QUIC-lite, but not the common packet
/// pool or the common UART task. Recovery uses this narrow lane for its
/// schema-defined bootstrap/profile controls and returns compact CBOR records
/// on the same physical bearer.
fn receive_uart_raw_ingress(_item: crate::shared_ingress_esp::IngressPacket, packet: &[u8]) {
    if let Ok(request) = dmesh_server::raw_wifi::decode_raw_wifi_handler(packet) {
        // Lab control is a bounded exception-plane operation.  It has no
        // QUIC ledger and never changes NVS; stream callers use the identical
        // request/response bytes through Main's registered hardware handler.
        let mut response = [0u8; dmesh_server::raw_wifi::RAW_WIFI_SNAPSHOT_MAX_BYTES];
        match crate::wifi_radio_lab_esp::handle_encoded(request, &mut response) {
            Ok(used) => {
                let _ = crate::commands::send_record(&response[..used]);
            }
            Err(error) => crate::commands::send_response(error.as_bytes()),
        }
        return;
    }
    if let Ok(request) = dmesh_server::raw_wifi::decode_raw_wifi_tx(packet) {
        match crate::wifi_radio_lab_esp::transmit_raw_action(request) {
            Ok(bytes) => crate::commands::send_response(
                alloc::format!("radio raw action sent bytes={bytes}").as_bytes(),
            ),
            Err(error) => crate::commands::send_response(error.as_bytes()),
        }
        return;
    }
    let params = unsafe { &mut *core::ptr::addr_of_mut!(TRANSPORT_PROFILE) };
    if crate::commands::apply_profile_command(packet, params).is_none() {
        crate::commands::send_response(b"protocol rejected");
    } else {
        crate::state::direct_record_accepted();
    }
}

/// Run the shared Recovery-style multi-bearer transport service loop.
///
/// The only Recovery-specific operation is supplied as `complete_main_flash`:
/// it selects Main and reboots only after a verified Main image is durable.
/// Main supplies a different completion policy for its allowed targets.
pub fn run(_complete_main_flash: fn() -> bool) {
    esp_idf_sys::link_patches();
    if !unsafe { crate::uart_esp::install_l2_driver() } {
        return;
    }
    // Populate the shared profile before accepting raw-CBOR commands; this
    // prevents a first UART record racing an NVS load and being overwritten.
    let params = core::ptr::addr_of_mut!(TRANSPORT_PROFILE);
    unsafe {
        let _ = crate::wifi_esp::initialize_nvs();
        (*params).command_mode = command_mode_from_stage2_nvs();
        crate::wifi_esp::load_preferred_ssid(&mut *params);
    }
    // A one-shot Stage2 selection reaches Recovery while normal boot remains
    // Main.  With a complete persisted STA profile, start that requested
    // recovery transfer immediately. `boot_target=2` is deliberately
    // different: it is an operator-selected command shell, so it keeps the
    // profile inert until an explicit command arrives.
    if unsafe { !(*params).command_mode && (*params).has_flash_profile() } {
        unsafe {
            (*params).run_requested = true;
        }
    }
    if !unsafe { crate::uart_esp::start_shared_l2(receive_uart_ingress, receive_uart_raw_ingress) }
    {
        return;
    }
    crate::commands::send_response(b"recovery boot");
    send_boot_identity(2, 2);
    // Wait briefly for the preferred SSID. Recovery must not start a
    // partially configured STA while the managed UART handoff is arriving.
    for _ in 0..crate::uart_esp::COMMAND_GRACE_TICKS {
        if unsafe { TRANSPORT_PROFILE.ssid_len != 0 } {
            break;
        }
        unsafe {
            esp_idf_sys::vTaskDelay(1);
        }
    }
    let mut wifi_started = false;
    let mut applied_raw_tx_rate = None;
    let mut applied_sta_driver_tx = None;
    let mut applied_sta_bssid_check_disabled = None;
    let mut applied_sta_ampdu_enabled = None;
    let mut applied_sta_11b_rates_disabled = None;
    let mut applied_sta_raw_rx_enabled = None;
    let mut applied_tx_burst_packets = None;
    // `espnow_capture` is the explicit opt-in for the combined STA/NAN/NOW
    // radio personality.  It is false for the pure STA/UDP6 performance
    // baseline, and changing it performs one logged upgrade/downgrade rather
    // than starting background radio callbacks beside that baseline.
    let mut nan_now_enabled = false;
    let mut raw_reported_at_ms = 0u64;
    let mut espnow_reported_at_tick = 0 as esp_idf_sys::TickType_t;
    let mut espnow_last_report = [0u32; 30];
    let mut espnow_has_reported = false;
    loop {
        crate::wifi_nonpromisc_probe_esp::poll();
        // Keep Recovery's common NAN acquisition/DW state machine identical
        // to Main. Starting capture without polling it leaves the initial
        // promiscuous acquisition state stale and makes later radio-control
        // transitions differ by image.
        crate::wifi_nan_dw_capture_esp::poll();
        // Command parsing and the mutable Recovery image have one owner
        // here. Bearers feed QUIC-lite; no raw command task is
        // started beside this worker.
        // Direct bootstrap records update this small command image
        // asynchronously. A plain read of `static mut` is undefined and can
        // be cached across the idle loop; the command generation provides
        // release ordering and this volatile snapshot makes it visible here.
        let snapshot = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TRANSPORT_PROFILE)) };
        if (snapshot.command_mode || snapshot.run_requested)
            && snapshot.has_flash_profile()
            && !wifi_started
        {
            crate::wifi_esp::init_sta(&snapshot);
            applied_raw_tx_rate = Some(snapshot.raw_tx_rate);
            crate::wifi_raw_udp6_esp::set_sta_driver_tx(snapshot.sta_driver_tx);
            applied_sta_driver_tx = Some(snapshot.sta_driver_tx);
            applied_sta_bssid_check_disabled = Some(snapshot.sta_bssid_check_disabled);
            applied_sta_ampdu_enabled = Some(snapshot.sta_ampdu_enabled);
            applied_sta_11b_rates_disabled = Some(snapshot.sta_11b_rates_disabled);
            applied_sta_raw_rx_enabled = Some(snapshot.sta_raw_rx_enabled);
            applied_tx_burst_packets = Some(snapshot.tx_burst_packets);
            crate::commands::send_response(if snapshot.sta_driver_tx {
                b"raw udp6 STA driver tx enabled"
            } else {
                b"raw udp6 STA raw tx enabled"
            });
            unsafe {
                RAW_ASSOCIATION = raw_association(&snapshot);
            }
            if snapshot.sta_raw_rx_enabled && crate::wifi_esp::start_raw_udp6(receive_raw_udp6) {
                unsafe {
                    crate::wifi_raw_udp6_esp::set_tx_burst_packets(
                        RAW_ASSOCIATION.tx_burst_packets,
                    );
                }
                crate::wifi_raw_udp6_esp::set_poll_handler(Some(poll_raw_udp6));
                crate::commands::send_response(b"raw udp6 bearer started");
            } else if snapshot.sta_raw_rx_enabled {
                crate::commands::send_response(b"raw udp6 bearer failed");
            }
            if !snapshot.sta_raw_rx_enabled {
                crate::commands::send_response(b"wifi STA esp-netif RX enabled");
            }
            // Recovery tests one hardware mode at a time.  Its active mode
            // is associated raw UDP6; ESP-NOW/action, ROC and promiscuous
            // NAN capture are separate modes selected by Main/radio control,
            // never background companions which can alter callbacks or PHY
            // timing during a UDP reliability measurement.
            wifi_started = true;
        }
        if wifi_started && applied_raw_tx_rate != Some(snapshot.raw_tx_rate) {
            // Some C6/AP combinations reject association when the public
            // raw-rate knob is programmed before start. Apply it to the
            // already-associated STA and retain the exact driver result.
            if crate::wifi_esp::configure_raw_tx_rate(snapshot.raw_tx_rate) {
                applied_raw_tx_rate = Some(snapshot.raw_tx_rate);
                crate::commands::send_response(b"raw udp6 tx rate updated");
            } else {
                crate::commands::send_response(b"raw udp6 tx rate failed");
            }
        }
        if wifi_started && applied_sta_driver_tx != Some(snapshot.sta_driver_tx) {
            crate::wifi_raw_udp6_esp::set_sta_driver_tx(snapshot.sta_driver_tx);
            applied_sta_driver_tx = Some(snapshot.sta_driver_tx);
            crate::commands::send_response(if snapshot.sta_driver_tx {
                b"raw udp6 STA driver tx enabled"
            } else {
                b"raw udp6 STA raw tx enabled"
            });
        }
        if wifi_started && applied_sta_raw_rx_enabled != Some(snapshot.sta_raw_rx_enabled) {
            crate::wifi_raw_udp6_esp::stop();
            unsafe { reset_raw_service() };
            applied_sta_raw_rx_enabled = Some(snapshot.sta_raw_rx_enabled);
            if snapshot.sta_raw_rx_enabled {
                unsafe { RAW_ASSOCIATION = raw_association(&snapshot); }
                if crate::wifi_esp::start_raw_udp6(receive_raw_udp6) {
                    unsafe {
                        crate::wifi_raw_udp6_esp::set_tx_burst_packets(
                            RAW_ASSOCIATION.tx_burst_packets,
                        );
                    }
                    crate::wifi_raw_udp6_esp::set_poll_handler(Some(poll_raw_udp6));
                    crate::commands::send_response(b"raw udp6 STA RX enabled");
                } else {
                    crate::commands::send_response(b"raw udp6 STA RX failed");
                }
            } else {
                crate::commands::send_response(b"wifi STA esp-netif RX enabled");
            }
        }
        if wifi_started
            && (applied_sta_ampdu_enabled != Some(snapshot.sta_ampdu_enabled)
                || applied_sta_11b_rates_disabled != Some(snapshot.sta_11b_rates_disabled))
        {
            // AMPDU and the legacy basic-rate policy are applied before STA
            // start. Drop the bounded bearer, release the driver/netif, and
            // associate again; this starts no extra task.
            if nan_now_enabled {
                crate::wifi_esp::stop_nan_now();
                nan_now_enabled = false;
            }
            crate::wifi_raw_udp6_esp::stop();
            unsafe { reset_raw_service() };
            crate::wifi_esp::restart_sta_driver_runtime();
            wifi_started = false;
            applied_raw_tx_rate = None;
            applied_sta_driver_tx = None;
            applied_sta_bssid_check_disabled = None;
            applied_sta_ampdu_enabled = None;
            applied_sta_11b_rates_disabled = None;
            applied_sta_raw_rx_enabled = None;
            applied_tx_burst_packets = None;
            continue;
        }
        if wifi_started
            && (applied_sta_bssid_check_disabled != Some(snapshot.sta_bssid_check_disabled)
                || applied_tx_burst_packets != Some(snapshot.tx_burst_packets))
        {
            // The private enable/disable pair reports success live, but a
            // false->true transition loses raw NDP on C6 until Wi-Fi is
            // restarted. Apply this pre-association policy through the one
            // existing STA lifecycle instead of claiming a broken live
            // transition succeeded.
            if nan_now_enabled {
                crate::wifi_esp::stop_nan_now();
                nan_now_enabled = false;
            }
            crate::wifi_raw_udp6_esp::stop();
            unsafe { reset_raw_service() };
            crate::wifi_esp::restart_sta_runtime();
            wifi_started = false;
            applied_raw_tx_rate = None;
            applied_sta_driver_tx = None;
            applied_sta_bssid_check_disabled = None;
            applied_sta_ampdu_enabled = None;
            applied_sta_11b_rates_disabled = None;
            applied_sta_raw_rx_enabled = None;
            applied_tx_burst_packets = None;
            continue;
        }
        if wifi_started && snapshot.espnow_capture != nan_now_enabled {
            if snapshot.espnow_capture {
                let enabled = crate::wifi_esp::start_nan_now(receive_espnow);
                if enabled {
                    crate::wifi_espnow_esp::set_poll_handler(Some(poll_espnow));
                }
                nan_now_enabled = enabled;
                crate::commands::send_response(if enabled {
                    b"wifi NAN/NOW coexistence enabled"
                } else {
                    b"wifi NAN/NOW coexistence failed"
                });
            } else {
                crate::wifi_esp::stop_nan_now();
                nan_now_enabled = false;
                crate::commands::send_response(b"wifi NAN/NOW coexistence disabled");
            }
        }
        // Raw Ethernet owns its FreeRTOS ingress task and accepts
        // host-initiated QUIC-lite services. There is no legacy client
        // fallback: a profile only controls association and raw bearer
        // runtime settings.
        unsafe { esp_idf_sys::vTaskDelay(10) };
    }
}

/// Bounded boot identity exception record. It is a shared firmware bootstrap
/// event, not a Recovery command or UART-owned schema.
pub fn send_boot_identity(role: u8, partition: u8) {
    let payload = dmesh_server::recovery::boot_identity_payload(role, partition);
    let _ = crate::commands::send_record(&payload);
}
