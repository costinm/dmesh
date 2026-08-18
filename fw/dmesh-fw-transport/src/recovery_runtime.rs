// IMPORTANT: This is shared no-std ESP firmware code. Host-neutral protocol
// behavior remains in quic-lite/dmesh-server; this worker composes ESP UART,
// NVS, STA/UDP, and flash adapters for Recovery and later Main reuse.
//! Shared no-std Recovery/Main transport worker.
//!
//! The reusable pieces are split by bearer: `uart` handles the command/control
//! channel, `wifi` owns STA setup and the UDP transport adapter, and
//! `udp_flash` consumes ordered application stream bytes.
static mut TRANSPORT_PROFILE: crate::TransportProfile = crate::TransportProfile::new();
static mut RAW_ASSOCIATION: dmesh_server::raw_iperf::RawAssociationProfile =
    dmesh_server::raw_iperf::RawAssociationProfile::c6_default();

fn raw_association(
    profile: &crate::TransportProfile,
) -> dmesh_server::raw_iperf::RawAssociationProfile {
    let window = if profile.iperf_window_packets == 0 {
        crate::RAW_IPERF_HISTORY_CAPACITY
    } else {
        usize::from(profile.iperf_window_packets)
    };
    dmesh_server::raw_iperf::RawAssociationProfile {
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
        tx_burst_packets: if profile.iperf_burst_packets == 0 {
            window
        } else {
            usize::from(profile.iperf_burst_packets)
        },
    }
    .clamp::<{ crate::RAW_IPERF_HISTORY_CAPACITY }>()
}

// Recovery's UART and raw UDP6 diagnostics use the same host-tested packet
// service. The bearer-specific code below only supplies the return path.
static mut UART_IPERF_SERVER: Option<crate::RawIperfServer> = None;
static mut UART_RESPONSE: [u8; crate::TRANSPORT_MTU] = [0; crate::TRANSPORT_MTU];

#[cfg(feature = "wifi-raw-udp6")]
static mut RAW_IPERF_SERVER: Option<crate::RawIperfServer> = None;
#[cfg(feature = "wifi-espnow")]
static mut ESPNOW_IPERF_SERVER: Option<crate::RawIperfServer> = None;

/// Recovery is only the first consumer of this generic raw bearer.  Its
/// handler contains no flash, Wi-Fi, or address policy: those stay outside
/// the host-tested IPERF server and ESP adapter respectively.
#[cfg(feature = "wifi-raw-udp6")]
fn receive_raw_udp6(
    _peer: crate::wifi_raw_udp6_esp::RawUdp6Peer,
    packet: &[u8],
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    unsafe {
        let slot = core::ptr::addr_of_mut!(RAW_IPERF_SERVER);
        if (*slot).is_none() {
            *slot = Some(crate::RawIperfServer::new_with_association(
                quic_lite::ConnectionId::new(0x5241_5736).expect("nonzero raw server CID"),
                quic_lite::ConnectionLimits::default(),
                *core::ptr::addr_of!(RAW_ASSOCIATION),
            ));
        }
        let server = match &mut *slot {
            Some(server) => server,
            None => return None,
        };
        match server.receive(packet, response) {
            Ok(response) => response,
            Err(_error) => {
                crate::commands::send_stat(b"raw udp6 server error=", 1);
                None
            }
        }
    }
}

#[cfg(feature = "wifi-raw-udp6")]
fn poll_raw_udp6(
    _peer: crate::wifi_raw_udp6_esp::RawUdp6Peer,
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    unsafe {
        (*core::ptr::addr_of_mut!(RAW_IPERF_SERVER))
            .as_mut()?
            .poll(response)
            .ok()
            .flatten()
    }
}

/// The action bearer has its own bounded DCID table so an ESP-NOW test cannot
/// steal an active UDP6 diagnostic connection. The application protocol is
/// otherwise identical and stays in the host-tested `RawIperfServer`.
#[cfg(feature = "wifi-espnow")]
fn receive_espnow(
    _peer: crate::wifi_espnow_esp::EspNowPeer,
    packet: &[u8],
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    unsafe {
        let slot = core::ptr::addr_of_mut!(ESPNOW_IPERF_SERVER);
        if (*slot).is_none() {
            *slot = Some(dmesh_server::raw_iperf::RawIperfServer::new(
                quic_lite::ConnectionId::new(0x4553_504e).expect("nonzero espnow server CID"),
            ));
        }
        (*slot).as_mut()?.receive(packet, response).ok().flatten()
    }
}

/// Shared-pool UART callback for the small Recovery regression profile.
/// `uart_esp` has already decoded PPP and placed the datagram in the common
/// packet pool; this function owns no UART queue or separate receive buffer.
fn receive_uart_ingress(_item: crate::shared_ingress_esp::IngressPacket, packet: &[u8]) {
    unsafe {
        let server_slot = core::ptr::addr_of_mut!(UART_IPERF_SERVER);
        if (*server_slot).is_none() {
            *server_slot = Some(dmesh_server::raw_iperf::RawIperfServer::new(
                quic_lite::ConnectionId::new(0x5541_5254).expect("nonzero UART server CID"),
            ));
        }
        let response = &mut *core::ptr::addr_of_mut!(UART_RESPONSE);
        let Some(server) = (*server_slot).as_mut() else {
            return;
        };
        let Ok(Some(used)) = server.receive(packet, response) else {
            return;
        };
        if used <= response.len() {
            let _ = crate::uart_esp::send_transport_packet(&response[..used]);
        }
    }
}

/// Raw PPP records deliberately bypass QUIC-lite, but not the common packet
/// pool or the common UART task. Recovery uses this narrow lane for its
/// schema-defined bootstrap/profile controls and returns compact CBOR records
/// on the same physical bearer.
fn receive_uart_raw_ingress(_item: crate::shared_ingress_esp::IngressPacket, packet: &[u8]) {
    let params = unsafe { &mut *core::ptr::addr_of_mut!(TRANSPORT_PROFILE) };
    if crate::commands::accept_packet(packet, params).is_none() {
        crate::commands::send_response(b"protocol rejected");
    }
}

/// Run the shared Recovery-style multi-bearer transport service loop.
///
/// The only Recovery-specific operation is supplied as `complete_main_flash`:
/// it selects Main and reboots only after a verified Main image is durable.
/// Main supplies a different completion policy for its allowed targets.
pub fn run(complete_main_flash: fn() -> bool) {
    #[cfg(feature = "wifi-raw-udp6")]
    let _ = complete_main_flash;
    esp_idf_sys::link_patches();
    if !unsafe { crate::uart_esp::install_l2_driver() } {
        return;
    }
    // Populate the shared profile before accepting raw-CBOR commands; this
    // prevents a first UART record racing an NVS load and being overwritten.
    let params = core::ptr::addr_of_mut!(TRANSPORT_PROFILE);
    unsafe {
        crate::esp_nvs::load_from_nvs(&mut *params);
    }
    // A one-shot Stage2 selection reaches Recovery while normal boot remains
    // Main.  With a complete persisted STA profile, start that requested
    // recovery transfer immediately.  `boot_target=2` is deliberately
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
    // Wait briefly for the explicit STA profile. Recovery must not start a
    // partially configured client while the managed UART handoff is arriving.
    for _ in 0..crate::uart_esp::COMMAND_GRACE_TICKS {
        if unsafe { TRANSPORT_PROFILE.server_len != 0 } {
            break;
        }
        unsafe {
            esp_idf_sys::vTaskDelay(1);
        }
    }
    let mut wifi_started = false;
    #[cfg(feature = "wifi-raw-udp6")]
    let mut applied_raw_tx_rate = None;
    #[cfg(feature = "wifi-raw-udp6")]
    let mut applied_raw_burst_packets = None;
    #[cfg(feature = "wifi-raw-udp6")]
    let mut raw_reported_at_ms = 0u64;
    #[cfg(feature = "wifi-espnow")]
    let mut espnow_reported_at_ms = 0u64;
    loop {
        // Command parsing and the mutable Recovery image have one owner
        // here. Bearers feed QUIC-lite; no raw UDP command/socket task is
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
            #[cfg(feature = "wifi-raw-udp6")]
            if !crate::wifi_esp::configure_raw_tx_rate(snapshot.raw_tx_rate) {
                crate::commands::send_response(b"raw udp6 tx rate failed");
            }
            #[cfg(feature = "wifi-raw-udp6")]
            {
                applied_raw_tx_rate = Some(snapshot.raw_tx_rate);
                applied_raw_burst_packets = Some(snapshot.iperf_burst_packets);
            }
            #[cfg(feature = "wifi-raw-udp6")]
            unsafe {
                RAW_ASSOCIATION = raw_association(&snapshot);
            }
            #[cfg(feature = "wifi-raw-udp6")]
            if crate::wifi_esp::start_raw_udp6(receive_raw_udp6) {
                unsafe {
                    crate::wifi_raw_udp6_esp::set_tx_burst_packets(
                        RAW_ASSOCIATION.tx_burst_packets,
                    );
                }
                crate::wifi_raw_udp6_esp::set_poll_handler(Some(poll_raw_udp6));
                crate::commands::send_response(b"raw udp6 bearer started");
            } else {
                crate::commands::send_response(b"raw udp6 bearer failed");
            }
            #[cfg(feature = "wifi-espnow")]
            if crate::wifi_esp::start_espnow(receive_espnow) {
                crate::commands::send_response(b"raw espnow bearer started");
            } else {
                crate::commands::send_response(b"raw espnow bearer failed");
            }
            wifi_started = true;
        }
        #[cfg(feature = "wifi-raw-udp6")]
        if wifi_started && applied_raw_tx_rate != Some(snapshot.raw_tx_rate) {
            if crate::wifi_esp::configure_raw_tx_rate(snapshot.raw_tx_rate) {
                applied_raw_tx_rate = Some(snapshot.raw_tx_rate);
                crate::commands::send_response(b"raw udp6 tx rate updated");
            } else {
                crate::commands::send_response(b"raw udp6 tx rate failed");
            }
        }
        #[cfg(feature = "wifi-raw-udp6")]
        if wifi_started && applied_raw_burst_packets != Some(snapshot.iperf_burst_packets) {
            let association = raw_association(&snapshot);
            unsafe {
                RAW_ASSOCIATION = association;
            }
            crate::wifi_raw_udp6_esp::set_tx_burst_packets(association.tx_burst_packets);
            applied_raw_burst_packets = Some(snapshot.iperf_burst_packets);
            crate::commands::send_stat(b"raw udp6 tx burst=", association.tx_burst_packets as u64);
        }
        #[cfg(feature = "wifi-espnow")]
        if wifi_started {
            let now_ms = unsafe { (esp_idf_sys::esp_timer_get_time().max(0) as u64) / 1_000 };
            if now_ms.saturating_sub(espnow_reported_at_ms) >= 5_000 {
                let (management, beacons, nan_beacons, action_frames) =
                    crate::wifi_espnow_esp::management_stats();
                let (rx, drops, tx, failures) = crate::wifi_espnow_esp::stats();
                crate::commands::send_stat(b"espnow mgmt=", management as u64);
                crate::commands::send_stat(b"espnow beacons=", beacons as u64);
                crate::commands::send_stat(b"espnow nan_beacons=", nan_beacons as u64);
                crate::commands::send_stat(b"espnow action_frames=", action_frames as u64);
                crate::commands::send_stat(b"espnow rx=", rx as u64);
                crate::commands::send_stat(b"espnow rx_drops=", drops as u64);
                crate::commands::send_stat(b"espnow tx=", tx as u64);
                crate::commands::send_stat(b"espnow tx_failures=", failures as u64);
                espnow_reported_at_ms = now_ms;
            }
        }
        #[cfg(feature = "wifi-raw-udp6")]
        if wifi_started {
            let now_ms = unsafe { (esp_idf_sys::esp_timer_get_time().max(0) as u64) / 1_000 };
            if now_ms.saturating_sub(raw_reported_at_ms) >= 5_000 {
                let (rx, drops, invalid, delivered, tx, failures) =
                    crate::wifi_raw_udp6_esp::stats();
                crate::commands::send_benchmark_stats(&[
                    (120, rx as u64),
                    (121, drops as u64),
                    (122, invalid as u64),
                    (123, delivered as u64),
                    (124, tx as u64),
                    (125, failures as u64),
                ]);
                raw_reported_at_ms = now_ms;
            }
        }
        #[cfg(feature = "wifi-raw-udp6")]
        {
            // The raw bearer owns its FreeRTOS task and accepts host-initiated
            // QUIC-lite IPERF. Do not enter the legacy Recovery client/socket
            // worker from this feature path.
            unsafe { esp_idf_sys::vTaskDelay(10) };
            continue;
        }
        #[cfg(not(feature = "wifi-raw-udp6"))]
        if snapshot.run_requested && snapshot.has_flash_profile() {
            // Capture this before entering the synchronous worker. A command
            // received while its final telemetry is being emitted advances
            // the generation; sampling only after return loses that command
            // and makes back-to-back host benchmarks appear to hang.
            let generation = crate::state::direct_record_generation();
            crate::commands::send_response(b"transport worker begin");
            crate::wifi_esp::run_transport(&snapshot, complete_main_flash);
            crate::commands::send_response(b"transport worker returned");
            if !snapshot.benchmark {
                break;
            }
            // Benchmark mode is deliberately reusable: the next UART
            // Recovery command can select another server/port/profile without
            // rebooting or reinitializing the STA.
            while !crate::state::direct_record_generation_changed(generation) {
                unsafe { esp_idf_sys::vTaskDelay(10) };
            }
        } else {
            // The device-wide NVS profile only supplies STA settings. It is
            // inert until a direct bootstrap record requests a QUIC-lite
            // transfer run.
            unsafe { esp_idf_sys::vTaskDelay(10) };
        }
    }
    #[cfg(not(feature = "wifi-raw-udp6"))]
    loop {
        unsafe {
            esp_idf_sys::vTaskDelay(1000);
        }
    }
}

/// Bounded boot identity exception record. It is a shared firmware bootstrap
/// event, not a Recovery command or UART-owned schema.
pub fn send_boot_identity(role: u8, partition: u8) {
    let payload = dmesh_server::recovery::boot_identity_payload(role, partition);
    let _ = crate::uart_esp::send_direct_record(&payload);
}
