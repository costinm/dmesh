//! Shared ESP adapter for the host-tested `dmesh_server::raw_wifi` handlers.
//!
//! It owns only ESP-IDF state transitions and counter sampling.  CBOR
//! parsing, handler method IDs, snapshots, and delta semantics are in
//! `dmesh-server`, so direct PPP and QUIC stream callers use identical bytes.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

use dmesh_server::raw_wifi::{
    RAW_WIFI_METHOD_CHECK, RAW_WIFI_METHOD_CONTROL, RAW_WIFI_METHOD_RESET_COUNTERS,
    RAW_WIFI_METHOD_SNAPSHOT, RawWifiApMode, RawWifiControlRequest, RawWifiCounters,
    RawWifiBearer, RawWifiDwPolicy, RawWifiInterface, RawWifiLabRequest, RawWifiRate, RawWifiRxFilter,
    RawWifiSnapshot, RawWifiStaMode, RawWifiStaState, RawWifiTxRequest,
};

static EPOCH: AtomicU32 = AtomicU32::new(1);
static TX_INTERFACE: AtomicU8 = AtomicU8::new(0);
static TX_RATE: AtomicU8 = AtomicU8::new(0);
// Unassociated NAN/NOW starts with broadcast Address-1.  The peer identity is
// still carried by the QUIC/raw-service handshake; unicast can be selected by
// an explicit lab control once a driver-specific peer path is known.
static ACTION_DESTINATION_BROADCAST: AtomicBool = AtomicBool::new(true);

/// Return the runtime-selected action egress interface.
///
/// `radio.control.interface` is not only a raw-frame-injection setting: the
/// shared NOW-like bearer must use the same selected local link identity for
/// its replies.  Keeping that policy here makes it observable in the common
/// snapshot and lets the e2e matrix exercise STA and AP action TX without a
/// firmware rebuild.  `Auto` deliberately preserves the production default
/// of the STA interface; AP is an explicit topology choice.
pub(crate) fn action_tx_interface() -> RawWifiInterface {
    interface_from(TX_INTERFACE.load(Ordering::Acquire)).unwrap_or(RawWifiInterface::Auto)
}

/// Whether the shared action bearer sends broadcast Address-1 for a
/// non-promiscuous receive-filter experiment. Its QUIC/raw-service peer
/// identity remains the source MAC, so this is not another transport.
pub(crate) fn action_destination_broadcast() -> bool {
    ACTION_DESTINATION_BROADCAST.load(Ordering::Acquire)
}

/// MAC placed in an action frame for the currently selected local interface.
/// ESP-IDF does not normalize AP and STA identities in APSTA mode.
pub(crate) fn action_tx_mac() -> Option<[u8; 6]> {
    let interface = match action_tx_interface() {
        RawWifiInterface::Auto | RawWifiInterface::Sta => crate::wifi_esp::RadioInterface::Sta,
        RawWifiInterface::Ap => crate::wifi_esp::RadioInterface::Ap,
        RawWifiInterface::Nan => return None,
    };
    crate::wifi_esp::interface_mac(interface)
}

/// True if `source` names either active local Wi-Fi identity. This prevents a
/// driver self-echo from consuming shared ingress merely because AP and STA
/// MACs differ in APSTA mode.
pub(crate) fn is_local_action_source(source: [u8; 6]) -> bool {
    crate::wifi_esp::interface_mac(crate::wifi_esp::RadioInterface::Sta) == Some(source)
        || (crate::wifi_esp::lab_open_ap_active()
            && crate::wifi_esp::interface_mac(crate::wifi_esp::RadioInterface::Ap) == Some(source))
}

fn interface_from(value: u8) -> Option<RawWifiInterface> {
    match value {
        0 => Some(RawWifiInterface::Auto),
        1 => Some(RawWifiInterface::Sta),
        2 => Some(RawWifiInterface::Ap),
        3 => Some(RawWifiInterface::Nan),
        _ => None,
    }
}

/// Registered method ID used to encode a response to `request`.
pub const fn response_method(request: RawWifiLabRequest) -> Option<u64> {
    match request {
        RawWifiLabRequest::Control(_) => Some(RAW_WIFI_METHOD_CONTROL),
        RawWifiLabRequest::Snapshot => Some(RAW_WIFI_METHOD_SNAPSHOT),
        RawWifiLabRequest::ResetCounters => Some(RAW_WIFI_METHOD_RESET_COUNTERS),
        RawWifiLabRequest::Check(_) => Some(RAW_WIFI_METHOD_CHECK),
        RawWifiLabRequest::Iperf(_) => Some(dmesh_server::raw_wifi::RAW_WIFI_METHOD_IPERF),
    }
}

fn interface_value(value: RawWifiInterface) -> u8 {
    match value {
        RawWifiInterface::Auto => 0,
        RawWifiInterface::Sta => 1,
        RawWifiInterface::Ap => 2,
        RawWifiInterface::Nan => 3,
    }
}

fn rate_from(value: u8) -> Option<RawWifiRate> {
    match value {
        0 => Some(RawWifiRate::Auto),
        6 => Some(RawWifiRate::Mbps6),
        9 => Some(RawWifiRate::Mbps9),
        12 => Some(RawWifiRate::Mbps12),
        18 => Some(RawWifiRate::Mbps18),
        24 => Some(RawWifiRate::Mbps24),
        36 => Some(RawWifiRate::Mbps36),
        48 => Some(RawWifiRate::Mbps48),
        54 => Some(RawWifiRate::Mbps54),
        _ => None,
    }
}

fn rate_value(value: RawWifiRate) -> u8 {
    match value {
        RawWifiRate::Auto => 0,
        RawWifiRate::Mbps6 => 6,
        RawWifiRate::Mbps9 => 9,
        RawWifiRate::Mbps12 => 12,
        RawWifiRate::Mbps18 => 18,
        RawWifiRate::Mbps24 => 24,
        RawWifiRate::Mbps36 => 36,
        RawWifiRate::Mbps48 => 48,
        RawWifiRate::Mbps54 => 54,
    }
}

fn channel() -> Option<u8> {
    crate::wifi_esp::current_channel().map(|(primary, _)| primary)
}

fn set_channel(channel: u8) -> bool {
    crate::wifi_esp::set_ht20_channel(channel)
}

fn set_promiscuous(enabled: bool) -> bool {
    crate::wifi_esp::set_promiscuous(enabled)
}

fn set_rx_filter(filter: RawWifiRxFilter) -> bool {
    let mask = match filter {
        RawWifiRxFilter::Management => esp_idf_sys::WIFI_PROMIS_FILTER_MASK_MGMT,
        RawWifiRxFilter::ManagementAndData => {
            esp_idf_sys::WIFI_PROMIS_FILTER_MASK_MGMT | esp_idf_sys::WIFI_PROMIS_FILTER_MASK_DATA
        }
    };
    let mut value = esp_idf_sys::wifi_promiscuous_filter_t { filter_mask: mask };
    crate::wifi_esp::set_promiscuous_filter(&mut value)
}

fn policy_value(policy: RawWifiDwPolicy) -> u8 {
    match policy {
        RawWifiDwPolicy::Normal => 0,
        RawWifiDwPolicy::Disabled => 1,
        RawWifiDwPolicy::Manual => 2,
    }
}

/// Capture current radio state and monotonic raw action counters.  The
/// snapshot is intentionally cheap and has no UART/CBOR side effect.
pub fn snapshot() -> RawWifiSnapshot {
    let (rx, drops, tx, failures) = crate::wifi_espnow_esp::stats();
    let (dispatcher, _tx_hook, parser_rejected, self_echo) =
        crate::wifi_espnow_esp::receive_diagnostics();
    let (
        _peer_mismatches,
        client_receive_ok,
        client_receive_errors,
        last_client_error,
        client_bootstrap_acks,
        client_stream_packets,
        client_other_packets,
    ) = crate::wifi_espnow_esp::client_diagnostics();
    let (
        tx_duration_us_total,
        tx_duration_us_max,
        tx_duration_le_250us,
        tx_duration_le_750us,
        tx_duration_le_2ms,
        tx_duration_gt_2ms,
    ) = crate::wifi_espnow_esp::tx_timing();
    let (action_service_bytes, _action_service_errors, action_service_elapsed_us) =
        crate::wifi_espnow_esp::raw_client_result();
    let (udp6_service_bytes, _udp6_service_errors, udp6_service_elapsed_us) =
        crate::wifi_raw_udp6_esp::raw_client_result();
    // One raw service is admitted at a time by the probe executor. Select
    // the active/recent bearer result rather than inventing a separate
    // response schema for UDP6; the shared snapshot records bytes and time
    // identically for NOW and raw IPv6.
    let use_udp6_client = crate::wifi_raw_udp6_esp::raw_client_active()
        || (udp6_service_bytes != 0 && action_service_bytes == 0);
    let (raw_service_bytes, raw_service_elapsed_us) = if use_udp6_client {
        (udp6_service_bytes, udp6_service_elapsed_us)
    } else {
        (action_service_bytes, action_service_elapsed_us)
    };
    let (
        _frames,
        _bytes,
        beacons,
        sdfs,
        followups,
        service_info_matched,
        service_info_enqueued,
        service_info_dropped,
    ) = crate::wifi_nan_dw_capture_esp::stats();
    let (vendor_beacon_ies, vendor_nan_beacon_ies, vendor_other_ies) =
        crate::wifi_nonpromisc_probe_esp::stats();
    let (roc_frames, _roc_bytes, roc_requests, roc_failures, roc_espnow, roc_nan, roc_other) =
        crate::wifi_nonpromisc_probe_esp::action_stats();
    let (armed, _arms, comparator_errors) = crate::wifi_nan_dw_capture_esp::filter_stats();
    let (bssid, _anchor, capturing) = crate::wifi_nan_dw_capture_esp::sync_diagnostics();
    let (
        udp6_rx_frames,
        udp6_rx_queue_drops,
        udp6_rx_invalid,
        udp6_udp_delivered,
        _udp6_tx_frames,
        _udp6_tx_failures,
    ) = crate::wifi_raw_udp6_esp::stats();
    let (
        udp6_ndp_advertisements,
        udp6_tx_failures,
        udp6_last_tx_result,
        udp6_raw_tx_completions,
        udp6_raw_tx_completion_failures,
        udp6_raw_tx_completion_rate,
    ) = crate::wifi_raw_udp6_esp::diagnostics();
    let (udp6_tx_submit_calls, udp6_tx_submit_us_total, udp6_tx_submit_us_max) =
        crate::wifi_raw_udp6_esp::tx_submit_timing();
    let (
        p2p_probe_requests,
        p2p_probe_responses,
        p2p_gas_requests,
        p2p_gas_responses,
        p2p_response_drops,
    ) = crate::wifi_esp::p2p_action_stats();
    RawWifiSnapshot {
        epoch: EPOCH.load(Ordering::Acquire),
        channel: channel(),
        sta_associated: Some(crate::wifi_esp::sta_associated()),
        promiscuous: crate::wifi_esp::promiscuous_enabled().ok(),
        dw_capturing: Some(capturing),
        nan_dw_interval: Some(crate::wifi_nan_dw_capture_esp::interval()),
        comparator_bssid: (bssid != [0; 6]).then_some(bssid),
        comparator_armed: Some(armed),
        comparator_errors,
        tx_interface: interface_from(TX_INTERFACE.load(Ordering::Acquire)),
        tx_rate: rate_from(TX_RATE.load(Ordering::Acquire)),
        ap_active: Some(crate::wifi_esp::lab_open_ap_active()),
        mac_ack: Some(crate::wifi_espnow_esp::mac_ack_enabled()),
        raw_service_active: Some(
            crate::wifi_espnow_esp::raw_client_active()
                || crate::wifi_raw_udp6_esp::raw_client_active(),
        ),
        last_tx_error: Some(crate::wifi_espnow_esp::last_tx_error() as u32),
        last_raw_client_error: Some(last_client_error),
        sta_mac: crate::wifi_esp::interface_mac(crate::wifi_esp::RadioInterface::Sta),
        ap_mac: crate::wifi_esp::lab_open_ap_active()
            .then(|| crate::wifi_esp::interface_mac(crate::wifi_esp::RadioInterface::Ap))
            .flatten(),
        action_destination_broadcast: Some(ACTION_DESTINATION_BROADCAST.load(Ordering::Acquire)),
        raw_service_bytes: Some(raw_service_bytes),
        raw_service_elapsed_us: Some(raw_service_elapsed_us),
        sta_driver_tx: Some(crate::wifi_raw_udp6_esp::sta_driver_tx_enabled()),
        sta_bssid_check_disabled: Some(crate::wifi_esp::sta_bssid_check_disabled()),
        sta_ampdu_enabled: Some(crate::wifi_esp::sta_ampdu_enabled()),
        sta_11b_rates_disabled: Some(crate::wifi_esp::sta_11b_rates_disabled()),
        sta_raw_rx_enabled: Some(crate::wifi_raw_udp6_esp::started()),
        sta_connect_to_associated_ms: crate::wifi_esp::sta_connect_to_associated_ms(),
        sta_last_disconnect_reason: Some(crate::wifi_esp::sta_last_disconnect_reason()),
        sta_ap_rssi_dbm: crate::wifi_esp::sta_ap_rssi_dbm(),
        udp6_tx_burst_packets: Some(crate::wifi_raw_udp6_esp::tx_burst_packets()),
        udp6_tx_submit_calls: Some(udp6_tx_submit_calls),
        udp6_tx_submit_us_total: Some(udp6_tx_submit_us_total),
        udp6_tx_submit_us_max: Some(udp6_tx_submit_us_max),
        counters: RawWifiCounters {
            tx_attempted: tx,
            tx_driver_accepted: tx.saturating_sub(failures),
            tx_driver_failed: failures,
            rx_driver_dispatch: dispatcher,
            rx_parser_accepted: rx,
            rx_parser_rejected: parser_rejected,
            rx_self_echo: self_echo,
            rx_dropped: drops,
            nan_beacons: beacons,
            nan_sdfs: sdfs,
            nan_followups: followups,
            nan_service_info_matched: service_info_matched,
            nan_service_info_enqueued: service_info_enqueued,
            nan_service_info_dropped: service_info_dropped,
            tx_duration_us_total,
            tx_duration_us_max,
            tx_duration_le_250us,
            tx_duration_le_750us,
            tx_duration_le_2ms,
            tx_duration_gt_2ms,
            raw_client_receive_ok: client_receive_ok,
            raw_client_receive_errors: client_receive_errors,
            raw_client_bootstrap_acks: client_bootstrap_acks,
            raw_client_stream_packets: client_stream_packets,
            raw_client_other_packets: client_other_packets,
            roc_action_listen_requests: roc_requests,
            roc_action_listen_failures: roc_failures,
            roc_action_frames: roc_frames,
            vendor_beacon_ies,
            vendor_nan_beacon_ies,
            vendor_other_ies,
            roc_espnow_actions: roc_espnow,
            roc_nan_actions: roc_nan,
            roc_other_actions: roc_other,
            udp6_rx_frames,
            udp6_rx_queue_drops,
            udp6_rx_invalid,
            udp6_udp_delivered,
            udp6_ndp_advertisements,
            udp6_tx_failures,
            udp6_last_tx_result,
            udp6_raw_tx_completions,
            udp6_raw_tx_completion_failures,
            udp6_raw_tx_completion_rate,
            p2p_probe_requests,
            p2p_probe_responses,
            p2p_gas_requests,
            p2p_gas_responses,
            p2p_response_drops,
        },
    }
}

fn apply_control(control: RawWifiControlRequest) -> Result<(), &'static str> {
    if control.disable_11b.is_some() {
        // ESP-IDF accepts this only before Wi-Fi start.  Do not claim that a
        // live control request modified PHY policy when it cannot.
        return Err("live disable_11b unsupported by ESP-IDF");
    }
    if let Some(interface) = control.interface {
        TX_INTERFACE.store(interface_value(interface), Ordering::Release);
    }
    if let Some(rate) = control.rate {
        if !crate::wifi_esp::configure_raw_tx_rate(rate_value(rate)) {
            return Err("raw TX rate rejected");
        }
        TX_RATE.store(rate_value(rate), Ordering::Release);
    }
    if let Some(mac_ack) = control.mac_ack {
        crate::wifi_espnow_esp::set_mac_ack_enabled(mac_ack);
    }
    if let Some(broadcast) = control.action_destination_broadcast {
        ACTION_DESTINATION_BROADCAST.store(broadcast, Ordering::Release);
    }
    // Apply this before a laboratory STA/AP transition. Those transitions
    // re-register the driver's global action hook; `wifi_esp` preserves this
    // state so a ROC-only request cannot briefly restore the NOW callback.
    if let Some(enabled) = control.action_dispatcher {
        if !crate::wifi_esp::set_now_dispatcher(enabled) {
            return Err("action dispatcher rejected");
        }
    }
    if let Some(duration_ms) = control.nan_capture_ms {
        if !crate::wifi_nan_dw_capture_esp::request_permissive_capture(duration_ms) {
            return Err("NAN permissive capture rejected");
        }
    }
    if let Some(state) = control.sta_state {
        let channel = control.channel.unwrap_or_else(|| channel().unwrap_or(6));
        crate::wifi_esp::set_lab_force_unassociated(
            matches!(state, RawWifiStaState::DisconnectHold),
            channel,
        );
    // APSTA owns its requested channel as part of its stop/configure/start
    // transaction below. Applying it first as an associated-STA retune makes
    // a valid `ap_mode=Open, channel=6` request reject itself.
    } else if control.ap_mode.is_none() && control.raw_sta_mode.is_none() {
        if let Some(channel) = control.channel {
            if !set_channel(channel) {
                return Err("channel rejected while associated");
            }
        }
    }
    if let Some(ap_mode) = control.ap_mode {
        let channel = control.channel.unwrap_or_else(|| channel().unwrap_or(6));
        // Keep the laboratory AP useful as the same 500-TU soft-NAN timing
        // fallback as the normal unassociated radio.  A caller may still
        // request a different explicit diagnostic interval.
        let beacon_tu = control.ap_beacon_tu.unwrap_or(500);
        if !crate::wifi_esp::set_lab_open_ap(
            matches!(ap_mode, RawWifiApMode::Open),
            channel,
            beacon_tu,
        ) {
            return Err("open AP transition rejected");
        }
    }
    if matches!(control.raw_sta_mode, Some(RawWifiStaMode::MainStyle)) {
        let channel = control.channel.unwrap_or_else(|| channel().unwrap_or(6));
        if !crate::wifi_esp::ensure_lab_main_style_raw_sta(channel) {
            return Err("Main-style raw STA transition rejected");
        }
    }
    if control.comparator_enabled == Some(true) && control.comparator_bssid.is_none() {
        return Err("comparator requires BSSID");
    }
    if control.comparator_bssid.is_some() || control.comparator_enabled.is_some() {
        if !crate::wifi_nan_dw_capture_esp::set_lab_comparator(
            control.comparator_bssid,
            control.comparator_enabled.unwrap_or(true),
        ) {
            return Err("A3 comparator rejected");
        }
    }
    if let Some(policy) = control.dw_policy {
        if !crate::wifi_nan_dw_capture_esp::set_lab_dw_policy(policy_value(policy)) {
            return Err("DW policy rejected");
        }
    }
    if let Some(filter) = control.rx_filter {
        if !set_rx_filter(filter) {
            return Err("RX filter rejected");
        }
    }
    if let Some(promiscuous) = control.promiscuous {
        if !set_promiscuous(promiscuous) {
            return Err("promiscuous state rejected");
        }
    }
    // Loop mode owns its initial request: `configure_loop` resets its
    // deadline and the common worker immediately arms one ROC lease. Issuing
    // a one-shot here as well creates overlapping four-second driver leases,
    // which trips the C6 Wi-Fi watchdog at lease expiry. A duration without
    // `roc_loop=true` remains the explicit one-shot operation.
    if control.roc_loop != Some(true) {
        if let Some(duration_ms) = control.roc_listen_ms {
            if !crate::wifi_nonpromisc_probe_esp::listen_on_current_channel(u32::from(duration_ms))
            {
                return Err("ROC action listener rejected");
            }
        }
    }
    if let Some(enabled) = control.roc_loop {
        let duration = control.roc_listen_ms.unwrap_or(0);
        if !crate::wifi_nonpromisc_probe_esp::configure_loop(enabled, u32::from(duration)) {
            return Err("ROC loop rejected");
        }
    }
    Ok(())
}

/// Apply one host-decoded registered handler.  It returns a snapshot for all
/// operations; callers encode it through `dmesh_server::raw_wifi` on either
/// direct PPP or a QUIC stream.
pub fn handle(request: RawWifiLabRequest) -> Result<RawWifiSnapshot, &'static str> {
    match request {
        RawWifiLabRequest::Control(control) => {
            apply_control(control)?;
            EPOCH.fetch_add(1, Ordering::AcqRel);
        }
        RawWifiLabRequest::ResetCounters => {
            crate::wifi_espnow_esp::reset_stats();
            crate::wifi_nan_dw_capture_esp::reset_stats();
            crate::wifi_nonpromisc_probe_esp::reset_stats();
            crate::wifi_raw_udp6_esp::reset_diagnostics();
            EPOCH.fetch_add(1, Ordering::AcqRel);
        }
        RawWifiLabRequest::Snapshot => {}
        RawWifiLabRequest::Check(check) => {
            // A check request is an observation/control operation.  Return
            // the common snapshot even if the client cannot be acquired or
            // its first action TX is rejected; `raw_service_active` and
            // `last_tx_error` make that result testable on the same bearer.
            let _ = crate::wifi_espnow_esp::start_check_client(
                crate::wifi_espnow_esp::EspNowPeer { mac: check.peer },
                check.nonce,
                check.timeout_ms,
            );
        }
        RawWifiLabRequest::Iperf(iperf) => {
            // This starts a device-originated peer run.  The immediate
            // snapshot records admission; the same bounded client publishes
            // live/final bytes and errors through the normal radio counters.
            let bearer = match iperf.bearer {
                RawWifiBearer::Auto if crate::wifi_esp::sta_associated() => RawWifiBearer::Udp6,
                RawWifiBearer::Auto => RawWifiBearer::Now,
                bearer => bearer,
            };
            let started = if bearer == RawWifiBearer::Udp6 {
                // In an associated probe row, raw UDP6 is the pair data
                // bearer. The initiating STA targets the peer's link-local
                // address derived from this same six-byte radio identity.
                crate::wifi_raw_udp6_esp::start_iperf_client(
                    iperf.peer,
                    iperf.bytes,
                    iperf.packet_size,
                    iperf.timeout_ms,
                )
            } else {
                crate::wifi_espnow_esp::start_iperf_client(
                    crate::wifi_espnow_esp::EspNowPeer { mac: iperf.peer },
                    iperf.bytes,
                    iperf.packet_size,
                    iperf.timeout_ms,
                )
            };
            if !started {
                return Err("raw IPERF client busy or rejected");
            }
        }
    }
    Ok(snapshot())
}

/// Apply a decoded request and encode its matching handler response into a
/// caller-owned bounded buffer.  UART direct PPP and QUIC stream adapters use
/// this exact function; neither owns a second radio response schema.
pub fn handle_encoded(request: RawWifiLabRequest, out: &mut [u8]) -> Result<usize, &'static str> {
    let method = response_method(request).ok_or("unsupported radio lab request")?;
    let snapshot = handle(request)?;
    dmesh_server::raw_wifi::encode_raw_wifi_snapshot(method, snapshot, out)
        .ok_or("radio snapshot buffer")
}

/// Send a caller-supplied public/vendor action frame through the common
/// ESP-IDF action lane. This is intentionally a raw-radio diagnostic, not a
/// QUIC service: direct PPP and stream adapters decode the same host-owned
/// `RawWifiTxRequest` before calling here. Complete non-action injection
/// remains platform-specific until its receive and sequence semantics are
/// covered by the same matrix.
pub fn transmit_raw_action(request: RawWifiTxRequest<'_>) -> Result<usize, &'static str> {
    if request.frame.len() < 24 || request.frame[0] != 0xd0 || request.frame[1] != 0 {
        return Err("raw action frame required");
    }
    if channel() != Some(request.channel) {
        return Err("raw action channel mismatch");
    }
    // NAN Follow-ups are discovery-window control, never generic immediate
    // action traffic. The DW owner validates the selected cluster and rejects
    // a host probe outside its bounded capture/send interval.
    if dmesh_rawnan::is_nan_followup(request.frame) {
        return crate::wifi_nan_dw_capture_esp::send_followup_frame(request.frame);
    }
    if request.rate != RawWifiRate::Auto
        && !crate::wifi_esp::configure_raw_tx_rate(rate_value(request.rate))
    {
        return Err("raw action rate rejected");
    }
    let interface = match request.interface {
        RawWifiInterface::Auto | RawWifiInterface::Sta => crate::wifi_esp::RadioInterface::Sta,
        RawWifiInterface::Ap => crate::wifi_esp::RadioInterface::Ap,
        RawWifiInterface::Nan => crate::wifi_esp::RadioInterface::Nan,
    };
    let destination = request.frame[4..10]
        .try_into()
        .map_err(|_| "raw action destination")?;
    let bssid = request.frame[16..22]
        .try_into()
        .map_err(|_| "raw action BSSID")?;
    if !crate::wifi_espnow_esp::transmit_public_action_on_interface(
        interface,
        destination,
        bssid,
        &request.frame[24..],
    ) {
        return Err("raw action driver rejected");
    }
    Ok(request.frame.len())
}
