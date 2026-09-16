//! Minimal Recovery STA/raw-UDP6 flash server.
//!
//! Main and Recovery use the same raw Ethernet UDP6 adapter, shared ingress
//! worker, QUIC-lite dispatcher, stream handlers, and flash sink. Recovery
//! owns only STA startup, periodic presence, deadline wakeups, and the final
//! Stage2 handoff. UART remains an unframed console output only.

const START_TIMEOUT_MS: u64 = 75_000;
const ANNOUNCE_INTERVAL_MS: u64 = 2_000;
static DEADLINE_OWNER_TASK: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

pub fn run() {
    esp_idf_sys::link_patches();
    // Recovery exposes only its running-image identity and the verified flash
    // operation. This is the same tagged QUIC handler used by Main and does
    // not install a diagnostic catalog, UART input, or another transport.
    let _ = dmesh_server::services::register_tagged_component(
        dmesh_server::services::FIRMWARE_COMPONENT,
        crate::firmware_identity::receive_tagged_identity,
    );
    let mut profile = crate::TransportProfile::new();
    if !crate::sta_profile_esp::load(&mut profile) {
        log(b"DMESH recovery: STA profile missing\n\0");
        return_to_main();
    }
    log(b"DMESH recovery: STA start\n\0");
    crate::wifi_esp::init_sta_configured(&profile);
    log(b"DMESH recovery: STA setup returned\n\0");

    // NVS credentials make association the only required network readiness
    // edge. Raw UDP6 derives its deterministic EUI-64 link-local address from
    // the STA MAC and does not depend on an lwIP address or socket.
    let started_us = now_us();
    let mut last_reconnect_ms = 0;
    let mut last_disconnect_reason = 0;
    while !crate::wifi_esp::sta_associated() {
        if elapsed_ms(started_us) >= START_TIMEOUT_MS {
            log(b"DMESH recovery: STA timeout\n\0");
            return_to_main();
        }
        let elapsed = elapsed_ms(started_us);
        let disconnect_reason = crate::wifi_esp::sta_last_disconnect_reason();
        if disconnect_reason != 0 && disconnect_reason != last_disconnect_reason {
            crate::commands::send_stat(
                b"DMESH recovery: STA disconnect_reason=",
                disconnect_reason as u64,
            );
            last_disconnect_reason = disconnect_reason;
        }
        if elapsed.saturating_sub(last_reconnect_ms) >= 5_000 {
            let _ = crate::wifi_esp::reconnect_sta_once();
            log(b"DMESH recovery: STA reconnect\n\0");
            last_reconnect_ms = elapsed;
        }
        delay_ms(50);
    }
    log(b"DMESH recovery: STA associated\n\0");

    // This is the exact raw association and physical adapter selected by
    // Main's STA epoch. Recovery installs no direct command catalog: only the
    // normal QUIC stream dispatcher can reach the flash handler.
    let association = crate::core_runtime::prepare_raw_association(&profile);
    let receive_limits = association
        .association
        .receive_limits(crate::TRANSPORT_MTU as u64, 4);
    unsafe {
        esp_idf_sys::esp_rom_printf(
            b"DMESH recovery: QUIC receive profile internal_free=%u packets=%u max_data=%u max_stream_data=%u\n\0"
                .as_ptr()
                .cast(),
            association.internal_available_bytes as u32,
            association.association.initial_window_packets as u32,
            receive_limits.max_data as u32,
            receive_limits.max_stream_data as u32,
        );
    }
    crate::wifi_raw_udp6_esp::set_sta_driver_tx(profile.sta_driver_tx);
    if !crate::wifi_esp::start_raw_udp6(
        crate::core_runtime::receive_raw_udp6,
        crate::core_runtime::reject_recovery_connectionless,
    ) {
        log(b"DMESH recovery: raw UDP6 start failed\n\0");
        return_to_main();
    }
    crate::wifi_raw_udp6_esp::set_poll_handler(Some(crate::core_runtime::poll_raw_udp6));
    log(b"DMESH recovery: raw UDP6 ready\n\0");
    log(b"DMESH recovery: upload wait\n\0");
    serve_upload(started_us);
}

fn serve_upload(started_us: u64) -> ! {
    // The shared ingress worker handles datagrams and pushed storage-ready
    // events. This small owner loop only supplies Recovery's periodic announce
    // and wakes the same connection timer Main uses when QUIC's deadline is
    // due; it never receives, parses, acknowledges, or retransmits a packet.
    let mut last_announce_ms = elapsed_ms(started_us).saturating_sub(ANNOUNCE_INTERVAL_MS);
    let mut complete_at_ms = None;
    let mut last_stats_ms = 0;
    let mut stats_reports = 0_u8;
    let mut last_udp_tx = 0_u32;
    let mut completion_gate = dmesh_server::transport::TerminalCompletionGate::default();
    DEADLINE_OWNER_TASK.store(
        unsafe { esp_idf_sys::xTaskGetCurrentTaskHandle() as usize },
        core::sync::atomic::Ordering::Release,
    );
    crate::core_runtime::install_connection_deadline_waker(Some(wake_deadline_owner));
    loop {
        let elapsed = elapsed_ms(started_us);
        if elapsed.saturating_sub(last_announce_ms) >= ANNOUNCE_INTERVAL_MS {
            if let Some((record, used)) =
                crate::main_runtime::recovery_discovery_record(elapsed / 1_000)
            {
                log(b"DMESH recovery: multicast announce\n\0");
                if crate::wifi_raw_udp6_esp::broadcast_announce(&record[..used]) {
                    log(b"DMESH recovery: multicast queued\n\0");
                } else {
                    log(b"DMESH recovery: multicast send failed\n\0");
                }
            } else {
                log(b"DMESH recovery: multicast record unavailable\n\0");
            }
            last_announce_ms = elapsed;
        }
        let udp_tx = crate::wifi_raw_udp6_esp::stats().3;
        if stats_reports < 6
            && udp_tx != last_udp_tx
            && elapsed.saturating_sub(last_stats_ms) >= 10_000
        {
            log_raw_stats();
            last_stats_ms = elapsed;
            stats_reports += 1;
            last_udp_tx = udp_tx;
        }

        if crate::flash::take_durable_flash_completion() {
            log(b"DMESH recovery: durable completion observed\n\0");
            completion_gate.application_complete();
        }
        if crate::core_runtime::take_terminal_response_delivered() {
            log(b"DMESH recovery: terminal response acknowledged\n\0");
            completion_gate.response_delivered();
        }
        if completion_gate.take_complete() && complete_at_ms.is_none() {
            log(b"DMESH recovery: terminal reply delivered\n\0");
            complete_at_ms = Some(elapsed);
        }
        if let Some(completed) = complete_at_ms {
            if elapsed.saturating_sub(completed) >= 250 {
                return_to_main();
            }
        }

        let announce_delay = ANNOUNCE_INTERVAL_MS
            .saturating_sub(elapsed.saturating_sub(last_announce_ms))
            .max(1) as u32;
        let completion_delay = complete_at_ms.map(|completed| {
            250_u64
                .saturating_sub(elapsed.saturating_sub(completed))
                .max(1) as u32
        });
        let wait_ms = crate::core_runtime::connection_delay_ms()
            .unwrap_or(announce_delay)
            .min(announce_delay)
            .min(completion_delay.unwrap_or(u32::MAX));
        wait_for_deadline_or_ingress(wait_ms);
        if crate::core_runtime::connection_delay_ms().is_some_and(|delay| delay <= 1) {
            crate::core_runtime::schedule_connection_timer();
        }
    }
}

fn log_raw_stats() {
    let (rx, drops, invalid, udp_tx, frames_tx, tx_failures) = crate::wifi_raw_udp6_esp::stats();
    unsafe {
        esp_idf_sys::esp_rom_printf(
            b"DMESH recovery: raw stats rx=%u drops=%u invalid=%u udp_tx=%u frames_tx=%u tx_fail=%u\n\0"
                .as_ptr()
                .cast(),
            rx,
            drops,
            invalid,
            udp_tx,
            frames_tx,
            tx_failures,
        );
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

fn wake_deadline_owner() {
    let task = DEADLINE_OWNER_TASK.load(core::sync::atomic::Ordering::Acquire);
    if task != 0 {
        unsafe {
            let _ = esp_idf_sys::xTaskGenericNotify(
                task as esp_idf_sys::TaskHandle_t,
                0,
                1,
                esp_idf_sys::eNotifyAction_eSetBits,
                core::ptr::null_mut(),
            );
        }
    }
}

fn wait_for_deadline_or_ingress(ms: u32) {
    let ticks = (u64::from(ms) * u64::from(esp_idf_sys::configTICK_RATE_HZ)).div_ceil(1_000);
    unsafe {
        let _ = esp_idf_sys::xTaskGenericNotifyWait(
            0,
            0,
            u32::MAX,
            core::ptr::null_mut(),
            ticks.max(1) as _,
        );
    }
}

pub(crate) fn log(message: &'static [u8]) {
    unsafe { esp_idf_sys::esp_rom_printf(message.as_ptr().cast()) };
}

fn return_to_main() -> ! {
    if crate::rtc::arm_main() {
        log(b"DMESH recovery: handoff Main armed\n\0");
    } else {
        log(b"DMESH recovery: handoff Main readback failed\n\0");
    }
    // Recovery owns this control task, rather than the raw ingress worker, so
    // complete the asynchronous STA leave before Stage2 selects Main.
    crate::wifi_esp::stop_sta_for_reset();
    unsafe {
        esp_idf_sys::esp_rom_printf(
            b"DMESH recovery: handoff before reset=%u\n\0".as_ptr().cast(),
            crate::rtc::handoff() as u32,
        );
    }
    unsafe { esp_idf_sys::esp_restart() }
}
