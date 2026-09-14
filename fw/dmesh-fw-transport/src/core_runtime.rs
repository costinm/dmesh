// IMPORTANT: This is shared no-std ESP firmware code. Host-neutral protocol
// behavior remains in quic-lite/dmesh-server; this worker composes ESP UART,
// NVS, STA/UDP, and flash adapters for the shared firmware lanes.
//! Shared no-std transport worker used by Main and the frozen Recovery lane.
//!
//! The reusable pieces are split by bearer: `uart` handles the command/control
//! channel, `wifi` owns STA setup and the UDP transport adapter, and
//! application handlers consume ordered QUIC stream bytes.
// This association and dispatcher are one shared bearer service.  They are
// private on purpose: Main selects *when* the profile takes effect, while this
// module performs the paired association/dispatcher mutation atomically from
// that single runtime task.
static mut RAW_ASSOCIATION: quic_lite::AssociationProfile =
    quic_lite::AssociationProfile::c6_default();
// Recovery observes this application-delivery edge after the common
// dispatcher has consumed the ACK. Main uses the same edge immediately for
// its RTC recovery-boot request; no ACK details escape quic-lite.
static TERMINAL_RESPONSE_DELIVERED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
// Main and Recovery have different owner tasks, but the packet worker needs
// one common way to wake whichever owner currently owns the QUIC deadline.
// The hook is scheduling glue only: QUIC still calculates and emits every
// ACK, MAX_*, and PTO packet from its normal poll turn.
static CONNECTION_DEADLINE_WAKER: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

pub(crate) fn install_connection_deadline_waker(waker: Option<fn()>) {
    CONNECTION_DEADLINE_WAKER.store(
        waker.map(|wake| wake as usize).unwrap_or(0),
        core::sync::atomic::Ordering::Release,
    );
}

pub(crate) fn request_connection_deadline_recheck() {
    let waker = CONNECTION_DEADLINE_WAKER.load(core::sync::atomic::Ordering::Acquire);
    if waker != 0 {
        let waker: fn() = unsafe { core::mem::transmute(waker) };
        waker();
    } else {
        crate::main_runtime::request_connection_deadline_recheck();
    }
}

/// Select active association credit from current internal-memory headroom.
/// CONNECTION_HISTORY_CAPACITY is only the static allocation ceiling; the
/// advertised ledger, initial window, and default burst are selected for each
/// new association through the same QUIC-lite memory policy used by host
/// simulations.
fn firmware_datagram_association_for_available(
    available: u64,
) -> quic_lite::AssociationProfile {
    quic_lite::AssociationProfile::datagram_with_memory::<{ crate::CONNECTION_HISTORY_CAPACITY }>(
        quic_lite::ledger::LedgerMemorySnapshot {
            total_bytes: available,
            available_bytes: available,
        },
        1,
        crate::TRANSPORT_MTU,
        quic_lite::ledger::LedgerMemoryPolicy {
            min_packets: 2,
            max_packets: crate::CONNECTION_HISTORY_CAPACITY,
            memory_fraction_numerator: 1,
            memory_fraction_denominator: 8,
            reserve_bytes: 32 * 1024,
            metadata_bytes_per_packet: 96,
        },
    )
}

pub(crate) fn firmware_datagram_association() -> quic_lite::AssociationProfile {
    let capabilities = esp_idf_sys::MALLOC_CAP_INTERNAL | esp_idf_sys::MALLOC_CAP_8BIT;
    let available = unsafe { esp_idf_sys::heap_caps_get_free_size(capabilities) as u64 };
    firmware_datagram_association_for_available(available)
}

/// The sampled memory and resulting association are one admission decision.
/// Recovery logs this through its console-only boundary so a live window can
/// be compared directly with the host's injected-memory tests.
#[derive(Clone, Copy)]
pub(crate) struct RawAssociationSelection {
    pub association: quic_lite::AssociationProfile,
    pub internal_available_bytes: u64,
}

/// Derive the advertised receive budget from the association selected for
/// this boot.  The association's packet count is the device-owned memory
/// budget; it must not be discarded in favour of a fixed flash-sized window.
///
/// Four MTU-sized streams remain the minimum useful profile (command, logs,
/// transfer, and probe).  Above that floor, split the connection budget
/// evenly across those streams.  Handlers only consume ordered bytes; they
/// neither select nor publish a QUIC window.
fn firmware_receive_limits(
    association: quic_lite::AssociationProfile,
) -> quic_lite::ConnectionLimits {
    association.receive_limits(crate::TRANSPORT_MTU as u64, 4)
}

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
    // `transport.set uart=off` profile replaces it; a short debug window
    // would leave boot waiting for an event that only UART could deliver.
    // C6 USB-JTAG deliberately takes the no-op branch above: it is a packet
    // transport/debug facility, not a power-gated UART bridge.
    crate::uart_esp::set_always_on(enabled);
}

fn raw_association_for_available(
    profile: &crate::TransportProfile,
    available: u64,
) -> quic_lite::AssociationProfile {
    let mut association = firmware_datagram_association_for_available(available);
    association.tx_burst_packets = if profile.tx_burst_packets == 0 {
        association.history_packets
    } else {
        usize::from(profile.tx_burst_packets)
    };
    if profile.ack_frequency != 0 {
        association.ack_frequency = profile.ack_frequency;
    }
    if profile.ack_delay_ms != 0 {
        association.ack_delay_ms = profile.ack_delay_ms;
    }
    // ACK batching is association policy, selected from the shared
    // memory-based datagram profile. Raw UDP6, UART, and NOW must not
    // silently choose different credit/ACK semantics merely because one
    // final bearer is callback-driven.
    association
        // The raw callback pool is an adapter-owned, transient admission limit.
        // It must not alter QUIC's association/window contract: a packet dropped
        // before ingress is ordinary bearer loss, recovered from the shared
        // ledger exactly as it is on UART, NOW, and the host.
        .clamp::<{ crate::CONNECTION_HISTORY_CAPACITY }>()
}

pub(crate) fn raw_association(profile: &crate::TransportProfile) -> quic_lite::AssociationProfile {
    let capabilities = esp_idf_sys::MALLOC_CAP_INTERNAL | esp_idf_sys::MALLOC_CAP_8BIT;
    let available = unsafe { esp_idf_sys::heap_caps_get_free_size(capabilities) as u64 };
    raw_association_for_available(profile, available)
}

fn raw_association_selection(profile: &crate::TransportProfile) -> RawAssociationSelection {
    let capabilities = esp_idf_sys::MALLOC_CAP_INTERNAL | esp_idf_sys::MALLOC_CAP_8BIT;
    let available = unsafe { esp_idf_sys::heap_caps_get_free_size(capabilities) as u64 };
    RawAssociationSelection {
        association: raw_association_for_available(profile, available),
        internal_available_bytes: available,
    }
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
/// Wi-Fi callback or hardware state; it simply gives the shared connection
/// the matching QUIC-lite contract before an action frame constructs it.
pub fn espnow_association(profile: &crate::TransportProfile) -> quic_lite::AssociationProfile {
    // Keep one immediate ACK per packet, but admit the complete bounded C6
    // initial flight. This is set only at an explicit NAN/NOW epoch boundary,
    // before a new association is admitted; it creates neither a timer tick
    // nor an adapter-private egress queue.
    let mut association = firmware_datagram_association();
    association.ack_frequency = 1;
    if profile.ack_delay_ms != 0 {
        association.ack_delay_ms = profile.ack_delay_ms;
    }
    association.clamp::<{ crate::CONNECTION_HISTORY_CAPACITY }>()
}

type ConnectionDispatcher = dmesh_server::transport::ConnectionDispatcher<
    { crate::CONNECTION_HISTORY_CAPACITY },
    { crate::TRANSPORT_MTU },
    { crate::MAX_QUIC_ASSOCIATIONS },
>;

/// Allocate an opaque connection path handle from adapter-owned metadata.
/// Only this ESP integration decodes the handle back to a bearer address;
/// QUIC retains and compares `PathId` without knowing its representation.
pub const fn connection_path_id(transport_id: u8, peer: [u8; 6]) -> quic_lite::PathId {
    let value = ((transport_id as u64) << 48)
        | ((peer[0] as u64) << 40)
        | ((peer[1] as u64) << 32)
        | ((peer[2] as u64) << 24)
        | ((peer[3] as u64) << 16)
        | ((peer[4] as u64) << 8)
        | peer[5] as u64;
    match quic_lite::PathId::new(value) {
        Some(path) => path,
        None => panic!("ESP connection path must be nonzero"),
    }
}

/// Decode only this platform adapter's opaque path handle for diagnostic
/// rendering. QUIC-lite keeps the handle opaque and never learns a MAC,
/// UART port, or raw-UDP tuple.
pub(crate) const fn connection_path_transport(path: quic_lite::PathId) -> u8 {
    (path.value() >> 48) as u8
}

pub(crate) const fn connection_path_peer(path: quic_lite::PathId) -> [u8; 6] {
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

// The service endpoint is shared by UART, raw UDP6, and ESP-NOW. Its
// dispatcher/server metadata is fixed-size, so reserve it statically instead
// of entering the ESP heap on the first received radio frame. The potentially
// large QUIC ledger remains allocated by the service only after a valid OPEN.
static mut CONNECTION_DISPATCHER: core::mem::MaybeUninit<ConnectionDispatcher> =
    core::mem::MaybeUninit::uninit();
static CONNECTION_DISPATCHER_READY: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
/// Last server-side raw-QUIC parsing error. Client errors are already exposed
/// by the action adapter; this scalar closes the diagnostic gap when a peer
/// receives OPEN_ACK but the server rejects its following stream request.
/// It stores the portable compact error code, not packet bytes or state.
static CONNECTION_LAST_ERROR: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Read the bounded connection error diagnostic for the radio snapshot.
pub(crate) fn connection_last_error() -> u32 {
    CONNECTION_LAST_ERROR.load(core::sync::atomic::Ordering::Acquire)
}

/// Construct one ordinary QUIC responder with the firmware-wide CID and
/// stateless-reset policy.  This owns no bearer state: Main supplies its
/// raw-bearer association policy, while Recovery supplies its smaller
/// memory-derived profile over the same associated-STA raw UDP6 bearer.
pub(crate) fn new_connection_dispatcher(
    association: quic_lite::AssociationProfile,
) -> ConnectionDispatcher {
    let mut dispatcher = ConnectionDispatcher::new(
        initial_server_cid(),
        firmware_receive_limits(association),
        association,
    );
    // The normal profile is selected from live internal heap. For controlled
    // host stress tests, an OPEN may request a larger receive window up to
    // this compile-time allocation envelope; without that explicit request,
    // the live-heap profile above remains authoritative.
    dispatcher.set_receive_profile_ceiling(
        quic_lite::AssociationProfile {
            history_packets: crate::CONNECTION_HISTORY_CAPACITY,
            initial_window_packets: crate::CONNECTION_HISTORY_CAPACITY,
            tx_burst_packets: association.tx_burst_packets,
            ..association
        }
        .clamp::<{ crate::CONNECTION_HISTORY_CAPACITY }>(),
    );
    // Keep a Recovery OPEN_ACK and Main OPEN_ACK on the identical CID/reset
    // contract. The derived key contains no raw NVS secret and is unrelated
    // to Wi-Fi/NAN/NOW ownership.
    dispatcher.set_stateless_reset_key(crate::main_runtime::stateless_reset_key());
    // A firmware peer may intentionally retain and reuse its existing CID,
    // but a fresh OPEN is a new association and must first release completed
    // zero-stream associations. Host servers can retain many idle ledgers;
    // the ESP heap cannot safely accumulate one ledger per short-lived CLI
    // process while waiting for a possibly lost CLOSE. The shared association
    // table applies this setting only during fresh OPEN admission and never
    // reclaims an active stream or a duplicate OPEN.
    dispatcher.set_association_idle_timeout(Some(0));
    dispatcher
}

/// Seed each firmware boot with a distinct server CID sequence.  A
/// stateless-reset token is derived from the server CID, so reusing a fixed
/// seed makes a delayed reset from a pre-reset association valid for the new
/// Recovery listener.  The sequence remains monotonic and bounded inside the
/// QUIC dispatcher; this only chooses its first opaque value.
fn initial_server_cid() -> quic_lite::ConnectionId {
    let value = unsafe { esp_idf_sys::esp_random() }.max(1);
    quic_lite::ConnectionId::new(u64::from(value)).expect("nonzero ESP random CID")
}

unsafe fn connection_dispatcher_mut() -> &'static mut ConnectionDispatcher {
    if !CONNECTION_DISPATCHER_READY.load(core::sync::atomic::Ordering::Acquire) {
        let dispatcher = new_connection_dispatcher(*core::ptr::addr_of!(RAW_ASSOCIATION));
        // The same CID can keep an established association for later streams.
        // A fresh CID releases completed idle entries according to the
        // firmware-sized policy installed by `new_connection_dispatcher`.
        core::ptr::addr_of_mut!(CONNECTION_DISPATCHER)
            .write(core::mem::MaybeUninit::new(dispatcher));
        CONNECTION_DISPATCHER_READY.store(true, core::sync::atomic::Ordering::Release);
    }
    &mut *core::ptr::addr_of_mut!(CONNECTION_DISPATCHER).cast::<ConnectionDispatcher>()
}

unsafe fn connection_dispatcher_if_ready() -> Option<&'static mut ConnectionDispatcher> {
    CONNECTION_DISPATCHER_READY
        .load(core::sync::atomic::Ordering::Acquire)
        .then(|| {
            &mut *core::ptr::addr_of_mut!(CONNECTION_DISPATCHER).cast::<ConnectionDispatcher>()
        })
}

/// Install the association defaults that the next connection will use.
///
/// Called once during a STA/raw-radio start transition, before the receive
/// callback can construct a dispatcher.
pub(crate) fn prepare_raw_association(
    profile: &crate::TransportProfile,
) -> RawAssociationSelection {
    unsafe {
        let selection = raw_association_selection(profile);
        RAW_ASSOCIATION = selection.association;
        // This is normally called before receive starts, but making the
        // already-live case identical to NOW prevents a previous default
        // dispatcher from silently retaining its old receive limits.
        if let Some(service) = connection_dispatcher_if_ready() {
            service.set_association_defaults(selection.association);
        }
        selection
    }
}

/// Install the action-bearer association at an explicit NAN/NOW epoch
/// boundary. A previous connection may have been reached over UART or
/// UDP6, so replace it rather than letting an old bounded association
/// survive into the packet-at-a-time action path. The physical bearer is not
/// touched here; callers have already serialized the radio transition.
pub(crate) fn prepare_espnow_association(profile: &crate::TransportProfile) {
    unsafe {
        RAW_ASSOCIATION = espnow_association(profile);
        let association = RAW_ASSOCIATION;
        if let Some(service) = connection_dispatcher_if_ready() {
            service.set_association_defaults(association);
        }
    }
}

/// Replace the live connection's association defaults without changing radio
/// state.  Main calls this only for an explicit ACK/burst profile transition;
/// the raw callback never invokes it.  A not-yet-created dispatcher simply
/// picks up the prepared defaults on its first valid OPEN.
pub(crate) fn replace_raw_association(profile: &crate::TransportProfile) {
    unsafe {
        RAW_ASSOCIATION = raw_association(profile);
        let association = RAW_ASSOCIATION;
        if let Some(service) = connection_dispatcher_if_ready() {
            service.set_association_defaults(association);
        }
    }
}
// PPP needs a response buffer while its callback sends an immediate ACK. It
// is allocated only after the first valid UART service packet; this is bearer
// scratch, not a second QUIC ledger or egress queue.
static mut UART_SERVICE_RESPONSE: Option<alloc::boxed::Box<[u8; crate::TRANSPORT_MTU]>> = None;
/// Scratch for the typed connection deadline event. The shared ingress task
/// is its only user, exactly like normal raw ingress, so this adds neither a
/// bearer queue nor a second packet pool allocation.
static mut CONNECTION_TIMER_RESPONSE: [u8; crate::TRANSPORT_MTU] = [0; crate::TRANSPORT_MTU];

/// Opaque result of injecting one complete bearer frame into the shared QUIC
/// association owner.  A bearer may use `accepted` for local accounting, but
/// it must not derive that fact by decoding a QUIC header itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionFrameIngress {
    pub accepted: bool,
    pub response: Option<usize>,
}

pub fn receive_connection_frame(
    path: quic_lite::PathId,
    packet: &[u8],
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    receive_connection_frame_ingress(path, packet, response).response
}

/// Submit a complete frame plus its opaque path handle to the single
/// association owner.  This is the only firmware-facing API that reports
/// admission; Wi-Fi/NOW/UART adapters must not parse or peek at QUIC framing
/// to recreate the result.
pub fn receive_connection_frame_ingress(
    path: quic_lite::PathId,
    packet: &[u8],
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> ConnectionFrameIngress {
    unsafe {
        let service = connection_dispatcher_mut();
        // QUIC-lite's public transport clock is milliseconds on host and
        // device. ESP-IDF exposes microseconds; convert once at this adapter
        // boundary so ACK delay, credit retry, PTO, and idle retention use
        // the same units as dmesh-cli and host tests.
        let now_ms = (esp_idf_sys::esp_timer_get_time().max(0) as u64) / 1_000;
        // Component handlers execute synchronously inside `receive`. Give
        // them a pre-dispatch association snapshot rather than allowing a
        // diagnostic handler to re-enter this mutable shared owner.
        let connection_status = service.active_connection_status();
        let last_close_at = service.last_close_at();
        let terminal_before = service.terminal_response_snapshot();
        let receive =
            crate::relay_main::with_connection_status(connection_status, last_close_at, || {
                dmesh_server::transport::receive_server_turn(
                    service,
                    path,
                    packet,
                    now_ms,
                    response,
                    |service, now| crate::stream_handlers::before_receive(service, now),
                    |service, path, now, closed| {
                        crate::stream_handlers::after_receive(service, path, now, closed)
                    },
                )
            });
        let (accepted, result) = match receive {
            Ok(value) => (true, value),
            Err(error) => {
                CONNECTION_LAST_ERROR.store(
                    quic_lite::receive_error_code(error) as u32,
                    core::sync::atomic::Ordering::Release,
                );
                // Preserve connection-owned CID context beside the compact
                // error code. The frame adapter deliberately does not decode
                // QUIC headers or derive association state.
                let diagnostic = service.connection_id_diagnostic(packet);
                if let Some(received) = diagnostic.received {
                    crate::commands::send_stat(b"connection dcid=", received.value());
                }
                if let Some(expected) = diagnostic.expected {
                    crate::commands::send_stat(b"connection expected_dcid=", expected.value());
                }
                crate::commands::send_stat(
                    b"connection error=",
                    quic_lite::receive_error_code(error) as u64,
                );
                (false, None)
            }
        };
        if accepted {
            if let Some(receive_cid) = service.take_terminal_response_delivered() {
                TERMINAL_RESPONSE_DELIVERED.store(true, core::sync::atomic::Ordering::Release);
                crate::rtc::response_delivered(receive_cid);
            }
            if let Some(receive_cid) = service.terminal_response_started_after(terminal_before) {
                crate::rtc::bind_recovery_response(receive_cid);
            }
        }
        if connection_path_transport(path) == dmesh_server::transport_path::TransportId::NOW.0 {
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
        // The packet worker may just have created or advanced a server
        // association. Main could otherwise still be blocked with the old
        // (or no) deadline and miss the connection-owned PTO. This matters
        // equally when UART's single physical egress slot temporarily cannot
        // submit a generated control packet. This marker only wakes Main to
        // recompute its one-shot timer; it neither polls nor sends here.
        if matches!(
            connection_path_transport(path),
            transport if transport == dmesh_server::transport_path::TransportId::NOW.0
                || transport == dmesh_server::transport_path::TransportId::UDP6.0
                || transport == dmesh_server::transport_path::TransportId::UART.0
        ) {
            request_connection_deadline_recheck();
        }
        ConnectionFrameIngress {
            accepted,
            response: result,
        }
    }
}

pub fn poll_connection(
    path: quic_lite::PathId,
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    unsafe {
        let service = connection_dispatcher_if_ready()?;
        let now_ms = (esp_idf_sys::esp_timer_get_time().max(0) as u64) / 1_000;
        let terminal_before = service.terminal_response_snapshot();
        let result = dmesh_server::transport::poll_server_turn(
            service,
            path,
            now_ms,
            600,
            response,
            |service, path, now| crate::stream_handlers::before_poll(service, path, now),
        )
        .ok()
        .flatten();
        if let Some(receive_cid) = service.take_terminal_response_delivered() {
            TERMINAL_RESPONSE_DELIVERED.store(true, core::sync::atomic::Ordering::Release);
            crate::rtc::response_delivered(receive_cid);
        }
        if let Some(receive_cid) = service.terminal_response_started_after(terminal_before) {
            crate::rtc::bind_recovery_response(receive_cid);
        }
        result
    }
}

/// Return the active connection's bounded ready-flight limit. Physical
/// adapters use this only as the cap passed to quic-lite's shared egress
/// drainer; packet eligibility remains connection-owned.
pub(crate) fn connection_tx_burst_packets() -> usize {
    unsafe {
        connection_dispatcher_if_ready()
            .map(|service| service.tx_burst_packets())
            .unwrap_or(1)
    }
}

/// Return the next transport-owned server deadline in Main milliseconds.
///
/// The raw endpoint reports only a pending ACK or retained-packet PTO in its
/// millisecond clock. Main converts that one value into a blocking queue
/// timeout; this does not create a periodic service tick. UART needs the same
/// one-shot PTO as UDP6/NOW when its single physical egress slot was full.
pub(crate) fn connection_delay_ms() -> Option<u32> {
    unsafe {
        let service = connection_dispatcher_if_ready()?;
        let (_, path, deadline_ms) = service.next_service_target(600)?;
        if !matches!(
            connection_path_transport(path),
            transport if transport == dmesh_server::transport_path::TransportId::NOW.0
                || transport == dmesh_server::transport_path::TransportId::UDP6.0
                || transport == dmesh_server::transport_path::TransportId::UART.0
        ) {
            return None;
        }
        let now_ms = (esp_idf_sys::esp_timer_get_time().max(0) as u64) / 1_000;
        Some(
            deadline_ms
                .saturating_sub(now_ms)
                .clamp(1, u64::from(u32::MAX)) as u32,
        )
    }
}

/// Ask the shared ingress owner for one normal application-maintenance turn.
///
/// Usually this is scheduled at a QUIC deadline. A handler may also request
/// it after admitting asynchronous storage work; the worker then runs the
/// same `before_poll` hook and QUIC decides whether any packet is due. It
/// does not create a flash-, ACK-, or bearer-specific service loop.
pub(crate) fn schedule_connection_timer() {
    let _ = crate::shared_ingress_esp::schedule_connection_timer(service_connection_timer);
}

/// Perform one server-side PTO turn on the packet worker. The reply path
/// comes from the accepted connection packet, not from an adapter-private
/// queue, so future multipath policy can replace this final transport match.
fn service_connection_timer() {
    unsafe {
        let Some(service) = connection_dispatcher_if_ready() else {
            return;
        };
        let Some((receive_cid, path, _)) = service.service_target_or_active(600) else {
            return;
        };
        if service.select_receive_cid(receive_cid) != Some(path) {
            return;
        }
        match connection_path_transport(path) {
            transport if transport == dmesh_server::transport_path::TransportId::UART.0 => {
                let Some(response) = (*core::ptr::addr_of_mut!(UART_SERVICE_RESPONSE)).as_mut()
                else {
                    return;
                };
                pump_uart_egress(path, response, None);
            }
            transport if transport == dmesh_server::transport_path::TransportId::NOW.0 => {
                let response = &mut *core::ptr::addr_of_mut!(CONNECTION_TIMER_RESPONSE);
                let Some(used) = poll_connection(path, response) else {
                    return;
                };
                if used <= response.len() {
                    let packet = &response[..used];
                    let _ = crate::wifi_espnow_esp::transmit_from_worker(
                        crate::wifi_espnow_esp::EspNowPeer {
                            mac: connection_path_peer(path),
                        },
                        packet,
                    );
                }
            }
            transport if transport == dmesh_server::transport_path::TransportId::UDP6.0 => {
                crate::wifi_raw_udp6_esp::poll_connection_timer();
            }
            _ => {}
        }
    }
}

/// Recovery is only the first consumer of this generic raw bearer.  Its
/// handler contains no flash, Wi-Fi, or address policy: those stay outside
/// the host-tested connection and ESP adapter respectively.
pub(crate) fn receive_raw_udp6(
    path: quic_lite::PathId,
    _peer: crate::wifi_raw_udp6_esp::RawUdp6Peer,
    packet: &[u8],
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    receive_connection_frame(path, packet, response)
}

/// Recovery installs no connectionless command catalog. Multicast presence
/// is outbound only; directed control and flashing use the ordinary QUIC
/// association handled by [`receive_raw_udp6`].
pub(crate) fn reject_recovery_connectionless(
    _peer: crate::wifi_raw_udp6_esp::RawUdp6Peer,
    _packet: &[u8],
    _response: &mut [u8; crate::TRANSPORT_MTU],
) -> crate::wifi_raw_udp6_esp::ConnectionlessUdp6Outcome {
    crate::wifi_raw_udp6_esp::ConnectionlessUdp6Outcome::Rejected
}

/// Construct a bounded connectionless application packet at the shared QUIC
/// dispatcher boundary. Physical UART/NOW/UDP adapters receive the completed
/// packet only; they must never select a QUIC header or packet number.
pub(crate) fn encode_connectionless_message(payload: &[u8], output: &mut [u8]) -> Option<usize> {
    dmesh_server::direct::ConnectionlessMessage::encode(payload, output)
}

/// Terminate one connectionless UDP record after the bearer has supplied only
/// its immutable path facts. Envelope and application classification belong
/// here, alongside the shared connection dispatcher, rather than in Wi-Fi.
pub(crate) fn receive_udp6_connectionless(
    peer: crate::wifi_raw_udp6_esp::RawUdp6Peer,
    packet: &[u8],
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> crate::wifi_raw_udp6_esp::ConnectionlessUdp6Outcome {
    if !dmesh_server::direct::ConnectionlessMessage::is_packet(packet) {
        return crate::wifi_raw_udp6_esp::ConnectionlessUdp6Outcome::Rejected;
    }
    match dmesh_server::direct::ConnectionlessMessage::receive(
        packet,
        response,
        |payload, response| {
            if let Some(announce) = dmesh_server::announce::decode_announce(payload) {
                crate::wifi_raw_udp6_esp::record_announce_peer(announce, peer.mac, peer.ip);
                return dmesh_server::direct::ConnectionlessDisposition::Handled;
            }
            let mut response_len = 0;
            if crate::main_runtime::receive_direct_request(payload, |record| {
                if record.len() <= response.len() {
                    response[..record.len()].copy_from_slice(record);
                    response_len = record.len();
                }
            }) {
                if response_len == 0 {
                    dmesh_server::direct::ConnectionlessDisposition::Handled
                } else {
                    dmesh_server::direct::ConnectionlessDisposition::Response(response_len)
                }
            } else {
                dmesh_server::direct::ConnectionlessDisposition::NotHandled
            }
        },
    ) {
        dmesh_server::direct::ConnectionlessDisposition::Response(used) => {
            crate::wifi_raw_udp6_esp::ConnectionlessUdp6Outcome::Response(used)
        }
        dmesh_server::direct::ConnectionlessDisposition::Handled => {
            crate::wifi_raw_udp6_esp::ConnectionlessUdp6Outcome::Handled
        }
        _ => crate::wifi_raw_udp6_esp::ConnectionlessUdp6Outcome::Rejected,
    }
}

/// Main-only raw UDP6 entry point. A matching forwarding DCID is submitted to
/// its configured local next hop; every other packet retains the existing raw
/// endpoint behavior. Recovery continues to call [`receive_raw_udp6`].
pub(crate) fn receive_main_raw_udp6(
    path: quic_lite::PathId,
    peer: crate::wifi_raw_udp6_esp::RawUdp6Peer,
    packet: &[u8],
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    // The connectionless long-header type carries only the shared direct allowlist: a directed discovery
    // request/reply or a complete `transport.set` profile. A bearer probe is
    // deliberately not a second diagnostic protocol; use directed discovery.
    if dmesh_server::direct::ConnectionlessMessage::is_packet(packet) {
        return match receive_udp6_connectionless(peer, packet, response) {
            crate::wifi_raw_udp6_esp::ConnectionlessUdp6Outcome::Response(used) => Some(used),
            crate::wifi_raw_udp6_esp::ConnectionlessUdp6Outcome::Handled
            | crate::wifi_raw_udp6_esp::ConnectionlessUdp6Outcome::Rejected => None,
        };
    }
    if crate::relay_main::forward(packet, response, |next_hop, payload| match next_hop {
        crate::relay_main::NextHop::Now(peer) => {
            crate::wifi_espnow_esp::transmit_from_worker(peer, payload)
        }
        crate::relay_main::NextHop::Udp6 { link, peer } => crate::wifi_raw_udp6_esp::transmit_udp6(
            link,
            peer,
            crate::wifi_raw_udp6_esp::RAW_UDP6_PORT,
            payload,
        ),
    }) {
        return None;
    }
    // Pairing requested on a normal QUIC stream must bind its reverse alias
    // to this exact UDP6 ingress.  The shared raw dispatcher remains bearer
    // neutral; this tiny scope supplies the platform route only while it
    // synchronously invokes the registered relay component.
    crate::relay_main::with_stream_ingress(
        crate::relay_main::NextHop::Udp6 {
            link: peer.link,
            peer,
        },
        || receive_raw_udp6(path, peer, packet, response),
    )
}

pub(crate) fn poll_raw_udp6(
    path: quic_lite::PathId,
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    poll_connection(path, response)
}

pub(crate) fn connection_reply_path() -> Option<quic_lite::PathId> {
    unsafe { connection_dispatcher_if_ready()?.reply_path() }
}

pub(crate) fn connection_has_path(path: quic_lite::PathId) -> bool {
    unsafe { connection_dispatcher_if_ready().is_some_and(|service| service.has_path(path)) }
}

/// Feed one complete ESP-NOW frame into the same connection dispatcher used
/// by UART and UDP6. The latest valid ingress path selects the reply without
/// replacing the logical connection or creating bearer-local DCID state.
pub(crate) fn receive_espnow(
    peer: crate::wifi_espnow_esp::EspNowPeer,
    packet: &[u8],
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    // Direct records use the same DMesh QUIC long-header envelope over NOW as
    // they do over UART and UDP6.  The action adapter supplies only peer MAC;
    // direct classification and response framing stay here with connection
    // dispatch.  A bare tagged record is never a direct packet on this path.
    if dmesh_server::direct::ConnectionlessMessage::is_packet(packet) {
        return match dmesh_server::direct::ConnectionlessMessage::receive(
            packet,
            response,
            |payload, response| {
                if let Some(announce) = dmesh_server::announce::decode_announce(payload) {
                    crate::wifi_raw_udp6_esp::record_connectionless_announce(announce, peer.mac);
                    return dmesh_server::direct::ConnectionlessDisposition::Handled;
                }
                let mut response_len = 0;
                if crate::main_runtime::receive_direct_request(payload, |record| {
                    if record.len() <= response.len() {
                        response[..record.len()].copy_from_slice(record);
                        response_len = record.len();
                    }
                }) {
                    if response_len == 0 {
                        dmesh_server::direct::ConnectionlessDisposition::Handled
                    } else {
                        dmesh_server::direct::ConnectionlessDisposition::Response(response_len)
                    }
                } else {
                    dmesh_server::direct::ConnectionlessDisposition::NotHandled
                }
            },
        ) {
            dmesh_server::direct::ConnectionlessDisposition::Response(used) => Some(used),
            _ => None,
        };
    }
    receive_connection_frame(
        connection_path_id(dmesh_server::transport_path::TransportId::NOW.0, peer.mac),
        packet,
        response,
    )
}

/// Main-only NOW entry point paired with [`receive_main_raw_udp6`]. Both
/// bearers use the same DCID registry and next-hop state; they differ only in
/// native framing and final egress submission.
pub(crate) fn receive_main_espnow(
    peer: crate::wifi_espnow_esp::EspNowPeer,
    packet: &[u8],
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    if crate::relay_main::forward(packet, response, |next_hop, payload| match next_hop {
        crate::relay_main::NextHop::Now(peer) => {
            crate::wifi_espnow_esp::transmit_from_worker(peer, payload)
        }
        crate::relay_main::NextHop::Udp6 { link, peer } => crate::wifi_raw_udp6_esp::transmit_udp6(
            link,
            peer,
            crate::wifi_raw_udp6_esp::RAW_UDP6_PORT,
            payload,
        ),
    }) {
        return None;
    }
    crate::relay_main::with_stream_ingress(crate::relay_main::NextHop::Now(peer), || {
        receive_espnow(peer, packet, response)
    })
}

pub(crate) fn poll_espnow(
    peer: crate::wifi_espnow_esp::EspNowPeer,
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    poll_connection(
        connection_path_id(dmesh_server::transport_path::TransportId::NOW.0, peer.mac),
        response,
    )
}

/// Shared-pool UART callback for the small Recovery regression profile.
/// `uart_esp` has already decoded PPP and placed the datagram in the common
/// packet pool; this function owns no UART queue or separate receive buffer.
pub(crate) fn receive_uart_ingress(_item: crate::shared_ingress_esp::IngressPacket, packet: &[u8]) {
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
        let path = connection_path_id(dmesh_server::transport_path::TransportId::UART.0, [0; 6]);
        let immediate = receive_connection_frame(path, packet, response);
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
/// the actual queue vacancy before calling `poll_connection`: polling an
/// endpoint that cannot submit would otherwise consume a ledger packet and
/// leave it waiting for a retransmission that no UART timer owns.
fn service_uart_egress_ready() {
    unsafe {
        let Some(response) = (*core::ptr::addr_of_mut!(UART_SERVICE_RESPONSE)).as_mut() else {
            return;
        };
        let path = connection_path_id(dmesh_server::transport_path::TransportId::UART.0, [0; 6]);
        pump_uart_egress(path, response, None);
    }
}

/// Notify the shared connection owner that an application stream's storage
/// completed work. This edge is independent of packet loss and bearer choice.
pub(crate) fn schedule_storage_ready() -> bool {
    crate::shared_ingress_esp::schedule_storage_ready(service_storage_ready)
}

/// Take the generic terminal stream delivery edge. Recovery combines this
/// with its durable-flash completion before arming Main; Main does not poll it.
pub(crate) fn take_terminal_response_delivered() -> bool {
    TERMINAL_RESPONSE_DELIVERED.swap(false, core::sync::atomic::Ordering::AcqRel)
}

/// Let the application publish newly available receive capacity to QUIC-lite,
/// then submit any resulting opaque transport packet on its active path.
fn service_storage_ready() {
    unsafe {
        let now_ms = (esp_idf_sys::esp_timer_get_time().max(0) as u64) / 1_000;
        let Some(service) = connection_dispatcher_if_ready() else {
            return;
        };
        let Ok(Some(path)) = crate::stream_handlers::storage_ready(service, now_ms) else {
            return;
        };
        match connection_path_transport(path) {
            transport if transport == dmesh_server::transport_path::TransportId::UART.0 => {
                let Some(response) = (*core::ptr::addr_of_mut!(UART_SERVICE_RESPONSE)).as_mut()
                else {
                    return;
                };
                pump_uart_egress(path, response, None);
            }
            transport if transport == dmesh_server::transport_path::TransportId::NOW.0 => {
                let response = &mut *core::ptr::addr_of_mut!(CONNECTION_TIMER_RESPONSE);
                if let Some(used) = poll_connection(path, response) {
                    let packet = &response[..used];
                    let _ = crate::wifi_espnow_esp::transmit_from_worker(
                        crate::wifi_espnow_esp::EspNowPeer {
                            mac: connection_path_peer(path),
                        },
                        packet,
                    );
                }
            }
            transport if transport == dmesh_server::transport_path::TransportId::UDP6.0 => {
                crate::wifi_raw_udp6_esp::poll_connection_timer();
            }
            _ => {}
        }
    }
}

/// Submit one QUIC-lite packet only when the physical UART writer has space.
///
/// A classic ESP32 deliberately has one MTU-sized egress slot to preserve
/// internal RAM. Unlike a socket, `poll_transmit` advances the QUIC ledger as
/// it produces a datagram, so capacity must be checked before polling rather
/// than treating a failed enqueue as ordinary packet loss.
fn pump_uart_egress(
    path: quic_lite::PathId,
    response: &mut [u8; crate::TRANSPORT_MTU],
    immediate: Option<usize>,
) {
    let (queued, capacity) = crate::uart_esp::transport_egress_capacity();
    if queued >= capacity {
        return;
    }
    let used = immediate.or_else(|| poll_connection(path, response));
    if let Some(used) = used.filter(|used| *used <= response.len()) {
        let packet = &response[..used];
        let _ = crate::uart_esp::send_transport_packet(packet);
    }
}
