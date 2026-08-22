// IMPORTANT: This is shared no-std ESP firmware code. Host-neutral protocol
// behavior remains in quic-lite/dmesh-server; this worker composes ESP UART,
// NVS, STA/UDP, and flash adapters for Recovery and later Main reuse.
//! Shared no-std Recovery/Main transport worker.
//!
//! The reusable pieces are split by bearer: `uart` handles the command/control
//! channel, `wifi` owns STA setup and the UDP transport adapter, and
//! `udp_flash` consumes ordered application stream bytes.
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

static mut TRANSPORT_PROFILE: crate::TransportProfile = crate::TransportProfile::new();
/// `TRANSPORT_PROFILE` is shared by the UART/NAN command worker and this
/// runtime task. It is a whole, fixed-size radio epoch, not an atomic scalar:
/// serialize its copy/update so a start never observes a torn or stale SSID.
static TRANSPORT_PROFILE_LOCK: AtomicBool = AtomicBool::new(false);
/// Bumped only after an accepted STA `transport.start` profile is committed.
/// The runtime consumes each value as one immutable Wi-Fi replacement epoch.
static STA_START_GENERATION: AtomicU32 = AtomicU32::new(0);
static mut RAW_ASSOCIATION: dmesh_server::raw_transport::RawAssociation =
    dmesh_server::raw_transport::RawAssociation::c6_default();
static mut ESPNOW_ASSOCIATION: dmesh_server::raw_transport::RawAssociation =
    dmesh_server::raw_transport::RawAssociation::conservative();

fn with_transport_profile<R>(operation: impl FnOnce(&mut crate::TransportProfile) -> R) -> R {
    while TRANSPORT_PROFILE_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    // The lock excludes the UART/NAN ingress worker while a fixed-size profile
    // is copied or updated. The callback never retains this reference.
    let result = operation(unsafe { &mut *core::ptr::addr_of_mut!(TRANSPORT_PROFILE) });
    TRANSPORT_PROFILE_LOCK.store(false, Ordering::Release);
    result
}

fn transport_profile_snapshot() -> crate::TransportProfile {
    with_transport_profile(|profile| *profile)
}

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

fn wants_sta(profile: &crate::TransportProfile) -> bool {
    matches!(
        profile.requested_transport,
        Some(dmesh_server::control::TransportKind::Sta)
    )
}

fn wants_nan(profile: &crate::TransportProfile) -> bool {
    matches!(
        profile.requested_transport,
        Some(dmesh_server::control::TransportKind::Nan)
    )
}

fn wants_sta_extensions(profile: &crate::TransportProfile) -> bool {
    profile.now != 2
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
            core::ptr::drop_in_place(
                core::ptr::addr_of_mut!(RAW_SERVICE).cast::<RawServiceDispatcher>(),
            );
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
    // Presence is one-way shared CBOR, not a QUIC-lite datagram. Retain it
    // before the action bearer reaches connection dispatch so unassociated
    // NAN+NOW nodes keep the same bounded discovery view as STA/UDP6 nodes.
    if let Some(announce) = dmesh_server::announce::decode_announce(packet) {
        crate::wifi_raw_udp6_esp::record_connectionless_announce(announce, peer.mac);
        return None;
    }
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
    // A boot/discovery presence record is bearer-neutral. UART does not carry
    // a remote radio address, so it uses the same shared device table with an
    // unspecified peer tuple rather than being parsed as a control command.
    if let Some(announce) = dmesh_server::announce::decode_announce(packet) {
        crate::wifi_raw_udp6_esp::record_connectionless_announce(announce, [0; 6]);
        return;
    }
    if dmesh_server::announce::is_followups_observed_request(packet) {
        let mut snapshots = [None; crate::wifi_nan_dw_capture_esp::FOLLOWUP_HISTORY_CAPACITY];
        crate::wifi_nan_dw_capture_esp::followup_history(&mut snapshots);
        let mut response = [0u8; crate::TRANSPORT_MTU];
        let mut entries = [dmesh_server::announce::ObservedFollowup {
            source: [0; 6], target: [0; 6], msg_type: 0, seq: 0,
            payload_len: 0, payload_hash: 0, last_seen_ms: 0,
        }; crate::wifi_nan_dw_capture_esp::FOLLOWUP_HISTORY_CAPACITY];
        let mut count = 0;
        for snapshot in snapshots.iter().flatten() {
            entries[count] = dmesh_server::announce::ObservedFollowup {
                source: snapshot.source,
                target: snapshot.target,
                msg_type: snapshot.msg_type,
                seq: snapshot.seq,
                payload_len: snapshot.payload_len,
                payload_hash: snapshot.payload_hash,
                last_seen_ms: snapshot.last_seen_ms,
            };
            count += 1;
        }
        if let Some(used) = dmesh_server::announce::encode_followups_observed_response(
            &entries[..count],
            &mut response,
        ) {
            let _ = crate::commands::send_record(&response[..used]);
        }
        return;
    }
    if dmesh_server::announce::is_observed_request(packet) {
        let mut snapshots = [None; 10];
        crate::wifi_raw_udp6_esp::announce_peers(&mut snapshots);
        let mut response = [0u8; crate::TRANSPORT_MTU];
        let mut entries = [dmesh_server::announce::ObservedAnnounce {
            device_id: &[], source_mac: [0; 6], source_ip: &[], uptime_secs: 0,
            transport_mode: 0, counters: 0, kind: 0, last_seen_ms: 0,
        }; 10];
        let mut count = 0;
        for snapshot in snapshots.iter().flatten() {
            entries[count] = dmesh_server::announce::ObservedAnnounce {
                device_id: &snapshot.device_id,
                source_mac: snapshot.source_mac,
                source_ip: &snapshot.source_ip,
                uptime_secs: snapshot.uptime_secs,
                transport_mode: snapshot.transport_mode,
                counters: snapshot.counters,
                kind: snapshot.kind,
                last_seen_ms: snapshot.last_seen_ms,
            };
            count += 1;
        }
        if let Some(used) = dmesh_server::announce::encode_observed_response(
            &entries[..count],
            &mut response,
        ) {
            let _ = crate::commands::send_record(&response[..used]);
        }
        return;
    }
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
    let mut control_result = None;
    let accepted = with_transport_profile(|params| {
        let Some(result) = crate::commands::apply_control_record_result(packet, params) else {
            return false;
        };
        control_result = Some(result);
        // A tagged request id opts into a correlated direct response.  This
        // remains the same CBOR envelope as a QUIC-lite handler reply and
        // does not reserve a response queue for fire-and-forget bootstrap.
        let mut response = [0u8; 128];
        if let Some(used) = crate::commands::encode_control_response(packet, params, &mut response)
        {
            let _ = crate::commands::send_record(&response[..used]);
        }
        true
    });
    if !accepted {
        crate::commands::send_response(b"protocol rejected");
    } else {
        crate::state::direct_record_accepted();
        if control_result.is_some_and(|result| result.transport_start && result.changed) {
            // Publish only after the complete profile is visible. Repeated
            // NAN SD/Pub records which resolve to the same profile are an
            // acknowledgement-only no-op: do not tear down Wi-Fi or reset a
            // usable STA/NOW association.
            STA_START_GENERATION.fetch_add(1, Ordering::Release);
        }
    }
}

/// Apply an active NAN Service Info payload as the same tagged-CBOR control
/// command accepted on UART. This runs on the common ingress worker after the
/// Wi-Fi owner has copied and released the promiscuous driver buffer; it must
/// never run in the NAN callback itself. The active SDF is one-way, so an
/// accepted correlated control response returns on the already-active NOW
/// bearer before the normal replacement loop changes radio mode.
fn receive_nan_service_info(peer: [u8; 6], packet: &[u8]) {
    if let Some(announce) = dmesh_server::announce::decode_announce(packet) {
        crate::wifi_raw_udp6_esp::record_connectionless_announce(announce, peer);
        return;
    }
    let mut control_result = None;
    let mut response = [0u8; 128];
    let mut response_len = 0;
    let accepted = with_transport_profile(|params| {
        let Some(result) = crate::commands::apply_control_record_result(packet, params) else {
            return false;
        };
        control_result = Some(result);
        response_len =
            crate::commands::encode_control_response(packet, params, &mut response).unwrap_or(0);
        true
    });
    if !accepted {
        crate::commands::send_stat(
            b"nan sd rejected peer=",
            u64::from_le_bytes([peer[0], peer[1], peer[2], peer[3], peer[4], peer[5], 0, 0]),
        );
        return;
    }
    crate::state::direct_record_accepted();
    if response_len != 0 {
        // An active Subscribe is a NAN rendezvous, so its correlated CBOR
        // response returns as one directed NAN Follow-up in this DW. A normal
        // Publish SI retains the established NOW broadcast response path.
        if crate::wifi_nan_dw_capture_esp::take_active_subscribe(peer) {
            let _ = crate::wifi_nan_dw_capture_esp::send_followup_response(
                peer,
                &response[..response_len],
            );
        } else {
            let _ = crate::wifi_espnow_esp::broadcast_record(&response[..response_len]);
        }
    }
    if control_result.is_some_and(|result| result.transport_start && result.changed) {
        STA_START_GENERATION.fetch_add(1, Ordering::Release);
    }
}

/// Run the shared Recovery-style multi-bearer transport service loop.
///
/// The only Recovery-specific operation is supplied as `complete_main_flash`:
/// it selects Main and reboots only after a verified Main image is durable.
/// Main supplies a different completion policy for its allowed targets.
#[derive(Clone, Copy)]
pub struct RuntimeBehavior {
    pub role: u8,
    pub partition: u8,
    pub boot_message: &'static [u8],
    pub mark_healthy: fn(),
}

pub struct FirmwareRuntime {
    behavior: RuntimeBehavior,
}

impl FirmwareRuntime {
    pub const fn new(behavior: RuntimeBehavior) -> Self {
        Self { behavior }
    }

    pub const fn main(mark_healthy: fn()) -> Self {
        Self::new(RuntimeBehavior {
            role: 1,
            partition: 1,
            boot_message: b"main core boot",
            mark_healthy,
        })
    }

    pub fn run(self) {
        run_with_boot_identity(
            self.behavior.role,
            self.behavior.partition,
            self.behavior.boot_message,
            self.behavior.mark_healthy,
        );
    }
}

pub fn run(_complete_main_flash: fn() -> bool) {
    run_with_boot_identity(2, 2, b"recovery boot", || {});
}

/// Run the shared core under Main's boot identity.
///
/// Main retains only its Stage2 health transition here.  Its former product
/// boot loop, power policy, and radio owners must be registered back through
/// dmesh-server one handler at a time; they may not compete with this shared
/// UART/STA/raw-service lifecycle.
pub fn run_main(mark_healthy: fn()) {
    FirmwareRuntime::main(mark_healthy).run();
}

fn run_with_boot_identity(
    role: u8,
    partition: u8,
    boot_message: &'static [u8],
    mark_healthy: fn(),
) {
    esp_idf_sys::link_patches();
    if !unsafe { crate::uart_esp::install_l2_driver() } {
        return;
    }
    // The association target comes only from `transport.start`; accept UART
    // or future NAN commands before considering any STA epoch.
    with_transport_profile(|params| {
        params.command_mode = unsafe { command_mode_from_stage2_nvs() };
    });
    if !unsafe { crate::uart_esp::start_shared_l2(receive_uart_ingress, receive_uart_raw_ingress) }
    {
        return;
    }
    crate::wifi_nan_dw_capture_esp::set_service_info_handler(Some(receive_nan_service_info));
    // The UART driver and common direct-control receiver are live before the
    // boot proof is emitted. Main uses this point to clear the Stage2
    // boot-failure marker; Recovery deliberately supplies a no-op callback.
    mark_healthy();
    crate::commands::send_response(boot_message);
    send_boot_identity(role, partition);
    send_boot_announce_uart(role, partition);
    // The idle/default personality is unassociated AP+NAN+NOW. With the
    // default DW interval of zero this is NOW-only: no raw UDP6 bearer and
    // no promiscuous NAN capture. Start it immediately and exactly once; an
    // explicit transport.start later is the only operation that replaces it.
    let initial_profile = transport_profile_snapshot();
    let mut nan_now_started = crate::wifi_esp::init_nan_now(&initial_profile, receive_espnow);
    if nan_now_started {
        crate::wifi_espnow_esp::set_poll_handler(Some(poll_espnow));
        send_boot_records_on_now(boot_message, role, partition);
    }
    let mut wifi_started = false;
    let mut applied_raw_tx_rate = None;
    let mut applied_sta_driver_tx = None;
    let mut applied_sta_bssid_check_disabled = None;
    let mut applied_sta_ampdu_enabled = None;
    let mut applied_sta_11b_rates_disabled = None;
    let mut applied_sta_raw_rx_enabled = None;
    let mut applied_ack_frequency = None;
    let mut applied_ack_delay_ms = None;
    let mut applied_tx_burst_packets = None;
    let mut applied_sta_start_generation = 0;
    // The boot setup is already the unassociated radio. Do not consume an
    // absent/default NAN generation by replacing its just-started driver.
    let mut applied_nan_start_generation = STA_START_GENERATION.load(Ordering::Acquire);
    // `now` and `nan_dw_interval` independently select STA extensions.
    let mut sta_extensions_enabled = false;
    let mut applied_nan_dw_interval = None;
    let mut raw_reported_at_ms = 0u64;
    let mut espnow_reported_at_tick = 0 as esp_idf_sys::TickType_t;
    let mut espnow_last_report = [0u32; 30];
    let mut espnow_has_reported = false;
    let mut last_discovery_announce_ms = 0u64;
    loop {
        crate::wifi_nonpromisc_probe_esp::poll();
        // Keep Recovery's common NAN acquisition/DW state machine identical
        // to Main. Starting capture without polling it leaves the initial
        // promiscuous acquisition state stale and makes later radio-control
        // transitions differ by image.
        crate::wifi_nan_dw_capture_esp::poll();
        let now_ms = (unsafe { esp_idf_sys::esp_timer_get_time() }.max(0) as u64) / 1_000;
        if (nan_now_started || wifi_started)
            && now_ms.saturating_sub(last_discovery_announce_ms) >= 15 * 60 * 1_000
        {
            send_discovery_announce(now_ms / 1_000, nan_now_started, wifi_started);
            last_discovery_announce_ms = now_ms;
        }
        // Command parsing and the mutable Recovery image have one owner
        // here. Bearers feed QUIC-lite; no raw command task is
        // started beside this worker.
        // A start publishes a complete, locked profile before its generation.
        // It may therefore replace an active epoch but can never race a
        // partial SSID/profile update from UART or future NAN Service Info.
        let requested_sta_start_generation = STA_START_GENERATION.load(Ordering::Acquire);
        let snapshot = transport_profile_snapshot();
        if wants_nan(&snapshot)
            && !wifi_started
            && applied_nan_start_generation != requested_sta_start_generation
        {
            if nan_now_started {
                crate::wifi_esp::stop_sta_extensions();
                crate::wifi_esp::stop_sta();
                crate::wifi_esp::restart_sta_driver_runtime();
            }
            nan_now_started = crate::wifi_esp::init_nan_now(&snapshot, receive_espnow);
            if nan_now_started {
                crate::wifi_espnow_esp::set_poll_handler(Some(poll_espnow));
            }
            applied_nan_start_generation = requested_sta_start_generation;
        }
        if wants_sta(&snapshot)
            && (!wifi_started || applied_sta_start_generation != requested_sta_start_generation)
        {
            if nan_now_started {
                crate::wifi_esp::stop_sta_extensions();
                crate::wifi_esp::stop_sta();
                crate::wifi_esp::restart_sta_driver_runtime();
                nan_now_started = false;
            }
            if wifi_started {
                if sta_extensions_enabled {
                    crate::wifi_esp::stop_sta_extensions();
                    sta_extensions_enabled = false;
                    applied_nan_dw_interval = None;
                }
                crate::wifi_raw_udp6_esp::stop();
                unsafe { reset_raw_service() };
                // Wi-Fi owns the complete driver/callback transition.
                crate::wifi_esp::replace_sta(&snapshot);
            } else {
                crate::wifi_esp::init_sta(&snapshot);
            }
            applied_sta_start_generation = requested_sta_start_generation;
            applied_raw_tx_rate = Some(snapshot.raw_tx_rate);
            crate::wifi_raw_udp6_esp::set_sta_driver_tx(snapshot.sta_driver_tx);
            applied_sta_driver_tx = Some(snapshot.sta_driver_tx);
            applied_sta_bssid_check_disabled = Some(snapshot.sta_bssid_check_disabled);
            applied_sta_ampdu_enabled = Some(snapshot.sta_ampdu_enabled);
            applied_sta_11b_rates_disabled = Some(snapshot.sta_11b_rates_disabled);
            applied_sta_raw_rx_enabled = Some(snapshot.sta_raw_rx_enabled);
            applied_ack_frequency = Some(snapshot.ack_frequency);
            applied_ack_delay_ms = Some(snapshot.ack_delay_ms);
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
                send_sta_boot_announce();
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
        if wifi_started && !wants_sta(&snapshot) {
            if sta_extensions_enabled {
                crate::wifi_esp::stop_sta_extensions();
                sta_extensions_enabled = false;
                applied_nan_dw_interval = None;
            }
            crate::wifi_raw_udp6_esp::stop();
            unsafe { reset_raw_service() };
            crate::wifi_esp::stop_sta();
            wifi_started = false;
            applied_raw_tx_rate = None;
            applied_sta_driver_tx = None;
            applied_sta_bssid_check_disabled = None;
            applied_sta_ampdu_enabled = None;
            applied_sta_11b_rates_disabled = None;
            applied_sta_raw_rx_enabled = None;
            applied_ack_frequency = None;
            applied_ack_delay_ms = None;
            applied_tx_burst_packets = None;
            crate::commands::send_response(b"transport STA stopped");
            nan_now_started = crate::wifi_esp::init_nan_now(&snapshot, receive_espnow);
            if nan_now_started {
                crate::wifi_espnow_esp::set_poll_handler(Some(poll_espnow));
                // This replacement has already consumed the complete NAN
                // profile that advanced the generation. Without recording it
                // here, the next loop sees the same generation as pending and
                // tears down this just-started DW/NOW epoch a second time.
                applied_nan_start_generation = requested_sta_start_generation;
            }
            continue;
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
                unsafe {
                    RAW_ASSOCIATION = raw_association(&snapshot);
                }
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
            if sta_extensions_enabled {
                crate::wifi_esp::stop_sta_extensions();
                sta_extensions_enabled = false;
                applied_nan_dw_interval = None;
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
            applied_ack_frequency = None;
            applied_ack_delay_ms = None;
            applied_tx_burst_packets = None;
            continue;
        }
        if wifi_started
            && applied_sta_bssid_check_disabled != Some(snapshot.sta_bssid_check_disabled)
        {
            // The private enable/disable pair reports success live, but a
            // false->true transition loses raw NDP on C6 until Wi-Fi is
            // restarted. Apply this pre-association policy through the one
            // existing STA lifecycle instead of claiming a broken live
            // transition succeeded.
            if sta_extensions_enabled {
                crate::wifi_esp::stop_sta_extensions();
                sta_extensions_enabled = false;
                applied_nan_dw_interval = None;
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
            applied_ack_frequency = None;
            applied_ack_delay_ms = None;
            applied_tx_burst_packets = None;
            continue;
        }
        if wifi_started
            && (applied_ack_frequency != Some(snapshot.ack_frequency)
                || applied_ack_delay_ms != Some(snapshot.ack_delay_ms)
                || applied_tx_burst_packets != Some(snapshot.tx_burst_packets))
        {
            // Connection policy is applied at association creation. Replace
            // only the bounded QUIC service so the next OPEN gets one
            // coherent ACK/burst profile; do not reconfigure the radio.
            unsafe {
                RAW_ASSOCIATION = raw_association(&snapshot);
                if let Some(service) = raw_service_if_ready() {
                    service.replace_association(RAW_ASSOCIATION);
                }
                crate::wifi_raw_udp6_esp::set_tx_burst_packets(RAW_ASSOCIATION.tx_burst_packets);
            }
            applied_ack_frequency = Some(snapshot.ack_frequency);
            applied_ack_delay_ms = Some(snapshot.ack_delay_ms);
            applied_tx_burst_packets = Some(snapshot.tx_burst_packets);
            crate::commands::send_response(b"connection association defaults updated");
        }
        if wifi_started && wants_sta_extensions(&snapshot) != sta_extensions_enabled {
            if wants_sta_extensions(&snapshot) {
                let enabled =
                    crate::wifi_esp::start_sta_extensions(receive_espnow, snapshot.nan_dw_interval);
                if enabled {
                    crate::wifi_espnow_esp::set_poll_handler(Some(poll_espnow));
                }
                sta_extensions_enabled = enabled;
                applied_nan_dw_interval = enabled.then_some(snapshot.nan_dw_interval);
                crate::commands::send_response(if enabled {
                    b"wifi NAN/NOW coexistence enabled"
                } else {
                    b"wifi NAN/NOW coexistence failed"
                });
            } else {
                crate::wifi_esp::stop_sta_extensions();
                sta_extensions_enabled = false;
                applied_nan_dw_interval = None;
                crate::commands::send_response(b"wifi STA/NAN/NOW DW capture disabled");
            }
        }
        if sta_extensions_enabled && applied_nan_dw_interval != Some(snapshot.nan_dw_interval) {
            if crate::wifi_esp::set_nan_dw_interval(snapshot.nan_dw_interval) {
                applied_nan_dw_interval = Some(snapshot.nan_dw_interval);
                crate::commands::send_response(b"wifi STA/NAN/NOW DW interval updated");
            } else {
                crate::commands::send_response(b"wifi STA/NAN/NOW DW interval rejected");
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
    let payload = dmesh_server::direct_iperf::boot_identity_payload(role, partition);
    let _ = crate::commands::send_record(&payload);
}

/// Publish the same boot records over NOW after the default unassociated
/// radio is live. UART remains the bootstrap/debug path, but a host should be
/// able to discover a freshly booted device without first changing its mode.
fn send_boot_records_on_now(boot_message: &[u8], role: u8, partition: u8) {
    if let Some(record) = dmesh_server::services::encode_status_text(boot_message) {
        let _ = crate::wifi_espnow_esp::broadcast_record(&record);
    }
    let identity = dmesh_server::direct_iperf::boot_identity_payload(role, partition);
    let _ = crate::wifi_espnow_esp::broadcast_record(&identity);
    send_announce_on_now(dmesh_server::announce::ANNOUNCE_BOOT, 0, role, partition);
}

/// Presence announcements use the same tagged-CBOR bytes on every direct
/// bearer. UART is available before any association; NOW joins once the boot
/// NAN+NOW radio is live. The raw UDP6 adapter will add its own multicast
/// egress once an associated peer/address exists.
fn send_boot_announce_uart(role: u8, partition: u8) {
    if let Some((record, used)) =
        announce_record(dmesh_server::announce::ANNOUNCE_BOOT, 0, role, partition)
    {
        let _ = crate::commands::send_record(&record[..used]);
        // NAN SD carries these exact tagged-CBOR presence bytes once a DW is
        // available; it is not a second firmware-only discovery protocol.
        let _ = crate::wifi_nan_dw_capture_esp::configure_active_publish(true, &record[..used]);
    }
}

fn send_discovery_announce(uptime_secs: u64, now_active: bool, sta_active: bool) {
    if let Some((record, used)) = announce_record(
        dmesh_server::announce::ANNOUNCE_DISCOVERY,
        uptime_secs,
        0,
        0,
    ) {
        let _ = crate::commands::send_record(&record[..used]);
        let _ = crate::wifi_nan_dw_capture_esp::configure_active_publish(true, &record[..used]);
        if now_active {
            let _ = crate::wifi_espnow_esp::broadcast_record(&record[..used]);
        }
        if sta_active {
            let _ = crate::wifi_raw_udp6_esp::broadcast_announce(&record[..used]);
        }
    }
}

fn send_sta_boot_announce() {
    if let Some((record, used)) = announce_record(dmesh_server::announce::ANNOUNCE_BOOT, 0, 0, 0) {
        let _ = crate::wifi_raw_udp6_esp::broadcast_announce(&record[..used]);
    }
}

fn send_announce_on_now(kind: u64, uptime_secs: u64, role: u8, partition: u8) {
    if let Some((record, used)) = announce_record(kind, uptime_secs, role, partition) {
        let _ = crate::wifi_espnow_esp::broadcast_record(&record[..used]);
    }
}

fn announce_record(
    kind: u64,
    uptime_secs: u64,
    role: u8,
    partition: u8,
) -> Option<([u8; 96], usize)> {
    let mac = crate::wifi_esp::interface_mac(crate::wifi_esp::RadioInterface::Sta)
        .or_else(|| crate::wifi_esp::interface_mac(crate::wifi_esp::RadioInterface::Ap))?;
    let mut id = [0; 16];
    id[..6].copy_from_slice(&mac);
    let transport_mode = if crate::wifi_esp::sta_associated() { 1 } else { 0 };
    let uptime_secs = u32::try_from(uptime_secs).unwrap_or(u32::MAX);
    let counters = (u32::from(role) << 8) | u32::from(partition);
    let announce = if kind == dmesh_server::announce::ANNOUNCE_BOOT {
        let mut boot = dmesh_server::announce::Announce::boot(id, 6, transport_mode);
        boot.uptime_secs = uptime_secs;
        boot.counters = counters;
        boot
    } else {
        dmesh_server::announce::Announce::discovery(id, 6, uptime_secs, transport_mode, counters)
    };
    let mut record = [0; 96];
    let used = dmesh_server::announce::encode(announce, &mut record)?;
    Some((record, used))
}
