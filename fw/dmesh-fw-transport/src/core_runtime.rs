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
static mut RAW_ASSOCIATION: quic_lite::AssociationProfile =
    quic_lite::AssociationProfile::c6_default();

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

fn raw_association(profile: &crate::TransportProfile) -> quic_lite::AssociationProfile {
    let window = crate::CONNECTION_HISTORY_CAPACITY;
    let tx_burst_packets = if profile.tx_burst_packets == 0 {
        window
    } else {
        usize::from(profile.tx_burst_packets)
    };
    quic_lite::AssociationProfile {
        history_packets: window,
        // Raw Ethernet ingress has one bounded shared packet queue. Return
        // QUIC-lite credit for every datagram rather than allow a persisted
        // generic association setting to hold a first eight-packet flight
        // behind a delayed ACK. This is the same C6 raw-bearer policy as
        // NOW, not STA-specific transfer behavior.
        ack_frequency: 1,
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
    .clamp::<{ crate::CONNECTION_HISTORY_CAPACITY }>()
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
    let mut association = quic_lite::AssociationProfile::c6_default();
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
// Bounded bring-up evidence for the shared delayed-ACK/PTO owner.  This is
// intentionally not a transport counter or retry policy: QUIC-lite retains
// both.  It distinguishes a missing Main deadline wake from a timer turn that
// had no packet ready while validating raw UDP6 on hardware.
static CONNECTION_TIMER_UDP6_REPORTS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Read the bounded connection error diagnostic for the radio snapshot.
pub(crate) fn connection_last_error() -> u32 {
    CONNECTION_LAST_ERROR.load(core::sync::atomic::Ordering::Acquire)
}

unsafe fn connection_dispatcher_mut() -> &'static mut ConnectionDispatcher {
    if !CONNECTION_DISPATCHER_READY.load(core::sync::atomic::Ordering::Acquire) {
        let mut dispatcher = ConnectionDispatcher::new(
            // An empty Initial DCID means this is a new association. The
            // shared dispatcher allocates a local, nonzero server CID instead
            // of deriving QUIC state from a radio MAC.
            quic_lite::ConnectionId::new(1).expect("one is a valid CID"),
            quic_lite::ConnectionLimits::default(),
            *core::ptr::addr_of!(RAW_ASSOCIATION),
        );
        // The dispatcher owns CID/restart behavior for UART, NOW, and UDP6.
        // Bearer adapters never see the NVS-derived branch or reset framing.
        dispatcher.set_stateless_reset_key(crate::main_runtime::stateless_reset_key());
        // Firmware keeps idle associations so later streams can reuse their
        // handshake and validated paths. QUIC-lite still reclaims the oldest
        // zero-active-stream association whenever this bounded table fills.
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
/// callback can construct a dispatcher.  Returning the burst limit keeps the
/// radio adapter independent of this private static state.
pub(crate) fn prepare_raw_association(profile: &crate::TransportProfile) -> usize {
    unsafe {
        RAW_ASSOCIATION = raw_association(profile);
        RAW_ASSOCIATION.tx_burst_packets
    }
}

/// Install the action-bearer association at an explicit NAN/NOW epoch
/// boundary. A previous connection may have been reached over UART or
/// UDP6, so replace it rather than letting an old eight-packet association
/// survive into the packet-at-a-time action path. The physical bearer is not
/// touched here; callers have already serialized the radio transition.
pub(crate) fn prepare_espnow_association(profile: &crate::TransportProfile) -> usize {
    unsafe {
        RAW_ASSOCIATION = espnow_association(profile);
        let association = RAW_ASSOCIATION;
        // The connection dispatcher controls QUIC admission, whereas the
        // action adapter controls how many already-admitted datagrams one
        // callback turn submits. Keep the two values synchronized here at
        // the epoch boundary; otherwise a stale adapter default can create a
        // radio burst that contradicts the selected association profile.
        crate::wifi_espnow_esp::set_tx_burst_packets(association.tx_burst_packets);
        if let Some(service) = connection_dispatcher_if_ready() {
            service.set_association_defaults(association);
        }
        association.tx_burst_packets
    }
}

/// Replace the live connection's association defaults without changing radio
/// state.  Main calls this only for an explicit ACK/burst profile transition;
/// the raw callback never invokes it.  A not-yet-created dispatcher simply
/// picks up the prepared defaults on its first valid OPEN.
pub(crate) fn replace_raw_association(profile: &crate::TransportProfile) -> usize {
    unsafe {
        RAW_ASSOCIATION = raw_association(profile);
        let association = RAW_ASSOCIATION;
        if let Some(service) = connection_dispatcher_if_ready() {
            service.set_association_defaults(association);
        }
        association.tx_burst_packets
    }
}
// Exactly one device-initiated object transfer may be active for the current
// one-association connection. The state is allocated only after a validated
// `flash` request; it is not a bearer queue and owns no copy of object data.
/// The only ESP flash handler state: an ordered signed-object receiver.  The
/// active connection's QUIC-lite mux owns all packet and stream mechanics.
struct FlashDownload {
    receiver: alloc::boxed::Box<crate::flash::SignedObjectFlashReceiver>,
    expires_at_us: u64,
}

impl FlashDownload {
    unsafe fn new_boxed(
        request: dmesh_server::protocol::FlashRequest<'_>,
        now_us: u64,
    ) -> Result<alloc::boxed::Box<Self>, crate::flash::FlashSinkError> {
        let receiver = crate::flash::new_boxed_receiver(request)?;
        let raw = alloc::alloc::alloc_zeroed(alloc::alloc::Layout::new::<Self>()) as *mut Self;
        if raw.is_null() {
            return Err(crate::flash::FlashSinkError::AllocationFailed);
        }
        core::ptr::addr_of_mut!((*raw).receiver).write(receiver);
        // A sender must keep advancing its ordered object stream.  Bound the
        // receiver lifetime after a lost CLI or bearer without creating a
        // UART/UDP/NOW-private timeout.
        core::ptr::addr_of_mut!((*raw).expires_at_us).write(now_us.saturating_add(30_000_000));
        Ok(alloc::boxed::Box::from_raw(raw))
    }

    fn receive_chunks(
        &mut self,
        chunks: alloc::vec::Vec<(alloc::vec::Vec<u8>, bool)>,
        now_us: u64,
    ) -> Result<(), ()> {
        let mut admitted = false;
        for (fragment, _) in chunks {
            self.receiver
                .push_ordered(&fragment)
                .map_err(|_| ())?;
            admitted = true;
        }
        // This is an idle deadline, not an overall-transfer deadline.  The
        // shared QUIC-lite endpoint can deliberately pace a large image for
        // longer than thirty seconds; each already-admitted ordered fragment
        // proves that its single association remains live.  A stalled client
        // still expires after the same bounded interval, while CLOSE clears
        // the receiver immediately.
        if admitted {
            self.expires_at_us = now_us.saturating_add(30_000_000);
        }
        self.receiver
            .sink_mut()
            .poll_completed()
            .map(|_| ())
            .map_err(|_| ())
    }

    fn is_complete_and_durable(&mut self) -> bool {
        self.receiver.is_complete() && self.receiver.sink_mut().is_durable()
    }

    fn is_expired(&self, now_us: u64) -> bool {
        now_us >= self.expires_at_us
    }
}

static mut FLASH_DOWNLOAD: Option<(quic_lite::PathId, alloc::boxed::Box<FlashDownload>)> = None;
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
        let now_us = esp_idf_sys::esp_timer_get_time().max(0) as u64;
        service.set_time(now_us);
        expire_flash_download(service, now_us);
        // Component handlers execute synchronously inside `receive`. Give
        // them a pre-dispatch association snapshot rather than allowing a
        // diagnostic handler to re-enter this mutable shared owner.
        let connection_status = service.active_connection_status();
        let last_close_at = service.last_close_at();
        let close_before = service.last_close_at();
        let receive =
            crate::relay_main::with_connection_status(connection_status, last_close_at, || {
                service.receive(path, packet, response)
            });
        let (accepted, mut result) = match receive {
            Ok(value) => match service.take_flash_request() {
                Some(request) => (
                    true,
                    begin_flash_download(service, path, request, response, value),
                ),
                None => (true, value),
            },
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
        if service.last_close_at() != close_before {
            // The QUIC association was retired, so neither its platform sink
            // nor its correlated request ID may poison the next attempt.
            abandon_flash_download(service, b"flash receiver closed");
        }
        let mut flash_completed = false;
        if accepted {
            if let Some((download_path, download)) =
                (*core::ptr::addr_of_mut!(FLASH_DOWNLOAD)).as_mut()
            {
                if *download_path == path {
                    let chunks = service.take_flash_object_chunks();
                    if !chunks.is_empty()
                        && download
                            .receive_chunks(
                                chunks,
                                esp_idf_sys::esp_timer_get_time().max(0) as u64,
                            )
                            .is_err()
                    {
                        // The ordered-stream callback has already performed
                        // QUIC framing/reassembly. This is therefore an
                        // object-record or sink admission failure, not a
                        // bearer retry condition.
                        crate::commands::send_response(b"flash object receiver rejected");
                    }
                    flash_completed = finish_flash_download();
                }
            }
        }
        // A handler may accept a request without an immediate application
        // response (notably object.flash while its durable sink is active).
        // QUIC-lite has still queued an ACK/MAX_DATA packet. Poll it on this
        // same bearer turn so raw UDP6/UART/NOW do not require an unrelated
        // later ingress packet merely to release client flow control.
        if accepted && result.is_none() {
            result = service.poll_for(path, response).ok().flatten();
        }
        // The final object fragment may have produced an ACK as the immediate
        // response.  Prefer the now-ready terminal stream response in this
        // same bearer turn so a one-packet egress budget cannot strand a
        // durable flash completion behind an idle poll timer.
        if flash_completed {
            result = service.poll_for(path, response).ok().flatten().or(result);
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
        // The packet worker may just have created or advanced a NOW server
        // association. Main could otherwise still be blocked with the old
        // (or no) deadline and miss the connection-owned PTO until an
        // unrelated NAN event occurs. This marker only wakes Main to
        // recompute its one-shot timer; it neither polls nor sends here.
        if matches!(
            connection_path_transport(path),
            transport if transport == dmesh_server::transport_path::TransportId::NOW.0
                || transport == dmesh_server::transport_path::TransportId::UDP6.0
        ) {
            crate::main_runtime::request_connection_deadline_recheck();
        }
        ConnectionFrameIngress {
            accepted,
            response: result,
        }
    }
}

/// Flash setup is cold and may construct a large receiver. Keep it out of the
/// raw packet service frame so a normal UDP/NOW/UART PROBE packet does not
/// reserve the flash constructor's stack footprint.
#[inline(never)]
unsafe fn begin_flash_download(
    service: &mut ConnectionDispatcher,
    path: quic_lite::PathId,
    request: alloc::vec::Vec<u8>,
    _response: &mut [u8; crate::TRANSPORT_MTU],
    fallback: Option<usize>,
) -> Option<usize> {
    let download_slot = core::ptr::addr_of_mut!(FLASH_DOWNLOAD);
    let Some(request) = dmesh_server::protocol::decode_flash_request(&request) else {
        let _ = service.complete_flash(alloc::vec::Vec::from(&b"flash invalid"[..]));
        return fallback;
    };
    // An incomplete receiver can survive only when its prior peer vanished
    // without CLOSE. This newly admitted request already owns the current
    // dispatcher's flash ID, so replace the orphaned sink instead of making
    // every later attempt require a board reset.
    if (*download_slot).take().is_some() {
        crate::commands::send_response(b"flash receiver replaced");
    }
    crate::commands::send_response(b"flash receiver allocating");
    let now_us = esp_idf_sys::esp_timer_get_time().max(0) as u64;
    match FlashDownload::new_boxed(request, now_us) {
        Ok(download) => {
            crate::commands::send_response(b"flash object stream armed");
            *download_slot = Some((path, download));
            fallback
        }
        Err(_) => {
            let _ = service.complete_flash(alloc::vec::Vec::from(&b"flash rejected"[..]));
            fallback
        }
    }
}

/// Complete the original `flash` request only after the sink has committed
/// all accepted blocks. The next normal connection poll emits this response.
unsafe fn finish_flash_download() -> bool {
    let download_slot = core::ptr::addr_of_mut!(FLASH_DOWNLOAD);
    let complete = (*download_slot)
        .as_mut()
        .is_some_and(|(_, download)| download.is_complete_and_durable());
    if !complete {
        return false;
    }
    *download_slot = None;
    if let Some(service) = connection_dispatcher_if_ready() {
        crate::commands::send_response(b"flash object durable");
        let _ = service.complete_flash(alloc::vec::Vec::from(&b"flash complete"[..]));
    }
    true
}

/// Resolve a lost/incomplete upload without relying on a particular bearer.
/// If the association is still live its original request receives the terminal
/// timeout response; QUIC-lite owns delivery/retransmission of that response.
unsafe fn expire_flash_download(service: &mut ConnectionDispatcher, now_us: u64) {
    let download_slot = core::ptr::addr_of_mut!(FLASH_DOWNLOAD);
    if !(*download_slot)
        .as_ref()
        .is_some_and(|(_, download)| download.is_expired(now_us))
    {
        return;
    }
    *download_slot = None;
    crate::commands::send_response(b"flash receiver timeout");
    let _ = service.complete_flash(alloc::vec::Vec::from(&b"flash timeout"[..]));
}

/// Release platform and dispatcher flash state after the peer's explicit
/// CLOSE. No reply is generated because that QUIC association is retired.
unsafe fn abandon_flash_download(service: &mut ConnectionDispatcher, reason: &[u8]) {
    if (*core::ptr::addr_of_mut!(FLASH_DOWNLOAD)).take().is_some() {
        crate::commands::send_response(reason);
    }
    service.abandon_flash();
}

pub fn poll_connection(
    path: quic_lite::PathId,
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    unsafe {
        let download_slot = core::ptr::addr_of_mut!(FLASH_DOWNLOAD);
        if (*download_slot).as_ref().is_some_and(|(download_path, _)| *download_path == path) {
            let _ = finish_flash_download();
        }
        let service = connection_dispatcher_if_ready()?;
        let now_us = esp_idf_sys::esp_timer_get_time().max(0) as u64;
        service.set_time(now_us);
        expire_flash_download(service, now_us);
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
pub(crate) fn connection_delay_ms() -> Option<u32> {
    unsafe {
        let service = connection_dispatcher_if_ready()?;
        let path = service.reply_path()?;
        if !matches!(
            connection_path_transport(path),
            transport if transport == dmesh_server::transport_path::TransportId::NOW.0
                || transport == dmesh_server::transport_path::TransportId::UDP6.0
        ) {
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
pub(crate) fn schedule_connection_timer() {
    let _ = crate::shared_ingress_esp::schedule_connection_timer(service_connection_timer);
}

/// Perform one server-side NOW PTO turn on the packet worker. The reply path
/// comes from the accepted connection packet, not from an adapter-private
/// queue, so future multipath policy can replace this final transport match.
fn service_connection_timer() {
    unsafe {
        let Some(service) = connection_dispatcher_if_ready() else {
            return;
        };
        let Some(path) = service.reply_path() else {
            return;
        };
        match connection_path_transport(path) {
            transport if transport == dmesh_server::transport_path::TransportId::NOW.0 => {
                let response = &mut *core::ptr::addr_of_mut!(CONNECTION_TIMER_RESPONSE);
                let Some(used) = poll_connection(path, response) else {
                    return;
                };
                if used <= response.len() {
                    let _ = crate::wifi_espnow_esp::transmit_from_worker(
                        crate::wifi_espnow_esp::EspNowPeer {
                            mac: connection_path_peer(path),
                        },
                        &response[..used],
                    );
                }
            }
            transport if transport == dmesh_server::transport_path::TransportId::UDP6.0 => {
                if CONNECTION_TIMER_UDP6_REPORTS.fetch_add(1, core::sync::atomic::Ordering::Relaxed) < 2 {
                    crate::commands::send_response(b"connection timer UDP6");
                }
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
    peer: crate::wifi_raw_udp6_esp::RawUdp6Peer,
    packet: &[u8],
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    receive_connection_frame(
        connection_path_id(dmesh_server::transport_path::TransportId::UDP6.0, peer.mac),
        packet,
        response,
    )
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
        || receive_raw_udp6(peer, packet, response),
    )
}

pub(crate) fn poll_raw_udp6(
    peer: crate::wifi_raw_udp6_esp::RawUdp6Peer,
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    poll_connection(
        connection_path_id(dmesh_server::transport_path::TransportId::UDP6.0, peer.mac),
        response,
    )
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

/// Pump only as many UART packets as the physical writer can accept now.
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
    let credit = capacity.saturating_sub(queued);
    if credit == 0 {
        return;
    }
    let _ = dmesh_server::transport::pump_egress(
        response,
        credit,
        immediate,
        |response| poll_connection(path, response),
        crate::uart_esp::send_transport_packet,
    );
}
