//! ESP partition sink for the bearer-neutral signed-object client.
//!
//! Record framing, manifest verification, stream ordering, and flow control
//! belong in `dmesh-server` and the selected transport. This module owns only
//! durable ESP erase/write operations.

use alloc::{boxed::Box, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use dmesh_server::verified_object::{ImageSink, BLOCK_SIZE};

/// No application bytes have arrived for this bounded period. This is a
/// receiver liveness guard, not a transport deadline: QUIC-lite continues to
/// own packet delivery and recovery below the flash sink.
// A disconnected flash client must not monopolize the sole receiver for
// minutes.  Continuous verified-object progress refreshes this guard, so it
// is not a throughput limit or a QUIC loss/PTO setting.
const FLASH_STREAM_IDLE_TIMEOUT_MS: u64 = 15_000;
const FLASH_ABORT_CLOSE_CODE: u64 = 0x10;
/// Stage2 occupies the boot region below the partition table.  A signed
/// object may select a narrower address within this region, never raw flash
/// beyond it.
const STAGE2_REGION_BYTES: usize = 0x7000;
/// Firmware bounds for the shared incremental signed-object receiver.
// A 4 MiB image has at most 1,024 4 KiB blocks. Its signed flat proof table
// is 8 KiB (plus the small CBOR envelope), so 10 KiB covers the complete
// addressable-image format with headroom. The receiver is allocated only
// while an update stream is active; it is application memory, never QUIC
// receive credit, and is not reserved by the ordinary Main/Recovery runtime.
pub const MAX_MANIFEST_BYTES: usize = 10 * 1024;
pub const MAX_BLOB_RECORD_BYTES: usize = 12 + BLOCK_SIZE;
pub type SignedObjectFlashReceiver = dmesh_server::verified_object::SignedObjectReceiver<
    EspPartitionSink,
    dmesh_server::verified_object::NoSignatureVerifier,
    MAX_MANIFEST_BYTES,
    MAX_BLOB_RECORD_BYTES,
>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlashSinkError {
    UnsupportedTarget,
    AddressOverrideUnsupported,
    MissingModuleName,
    PartitionUnavailable,
    AllocationFailed,
}

/// Numeric CPU selectors are the same catalog values used by `ObjectServer`.
/// The manifest binds this value; this target-local comparison is the final
/// guard before an app partition is erased.
const fn local_image_cpu() -> u8 {
    #[cfg(target_arch = "riscv32")]
    {
        13 // ESP32-C6
    }
    #[cfg(all(not(target_arch = "riscv32"), target_feature = "esp32s3ops"))]
    {
        9 // ESP32-S3
    }
    #[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
    {
        0 // classic ESP32
    }
}

impl FlashSinkError {
    /// A stable, non-sensitive reason for the application-level flash result.
    /// This is not a transport error: QUIC-lite has already admitted the
    /// command stream by the time a platform sink is selected.
    const fn response(self) -> &'static [u8] {
        match self {
            Self::UnsupportedTarget => b"flash rejected: unsupported target",
            Self::AddressOverrideUnsupported => b"flash rejected: address override",
            Self::MissingModuleName => b"flash rejected: module name",
            Self::PartitionUnavailable => b"flash rejected: partition unavailable",
            Self::AllocationFailed => b"flash rejected: allocation",
        }
    }
}

type ConnectionService = dmesh_server::transport::ConnectionDispatcher<
    { crate::CONNECTION_HISTORY_CAPACITY },
    { crate::TRANSPORT_MTU },
    { crate::MAX_QUIC_ASSOCIATIONS },
>;

/// One application stream receiver. QUIC-lite owns associations, packet
/// numbers, ACKs, retransmission, ordering, FIN, and flow control; this state
/// only consumes ordered bytes and reports durable storage capacity.
struct FlashStream {
    receiver: Box<SignedObjectFlashReceiver>,
    dry_run: bool,
    received_stream_bytes: usize,
    /// Application bytes that have already refreshed the exclusive-operation
    /// idle guard.  Packet receipt, ACKs, and QUIC retransmissions never
    /// update this marker.
    timeout_progress_bytes: usize,
    receiver_complete_reported: bool,
}

impl FlashStream {
    fn new(
        request: dmesh_server::verified_object::FlashRequest<'_>,
    ) -> Result<Self, FlashSinkError> {
        let dry_run = request.dry_run;
        let receiver = new_boxed_receiver(request)?;
        Ok(Self {
            receiver,
            dry_run,
            received_stream_bytes: 0,
            timeout_progress_bytes: 0,
            receiver_complete_reported: false,
        })
    }

    fn receive<R: dmesh_server::verified_object::OrderedStreamRead>(
        &mut self,
        reader: &mut R,
    ) -> Result<
        dmesh_server::verified_object::ObjectStreamRead,
        dmesh_server::verified_object::ImageError,
    > {
        let read = self.receiver.consume_stream_body(reader)?;
        self.received_stream_bytes = self
            .received_stream_bytes
            .saturating_add(read.consumed_bytes);
        Ok(read)
    }

    fn is_pristine(&self) -> bool {
        self.received_stream_bytes == 0
    }

    fn complete_and_durable(&mut self) -> bool {
        self.receiver.is_complete() && self.receiver.sink_mut().is_durable()
    }
}

/// Handler-neutral immediate-consumer entry point for the generic transport
/// stream API.  It avoids allocating a dispatcher-owned 1 KiB `Vec` just to
/// copy a packet that the signed-object receiver can consume synchronously.
/// QUIC-lite retains only an unread suffix and owns every transport action.
fn consume_active_flash_stream(bytes: &[u8], fin: bool) -> Result<usize, ()> {
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(ACTIVE_STREAM);
        let Some(owner) = slot.owner() else {
            return Ok(0);
        };
        let Some(stream) = slot.get_mut_for(owner) else {
            return Ok(0);
        };
        let mut reader = dmesh_server::verified_object::BorrowedOrderedRead::new(bytes, fin);
        match stream.receive(&mut reader) {
            Ok(_) => Ok(reader.consumed()),
            Err(error) => {
                log_receiver_error(error);
                Err(())
            }
        }
    }
}

fn refresh_idle_timeout_after_consumption(
    slot: &mut dmesh_server::verified_object::ExclusiveTransfer<FlashStream>,
    now_ms: u64,
) {
    let Some(owner) = slot.owner() else { return };
    let progressed = slot.get_mut_for(owner).is_some_and(|stream| {
        if stream.received_stream_bytes == stream.timeout_progress_bytes {
            false
        } else {
            stream.timeout_progress_bytes = stream.received_stream_bytes;
            true
        }
    });
    if progressed {
        slot.touch(owner, now_ms, FLASH_STREAM_IDLE_TIMEOUT_MS);
    }
}

// Exactly one object.flash operation may own the firmware update stream. It
// is keyed by QUIC-lite's receive CID, never by a UART, UDP, or radio path.
static mut ACTIVE_STREAM: dmesh_server::verified_object::ExclusiveTransfer<FlashStream> =
    dmesh_server::verified_object::ExclusiveTransfer::new();

/// Consume ordered bytes through the common deferred-reader boundary.
///
/// The host verified-object tests and firmware now follow this exact route:
/// QUIC-lite retains its own bounded receive state; the handler copies only
/// what its sink can accept; and the shared transport helper publishes credit
/// for that copied prefix.  In particular, an ESP flash completion never
/// resumes a special direct callback over a different ordered-byte contract.
unsafe fn consume_pending_stream(service: &mut ConnectionService, now_ms: u64) -> Result<(), ()> {
    let slot = &mut *core::ptr::addr_of_mut!(ACTIVE_STREAM);
    let Some(owner) = slot.owner() else {
        return Ok(());
    };
    if service.expected_receive_cid() != Some(owner) {
        return Ok(());
    }
    // Invoke the reader even when no byte is queued. A storage-ready edge can
    // complete the final asynchronous write after the handler already
    // consumed the stream FIN; `consume_stream_body` observes that state with
    // an empty reader and the generic transport helper publishes no credit.
    match dmesh_server::transport::consume_exclusive_inbound_stream(
        service,
        slot,
        owner,
        now_ms,
        FLASH_STREAM_IDLE_TIMEOUT_MS,
        |stream, reader| {
            let read = stream.receive(reader)?;
            Ok::<_, dmesh_server::verified_object::ImageError>(read.application_progress)
        },
    ) {
        Ok(_) => Ok(()),
        Err(dmesh_server::transport::ExclusiveInboundStreamTurnError::Consumer {
            request_id,
            error,
            ..
        }) => {
            log_receiver_error(error);
            // The console keeps the fuller diagnostic, but the authenticated
            // stream response must also distinguish an ordinary local
            // allocation failure from malformed or unauthenticated input.
            // These fixed strings are intentionally bounded and contain no
            // object identity, partition, or heap-address information.
            let _ = complete_error(service, request_id, receiver_error_response(error));
            let _ = slot.take_for(owner);
            set_transfer_active(false);
            Err(())
        }
        Err(dmesh_server::transport::ExclusiveInboundStreamTurnError::Transport(_)) => {
            crate::recovery_runtime::log(b"DMESH recovery: flash stream transport rejected\n\0");
            Err(())
        }
    }
}

fn receiver_error_response(error: dmesh_server::verified_object::ImageError) -> &'static [u8] {
    match error {
        dmesh_server::verified_object::ImageError::Truncated => b"flash object rejected: truncated",
        dmesh_server::verified_object::ImageError::Allocation => {
            b"flash object rejected: allocation"
        }
        dmesh_server::verified_object::ImageError::InvalidManifest => {
            b"flash object rejected: invalid manifest"
        }
        dmesh_server::verified_object::ImageError::InvalidBlock => {
            b"flash object rejected: invalid block"
        }
        dmesh_server::verified_object::ImageError::InvalidSignature => {
            b"flash object rejected: invalid signature"
        }
        dmesh_server::verified_object::ImageError::Sink => b"flash object rejected: sink",
    }
}

fn log_receiver_error(error: dmesh_server::verified_object::ImageError) {
    let message = match error {
        dmesh_server::verified_object::ImageError::Truncated => {
            b"DMESH flash: receiver error truncated\n\0".as_slice()
        }
        dmesh_server::verified_object::ImageError::Allocation => {
            b"DMESH flash: receiver error allocation\n\0".as_slice()
        }
        dmesh_server::verified_object::ImageError::InvalidManifest => {
            b"DMESH flash: receiver error invalid manifest\n\0".as_slice()
        }
        dmesh_server::verified_object::ImageError::InvalidBlock => {
            b"DMESH flash: receiver error invalid block\n\0".as_slice()
        }
        dmesh_server::verified_object::ImageError::InvalidSignature => {
            b"DMESH flash: receiver error invalid signature\n\0".as_slice()
        }
        dmesh_server::verified_object::ImageError::Sink => {
            b"DMESH flash: receiver error sink\n\0".as_slice()
        }
    };
    crate::recovery_runtime::log(message);
}

// The stream handler owns durable completion.  A reduced Recovery runtime may
// consume this edge to hand Stage2 back to Main; it is deliberately neither a
// bearer signal nor an extra flash protocol message.
static DURABLE_FLASH_COMPLETED: AtomicBool = AtomicBool::new(false);

// The stream handler publishes only its exclusive-operation lifetime. Main's
// radio owner may defer optional sidecar work, but this module never selects a
// bearer or calls a Wi-Fi driver API.
static FLASH_TRANSFER_ACTIVE: AtomicBool = AtomicBool::new(false);

fn set_transfer_active(active: bool) {
    if FLASH_TRANSFER_ACTIVE.swap(active, Ordering::AcqRel) != active {
        // This is a policy signal, not a bearer replacement: raw UDP6 stays
        // registered.  The Main radio owner stops optional NAN management
        // capture and public-action transmission immediately, because both
        // share scarce callback/driver resources with the initial object
        // flight.  Normal NAN/NOW scheduling resumes when the operation ends.
        crate::wifi_nan_dw_capture_esp::set_nan_action_tx_suppressed(active);
        crate::wifi_nan_dw_capture_esp::set_nan_capture_suspended(active);
        crate::main_runtime::request_deadline_recheck();
    }
}

pub(crate) fn transfer_active() -> bool {
    FLASH_TRANSFER_ACTIVE.load(Ordering::Acquire)
}

pub(crate) fn take_durable_flash_completion() -> bool {
    DURABLE_FLASH_COMPLETED.swap(false, Ordering::AcqRel)
}

unsafe fn begin(service: &mut ConnectionService, request: Vec<u8>, now_ms: u64) {
    let Some((request_id, request)) =
        dmesh_server::verified_object::decode_flash_handler_request(&request)
    else {
        return;
    };
    let Some(owner) = service.expected_receive_cid() else {
        let _ = complete_error(service, request_id, b"flash association unavailable");
        return;
    };
    let slot = &mut *core::ptr::addr_of_mut!(ACTIVE_STREAM);
    // Flash is rare, while Main's NAN management capture is optional. Quiesce
    // that sidecar *before* allocating the bounded receiver: on classic ESP32
    // its driver buffers can fragment the internal heap below one receiver
    // block even though aggregate free memory is sufficient. This is neither
    // a transport setting nor a flash protocol transition; it only brackets
    // the application operation that owns the allocation. If construction is
    // rejected, restore normal radio work immediately.
    let transfer_was_active = transfer_active();
    if !transfer_was_active {
        set_transfer_active(true);
    }
    match slot.try_start_or_replace_if(
        owner,
        request_id,
        now_ms,
        FLASH_STREAM_IDLE_TIMEOUT_MS,
        FlashStream::is_pristine,
        || {
            crate::commands::send_response(b"flash receiver allocating");
            FlashStream::new(request)
        },
    ) {
        Ok(()) => {
            crate::commands::send_response(b"flash object stream armed");
        }
        Err(dmesh_server::verified_object::ExclusiveTransferStartError::Start(error)) => {
            if !transfer_was_active {
                set_transfer_active(false);
            }
            let _ = complete_response(service, request_id, error.response());
        }
        Err(dmesh_server::verified_object::ExclusiveTransferStartError::Busy) => {
            // The multicast announce is discovery, not an invitation for every
            // observer to replace the current writer. Completion, association
            // close, and the bounded idle timeout are the only owners allowed
            // to release this operation.
            // A busy operation already owns the radio quiesce edge; do not
            // resume it on behalf of a rejected contender.
            let _ = complete_error(
                service,
                request_id,
                dmesh_server::verified_object::FLASH_BUSY_ERROR,
            );
            crate::commands::send_response(b"flash request rejected busy");
        }
    }
}

fn complete_error(
    service: &mut ConnectionService,
    request_id: u64,
    error: &[u8],
) -> Result<(), quic_lite::Error> {
    let mut tagged = alloc::vec![0; error.len().saturating_add(64)];
    let used = dmesh_server::tagged::encode_numeric_error(
        dmesh_server::verified_object::OBJECT_COMPONENT,
        dmesh_server::verified_object::OBJECT_FLASH_METHOD,
        request_id,
        error,
        &mut tagged,
    )
    .ok_or(quic_lite::Error::Invalid)?;
    tagged.truncate(used);
    service.complete_stream_command(tagged)
}

fn complete_response(
    service: &mut ConnectionService,
    request_id: u64,
    response: &[u8],
) -> Result<(), quic_lite::Error> {
    let mut tagged = alloc::vec![0; response.len().saturating_add(64)];
    let used = dmesh_server::tagged::encode_numeric_data_response(
        dmesh_server::verified_object::OBJECT_COMPONENT,
        dmesh_server::verified_object::OBJECT_FLASH_METHOD,
        request_id,
        response,
        core::str::from_utf8(response).is_ok(),
        &mut tagged,
    )
    .ok_or(quic_lite::Error::Invalid)?;
    tagged.truncate(used);
    service.complete_stream_command(tagged)
}

fn finish(
    service: &mut ConnectionService,
    slot: &mut dmesh_server::verified_object::ExclusiveTransfer<FlashStream>,
) -> bool {
    let Some(owner) = slot.owner() else {
        return false;
    };
    if !slot
        .get_mut_for(owner)
        .is_some_and(FlashStream::complete_and_durable)
    {
        return false;
    }
    let dry_run = slot
        .get_mut_for(owner)
        .map(|stream| stream.dry_run)
        .expect("durable stream checked above");
    let request_id = slot
        .request_id_for(owner)
        .expect("durable stream has a request id");
    if service.select_receive_cid(owner).is_none() {
        return false;
    }
    let _ = slot.take_for(owner);
    set_transfer_active(false);
    crate::commands::send_response(b"flash object durable");
    crate::recovery_runtime::log(b"DMESH recovery: flash object durable\n\0");
    if complete_response(service, request_id, b"flash complete").is_err() {
        crate::recovery_runtime::log(b"DMESH recovery: flash response rejected\n\0");
    } else {
        crate::recovery_runtime::log(b"DMESH recovery: flash response prepared\n\0");
    }
    // A dry-run validates the authenticated object stream without changing
    // flash or selecting Main. Recovery must remain available for the real
    // transfer that follows.
    if !dry_run {
        DURABLE_FLASH_COMPLETED.store(true, Ordering::Release);
    }
    true
}

pub(crate) unsafe fn expire(service: &mut ConnectionService, now_ms: u64) {
    let slot = &mut *core::ptr::addr_of_mut!(ACTIVE_STREAM);
    let Some((owner, request_id, _stream)) = slot.take_expired(now_ms) else {
        return;
    };
    set_transfer_active(false);
    let owner_selected = service.select_receive_cid(owner).is_some();
    crate::commands::send_response(b"flash receiver timeout");
    if owner_selected {
        let _ = complete_response(service, request_id, b"flash timeout");
    }
    // Queue the terminal application response first, then make this
    // association reclaimable on the next fresh OPEN. The close is wholly a
    // QUIC association operation; it does not create a flash-specific packet.
    let _ = service.close_receive_cid(owner, FLASH_ABORT_CLOSE_CODE);
}

/// Apply application-stream work after one QUIC receive turn. The caller
/// supplies only QUIC state and an opaque path; no UART, UDP, NOW, MAC, or
/// socket fact enters this module.
pub(crate) unsafe fn after_receive(
    service: &mut ConnectionService,
    _path: quic_lite::PathId,
    now_ms: u64,
    closed: bool,
) {
    if let Some(request) = service.take_stream_command() {
        begin(service, request, now_ms);
        let slot = &mut *core::ptr::addr_of_mut!(ACTIVE_STREAM);
        if let Some(owner) = slot.owner() {
            if service.expected_receive_cid() == Some(owner) {
                crate::recovery_runtime::log(b"DMESH recovery: flash receiver armed\n\0");
                // The generic consumer receives one ordered borrowed slice.
                // If storage stops it part way through, QUIC-lite itself
                // retains the suffix and resumes it through the same API;
                // no dispatcher or flash fragment queue is created.
                if dmesh_server::transport::prepare_inbound_stream_with_consumer(
                    service,
                    consume_active_flash_stream,
                )
                .is_err()
                {
                    crate::recovery_runtime::log(
                        b"DMESH recovery: flash stream prepare rejected\n\0",
                    );
                    crate::commands::send_response(b"flash stream prepare rejected");
                } else {
                    crate::recovery_runtime::log(b"DMESH recovery: flash stream prepared\n\0");
                }
            }
        } else {
            crate::recovery_runtime::log(b"DMESH recovery: flash receiver unavailable\n\0");
        }
    }
    if closed {
        let slot = &mut *core::ptr::addr_of_mut!(ACTIVE_STREAM);
        let closed_owner = slot
            .owner()
            .filter(|owner| service.last_closed_receive_cid() == Some(*owner));
        if let Some(owner) = closed_owner {
            if slot.take_for(owner).is_some() {
                set_transfer_active(false);
                crate::commands::send_response(b"flash receiver closed");
            }
        }
        service.abandon_stream_command();
        return;
    }
    let owner = (&*core::ptr::addr_of!(ACTIVE_STREAM)).owner();
    if let Some(owner) = owner {
        if service.expected_receive_cid() == Some(owner) {
            let _ = consume_pending_stream(service, now_ms);
            let slot = &mut *core::ptr::addr_of_mut!(ACTIVE_STREAM);
            refresh_idle_timeout_after_consumption(slot, now_ms);
            let receiver_completed = slot.get_mut_for(owner).is_some_and(|stream| {
                stream.receiver.is_complete() && !stream.receiver_complete_reported
            });
            if receiver_completed {
                // Recovery's UART is the only available postmortem surface
                // while validating a classic ESP32 STA upload. This records
                // semantic DONE admission, not a bearer-level ACK.
                crate::recovery_runtime::log(b"DMESH recovery: flash receiver complete\n\0");
                if let Some(stream) = slot.get_mut_for(owner) {
                    stream.receiver_complete_reported = true;
                }
            }
            let _ = finish(service, slot);
        }
    }
}

/// Poll durable completion before a normal QUIC transmit turn.
pub(crate) unsafe fn before_poll(
    service: &mut ConnectionService,
    _path: quic_lite::PathId,
    now_ms: u64,
) {
    {
        let slot = &mut *core::ptr::addr_of_mut!(ACTIVE_STREAM);
        if slot
            .owner()
            .is_some_and(|owner| service.expected_receive_cid() == Some(owner))
        {
            let _ = finish(service, slot);
        }
    }
    expire(service, now_ms);
}

/// Construct the hardware half of a shared `flash` request.
///
/// The caller still owns the signed-object GET and feeds its ordered response
/// bytes to the returned receiver. Stage2 is the one bounded raw region; all
/// application and module targets resolve through the partition table.
pub fn receiver_for_flash_request(
    request: dmesh_server::verified_object::FlashRequest<'_>,
) -> Result<SignedObjectFlashReceiver, FlashSinkError> {
    Ok(SignedObjectFlashReceiver::new(sink_for_flash_request(
        request,
    )?))
}

fn sink_for_flash_request(
    request: dmesh_server::verified_object::FlashRequest<'_>,
) -> Result<EspPartitionSink, FlashSinkError> {
    let target = request.object.target;
    let dry_run = request.dry_run;
    match target {
        2 => {
            let address = request.address.unwrap_or(0) as usize;
            let capacity = STAGE2_REGION_BYTES
                .checked_sub(address)
                .ok_or(FlashSinkError::AddressOverrideUnsupported)?;
            EspPartitionSink::new_raw(address, capacity, target, dry_run)
        }
        6 if request.address.is_none() => EspPartitionSink::new(b"main\0", target, dry_run),
        3 if request.address.is_none() => EspPartitionSink::new(b"recovery_app\0", target, dry_run)
            .or_else(|error| match error {
                FlashSinkError::PartitionUnavailable => {
                    EspPartitionSink::new(b"recovery\0", target, dry_run)
                }
                error => Err(error),
            }),
        7 if request.address.is_none() => {
            let name = request
                .object
                .name
                .ok_or(FlashSinkError::MissingModuleName)?;
            if name.is_empty() || name.iter().any(|byte| *byte == 0) {
                return Err(FlashSinkError::MissingModuleName);
            }
            // Module placement is the same numeric service-tag allocation
            // used by the loader and the direct provisioning tool. Modules
            // are regions inside the shared `data` partition, not app
            // partitions named after each module.
            let (offset, capacity) = match name {
                b"lora" => (0x00000, 0x20000),  // tag 43, two slots
                b"flash" => (0x10000, 0x10000), // tag 44, development alias
                b"hw" => (0x20000, 0x10000),    // tag 45
                b"hello" => (0x30000, 0x10000), // tag 46
                _ => return Err(FlashSinkError::MissingModuleName),
            };
            EspPartitionSink::new_region(b"data\0", offset, capacity, target, dry_run)
        }
        6 | 3 | 7 => return Err(FlashSinkError::AddressOverrideUnsupported),
        _ => return Err(FlashSinkError::UnsupportedTarget),
    }
}

/// Allocate the large flash receiver directly in heap storage.  The receiver
/// is an application sink; stream admission, ACKs, retransmission, and PTO
/// remain entirely in `dmesh_server::transport::ObjectClient`/QUIC-lite.
pub fn new_boxed_receiver(
    request: dmesh_server::verified_object::FlashRequest<'_>,
) -> Result<Box<SignedObjectFlashReceiver>, FlashSinkError> {
    // This runs only at the start of a rare update.  Pair it with the sink's
    // post-receiver snapshot below so an allocation rejection can distinguish
    // retained connection state from the receiver's bounded parser footprint.
    // It is console-only diagnostic output, not a transport or flash protocol
    // field.
    let caps = esp_idf_sys::MALLOC_CAP_INTERNAL | esp_idf_sys::MALLOC_CAP_8BIT;
    unsafe {
        esp_idf_sys::esp_rom_printf(
            b"DMESH recovery: flash receiver before free=%u largest=%u bytes=%u\n\0"
                .as_ptr()
                .cast(),
            esp_idf_sys::heap_caps_get_free_size(caps) as u32,
            esp_idf_sys::heap_caps_get_largest_free_block(caps) as u32,
            core::mem::size_of::<SignedObjectFlashReceiver>() as u32,
        );
    }
    match SignedObjectFlashReceiver::try_new_boxed_with(|| sink_for_flash_request(request)) {
        Ok(receiver) => Ok(receiver),
        Err(dmesh_server::verified_object::BoxedReceiverError::Sink(error)) => Err(error),
        Err(dmesh_server::verified_object::BoxedReceiverError::Allocation) => {
            // This allocation is intentionally transient. Report both aggregate
            // free internal RAM and its largest contiguous block: the former can
            // be adequate while fragmentation makes this receiver unavailable.
            let caps = esp_idf_sys::MALLOC_CAP_INTERNAL | esp_idf_sys::MALLOC_CAP_8BIT;
            crate::commands::send_stat(
                b"flash receiver alloc bytes=",
                core::mem::size_of::<SignedObjectFlashReceiver>() as u64,
            );
            crate::commands::send_stat(b"flash receiver heap free=", unsafe {
                esp_idf_sys::heap_caps_get_free_size(caps) as u64
            });
            crate::commands::send_stat(b"flash receiver heap largest=", unsafe {
                esp_idf_sys::heap_caps_get_largest_free_block(caps) as u64
            });
            Err(FlashSinkError::AllocationFailed)
        }
    }
}

/// ESP-IDF-backed durable sink for one application partition.
pub struct EspPartitionSink {
    partition: *const esp_idf_sys::esp_partition_t,
    base_address: usize,
    capacity: usize,
    target: u8,
    dry_run: bool,
    erase_us: u64,
    write_us: u64,
    writes: u64,
}

impl EspPartitionSink {
    /// Select a partition once for a requested object target. `label` must be
    /// NUL terminated because ESP-IDF retains no owned partition name.
    pub fn new(label: &[u8], target: u8, dry_run: bool) -> Result<Self, FlashSinkError> {
        Self::new_partition(
            esp_idf_sys::esp_partition_type_t_ESP_PARTITION_TYPE_APP,
            label,
            0,
            None,
            target,
            dry_run,
        )
    }

    fn new_region(
        label: &[u8],
        offset: usize,
        capacity: usize,
        target: u8,
        dry_run: bool,
    ) -> Result<Self, FlashSinkError> {
        Self::new_partition(
            esp_idf_sys::esp_partition_type_t_ESP_PARTITION_TYPE_DATA,
            label,
            offset,
            Some(capacity),
            target,
            dry_run,
        )
    }

    fn new_partition(
        partition_type: esp_idf_sys::esp_partition_type_t,
        label: &[u8],
        offset: usize,
        capacity: Option<usize>,
        target: u8,
        dry_run: bool,
    ) -> Result<Self, FlashSinkError> {
        if label.last().copied() != Some(0) {
            return Err(FlashSinkError::PartitionUnavailable);
        }
        let partition = unsafe {
            esp_idf_sys::esp_partition_find_first(
                partition_type,
                esp_idf_sys::esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_ANY,
                label.as_ptr().cast(),
            )
        };
        if partition.is_null() {
            return Err(FlashSinkError::PartitionUnavailable);
        }
        let partition_size = unsafe { (*partition).size as usize };
        let capacity = capacity.unwrap_or_else(|| partition_size.saturating_sub(offset));
        if capacity == 0
            || offset
                .checked_add(capacity)
                .is_none_or(|end| end > partition_size)
        {
            return Err(FlashSinkError::PartitionUnavailable);
        }
        Self::new_storage(partition, offset, capacity, target, dry_run)
    }

    /// Construct the strictly bounded raw Stage2 region.  This is not a
    /// general-purpose address writer: callers must have already selected the
    /// Stage2 target and `base_address + image_size` must remain in `capacity`.
    pub fn new_raw(
        base_address: usize,
        capacity: usize,
        target: u8,
        dry_run: bool,
    ) -> Result<Self, FlashSinkError> {
        if capacity == 0
            || base_address % BLOCK_SIZE != 0
            || base_address
                .checked_add(capacity)
                .is_none_or(|end| end > STAGE2_REGION_BYTES)
        {
            return Err(FlashSinkError::PartitionUnavailable);
        }
        Self::new_storage(core::ptr::null(), base_address, capacity, target, dry_run)
    }

    fn new_storage(
        partition: *const esp_idf_sys::esp_partition_t,
        base_address: usize,
        capacity: usize,
        target: u8,
        dry_run: bool,
    ) -> Result<Self, FlashSinkError> {
        Ok(Self {
            partition,
            base_address,
            capacity,
            target,
            dry_run,
            erase_us: 0,
            write_us: 0,
            writes: 0,
        })
    }

    pub fn stats(&self) -> (u64, u64, u64) {
        (self.erase_us, self.write_us, self.writes)
    }

    fn begin_image(&mut self, size: u32) -> Result<(), ()> {
        if size == 0 || size as usize > self.capacity {
            return Err(());
        }
        let erase_len = (size as usize + BLOCK_SIZE - 1) / BLOCK_SIZE * BLOCK_SIZE;
        if erase_len > self.capacity {
            return Err(());
        }
        if self.dry_run {
            return Ok(());
        }
        // `SignedObjectReceiver` owns the one ordinary 4 KiB block while it
        // validates it.  Write that borrowed block before returning, rather
        // than copying it into a second permanent-or-queued flash buffer.
        // This is the only ESP-specific operation; the caller sees a normal
        // synchronous `ImageSink` and returns QUIC credit after this method.
        crate::recovery_runtime::log(b"DMESH recovery: flash erase start\n\0");
        let started = unsafe { esp_idf_sys::esp_timer_get_time() as u64 };
        let result = if self.partition.is_null() {
            unsafe {
                esp_idf_sys::esp_flash_erase_region(
                    core::ptr::null_mut(),
                    self.base_address as u32,
                    erase_len as u32,
                )
            }
        } else {
            unsafe {
                esp_idf_sys::esp_partition_erase_range(self.partition, self.base_address, erase_len)
            }
        };
        self.erase_us = self.erase_us.saturating_add(
            (unsafe { esp_idf_sys::esp_timer_get_time() as u64 }).saturating_sub(started),
        );
        if result == esp_idf_sys::ESP_OK {
            crate::recovery_runtime::log(b"DMESH recovery: flash erase complete\n\0");
            Ok(())
        } else {
            crate::recovery_runtime::log(b"DMESH recovery: flash erase failed\n\0");
            Err(())
        }
    }

    fn write_image_block(&mut self, index: u32, data: &[u8]) -> Result<(), ()> {
        if self.dry_run {
            return Ok(());
        }
        let data_len = data.len();
        if data_len == 0 || data_len > BLOCK_SIZE {
            return Err(());
        }
        let started = unsafe { esp_idf_sys::esp_timer_get_time() as u64 };
        let result = if self.partition.is_null() {
            unsafe {
                esp_idf_sys::esp_flash_write(
                    core::ptr::null_mut(),
                    data.as_ptr().cast(),
                    (self.base_address + index as usize * BLOCK_SIZE) as u32,
                    data_len as u32,
                )
            }
        } else {
            unsafe {
                esp_idf_sys::esp_partition_write(
                    self.partition,
                    self.base_address + index as usize * BLOCK_SIZE,
                    data.as_ptr().cast(),
                    data_len,
                )
            }
        };
        self.write_us = self.write_us.saturating_add(
            (unsafe { esp_idf_sys::esp_timer_get_time() as u64 }).saturating_sub(started),
        );
        if result == esp_idf_sys::ESP_OK {
            self.writes = self.writes.saturating_add(1);
            Ok(())
        } else {
            crate::recovery_runtime::log(b"DMESH recovery: flash write failed\n\0");
            Err(())
        }
    }

    pub fn is_durable(&self) -> bool {
        true
    }

    pub fn pending_jobs(&self) -> u64 {
        0
    }
}

impl ImageSink for EspPartitionSink {
    type Error = ();
    fn begin(
        &mut self,
        manifest: &dmesh_server::verified_object::ImageManifest,
    ) -> Result<(), Self::Error> {
        if manifest.target != self.target
            || manifest.cpu != local_image_cpu()
            || manifest.block_size as usize != BLOCK_SIZE
        {
            return Err(());
        }
        self.begin_image(manifest.image_size)
    }
    fn write_block(&mut self, index: u32, data: &[u8]) -> Result<(), Self::Error> {
        self.write_image_block(index, data)
    }
    fn finish(
        &mut self,
        _: &dmesh_server::verified_object::ImageManifest,
    ) -> Result<(), Self::Error> {
        // ImageReceiver has checked each block against the authenticated
        // manifest digest before calling this hook. Recovery deliberately does
        // not re-hash the whole image: per-block proofs are its acceptance
        // rule, and avoiding the second linear hash keeps flash throughput
        // independent of image size.
        Ok(())
    }
    fn abort(&mut self) {}
}

impl dmesh_server::verified_object::StreamingImageSink for EspPartitionSink {
    fn poll_completed(
        &mut self,
    ) -> Result<dmesh_server::verified_object::StoragePoll, Self::Error> {
        Ok(dmesh_server::verified_object::StoragePoll::Ready)
    }
}
