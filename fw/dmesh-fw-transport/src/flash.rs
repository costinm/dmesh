//! ESP partition sink for the bearer-neutral signed-object client.
//!
//! Record framing, manifest verification, stream ordering, and flow control
//! belong in `dmesh-server` and the selected transport. This module owns only
//! durable ESP erase/write operations.

use alloc::{boxed::Box, vec::Vec};
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};
use dmesh_server::verified_object::{ImageSink, BLOCK_SIZE};

struct SliceStreamReader<'a> { bytes: &'a [u8], offset: usize }

impl dmesh_server::verified_object::OrderedStreamRead for SliceStreamReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> usize {
        let count = out.len().min(self.bytes.len().saturating_sub(self.offset));
        out[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        count
    }
}

// One verified-object blob is one 4 KiB image block.  Retaining a larger
// synthetic batch buys no transport property: the consumer returns stream
// credit only after this ordinary durable block is available again.
const FLASH_WRITE_BLOCKS: usize = 1;
const FLASH_WRITE_BATCH_BYTES: usize = BLOCK_SIZE * FLASH_WRITE_BLOCKS;
// Storage capacity is selected from the heap when the operation starts. Keep
// enough RAM for QUIC, the receiver, Wi-Fi, and worker metadata; actual
// allocation can reduce this choice further when the heap is fragmented.
// This is observed after the transient receiver has been allocated.  It
// covers the worker stack/queues and the active raw-UDP/QUIC runtime on the
// smallest classic Recovery image; the remaining space selects one ordinary
// image-block slot at admission.
const FLASH_HEAP_RESERVE_BYTES: usize = 16 * 1024;
const MIN_FLASH_WRITE_BUFFERS: usize = 1;
// Classic Recovery has one small worker and one parser scratch record in
// addition to this slot.  Advertising a second durable block would make the
// QUIC receive window exceed the measured usable heap.  This is application
// storage capacity, not a packet or transport credit setting.
const MAX_FLASH_WRITE_BUFFERS: usize = 1;
const FLASH_STORAGE_POLICY: dmesh_server::verified_object::StorageSlotPolicy =
    dmesh_server::verified_object::StorageSlotPolicy {
        reserve_bytes: FLASH_HEAP_RESERVE_BYTES,
        bytes_per_slot: FLASH_WRITE_BATCH_BYTES,
        minimum_slots: MIN_FLASH_WRITE_BUFFERS,
        maximum_slots: MAX_FLASH_WRITE_BUFFERS,
    };
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
// A 4 MiB image has at most 1,024 4 KiB blocks. Its current CBOR manifest
// carries one 16-byte digest prefix per block and is 16,448 bytes, so this bound
// covers the complete addressable image with format headroom. The receiver is
// allocated only while an update stream is active; it is not reserved by the
// ordinary Main/Recovery runtime.
// A 4-MiB image has at most 1024 4-KiB blocks.  Its signed flat proof table
// is 8 KiB (plus a small CBOR envelope), so 10 KiB is a hard format bound;
// it is application memory and never QUIC receive credit.
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
        &mut self, reader: &mut R,
    ) -> Result<dmesh_server::verified_object::ObjectStreamRead, dmesh_server::verified_object::ImageError> {
        let read = self.receiver.consume_one_stream_record(reader)?;
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

fn consume_active_flash_stream(bytes: &[u8], _fin: bool) -> Result<usize, ()> {
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(ACTIVE_STREAM);
        let Some(owner) = slot.owner() else { return Ok(0) };
        let Some(stream) = slot.get_mut_for(owner) else { return Ok(0) };
        let mut reader = SliceStreamReader { bytes, offset: 0 };
        match stream.receive(&mut reader) {
            Ok(_) => Ok(reader.offset),
            Err(error) => { log_receiver_error(error); Err(()) }
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

fn log_receiver_error(error: dmesh_server::verified_object::ImageError) {
    let message = match error {
        dmesh_server::verified_object::ImageError::Truncated => {
            b"DMESH flash: receiver error truncated\n\0".as_slice()
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
            let _ = complete_response(service, request_id, error.response());
        }
        Err(dmesh_server::verified_object::ExclusiveTransferStartError::Busy) => {
            // The multicast announce is discovery, not an invitation for every
            // observer to replace the current writer. Completion, association
            // close, and the bounded idle timeout are the only owners allowed
            // to release this operation.
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
                if dmesh_server::transport::prepare_inbound_stream_with_consumer(
                    service,
                    consume_active_flash_stream,
                ).is_err() {
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
                crate::commands::send_response(b"flash receiver closed");
            }
        }
        service.abandon_stream_command();
        return;
    }
    let slot = &mut *core::ptr::addr_of_mut!(ACTIVE_STREAM);
    if let Some(owner) = slot.owner() {
        if service.expected_receive_cid() == Some(owner) {
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
        if let Some(owner) = slot
            .owner()
            .filter(|owner| service.expected_receive_cid() == Some(*owner))
        {
            // Main and Recovery invoke this from their ordinary application
            // maintenance turn. It separates manifest admission from a
            // cache-disrupting erase; it is storage scheduling, never transport
            // policy.
            if let Some(stream) = slot.get_mut_for(owner) {
                if stream.receiver.poll_storage_before_transport().is_err() {
                    crate::commands::send_response(b"flash erase queue rejected");
                }
            }
            let _ = finish(service, slot);
        }
    }
    expire(service, now_ms);
}

/// Consume completed storage work and publish the released receive window to
/// QUIC-lite. The returned opaque path tells the generic runtime only where
/// pending QUIC output should be polled.
pub(crate) unsafe fn storage_ready(
    service: &mut ConnectionService,
    now_ms: u64,
) -> Result<Option<quic_lite::PathId>, ()> {
    let slot = &mut *core::ptr::addr_of_mut!(ACTIVE_STREAM);
    let Some(owner) = slot.owner() else {
        return Ok(None);
    };
    let Some(path) = service.select_receive_cid(owner) else {
        return Ok(None);
    };
    if service.resume_inbound_stream_consumer().is_err() {
        crate::commands::send_response(b"flash stream consume rejected");
        return Err(());
    }
    refresh_idle_timeout_after_consumption(slot, now_ms);
    let _ = finish(service, slot);
    Ok(Some(path))
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
            let mut label = Vec::with_capacity(name.len() + 1);
            label.extend_from_slice(name);
            label.push(0);
            EspPartitionSink::new(&label, target, dry_run)
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
    free_blocks: Vec<Box<[u8; FLASH_WRITE_BATCH_BYTES]>>,
    worker: Option<FlashWorker>,
    // Blob slots accepted before the initial receive-credit boundary. The
    // erase must not begin in the callback that admits that boundary:
    // ESP32-C6 flash erase pauses Wi-Fi globally even when performed by a
    // separate FreeRTOS task. The next application maintenance turn starts
    // it after the receiver has published its current storage capacity.
    waiting_writes: Vec<FlashJob>,
    // One authenticated 4 KiB block may wait briefly for its contiguous
    // successor. `finish` flushes this job for an image whose final block is
    // short or odd, so acceptance never depends on an artificial pair.
    staged_write: Option<FlashJob>,
    erase_len: usize,
    // Erasing an executing application's peer partition temporarily affects
    // the C6 flash/cache path. Do not start it from the manifest-admission
    // callback; begin from a later application maintenance turn instead.
    erase_work: dmesh_server::verified_object::DeferredStorageWork,
    erase_complete: bool,
    pending_jobs: usize,
    erase_us: u64,
    write_us: u64,
    writes: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FlashJob {
    kind: u8,
    partition: *const esp_idf_sys::esp_partition_t,
    base_address: usize,
    index: u32,
    len: usize,
    data: *mut [u8; FLASH_WRITE_BATCH_BYTES],
}

const FLASH_JOB_ERASE: u8 = 1;
const FLASH_JOB_WRITE: u8 = 2;
// ESP-IDF is configured to yield inside a long erase
// (`CONFIG_SPI_FLASH_YIELD_DURING_ERASE`). Keep the whole manifest-bounded
// destination as one worker job: Recovery does not turn individual sectors
// into application events or transport scheduling decisions.

#[repr(C)]
#[derive(Clone, Copy)]
struct FlashCompletion {
    kind: u8,
    index: u32,
    data: *mut [u8; FLASH_WRITE_BATCH_BYTES],
    elapsed_us: u64,
    result: i32,
}

#[derive(Clone, Copy)]
struct FlashWorker {
    work: esp_idf_sys::QueueHandle_t,
    done: esp_idf_sys::QueueHandle_t,
}

impl FlashWorker {
    fn new(write_buffers: usize) -> Option<Self> {
        if write_buffers == 0 {
            return None;
        }
        let work = unsafe {
            esp_idf_sys::xQueueCreateWithCaps(
                (write_buffers + 1) as _,
                core::mem::size_of::<FlashJob>() as _,
                // On classic ESP32, INTERNAL alone may select instruction
                // RAM. FreeRTOS queue metadata is byte-addressed, so require
                // data-capable internal RAM as well.
                (esp_idf_sys::MALLOC_CAP_INTERNAL | esp_idf_sys::MALLOC_CAP_8BIT) as _,
            )
        };
        let done = unsafe {
            esp_idf_sys::xQueueCreateWithCaps(
                write_buffers as _,
                core::mem::size_of::<FlashCompletion>() as _,
                (esp_idf_sys::MALLOC_CAP_INTERNAL | esp_idf_sys::MALLOC_CAP_8BIT) as _,
            )
        };
        if work.is_null() || done.is_null() {
            if !work.is_null() {
                unsafe { esp_idf_sys::vQueueDeleteWithCaps(work) };
            }
            if !done.is_null() {
                unsafe { esp_idf_sys::vQueueDeleteWithCaps(done) };
            }
            return None;
        }
        let worker = Self { work, done };
        // The recovery process owns this task until it reboots.  Passing a
        // copied pair of queue handles avoids a borrowed EspPartitionSink pointer in
        // the RTOS task, so no callback can observe a dropped handler.
        let task_state = Box::into_raw(Box::new(worker));
        let mut task = core::ptr::null_mut();
        let result = unsafe {
            esp_idf_sys::xTaskCreatePinnedToCore(
                Some(flash_worker_task),
                b"flash\0".as_ptr().cast(),
                4096,
                task_state.cast::<c_void>(),
                // The common packet worker is priority 5 and can remain
                // runnable while a sender retransmits against a full receive
                // window.  Flash completion is the only event which returns
                // that handler-owned capacity, so it must not be starved by
                // packet ingress on the same classic-ESP32 core.  This is
                // FreeRTOS scheduling only: QUIC credit is still published
                // exclusively through the shared StorageReady edge.
                6,
                &mut task,
                0,
            )
        };
        if result != 1 || task.is_null() {
            unsafe {
                drop(Box::from_raw(task_state));
                esp_idf_sys::vQueueDeleteWithCaps(work);
                esp_idf_sys::vQueueDeleteWithCaps(done);
            }
            return None;
        }
        Some(worker)
    }

    fn enqueue(&self, job: FlashJob) -> bool {
        unsafe {
            esp_idf_sys::xQueueGenericSend(
                self.work,
                (&job as *const FlashJob).cast::<c_void>(),
                0,
                0,
            ) == 1
        }
    }

    fn take_completion(&self) -> Option<FlashCompletion> {
        let mut completion = FlashCompletion {
            kind: 0,
            index: 0,
            data: core::ptr::null_mut(),
            elapsed_us: 0,
            result: esp_idf_sys::ESP_FAIL,
        };
        (unsafe {
            esp_idf_sys::xQueueReceive(
                self.done,
                (&mut completion as *mut FlashCompletion).cast::<c_void>(),
                0,
            )
        } == 1)
            .then_some(completion)
    }
}

unsafe extern "C" fn flash_worker_task(parameter: *mut c_void) {
    // This Box intentionally lives for Recovery's process lifetime; the task
    // owns no pointer back into the application receiver.
    let worker = unsafe { Box::from_raw(parameter.cast::<FlashWorker>()) };
    loop {
        let mut job = FlashJob {
            kind: 0,
            partition: core::ptr::null(),
            base_address: 0,
            index: 0,
            len: 0,
            data: core::ptr::null_mut(),
        };
        if unsafe {
            esp_idf_sys::xQueueReceive(
                worker.work,
                (&mut job as *mut FlashJob).cast::<c_void>(),
                u32::MAX,
            )
        } != 1
        {
            continue;
        }
        if job.kind == FLASH_JOB_ERASE {
            crate::recovery_runtime::log(b"DMESH recovery: flash erase start\n\0");
        }
        let started = unsafe { esp_idf_sys::esp_timer_get_time() as u64 };
        let result = match job.kind {
            FLASH_JOB_ERASE if job.partition.is_null() => unsafe {
                esp_idf_sys::esp_flash_erase_region(
                    core::ptr::null_mut(),
                    job.base_address as u32,
                    job.len as u32,
                )
            },
            FLASH_JOB_ERASE => unsafe {
                esp_idf_sys::esp_partition_erase_range(job.partition, 0, job.len)
            },
            FLASH_JOB_WRITE if job.partition.is_null() => unsafe {
                esp_idf_sys::esp_flash_write(
                    core::ptr::null_mut(),
                    job.data.cast(),
                    (job.base_address + job.index as usize * BLOCK_SIZE) as u32,
                    job.len as u32,
                )
            },
            FLASH_JOB_WRITE => unsafe {
                esp_idf_sys::esp_partition_write(
                    job.partition,
                    job.index as usize * BLOCK_SIZE,
                    job.data.cast(),
                    job.len,
                )
            },
            _ => esp_idf_sys::ESP_FAIL,
        };
        let elapsed_us =
            (unsafe { esp_idf_sys::esp_timer_get_time() as u64 }).saturating_sub(started);
        let completion = FlashCompletion {
            kind: job.kind,
            index: job.index,
            data: job.data,
            elapsed_us,
            result,
        };
        if job.kind == FLASH_JOB_ERASE {
            crate::recovery_runtime::log(b"DMESH recovery: flash erase complete\n\0");
        }
        // A full completion queue means every retained slot is accounted for
        // by the receive task. Blocking preserves ownership rather than
        // dropping a buffer or releasing credit prematurely.
        let _ = unsafe {
            esp_idf_sys::xQueueGenericSend(
                worker.done,
                (&completion as *const FlashCompletion).cast::<c_void>(),
                u32::MAX,
                0,
            )
        };
        // Publish the durable-completion edge after the completion itself is
        // visible. On Main this wakes the one connection owner so QUIC-lite
        // can emit its MAX_DATA/MAX_STREAM_DATA update when the peer has
        // exhausted published receive credit. The shared ingress queue is not
        // installed in reduced Recovery, where this returns false and its
        // bounded UDP turn performs the same handler-neutral poll.
        let _ = crate::core_runtime::schedule_storage_ready();
    }
}

fn allocate_block() -> Option<Box<[u8; FLASH_WRITE_BATCH_BYTES]>> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(FLASH_WRITE_BATCH_BYTES).ok()?;
    bytes.resize(FLASH_WRITE_BATCH_BYTES, 0);
    bytes.into_boxed_slice().try_into().ok()
}

impl EspPartitionSink {
    /// Select a partition once for a requested object target. `label` must be
    /// NUL terminated because ESP-IDF retains no owned partition name.
    pub fn new(label: &[u8], target: u8, dry_run: bool) -> Result<Self, FlashSinkError> {
        if label.last().copied() != Some(0) {
            return Err(FlashSinkError::PartitionUnavailable);
        }
        let partition = unsafe {
            esp_idf_sys::esp_partition_find_first(
                esp_idf_sys::esp_partition_type_t_ESP_PARTITION_TYPE_APP,
                esp_idf_sys::esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_ANY,
                label.as_ptr().cast(),
            )
        };
        if partition.is_null() {
            return Err(FlashSinkError::PartitionUnavailable);
        }
        Self::new_storage(
            partition,
            0,
            unsafe { (*partition).size as usize },
            target,
            dry_run,
        )
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
        // A dry run verifies the exact streamed object and exercises normal
        // QUIC flow control, but it neither retains a write batch nor starts
        // the flash worker.  Do not reject it merely because the durable
        // writer's 32 KiB reserve is unavailable: its one-batch advertised
        // window is parser accounting, not an allocation of flash buffers.
        let selected_buffers = if dry_run {
            MIN_FLASH_WRITE_BUFFERS
        } else {
            let caps = esp_idf_sys::MALLOC_CAP_INTERNAL | esp_idf_sys::MALLOC_CAP_8BIT;
            let available = unsafe { esp_idf_sys::heap_caps_get_free_size(caps) as usize };
            let selected = FLASH_STORAGE_POLICY.slots_for(available);
            if selected == 0 {
                let largest = unsafe { esp_idf_sys::heap_caps_get_largest_free_block(caps) };
                // Recovery has no framed UART transport, so report this only
                // to its output console.  The values identify whether the
                // rejection is policy headroom or heap fragmentation; they
                // do not participate in stream/QUIC flow control.
                unsafe {
                    esp_idf_sys::esp_rom_printf(
                        b"DMESH recovery: flash heap free=%u largest=%u reserve=%u slot=%u\n\0"
                            .as_ptr()
                            .cast(),
                        available as u32,
                        largest,
                        FLASH_STORAGE_POLICY.reserve_bytes as u32,
                        FLASH_STORAGE_POLICY.bytes_per_slot as u32,
                    );
                }
                return Err(FlashSinkError::AllocationFailed);
            }
            selected
        };
        let mut free_blocks = Vec::with_capacity(if dry_run { 0 } else { selected_buffers });
        if !dry_run {
            for _ in 0..selected_buffers {
                match allocate_block() {
                    Some(block) => free_blocks.push(block),
                    None if free_blocks.len() >= MIN_FLASH_WRITE_BUFFERS => break,
                    None => return Err(FlashSinkError::AllocationFailed),
                }
            }
        }
        let write_buffers = if dry_run {
            selected_buffers
        } else {
            free_blocks.len()
        };
        let worker = if dry_run {
            None
        } else {
            Some(FlashWorker::new(write_buffers).ok_or(FlashSinkError::AllocationFailed)?)
        };
        Ok(Self {
            partition,
            base_address,
            capacity,
            target,
            dry_run,
            free_blocks,
            worker,
            waiting_writes: Vec::with_capacity(if dry_run { 0 } else { write_buffers }),
            staged_write: None,
            erase_len: 0,
            erase_work: dmesh_server::verified_object::DeferredStorageWork::new(),
            erase_complete: dry_run,
            pending_jobs: 0,
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
        // Start one manifest-bounded erase. The worker is the only blocking
        // owner; stream callbacks only enqueue verified writes.
        let erase_len = (size as usize + BLOCK_SIZE - 1) / BLOCK_SIZE * BLOCK_SIZE;
        if erase_len > self.capacity {
            return Err(());
        }
        if self.dry_run {
            return Ok(());
        }
        self.erase_len = erase_len;
        // Manifest verification happens in the stream callback. Merely mark
        // the erase here; the next ordinary application maintenance edge
        // enqueues it on the worker. Waiting until every receive slot is full
        // creates a circular dependency: the sender exhausts its window while
        // the sink waits for another packet before it starts reclaiming it.
        self.request_erase();
        // Ask the common connection owner for exactly one later maintenance
        // turn.  A host may send its first BLOB immediately after receiving
        // the manifest ACK, before the normal PTO deadline; without this
        // wake the erase would depend on a further inbound datagram.  The
        // scheduled turn still enters through `poll_connection` and its
        // handler-neutral `before_poll` hook, rather than making the stream
        // callback touch QUIC state or start the erase itself.
        crate::core_runtime::schedule_connection_timer();
        Ok(())
    }

    fn request_erase(&mut self) {
        if !self.erase_complete && self.pending_jobs == 0 {
            self.erase_work.request();
        }
    }

    fn start_deferred_erase(&mut self) -> Result<(), ()> {
        if self.dry_run || !self.erase_work.take() {
            return Ok(());
        }
        // Manifest admission and the potentially cache-disrupting erase are
        // distinct application turns. One deferral is sufficient: requiring
        // a second later turn deadlocks when the peer has consumed the entire
        // advertised storage window and has no packet left to send.
        let worker = self.worker.ok_or(())?;
        if !worker.enqueue(FlashJob {
            kind: FLASH_JOB_ERASE,
            partition: self.partition,
            base_address: self.base_address,
            index: 0,
            len: self.erase_len,
            data: core::ptr::null_mut(),
        }) {
            self.erase_work.request();
            return Err(());
        }
        self.pending_jobs = self.pending_jobs.saturating_add(1);
        crate::recovery_runtime::log(b"DMESH recovery: flash erase queued\n\0");
        Ok(())
    }

    fn enqueue_write(&mut self, job: FlashJob) -> Result<(), ()> {
        if self.erase_complete {
            if !self.worker.expect("production worker").enqueue(job) {
                return Err(());
            }
            self.pending_jobs = self.pending_jobs.saturating_add(1);
        } else {
            self.waiting_writes.push(job);
            if self.free_blocks.is_empty() && self.staged_write.is_none() {
                self.request_erase();
            }
        }
        Ok(())
    }

    fn write_image_block(&mut self, index: u32, data: &[u8]) -> Result<(), ()> {
        if self.dry_run {
            return Ok(());
        }
        let data_len = data.len();
        if data_len == 0 || data_len > BLOCK_SIZE {
            return Err(());
        }
        if let Some(mut job) = self.staged_write.take() {
            if index != job.index.saturating_add(1)
                || job.len.saturating_add(data_len) > FLASH_WRITE_BATCH_BYTES
            {
                self.staged_write = Some(job);
                return Err(());
            }
            unsafe {
                (&mut *job.data)[job.len..job.len + data_len].copy_from_slice(data);
            }
            job.len += data_len;
            return self.enqueue_write(job);
        }

        let mut slot = self.free_blocks.pop().ok_or(())?;
        slot[..data_len].copy_from_slice(data);
        let job = FlashJob {
            kind: FLASH_JOB_WRITE,
            partition: self.partition,
            base_address: self.base_address,
            index,
            len: data_len,
            data: Box::into_raw(slot),
        };
        if data_len == FLASH_WRITE_BATCH_BYTES {
            self.enqueue_write(job)
        } else {
            self.staged_write = Some(job);
            Ok(())
        }
    }

    /// Poll completed flash jobs without blocking the stream receive path.
    pub fn poll_completed(&mut self) -> Result<(), ()> {
        if self.dry_run {
            return Ok(());
        }
        let worker = self.worker.expect("production worker");
        while let Some(completion) = worker.take_completion() {
            self.pending_jobs = self.pending_jobs.saturating_sub(1);
            match completion.kind {
                FLASH_JOB_ERASE => {
                    self.erase_us = self.erase_us.saturating_add(completion.elapsed_us);
                    self.erase_complete = true;
                    crate::recovery_runtime::log(b"DMESH recovery: flash erase complete\n\0");
                    for job in self.waiting_writes.drain(..) {
                        if !worker.enqueue(job) {
                            return Err(());
                        }
                        self.pending_jobs = self.pending_jobs.saturating_add(1);
                    }
                }
                FLASH_JOB_WRITE => {
                    if completion.data.is_null() {
                        return Err(());
                    }
                    self.write_us = self.write_us.saturating_add(completion.elapsed_us);
                    self.writes = self.writes.saturating_add(1);
                    self.free_blocks
                        .push(unsafe { Box::from_raw(completion.data) });
                }
                _ => return Err(()),
            }
            if completion.result != esp_idf_sys::ESP_OK {
                crate::recovery_runtime::log(match completion.kind {
                    FLASH_JOB_ERASE => b"DMESH recovery: flash erase failed\n\0",
                    FLASH_JOB_WRITE => b"DMESH recovery: flash write failed\n\0",
                    _ => b"DMESH recovery: flash worker failed\n\0",
                });
                return Err(());
            }
        }
        Ok(())
    }

    pub fn is_durable(&self) -> bool {
        self.dry_run || (self.erase_complete && self.pending_jobs == 0)
    }

    fn poll_before_transport(&mut self) -> Result<(), ()> {
        self.start_deferred_erase()
    }

    /// Compact post-DONE diagnostic: queued worker operations.  It is read
    /// only while Recovery waits for durability, never from the packet path.
    pub fn pending_jobs(&self) -> u64 {
        self.pending_jobs as u64
    }
}

impl ImageSink for EspPartitionSink {
    type Error = ();
    fn begin(
        &mut self,
        manifest: &dmesh_server::verified_object::ImageManifest,
    ) -> Result<(), Self::Error> {
        if manifest.target != self.target || manifest.block_size as usize != BLOCK_SIZE {
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
        if let Some(job) = self.staged_write.take() {
            self.enqueue_write(job)?;
        }
        self.request_erase();
        Ok(())
    }
    fn abort(&mut self) {
        if let Some(job) = self.staged_write.take() {
            if !job.data.is_null() {
                self.free_blocks.push(unsafe { Box::from_raw(job.data) });
            }
        }
    }
}

impl dmesh_server::verified_object::StreamingImageSink for EspPartitionSink {
    fn poll_completed(
        &mut self,
    ) -> Result<dmesh_server::verified_object::StoragePoll, Self::Error> {
        EspPartitionSink::poll_completed(self)
            .map(|()| {
                if self.dry_run
                    || (self.erase_complete
                        && (self.staged_write.is_some() || !self.free_blocks.is_empty()))
                {
                    dmesh_server::verified_object::StoragePoll::Ready
                } else {
                    dmesh_server::verified_object::StoragePoll::Pending
                }
            })
    }

    fn poll_before_transport(&mut self) -> Result<(), Self::Error> {
        EspPartitionSink::poll_before_transport(self)
    }
}
