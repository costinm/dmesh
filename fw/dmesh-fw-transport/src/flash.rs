//! ESP partition sink for the bearer-neutral signed-object client.
//!
//! Record framing, manifest verification, stream ordering, and flow control
//! belong in `dmesh-server` and the selected transport. This module owns only
//! durable ESP erase/write operations.

use alloc::{
    alloc::{Layout, alloc_zeroed},
    boxed::Box,
    vec::Vec,
};
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};
use dmesh_server::protocol::{BLOCK_SIZE, ImageSink};

const PENDING_FLASH_BLOCKS: usize = 8;
const FLASH_WRITE_BLOCKS: usize = 2;
const FLASH_WRITE_BATCH_BYTES: usize = BLOCK_SIZE * FLASH_WRITE_BLOCKS;
const BLOCK_RECORD_OVERHEAD: usize = 5 + 12;
/// No application bytes have arrived for this bounded period. This is a
/// receiver liveness guard, not a transport retransmission deadline: QUIC-lite
/// continues to own ACK/PTO behavior below the flash sink.
const FLASH_STREAM_IDLE_TIMEOUT_US: u64 = 120_000_000;
/// Stage2 occupies the boot region below the partition table.  A signed
/// object may select a narrower address within this region, never raw flash
/// beyond it.
const STAGE2_REGION_BYTES: usize = 0x7000;
/// Firmware bounds for the shared incremental signed-object receiver.
pub const MAX_MANIFEST_BYTES: usize = 48 * 1024;
pub const MAX_BLOB_RECORD_BYTES: usize = 12 + BLOCK_SIZE;
pub type SignedObjectFlashReceiver = dmesh_server::protocol::SignedObjectReceiver<
    EspPartitionSink,
    dmesh_server::protocol::NoSignatureVerifier,
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
    expires_at_us: u64,
}

impl FlashStream {
    unsafe fn new_boxed(
        request: dmesh_server::protocol::FlashRequest<'_>,
        now_us: u64,
    ) -> Result<Box<Self>, FlashSinkError> {
        let receiver = new_boxed_receiver(request)?;
        let raw = alloc_zeroed(Layout::new::<Self>()) as *mut Self;
        if raw.is_null() {
            return Err(FlashSinkError::AllocationFailed);
        }
        core::ptr::addr_of_mut!((*raw).receiver).write(receiver);
        core::ptr::addr_of_mut!((*raw).expires_at_us)
            .write(now_us.saturating_add(FLASH_STREAM_IDLE_TIMEOUT_US));
        Ok(Box::from_raw(raw))
    }

    fn receive(&mut self, chunks: Vec<(Vec<u8>, bool)>, now_us: u64) -> Result<usize, ()> {
        let mut admitted = false;
        for (bytes, _) in chunks {
            self.receiver.push_ordered(&bytes).map_err(|_| ())?;
            admitted = true;
        }
        if admitted {
            self.expires_at_us = now_us.saturating_add(FLASH_STREAM_IDLE_TIMEOUT_US);
        }
        self.receiver.sink_mut().poll_completed()
    }

    fn receive_window_bytes(&mut self) -> usize {
        self.receiver.sink_mut().receive_window_bytes()
    }

    fn complete_and_durable(&mut self) -> bool {
        self.receiver.is_complete() && self.receiver.sink_mut().is_durable()
    }
}

// Exactly one object.flash operation may own the firmware update stream. It
// contains no bearer identity beyond QUIC-lite's opaque PathId.
static mut ACTIVE_STREAM: Option<(quic_lite::PathId, Box<FlashStream>)> = None;

// The stream handler owns durable completion.  A reduced Recovery runtime may
// consume this edge to hand Stage2 back to Main; it is deliberately neither a
// bearer signal nor an extra flash protocol message.
static DURABLE_FLASH_COMPLETED: AtomicBool = AtomicBool::new(false);

pub(crate) fn take_durable_flash_completion() -> bool {
    DURABLE_FLASH_COMPLETED.swap(false, Ordering::AcqRel)
}

unsafe fn begin(
    service: &mut ConnectionService,
    path: quic_lite::PathId,
    request: Vec<u8>,
    now_us: u64,
) {
    let Some(request) = dmesh_server::protocol::decode_flash_request(&request) else {
        let _ = service.complete_flash(Vec::from(&b"flash invalid"[..]));
        return;
    };
    let slot = core::ptr::addr_of_mut!(ACTIVE_STREAM);
    if (*slot).take().is_some() {
        crate::commands::send_response(b"flash receiver replaced");
    }
    crate::commands::send_response(b"flash receiver allocating");
    match FlashStream::new_boxed(request, now_us) {
        Ok(stream) => {
            crate::commands::send_response(b"flash object stream armed");
            *slot = Some((path, stream));
        }
        Err(_) => {
            let _ = service.complete_flash(Vec::from(&b"flash rejected"[..]));
        }
    }
}

unsafe fn finish(service: &mut ConnectionService) -> bool {
    let slot = core::ptr::addr_of_mut!(ACTIVE_STREAM);
    if !(*slot)
        .as_mut()
        .is_some_and(|(_, stream)| stream.complete_and_durable())
    {
        return false;
    }
    *slot = None;
    crate::commands::send_response(b"flash object durable");
    let _ = service.complete_flash(Vec::from(&b"flash complete"[..]));
    DURABLE_FLASH_COMPLETED.store(true, Ordering::Release);
    true
}

pub(crate) unsafe fn expire(service: &mut ConnectionService, now_us: u64) {
    let slot = core::ptr::addr_of_mut!(ACTIVE_STREAM);
    if !(*slot)
        .as_ref()
        .is_some_and(|(_, stream)| now_us >= stream.expires_at_us)
    {
        return;
    }
    *slot = None;
    crate::commands::send_response(b"flash receiver timeout");
    let _ = service.complete_flash(Vec::from(&b"flash timeout"[..]));
}

/// Apply application-stream work after one QUIC receive turn. The caller
/// supplies only QUIC state and an opaque path; no UART, UDP, NOW, MAC, or
/// socket fact enters this module.
pub(crate) unsafe fn after_receive(
    service: &mut ConnectionService,
    path: quic_lite::PathId,
    now_us: u64,
    closed: bool,
    mut response_len: Option<usize>,
    response: &mut [u8; crate::TRANSPORT_MTU],
) -> Option<usize> {
    if let Some(request) = service.take_flash_request() {
        begin(service, path, request, now_us);
    }
    if closed {
        if (*core::ptr::addr_of_mut!(ACTIVE_STREAM)).take().is_some() {
            crate::commands::send_response(b"flash receiver closed");
        }
        service.abandon_flash();
        return response_len;
    }
    let mut completed = false;
    let mut released_credit = false;
    if let Some((active_path, stream)) = (*core::ptr::addr_of_mut!(ACTIVE_STREAM)).as_mut() {
        if *active_path == path {
            match stream.receive(service.take_flash_object_chunks(), now_us) {
                Ok(credit) if credit != 0 => {
                    crate::recovery_runtime::log(b"DMESH recovery: flash storage released\n\0");
                    if service
                        .grant_flash_receive_window(stream.receive_window_bytes())
                        .is_err()
                    {
                        crate::commands::send_response(b"flash credit rejected");
                    } else {
                        released_credit = true;
                    }
                }
                Ok(_) => {}
                Err(()) => {
                    crate::recovery_runtime::log(b"DMESH recovery: flash object rejected\n\0");
                    crate::commands::send_response(b"flash object receiver rejected");
                }
            }
            completed = finish(service);
        }
    }
    // `service.receive` may already have produced the ACK for this packet
    // before the application sink published its newly free storage. Prefer a
    // second, ordinary QUIC-lite control poll in that case: it carries the
    // MAX_DATA/MAX_STREAM_DATA update that unblocks the peer.  Keeping the
    // earlier ACK instead would consume the one socket send turn and strand a
    // dry-run or fast flash sink at its initial byte window.
    if released_credit || response_len.is_none() {
        response_len = service.poll_for(path, response).ok().flatten();
    }
    if completed {
        response_len = service
            .poll_for(path, response)
            .ok()
            .flatten()
            .or(response_len);
    }
    response_len
}

/// Poll durable completion before a normal QUIC transmit turn.
pub(crate) unsafe fn before_poll(
    service: &mut ConnectionService,
    path: quic_lite::PathId,
    now_us: u64,
) {
    if (*core::ptr::addr_of_mut!(ACTIVE_STREAM))
        .as_ref()
        .is_some_and(|(active_path, _)| *active_path == path)
    {
        let _ = finish(service);
    }
    expire(service, now_us);
}

/// Consume completed storage work and publish the released receive window to
/// QUIC-lite. The returned opaque path tells the generic runtime only where
/// pending QUIC output should be polled.
pub(crate) unsafe fn storage_ready(
    service: &mut ConnectionService,
    now_us: u64,
) -> Result<Option<quic_lite::PathId>, ()> {
    let Some((path, stream)) = (*core::ptr::addr_of_mut!(ACTIVE_STREAM)).as_mut() else {
        return Ok(None);
    };
    let path = *path;
    let credit = stream.receive(Vec::new(), now_us)?;
    if credit != 0 {
        service
            .grant_flash_receive_window(stream.receive_window_bytes())
            .map_err(|_| ())?;
    }
    let _ = finish(service);
    Ok(Some(path))
}

/// Construct the hardware half of a shared `flash` request.
///
/// The caller still owns the signed-object GET and feeds its ordered response
/// bytes to the returned receiver. Stage2 is the one bounded raw region; all
/// application and module targets resolve through the partition table.
pub fn receiver_for_flash_request(
    request: dmesh_server::protocol::FlashRequest<'_>,
) -> Result<SignedObjectFlashReceiver, FlashSinkError> {
    Ok(SignedObjectFlashReceiver::new(sink_for_flash_request(
        request,
    )?))
}

fn sink_for_flash_request(
    request: dmesh_server::protocol::FlashRequest<'_>,
) -> Result<EspPartitionSink, FlashSinkError> {
    let target = request.object.target;
    let dry_run = request.dry_run;
    let sink = match target {
        2 => {
            let address = request.address.unwrap_or(0) as usize;
            let capacity = STAGE2_REGION_BYTES
                .checked_sub(address)
                .ok_or(FlashSinkError::AddressOverrideUnsupported)?;
            EspPartitionSink::new_raw(address, capacity, target, dry_run)
        }
        6 if request.address.is_none() => EspPartitionSink::new(b"main\0", target, dry_run),
        3 if request.address.is_none() => EspPartitionSink::new(b"recovery_app\0", target, dry_run)
            .or_else(|| EspPartitionSink::new(b"recovery\0", target, dry_run)),
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
    .ok_or(FlashSinkError::PartitionUnavailable)?;
    Ok(sink)
}

/// Allocate the large flash receiver directly in heap storage.  The receiver
/// is an application sink; stream admission, ACKs, retransmission, and PTO
/// remain entirely in `dmesh_server::transport::ObjectClient`/QUIC-lite.
pub fn new_boxed_receiver(
    request: dmesh_server::protocol::FlashRequest<'_>,
) -> Result<Box<SignedObjectFlashReceiver>, FlashSinkError> {
    let sink = sink_for_flash_request(request)?;
    let raw = unsafe {
        alloc_zeroed(Layout::new::<SignedObjectFlashReceiver>()) as *mut SignedObjectFlashReceiver
    };
    if raw.is_null() {
        return Err(FlashSinkError::AllocationFailed);
    }
    unsafe {
        SignedObjectFlashReceiver::new_in_place(
            &mut *(raw.cast::<core::mem::MaybeUninit<SignedObjectFlashReceiver>>()),
            sink,
        );
        Ok(Box::from_raw(raw))
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
    // Blob slots accepted before the initial receive-credit boundary.  The
    // erase must not begin while those radio packets are still in flight:
    // ESP32-C6 flash erase pauses Wi-Fi globally even when performed by a
    // separate FreeRTOS task.  Keep the bounded jobs until the bearer has
    // ACKed that flight and flow control has stopped the sender.
    waiting_writes: Vec<FlashJob>,
    // One authenticated 4 KiB block may wait briefly for its contiguous
    // successor. `finish` flushes this job for an image whose final block is
    // short or odd, so acceptance never depends on an artificial pair.
    staged_write: Option<FlashJob>,
    erase_len: usize,
    erase_complete: bool,
    pending_jobs: usize,
    ready_credit: usize,
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
    credit: usize,
}

const FLASH_JOB_ERASE: u8 = 1;
const FLASH_JOB_WRITE: u8 = 2;
// ESP-IDF is configured to yield inside a long erase
// (`CONFIG_SPI_FLASH_YIELD_DURING_ERASE`).  Keep the whole manifest-bounded
// destination as one worker job: Recovery does not turn individual sectors
// into application events or transport scheduling decisions.  In particular,
// the range job means a completed erase is an unambiguous prerequisite for
// every queued write, rather than a sequence of 4 KiB erase/write races.

#[repr(C)]
#[derive(Clone, Copy)]
struct FlashCompletion {
    kind: u8,
    index: u32,
    data: *mut [u8; FLASH_WRITE_BATCH_BYTES],
    credit: usize,
    elapsed_us: u64,
    result: i32,
}

#[derive(Clone, Copy)]
struct FlashWorker {
    work: esp_idf_sys::QueueHandle_t,
    done: esp_idf_sys::QueueHandle_t,
}

impl FlashWorker {
    fn new() -> Option<Self> {
        let work = unsafe {
            esp_idf_sys::xQueueCreateWithCaps(
                (PENDING_FLASH_BLOCKS / FLASH_WRITE_BLOCKS + 1) as _,
                core::mem::size_of::<FlashJob>() as _,
                esp_idf_sys::MALLOC_CAP_INTERNAL as _,
            )
        };
        let done = unsafe {
            esp_idf_sys::xQueueCreateWithCaps(
                (PENDING_FLASH_BLOCKS / FLASH_WRITE_BLOCKS) as _,
                core::mem::size_of::<FlashCompletion>() as _,
                esp_idf_sys::MALLOC_CAP_INTERNAL as _,
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
                4,
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
            credit: 0,
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
            credit: 0,
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
            credit: job.credit,
            elapsed_us,
            result,
        };
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
        // The peer may now be fully ACKed and blocked solely on the receive
        // window. Wake the common connection owner explicitly; a duplicate
        // packet or loss timer is neither required nor expected.
        let _ = crate::core_runtime::schedule_storage_ready();
    }
}

fn allocate_block() -> Option<Box<[u8; FLASH_WRITE_BATCH_BYTES]>> {
    let layout = Layout::new::<[u8; FLASH_WRITE_BATCH_BYTES]>();
    let raw = unsafe { alloc_zeroed(layout) as *mut [u8; FLASH_WRITE_BATCH_BYTES] };
    (!raw.is_null()).then(|| unsafe { Box::from_raw(raw) })
}

impl EspPartitionSink {
    /// Select a partition once for a requested object target. `label` must be
    /// NUL terminated because ESP-IDF retains no owned partition name.
    pub fn new(label: &[u8], target: u8, dry_run: bool) -> Option<Self> {
        if label.is_empty() || *label.last()? != 0 {
            return None;
        }
        let partition = unsafe {
            esp_idf_sys::esp_partition_find_first(
                esp_idf_sys::esp_partition_type_t_ESP_PARTITION_TYPE_APP,
                esp_idf_sys::esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_ANY,
                label.as_ptr().cast(),
            )
        };
        if partition.is_null() {
            return None;
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
    ) -> Option<Self> {
        if capacity == 0
            || base_address % BLOCK_SIZE != 0
            || base_address.checked_add(capacity)? > STAGE2_REGION_BYTES
        {
            return None;
        }
        Self::new_storage(core::ptr::null(), base_address, capacity, target, dry_run)
    }

    fn new_storage(
        partition: *const esp_idf_sys::esp_partition_t,
        base_address: usize,
        capacity: usize,
        target: u8,
        dry_run: bool,
    ) -> Option<Self> {
        let mut free_blocks = Vec::with_capacity(if dry_run {
            0
        } else {
            PENDING_FLASH_BLOCKS / FLASH_WRITE_BLOCKS
        });
        if !dry_run {
            for _ in 0..PENDING_FLASH_BLOCKS / FLASH_WRITE_BLOCKS {
                free_blocks.push(allocate_block()?);
            }
        }
        let worker = if dry_run {
            None
        } else {
            Some(FlashWorker::new()?)
        };
        Some(Self {
            partition,
            base_address,
            capacity,
            target,
            dry_run,
            free_blocks,
            worker,
            waiting_writes: Vec::with_capacity(if dry_run {
                0
            } else {
                PENDING_FLASH_BLOCKS / FLASH_WRITE_BLOCKS
            }),
            staged_write: None,
            erase_len: 0,
            erase_complete: dry_run,
            pending_jobs: 0,
            ready_credit: 0,
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
        let worker = self.worker.ok_or(())?;
        if !worker.enqueue(FlashJob {
            kind: FLASH_JOB_ERASE,
            partition: self.partition,
            base_address: self.base_address,
            index: 0,
            len: erase_len,
            data: core::ptr::null_mut(),
            credit: 0,
        }) {
            return Err(());
        }
        self.erase_len = erase_len;
        self.pending_jobs = self.pending_jobs.saturating_add(1);
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
        }
        Ok(())
    }

    fn write_image_block(&mut self, index: u32, data: &[u8]) -> Result<(), ()> {
        if self.dry_run {
            self.release_record_credit(data.len().saturating_add(BLOCK_RECORD_OVERHEAD));
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
            job.credit = job
                .credit
                .saturating_add(data_len.saturating_add(BLOCK_RECORD_OVERHEAD));
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
            credit: data_len.saturating_add(BLOCK_RECORD_OVERHEAD),
        };
        if data_len == FLASH_WRITE_BATCH_BYTES {
            self.enqueue_write(job)
        } else {
            self.staged_write = Some(job);
            Ok(())
        }
    }

    fn release_record_credit(&mut self, credit: usize) {
        self.ready_credit = self.ready_credit.saturating_add(credit);
    }

    /// Current bounded application storage available for one more ordered
    /// stream window. QUIC-lite uses this as a sliding-window capacity, not
    /// as an increment: reporting only a just-completed record could leave a
    /// peer below its already-advertised initial window forever.
    pub fn receive_window_bytes(&self) -> usize {
        const RECORD_BYTES: usize = BLOCK_SIZE + BLOCK_RECORD_OVERHEAD;
        if self.dry_run {
            return PENDING_FLASH_BLOCKS * RECORD_BYTES;
        }
        let free_blocks = self.free_blocks.len() * FLASH_WRITE_BLOCKS;
        let staged_space = self
            .staged_write
            .as_ref()
            .map(|job| FLASH_WRITE_BATCH_BYTES.saturating_sub(job.len) / BLOCK_SIZE)
            .unwrap_or(0);
        free_blocks.saturating_add(staged_space) * RECORD_BYTES
    }

    /// Poll completed flash jobs without blocking the stream receive path.
    pub fn poll_completed(&mut self) -> Result<usize, ()> {
        if self.dry_run {
            // Dry-run mode owns no retained flash block, so all accepted
            // records are immediately reusable.
            return Ok(core::mem::take(&mut self.ready_credit));
        }
        let worker = self.worker.expect("production worker");
        while let Some(completion) = worker.take_completion() {
            self.pending_jobs = self.pending_jobs.saturating_sub(1);
            match completion.kind {
                FLASH_JOB_ERASE => {
                    self.erase_us = self.erase_us.saturating_add(completion.elapsed_us);
                    self.erase_complete = true;
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
                    self.release_record_credit(completion.credit);
                }
                _ => return Err(()),
            }
            if completion.result != esp_idf_sys::ESP_OK {
                return Err(());
            }
        }
        Ok(core::mem::take(&mut self.ready_credit))
    }

    pub fn is_durable(&self) -> bool {
        self.dry_run || (self.erase_complete && self.pending_jobs == 0)
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
        manifest: &dmesh_server::protocol::ImageManifest,
    ) -> Result<(), Self::Error> {
        if manifest.target != self.target || manifest.block_size as usize != BLOCK_SIZE {
            return Err(());
        }
        self.begin_image(manifest.image_size)
    }
    fn write_block(&mut self, index: u32, data: &[u8]) -> Result<(), Self::Error> {
        self.write_image_block(index, data)
    }
    fn finish(&mut self, _: &dmesh_server::protocol::ImageManifest) -> Result<(), Self::Error> {
        // ImageReceiver has checked each block against the authenticated
        // manifest digest before calling this hook. Recovery deliberately does
        // not re-hash the whole image: per-block proofs are its acceptance
        // rule, and avoiding the second linear hash keeps flash throughput
        // independent of image size.
        if let Some(job) = self.staged_write.take() {
            self.enqueue_write(job)?;
        }
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
