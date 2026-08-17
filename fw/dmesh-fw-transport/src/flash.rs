// IMPORTANT: This is shared no-std ESP firmware code. Record framing and
// object validation belong in dmesh-server; this file owns ESP partition I/O,
// flash-worker scheduling, and real firmware receive-credit release.
//! Application stream handler for Main flashing.
//!
//! `wifi.rs` owns the socket/bearer adapter and passes opaque transport output
//! back to the bearer. This module receives only ordered stream callbacks,
//! converts object records into image events, and writes the Main partition.

use alloc::{
    alloc::{alloc_zeroed, Layout},
    boxed::Box,
    sync::Arc,
    vec::Vec,
};
use core::ffi::c_void;
use dmesh_server::protocol::{verified_object_record_credit, ObjectRecordCredit};
use dmesh_server::protocol::{
    FixedRecordDecoder, ImageEvent, ImageReceiver, ImageSink, RecordEvents, BLOCK_SIZE,
    RECORD_BLOB, RECORD_DONE, RECORD_MANIFEST,
};
use quic_lite::{
    callback::{CallbackStreams, CopyingError, CopyingStreamEvents},
    StreamFrame,
};

pub(crate) const OBJECT_STREAM: u64 = 3;
// A 4 MiB image has at most 1024 blocks; its canonical CBOR digest table is
// below 48 KiB. This allocation is bounded and made once per transfer.
const MAX_MANIFEST_BYTES: usize = 48 * 1024;
const MAX_BLOB_RECORD_BYTES: usize = 12 + BLOCK_SIZE;
// Keep a fixed 32 KiB application pool.  The matching transport bootstrap
// credit is eight complete blob records; this leaves internal-RAM headroom for
// the manifest table, lwIP queues, Wi-Fi, and the flash worker. Returning
// credit only as this pool is reused makes the negotiated number real.
const PENDING_FLASH_BLOCKS: usize = 8;
// The ESP-IDF C6 configuration writes flash in 8 KiB chunks.  ImageReceiver
// authenticates strictly increasing block indices, so two verified 4 KiB
// blocks can safely share one worker-owned contiguous write buffer.  Four
// slots retain the same eight-record application credit as before.
const FLASH_WRITE_BLOCKS: usize = 2;
const FLASH_WRITE_BATCH_BYTES: usize = BLOCK_SIZE * FLASH_WRITE_BLOCKS;
const BLOCK_RECORD_OVERHEAD: usize = 5 + 12;
// Object transfer intentionally finishes one record before opening the next.
// The peer can therefore be flow-credit blocked just below the byte limit
// when the remaining credit cannot fit another complete blob record.
const BOOTSTRAP_ERASE_READY_BYTES: usize =
    quic_lite::RECOVERY_INITIAL_MAX_DATA as usize - (BLOCK_RECORD_OVERHEAD + BLOCK_SIZE);
type RecoveryRecordDecoder = FixedRecordDecoder<MAX_MANIFEST_BYTES, MAX_BLOB_RECORD_BYTES>;

struct RecoveryRecordSink<'a> {
    receiver: &'a mut ImageReceiver<MainSink>,
    manifest_ok: &'a mut bool,
    block_records: &'a mut usize,
    complete: &'a mut bool,
    benchmark: bool,
}

impl RecordEvents for RecoveryRecordSink<'_> {
    type Error = ();

    fn record(&mut self, kind: u8, payload: &[u8]) -> Result<(), Self::Error> {
        if kind == RECORD_MANIFEST {
            if *self.manifest_ok || self.receiver.on_manifest(payload).is_err() {
                crate::commands::send_response(b"udp manifest rejected");
                return Err(());
            }
            // The verified manifest remains in ImageReceiver's one bounded
            // allocation for the rest of this transfer.  It does not consume
            // one of the reusable flash slots, so returning its stream
            // credit cannot make the sender outrun a dynamic buffer.
            if let Some(ObjectRecordCredit::Immediate(credit)) =
                verified_object_record_credit(kind, payload.len(), self.benchmark)
            {
                self.receiver.sink_mut().release_record_credit(credit);
            }
            if !self.benchmark {
                crate::commands::send_response(b"udp manifest accepted");
            }
            *self.manifest_ok = true;
            return Ok(());
        }
        if kind == RECORD_BLOB {
            if !*self.manifest_ok {
                return Err(());
            }
            *self.block_records = self.block_records.saturating_add(1);
            // Do not emit progress here. UART/UDP logging can block for a
            // scheduler tick; even one record per sixteen blocks repeatedly
            // stalls the receive/ACK path. Completion counters are reported
            // in the final compact numeric record instead.
            if let Err(error) = self
                .receiver
                .on_block_with_hasher(payload, crate::crypto_esp::sha256_native)
            {
                crate::commands::send_response(match error {
                    dmesh_server::protocol::ImageError::Truncated => b"udp block truncated",
                    dmesh_server::protocol::ImageError::InvalidManifest => {
                        b"udp block before manifest"
                    }
                    dmesh_server::protocol::ImageError::InvalidBlock => b"udp block invalid",
                    dmesh_server::protocol::ImageError::InvalidSignature => {
                        b"udp block signature invalid"
                    }
                    dmesh_server::protocol::ImageError::Sink => b"udp flash sink failed",
                });
                return Err(());
            }
            // Production returns this credit when the flash worker gives the
            // block slot back. Benchmark mode has no worker or retained block
            // slot, so its verified record is reusable immediately. Without
            // this, a dry run advances only through the bootstrap window and
            // then correctly—but permanently—hits flow control.
            if let Some(ObjectRecordCredit::Immediate(credit)) =
                verified_object_record_credit(kind, payload.len(), self.benchmark)
            {
                self.receiver.sink_mut().release_record_credit(credit);
            }
            return Ok(());
        }
        if kind == RECORD_DONE && *self.manifest_ok {
            match self.receiver.on_done() {
                Ok(ImageEvent::Complete) => {
                    if !self.benchmark {
                        crate::commands::send_response(b"udp done record");
                    }
                    *self.complete = true;
                    if let Some(ObjectRecordCredit::Immediate(credit)) =
                        verified_object_record_credit(kind, payload.len(), self.benchmark)
                    {
                        self.receiver.sink_mut().release_record_credit(credit);
                    }
                    return Ok(());
                }
                Err(_) => {
                    crate::commands::send_response(b"udp image rejected");
                    return Err(());
                }
                Ok(_) => return Err(()),
            }
        }
        Err(())
    }
}

struct RecoveryStreamSink<'a> {
    decoder: &'a mut RecoveryRecordDecoder,
    receiver: &'a mut ImageReceiver<MainSink>,
    manifest_ok: &'a mut bool,
    block_records: &'a mut usize,
    complete: &'a mut bool,
    bytes: usize,
    benchmark: bool,
}

// ARCHITECTURAL BOUNDARY -- this adapter receives ordered application bytes
// only. It must never parse or generate datagrams, ACKs, packet numbers,
// retransmission, flow-control, or duplicate-suppression state. The
// quic-lite callback driver owns all of those transport concerns; this
// file only consumes its stream callback and reports application bytes used.
impl CopyingStreamEvents for RecoveryStreamSink<'_> {
    type Error = ();

    fn stream_chunk(
        &mut self,
        stream: u64,
        _offset: u64,
        _end: bool,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        if stream == OBJECT_STREAM {
            let mut records = RecoveryRecordSink {
                receiver: self.receiver,
                manifest_ok: self.manifest_ok,
                block_records: self.block_records,
                complete: self.complete,
                benchmark: self.benchmark,
            };
            self.decoder.push(bytes, &mut records).map_err(|_| ())?;
        } else {
            return Err(());
        }
        self.bytes = self.bytes.saturating_add(bytes.len());
        Ok(())
    }

    fn stream_finished(&mut self, _stream: u64) {}
}

struct MainSink {
    partition: *const esp_idf_sys::esp_partition_t,
    benchmark: bool,
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
    erase_started: bool,
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
        // copied pair of queue handles avoids a borrowed MainSink pointer in
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
    // owns no pointer back into FlashHandler or ImageReceiver.
    let worker = unsafe { Box::from_raw(parameter.cast::<FlashWorker>()) };
    loop {
        let mut job = FlashJob {
            kind: 0,
            partition: core::ptr::null(),
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
            FLASH_JOB_ERASE => unsafe {
                esp_idf_sys::esp_partition_erase_range(job.partition, 0, job.len)
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
    }
}

fn allocate_block() -> Option<Box<[u8; FLASH_WRITE_BATCH_BYTES]>> {
    let layout = Layout::new::<[u8; FLASH_WRITE_BATCH_BYTES]>();
    let raw = unsafe { alloc_zeroed(layout) as *mut [u8; FLASH_WRITE_BATCH_BYTES] };
    (!raw.is_null()).then(|| unsafe { Box::from_raw(raw) })
}

impl MainSink {
    fn new(benchmark: bool) -> Option<Self> {
        let label = b"main\0";
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
        let mut free_blocks = Vec::with_capacity(if benchmark {
            0
        } else {
            PENDING_FLASH_BLOCKS / FLASH_WRITE_BLOCKS
        });
        if !benchmark {
            for _ in 0..PENDING_FLASH_BLOCKS / FLASH_WRITE_BLOCKS {
                free_blocks.push(allocate_block()?);
            }
        }
        let worker = if benchmark {
            None
        } else {
            Some(FlashWorker::new()?)
        };
        Some(Self {
            partition,
            benchmark,
            free_blocks,
            worker,
            waiting_writes: Vec::with_capacity(if benchmark {
                0
            } else {
                PENDING_FLASH_BLOCKS / FLASH_WRITE_BLOCKS
            }),
            staged_write: None,
            erase_len: 0,
            erase_started: false,
            erase_complete: benchmark,
            pending_jobs: 0,
            ready_credit: 0,
            erase_us: 0,
            write_us: 0,
            writes: 0,
        })
    }

    fn stats(&self) -> (u64, u64, u64) {
        (self.erase_us, self.write_us, self.writes)
    }

    fn begin_image(&mut self, size: u32) -> Result<(), ()> {
        if size == 0 || size > unsafe { (*self.partition).size } {
            return Err(());
        }
        // Erase once after the verified manifest has bounded the destination.
        // Per-4 KiB erase calls stall the same task that drains lwIP and emits
        // transport ACKs, multiplying radio pauses across the whole image.
        let erase_len = (size as usize + BLOCK_SIZE - 1) / BLOCK_SIZE * BLOCK_SIZE;
        if erase_len > unsafe { (*self.partition).size as usize } {
            return Err(());
        }
        if self.benchmark {
            return Ok(());
        }
        self.erase_len = erase_len;
        Ok(())
    }

    /// Begin the one manifest-bounded erase only after Recovery has received
    /// the complete bootstrap receive window.  At that point `wifi.rs` has
    /// emitted its ACK/control for the final bounded packet burst, and the
    /// peer cannot inject further stream bytes until this sink returns flow
    /// credit. ESP-IDF yields internally while erasing; Recovery sees only
    /// this single application job.
    fn start_erase_after_bootstrap(
        &mut self,
        stream_bytes: usize,
        complete: bool,
    ) -> Result<(), ()> {
        if self.benchmark
            || self.erase_started
            || (!complete && stream_bytes < BOOTSTRAP_ERASE_READY_BYTES)
        {
            return Ok(());
        }
        let worker = self.worker.ok_or(())?;
        if !worker.enqueue(FlashJob {
            kind: FLASH_JOB_ERASE,
            partition: self.partition,
            index: 0,
            len: self.erase_len,
            data: core::ptr::null_mut(),
            credit: 0,
        }) {
            return Err(());
        }
        self.erase_started = true;
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
        if self.benchmark {
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

    fn flush(&mut self) -> Result<usize, ()> {
        if self.benchmark {
            // Benchmark mode skips erase/write, so accepted records are
            // immediately reusable storage.  It must return the same
            // deferred stream credit that production returns after a worker
            // completion; returning zero here stalls exactly at bootstrap
            // credit and makes the object benchmark a false throughput test.
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

    fn durable(&self) -> bool {
        self.benchmark || (self.erase_complete && self.pending_jobs == 0)
    }

    /// Compact post-DONE diagnostic: queued worker operations.  It is read
    /// only while Recovery waits for durability, never from the packet path.
    fn pending_jobs(&self) -> u64 {
        self.pending_jobs as u64
    }
}

impl ImageSink for MainSink {
    type Error = ();
    fn begin(
        &mut self,
        manifest: &dmesh_server::protocol::ImageManifest,
    ) -> Result<(), Self::Error> {
        if manifest.target != 6 || manifest.block_size as usize != BLOCK_SIZE {
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

pub(crate) struct FlashHandler {
    records: Box<RecoveryRecordDecoder>,
    ordered: CallbackStreams<Arc<Vec<u8>>>,
    receiver: ImageReceiver<MainSink>,
    manifest_ok: bool,
    delivered_bytes: usize,
    block_records: usize,
    complete: bool,
    benchmark: bool,
}

impl FlashHandler {
    pub(crate) fn new(benchmark: bool) -> Option<Self> {
        // `RecoveryRecordDecoder::new()` contains a 48 KiB manifest array.
        // Constructing it as the argument to Box::new first places that array
        // on Recovery's 16 KiB main-task stack, causing a stack-protection
        // reset under the first stream callback. All-zero bytes are exactly
        // its initial state, so allocate the one bounded decoder directly in
        // the heap and never create a stack-sized temporary.
        let layout = Layout::new::<RecoveryRecordDecoder>();
        let raw = unsafe { alloc_zeroed(layout) as *mut RecoveryRecordDecoder };
        if raw.is_null() {
            return None;
        }
        Some(Self {
            records: unsafe { Box::from_raw(raw) },
            // The host may have a full bounded transport window in flight.
            // Keep enough retained stream bytes for that window so transport
            // can deliver out of order and the callback layer can release
            // them in offset order without dropping an already-ACKed packet.
            // Keep the receiver's retained out-of-order bytes above the
            // advertised host sender window. A loss of the first packet in a
            // full burst must not turn into a callback-capacity failure.
            ordered: CallbackStreams::new(2, quic_lite::RECOVERY_REORDER_CAPACITY_BYTES),
            // Recovery currently has no configured image-signing public key.
            // ImageReceiver therefore fails closed on a signed manifest;
            // provisioning a key must provide a SignatureVerifier here rather
            // than bypassing the manifest check.
            receiver: ImageReceiver::new(MainSink::new(benchmark)?),
            manifest_ok: false,
            delivered_bytes: 0,
            block_records: 0,
            complete: false,
            benchmark,
        })
    }

    pub(crate) fn benchmark_stats(&self) -> (usize, usize) {
        (self.delivered_bytes, self.block_records)
    }

    pub(crate) fn flash_stats(&mut self) -> (u64, u64, u64) {
        self.receiver.sink_mut().stats()
    }

    /// Collect flash-worker completions after the bearer has emitted an ACK
    /// for a drained burst. Returned bytes have a reusable storage slot, so
    /// the bearer may return only that transport stream credit.
    pub(crate) fn flush_pending(&mut self) -> Result<usize, ()> {
        self.receiver.sink_mut().flush()
    }

    /// Start erase after the bearer has ACKed the complete bounded bootstrap
    /// receive window.  This is application storage scheduling only; it does
    /// not inspect or encode transport control.
    pub(crate) fn start_erase_after_bootstrap(&mut self) -> Result<(), ()> {
        self.receiver
            .sink_mut()
            .start_erase_after_bootstrap(self.delivered_bytes, self.complete)
    }

    pub(crate) fn durable(&mut self) -> bool {
        self.receiver.sink_mut().durable()
    }

    pub(crate) fn pending_flash_jobs(&mut self) -> u64 {
        self.receiver.sink_mut().pending_jobs()
    }

    /// Consume one already accepted stream callback. Datagram scheduling,
    /// transport control, and flow credit remain entirely in quic-lite.
    pub(crate) fn handle_stream(&mut self, stream: StreamFrame<'_>) -> Result<(bool, usize), ()> {
        if stream.id != OBJECT_STREAM {
            return Ok((false, 0));
        }
        let (consumed, complete) = {
            let mut complete = false;
            let mut sink = RecoveryStreamSink {
                decoder: &mut self.records,
                receiver: &mut self.receiver,
                manifest_ok: &mut self.manifest_ok,
                block_records: &mut self.block_records,
                complete: &mut complete,
                bytes: 0,
                benchmark: self.benchmark,
            };
            let callback_result = self.ordered.receive_copying_borrowed(
                stream.id,
                stream.data,
                stream.offset,
                stream.fin,
                || Arc::new(stream.data.to_vec()),
                &mut sink,
            );
            if let Err(error) = callback_result {
                crate::commands::send_response(match error {
                    CopyingError::Transport(error) => match error {
                        quic_lite::callback::CallbackError::InvalidOverlap => {
                            b"udp callback invalid overlap"
                        }
                        quic_lite::callback::CallbackError::InvalidFin => {
                            b"udp callback invalid fin"
                        }
                        quic_lite::callback::CallbackError::InvalidCompletion => {
                            b"udp callback invalid completion"
                        }
                        quic_lite::callback::CallbackError::Capacity => b"udp callback capacity",
                        quic_lite::callback::CallbackError::Reset => b"udp callback reset",
                    },
                    CopyingError::Callback(_) => b"udp callback application failed",
                });
                return Err(());
            }
            (sink.bytes, complete)
        };
        self.delivered_bytes = self.delivered_bytes.saturating_add(consumed);
        self.complete |= complete;
        // The caller uses this count only to distinguish a newly delivered
        // range from CallbackStreams' zero-byte retransmission result. Flow
        // credit remains deferred until `flush_pending()` releases storage.
        Ok((complete, consumed))
    }
}
