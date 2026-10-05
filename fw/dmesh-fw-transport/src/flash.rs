//! Bearer-neutral flash handling for Main and Recovery.
//!
//! `object.flash` is an ordinary registered stream handler (`POST /flash`): a request header
//! carrying cpu, target, destination and the content length, then the image as the raw request
//! body, then FIN, answered with a terminal response header. The shared handler stream layer owns
//! header parsing and body delivery; this module owns only request admission and durable partition
//! writes, as a body sink that knows its own block size.

use alloc::{boxed::Box, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use dmesh_server::cbor::FieldValue::{self, Unsigned as U, Text as T, Null};
use dmesh_server::object_transfer::{FlashStartError, ImageSink, ImageWriter};

const STAGE2_REGION_BYTES: usize = 0x7000;
/// The write unit and erase granularity this sink offers to the shared writer.
const BLOCK_SIZE: usize = 4096;
const FLASH_PROGRESS_INTERVAL_MS: u64 = 5_000;

type Receiver = ImageWriter<EspPartitionSink>;

/// Application progress of the one active transfer, for periodic reports.
struct FlashProgress {
    request_id: u64,
    association: Option<quic_lite::QuicAssociation>,
    stream_id: Option<u64>,
    received: u64,
    last_progress_ms: u64,
    started_ms: u64,
    last_report_ms: u64,
}

static mut PROGRESS: Option<FlashProgress> = None;
static TRANSFER_ACTIVE: AtomicBool = AtomicBool::new(false);
static DURABLE_COMPLETED: AtomicBool = AtomicBool::new(false);

fn progress() -> &'static mut Option<FlashProgress> {
    // The QUIC owner task is the only caller.
    unsafe { &mut *core::ptr::addr_of_mut!(PROGRESS) }
}

/// The ESP platform for the shared `object.flash` handler.
pub struct EspFlashPlatform;

/// The receiver owns raw ESP partition pointers. Main drives every handler
/// stream from one owner task, so it is never used from two threads.
struct OwnerOnly<T>(T);
unsafe impl<T> Send for OwnerOnly<T> {}

/// The request body of one flash operation.
struct FlashSink {
    receiver: OwnerOnly<Box<Receiver>>,
    request_id: u64,
    dry_run: bool,
    received: u64,
    ended: bool,
}

impl dmesh_server::object_transfer::FlashPlatform for EspFlashPlatform {
    fn start(
        &self,
        request: dmesh_server::object_transfer::FlashRequest<'_>,
        id: u64,
        context: dmesh_server::registry::CallContext,
    ) -> Result<Box<dyn dmesh_server::stream::BodySink>, dmesh_server::object_transfer::FlashStartError>
    {
        if TRANSFER_ACTIVE.load(Ordering::Acquire) {
            return Err(FlashStartError::Busy);
        }
        let receiver = new_receiver(request)?;
        DURABLE_COMPLETED.store(false, Ordering::Release);
        *progress() = Some(FlashProgress {
            request_id: id,
            association: context.association,
            stream_id: context.stream_id,
            received: 0,
            last_progress_ms: now_ms(),
            started_ms: now_ms(),
            last_report_ms: now_ms(),
        });
        set_transfer_active(true);
        if let (Some(association), Some(stream_id)) = (context.association, context.stream_id) {
            log_flash_event(
                "admitted",
                id,
                association,
                stream_id,
                0,
                0,
                "result=accepted",
            );
        }
        Ok(Box::new(FlashSink {
            receiver: OwnerOnly(receiver),
            request_id: id,
            dry_run: request.dry_run,
            received: 0,
            ended: false,
        }))
    }
}

impl FlashSink {
    fn end(&mut self) {
        if !self.ended {
            self.ended = true;
            *progress() = None;
            set_transfer_active(false);
        }
    }

    fn context(&self) -> (Option<quic_lite::QuicAssociation>, Option<u64>) {
        progress()
            .as_ref()
            .map_or((None, None), |progress| (progress.association, progress.stream_id))
    }
}

impl dmesh_server::stream::BodySink for FlashSink {
    fn write(&mut self, chunk: &[u8], _fin: bool) -> Result<usize, Vec<u8>> {
        match self.receiver.0.write(chunk) {
            Ok(()) => {
                let consumed = chunk.len();
                self.received = self.received.saturating_add(consumed as u64);
                if let Some(progress) = progress().as_mut() {
                    progress.received = self.received;
                    if consumed != 0 {
                        progress.last_progress_ms = now_ms();
                    }
                }
                Ok(consumed)
            }
            Err(error) => {
                let (association, stream_id) = self.context();
                log_receiver_error(
                    self.request_id,
                    association,
                    stream_id,
                    self.received,
                    &error,
                );
                self.end();
                Err(flash_result(self.request_id, b"flash object rejected", true))
            }
        }
    }

    fn finish(mut self: Box<Self>) -> dmesh_server::stream::Response {
        let (association, stream_id) = self.context();
        let result = self.receiver.0.finish();
        let complete = result.is_ok() && self.receiver.0.is_complete();
        if let (Some(association), Some(stream_id)) = (association, stream_id) {
            log_flash_event(
                if complete { "complete" } else { "rejected" },
                self.request_id,
                association,
                stream_id,
                self.received,
                self.received,
                if complete {
                    "result=ok"
                } else {
                    "reason=object_validation"
                },
            );
        }
        let handoff_after_response = complete && !self.dry_run;
        self.end();
        let response = dmesh_server::stream::Response::header(if complete {
            flash_result(self.request_id, b"flash complete", false)
        } else {
            flash_result(self.request_id, b"flash object rejected", true)
        });
        if handoff_after_response {
            response.after_finish(|| DURABLE_COMPLETED.store(true, Ordering::Release))
        } else {
            response
        }
    }

    fn abort(mut self: Box<Self>) {
        let (association, stream_id) = self.context();
        if let (Some(association), Some(stream_id)) = (association, stream_id) {
            log_flash_event(
                "idle_timeout",
                self.request_id,
                association,
                stream_id,
                self.received,
                self.received,
                "reason=no_application_progress",
            );
        }
        self.receiver.0.abort();
        self.end();
    }
}

impl Drop for FlashSink {
    fn drop(&mut self) {
        self.end();
    }
}

/// Whether the exclusive object writer currently owns a transfer.
pub fn transfer_active() -> bool {
    TRANSFER_ACTIVE.load(Ordering::Acquire)
}

/// Observe successful durable completion followed by finishing the ordinary
/// handler response. Recovery uses this edge to hand
/// control back to Stage2; Main simply leaves the updated partition in place.
pub fn take_durable_flash_completion() -> bool {
    DURABLE_COMPLETED.swap(false, Ordering::AcqRel)
}

fn set_transfer_active(active: bool) {
    if TRANSFER_ACTIVE.swap(active, Ordering::AcqRel) != active {
        // Pause optional NAN sidecar work while the object receiver is
        // erasing/writing. This changes no bearer registration or selection.
        crate::wifi_nan_dw_capture_esp::set_nan_action_tx_suppressed(active);
        crate::wifi_nan_dw_capture_esp::set_nan_capture_suspended(active);
        crate::main_runtime::request_deadline_recheck();
    }
}

/// Earliest application progress report, for the existing QUIC owner timer.
pub(crate) fn next_report_delay_ms(now: u64) -> Option<u32> {
    let active = progress().as_ref()?;
    Some(
        active
            .last_report_ms
            .saturating_add(FLASH_PROGRESS_INTERVAL_MS)
            .saturating_sub(now)
            .min(u64::from(u32::MAX)) as u32,
    )
}

/// Report application byte progress alongside QUIC transport counters.
pub(crate) fn report_progress(
    now: u64,
    mut telemetry: impl FnMut(quic_lite::QuicAssociation) -> Option<quic_lite::AssociationTelemetry>,
) -> bool {
    let Some(session) = progress().as_mut() else {
        return false;
    };
    if now
        < session
            .last_report_ms
            .saturating_add(FLASH_PROGRESS_INTERVAL_MS)
    {
        return false;
    }
    let snapshot = session.association.and_then(|association| telemetry(association));
    let idle_ms = now.saturating_sub(session.last_progress_ms);
    let elapsed_ms = now.saturating_sub(session.started_ms);
    emit_event("object_flash.progress", &[
        (1, U(session.request_id)), (2, session.stream_id.map(U).unwrap_or(Null)),
        (3, U(session.received)), (4, U(elapsed_ms)), (5, U(idle_ms)),
    ]);
    if let Some(snapshot) = snapshot {
        let stats = snapshot.transport;
        emit_event("object_flash.quic_progress", &[
            (1, U(session.request_id)), (2, session.stream_id.map(U).unwrap_or(Null)),
            (10, U(stats.received_packets)), (11, U(stats.sent_packets)),
            (12, U(stats.sent_stream_packets)), (13, U(stats.sent_control_packets)),
            (14, snapshot.largest_acked_by_peer.map(|pn| U(u64::from(pn))).unwrap_or(Null)),
            (15, U(snapshot.bytes_in_flight)), (16, U(stats.retransmitted_packets)),
            (17, U(stats.loss_events)), (18, U(stats.inferred_missing_packets)),
            (19, U(stats.duplicate_packets)), (20, U(stats.submission_failures)),
            (21, U(stats.stream_packets)), (22, U(stats.control_packets)),
            (23, U(stats.out_of_order_packets)), (24, U(snapshot.peer_max_data)),
            (25, U(snapshot.peer_sent_data)), (26, U(stats.ack_ranges_dropped)),
            (27, U(stats.pto_retransmitted_packets)),
        ]);
    } else {
        emit_event("object_flash.quic_progress", &[(1, U(session.request_id)), (10, Null)]);
    }
    session.last_report_ms = now;
    true
}

/// Temporary debug report: owner deadline, packet pressure, and UDP6 adapter
/// counters. Identical for Main and Recovery; UDP counters are explicitly
/// named and are not attributed to the association's other bearers.
pub(crate) fn report_owner_progress(now: u64, deadline_ms: Option<u64>, pool_available: usize) {
    let (rx, drops, invalid, udp_tx, frames_tx, failures) = crate::wifi_raw_udp6_esp::stats();
    let memory = crate::shared_ingress_esp::memory_stats();
    let _ = now;
    emit_event("object_flash.owner_progress", &[
        (1, deadline_ms.map(U).unwrap_or(Null)), (2, U(pool_available as u64)),
        (3, U(u64::from(rx))), (4, U(u64::from(drops))), (5, U(u64::from(invalid))),
        (6, U(u64::from(udp_tx))), (7, U(u64::from(frames_tx))), (8, U(u64::from(failures))),
        (9, U(u64::from(memory.free_internal_bytes))),
        (10, U(u64::from(memory.min_free_internal_bytes))),
        (11, U(u64::from(memory.largest_internal_block_bytes))),
    ]);
}

/// The terminal `POST /flash` response header: status 200 with the result text, or 400 with the
/// error text.
fn flash_result(request_id: u64, message: &[u8], error: bool) -> Vec<u8> {
    let mut response = vec![0; message.len().saturating_add(64)];
    let used = dmesh_server::http::encode_response(
        dmesh_server::http::verb::POST,
        request_id,
        if error { 400 } else { 200 },
        message,
        &mut response,
    )
    .unwrap_or(0);
    response.truncate(used);
    response
}

fn now_ms() -> u64 {
    (unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 }) / 1_000
}

pub(crate) fn log_flash_event(
    event: &str,
    request_id: u64,
    _association: quic_lite::QuicAssociation,
    stream_id: u64,
    received: u64,
    declared: u64,
    detail: &str,
) {
    emit_event("object_flash.event", &[
        (1, U(request_id)), (2, U(stream_id)), (3, U(received)),
        (4, U(declared)), (5, T(event)), (6, T(detail)),
    ]);
}

fn log_receiver_error(
    request_id: u64,
    _association: Option<quic_lite::QuicAssociation>,
    stream_id: Option<u64>,
    received: u64,
    error: &dmesh_server::object_transfer::ImageError,
) {
    use dmesh_server::object_transfer::ImageError;
    let reason = match error {
        ImageError::Allocation => "allocation", ImageError::Length => "length",
        ImageError::Sink => "sink",
    };
    emit_event("object_flash.receiver_rejected", &[
        (1, U(request_id)), (2, stream_id.map(U).unwrap_or(Null)), (3, U(received)), (4, T(reason)),
    ]);
}

fn emit_event(kind: &str, fields: &[(u64, FieldValue<'_>)]) {
    static SEQUENCE: AtomicU32 = AtomicU32::new(0);
    let mut out = [0u8; 512];
    let Some(used) = dmesh_server::cbor::encode_fields(&mut out, fields) else { return; };
    let record = dmesh_server::log_watch::LogRecord {
        seq: u64::from(SEQUENCE.fetch_add(1, Ordering::Relaxed)) + 1,
        time_ms: now_ms(),
        level: if kind == "object_flash.receiver_rejected" {
            dmesh_server::log_watch::LEVEL_ERROR
        } else { dmesh_server::log_watch::LEVEL_INFO },
        source: "flash".into(),
        kind: Some(kind.into()), text: alloc::string::String::new(),
        fields: Some(out[..used].to_vec()),
    };
    let _ = crate::uart_esp::send_log_record(&record.encode());
}

/// Admit a request: the image must be for this CPU, name a writable destination, and fit it.
fn new_receiver(
    request: dmesh_server::object_transfer::FlashRequest<'_>,
) -> Result<Box<Receiver>, FlashStartError> {
    if request.object.cpu != local_cpu() {
        return Err(FlashStartError::InvalidTarget);
    }
    let sink = sink_for_request(request).map_err(|_| FlashStartError::InvalidTarget)?;
    let len = request.len as usize;
    let erase_len = len.checked_add(BLOCK_SIZE - 1).map(|n| n / BLOCK_SIZE * BLOCK_SIZE);
    if len == 0 || erase_len.is_none_or(|erase_len| erase_len > sink.capacity) {
        return Err(FlashStartError::TooLarge);
    }
    ImageWriter::try_new(sink, request.len)
        .map(Box::new)
        .map_err(|error| match error {
            dmesh_server::object_transfer::ImageError::Length => FlashStartError::TooLarge,
            _ => FlashStartError::Unsupported,
        })
}

fn sink_for_request(
    request: dmesh_server::object_transfer::FlashRequest<'_>,
) -> Result<EspPartitionSink, ()> {
    let target = request.object.target;
    let (partition_type, label, base, capacity) = match target {
        2 => {
            let address = request.address.unwrap_or(0) as usize;
            let capacity = STAGE2_REGION_BYTES.checked_sub(address).ok_or(())?;
            return EspPartitionSink::new_raw(address, capacity, target, request.dry_run);
        }
        6 if request.address.is_none() => (
            esp_idf_sys::esp_partition_type_t_ESP_PARTITION_TYPE_APP,
            b"main\0".as_slice(),
            0,
            None,
        ),
        3 if request.address.is_none() => {
            return EspPartitionSink::new_partition(
                esp_idf_sys::esp_partition_type_t_ESP_PARTITION_TYPE_APP,
                b"recovery_app\0",
                0,
                None,
                target,
                request.dry_run,
            )
            .or_else(|_| {
                EspPartitionSink::new_partition(
                    esp_idf_sys::esp_partition_type_t_ESP_PARTITION_TYPE_APP,
                    b"recovery\0",
                    0,
                    None,
                    target,
                    request.dry_run,
                )
            });
        }
        7 if request.address.is_none() => {
            let name = request.object.name.ok_or(())?;
            let (offset, size) = match name {
                b"lora" => (0x00000, 0x20000),
                b"flash" => (0x10000, 0x10000),
                b"hw" => (0x20000, 0x10000),
                b"hello" => (0x30000, 0x10000),
                _ => return Err(()),
            };
            return EspPartitionSink::new_region(b"data\0", offset, size, target, request.dry_run);
        }
        _ => return Err(()),
    };
    EspPartitionSink::new_partition(
        partition_type,
        label,
        base,
        capacity,
        target,
        request.dry_run,
    )
}

const fn local_cpu() -> u8 {
    #[cfg(target_arch = "riscv32")]
    {
        13
    }
    #[cfg(all(not(target_arch = "riscv32"), target_feature = "esp32s3ops"))]
    {
        9
    }
    #[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
    {
        0
    }
}

/// Synchronous ESP-IDF partition sink. The shared writer offers one block at a time, so writes
/// complete before their stream bytes are released.
pub struct EspPartitionSink {
    partition: *const esp_idf_sys::esp_partition_t,
    address: usize,
    capacity: usize,
    target: u8,
    dry_run: bool,
    erase: EraseTiming,
}

// All region-erase drivers in the configured ESP-IDF support 64 KiB blocks.
// Whole-chip erase must never be used for an image/partition update.
const ERASE_BLOCK_BYTES: usize = 64 * 1024;

#[derive(Default)]
struct EraseTiming {
    planned: usize,
    erased: usize,
    calls: u64,
    total_us: u64,
    longest_us: u64,
    writes_us: u64,
}

fn flash_clock_us() -> u64 {
    unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 }
}

impl EspPartitionSink {
    fn erase_next(&mut self, count: usize) -> Result<(), ()> {
        let offset = self.address.checked_add(self.erase.erased).ok_or(())?;
        let started = flash_clock_us();
        let result = unsafe {
            if self.partition.is_null() {
                esp_idf_sys::esp_flash_erase_region(core::ptr::null_mut(), offset as u32, count as u32)
            } else {
                esp_idf_sys::esp_partition_erase_range(self.partition, offset, count)
            }
        };
        let elapsed = flash_clock_us().saturating_sub(started);
        self.erase.calls += 1;
        self.erase.total_us = self.erase.total_us.saturating_add(elapsed);
        self.erase.longest_us = self.erase.longest_us.max(elapsed);
        emit_event("object_flash.erase", &[
            (1, U(progress().as_ref().map_or(0, |p| p.request_id))),
            (2, U(u64::from(self.target))), (3, U(offset as u64)),
            (4, U(count as u64)), (5, U(elapsed)), (6, U(self.erase.total_us)),
            (7, T("incremental64")),
            (8, FieldValue::Bool(result == esp_idf_sys::ESP_OK)),
        ]);
        if result != esp_idf_sys::ESP_OK { return Err(()); }
        self.erase.erased = self.erase.erased.checked_add(count).ok_or(())?;
        Ok(())
    }

    fn new_partition(
        kind: esp_idf_sys::esp_partition_type_t,
        label: &[u8],
        offset: usize,
        capacity: Option<usize>,
        target: u8,
        dry_run: bool,
    ) -> Result<Self, ()> {
        if label.last() != Some(&0) {
            return Err(());
        }
        let partition = unsafe {
            esp_idf_sys::esp_partition_find_first(
                kind,
                esp_idf_sys::esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_ANY,
                label.as_ptr().cast(),
            )
        };
        if partition.is_null() {
            return Err(());
        }
        let partition_size = unsafe { (*partition).size as usize };
        let capacity = capacity.unwrap_or_else(|| partition_size.saturating_sub(offset));
        if capacity == 0
            || offset
                .checked_add(capacity)
                .is_none_or(|end| end > partition_size)
        {
            return Err(());
        }
        Ok(Self {
            partition,
            address: offset,
            capacity,
            target,
            dry_run,
            erase: EraseTiming::default(),
        })
    }

    fn new_region(
        label: &[u8],
        offset: usize,
        capacity: usize,
        target: u8,
        dry_run: bool,
    ) -> Result<Self, ()> {
        Self::new_partition(
            esp_idf_sys::esp_partition_type_t_ESP_PARTITION_TYPE_DATA,
            label,
            offset,
            Some(capacity),
            target,
            dry_run,
        )
    }

    fn new_raw(address: usize, capacity: usize, target: u8, dry_run: bool) -> Result<Self, ()> {
        if capacity == 0
            || address % BLOCK_SIZE != 0
            || address
                .checked_add(capacity)
                .is_none_or(|end| end > STAGE2_REGION_BYTES)
        {
            return Err(());
        }
        Ok(Self {
            partition: core::ptr::null(),
            address,
            capacity,
            target,
            dry_run,
            erase: EraseTiming::default(),
        })
    }
}

impl ImageSink for EspPartitionSink {
    type Error = ();

    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn begin(&mut self, len: u32) -> Result<(), ()> {
        let image_len = len as usize;
        let erase_len = image_len.checked_add(BLOCK_SIZE - 1).ok_or(())? / BLOCK_SIZE * BLOCK_SIZE;
        if image_len == 0 || erase_len > self.capacity {
            return Err(());
        }
        if self.dry_run {
            return Ok(());
        }
        // Erase one hardware block on demand before writing into it. Keeping
        // begin nonblocking avoids the former whole-image transport pause.
        self.erase = EraseTiming { planned: erase_len, ..Default::default() };
        Ok(())
    }

    fn write_block(&mut self, index: u32, bytes: &[u8]) -> Result<(), ()> {
        if self.dry_run {
            return Ok(());
        }
        let relative = (index as usize).checked_mul(BLOCK_SIZE).ok_or(())?;
        let end = relative.checked_add(bytes.len()).ok_or(())?;
        if end > self.erase.planned { return Err(()); }
        while self.erase.erased < end {
            let base = if self.partition.is_null() { 0 } else { unsafe { (*self.partition).address as usize } };
            let address = base.checked_add(self.address).and_then(|base| base.checked_add(self.erase.erased)).ok_or(())?;
            let count = dmesh_server::object_transfer::next_erase_chunk_len(
                address, self.erase.planned - self.erase.erased, BLOCK_SIZE, ERASE_BLOCK_BYTES,
            ).ok_or(())?;
            self.erase_next(count)?;
        }
        let offset = self
            .address
            .checked_add(index as usize * BLOCK_SIZE)
            .ok_or(())?;
        let started = flash_clock_us();
        let result = unsafe {
            if self.partition.is_null() {
                esp_idf_sys::esp_flash_write(
                    core::ptr::null_mut(),
                    bytes.as_ptr().cast(),
                    offset as u32,
                    bytes.len() as u32,
                )
            } else {
                esp_idf_sys::esp_partition_write(
                    self.partition,
                    offset,
                    bytes.as_ptr().cast(),
                    bytes.len(),
                )
            }
        };
        self.erase.writes_us = self.erase.writes_us.saturating_add(flash_clock_us().saturating_sub(started));
        (result == esp_idf_sys::ESP_OK).then_some(()).ok_or(())
    }

    fn finish(&mut self) -> Result<(), ()> {
        emit_event("object_flash.storage_timing", &[
            (1, U(progress().as_ref().map_or(0, |p| p.request_id))),
            (2, U(u64::from(self.target))), (3, U(self.erase.erased as u64)),
            (4, U(self.erase.calls)), (5, U(self.erase.total_us)),
            (6, U(self.erase.longest_us)), (7, U(self.erase.writes_us)),
            (8, T("incremental64")),
        ]);
        Ok(())
    }
    fn abort(&mut self) {}
}
