//! Bearer-neutral signed-object flash handling for Main and Recovery.
//!
//! `object.flash` is an ordinary registered stream handler: a request header,
//! then the length-prefixed signed manifest and image as the raw request
//! body, then FIN, answered with a terminal response header. The shared
//! handler stream layer owns header parsing and body delivery; this module
//! owns only request admission, image verification, and durable partition
//! writes, as a body sink.

use alloc::{boxed::Box, vec, vec::Vec};
use core::{
    fmt::{self, Write},
    sync::atomic::{AtomicBool, Ordering},
};
use dmesh_server::verified_object::{BLOCK_SIZE, ImageSink, StreamingImageSink};

const STAGE2_REGION_BYTES: usize = 0x7000;
const MAX_MANIFEST_BYTES: usize = 10 * 1024;
const MAX_BLOB_RECORD_BYTES: usize = 12 + BLOCK_SIZE;
const FLASH_PROGRESS_INTERVAL_MS: u64 = 5_000;

type Receiver = dmesh_server::verified_object::SignedObjectReceiver<
    EspPartitionSink,
    dmesh_server::verified_object::NoSignatureVerifier,
    MAX_MANIFEST_BYTES,
    MAX_BLOB_RECORD_BYTES,
>;

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

impl dmesh_server::verified_object::FlashPlatform for EspFlashPlatform {
    fn start(
        &self,
        request: dmesh_server::verified_object::FlashRequest<'_>,
        id: u64,
        context: dmesh_server::registry::CallContext,
    ) -> Result<Box<dyn dmesh_server::stream::BodySink>, dmesh_server::verified_object::FlashStartError>
    {
        if TRANSFER_ACTIVE.load(Ordering::Acquire) {
            return Err(dmesh_server::verified_object::FlashStartError::Busy);
        }
        let receiver = new_receiver(request)
            .map_err(|_| dmesh_server::verified_object::FlashStartError::InvalidTarget)?;
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
        match self.receiver.0.push_ordered(chunk) {
            Ok(consumed) => {
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
        let result = self.receiver.0.finish_ordered();
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
        if complete && !self.dry_run {
            DURABLE_COMPLETED.store(true, Ordering::Release);
        }
        self.end();
        dmesh_server::stream::Response::header(if complete {
            flash_result(self.request_id, b"flash complete", false)
        } else {
            flash_result(self.request_id, b"flash object rejected", true)
        })
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

/// Observe successful durable completion. Recovery uses this edge to hand
/// control back to Stage2; Main simply leaves the updated partition in place.
pub fn take_durable_flash_completion() -> bool {
    DURABLE_COMPLETED.swap(false, Ordering::AcqRel)
}

fn set_transfer_active(active: bool) {
    if TRANSFER_ACTIVE.swap(active, Ordering::AcqRel) != active {
        // Pause optional NAN sidecar work while the signed object receiver is
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
) {
    let Some(session) = progress().as_mut() else {
        return;
    };
    if now
        < session
            .last_report_ms
            .saturating_add(FLASH_PROGRESS_INTERVAL_MS)
    {
        return;
    }
    let snapshot = session.association.and_then(|association| telemetry(association));
    let mut line = LogLine::new();
    let idle_ms = now.saturating_sub(session.last_progress_ms);
    let elapsed_ms = now.saturating_sub(session.started_ms);
    let _ = write!(
        line,
        "ts_ms={now} level=info event=object_flash.progress request_id={} association={:?} stream_id={:?} received_bytes={} elapsed_ms={} idle_ms={}",
        session.request_id,
        session.association,
        session.stream_id,
        session.received,
        elapsed_ms,
        idle_ms,
    );
    if let Some(snapshot) = snapshot {
        let stats = snapshot.transport;
        let _ = write!(
            line,
            " quic_rx={} quic_tx={} quic_tx_stream={} quic_tx_control={} quic_acked_by_peer_valid={} quic_acked_by_peer_pn={} quic_in_flight_bytes={} quic_retransmit={} quic_loss_events={} quic_rx_missing={} quic_duplicates={} quic_submission_failures={}",
            stats.received_packets,
            stats.sent_packets,
            stats.sent_stream_packets,
            stats.sent_control_packets,
            u8::from(snapshot.largest_acked_by_peer.is_some()),
            snapshot.largest_acked_by_peer.unwrap_or(0),
            snapshot.bytes_in_flight,
            stats.retransmitted_packets,
            stats.loss_events,
            stats.inferred_missing_packets,
            stats.duplicate_packets,
            stats.submission_failures,
        );
    } else {
        let _ = line.write_str(" quic=unavailable");
    }
    emit(line);
    session.last_report_ms = now;
}

fn flash_result(request_id: u64, message: &[u8], error: bool) -> Vec<u8> {
    let mut response = vec![0; message.len().saturating_add(64)];
    let used = if error {
        dmesh_server::tagged::encode_numeric_error(
            dmesh_server::verified_object::OBJECT_COMPONENT,
            dmesh_server::verified_object::OBJECT_FLASH_METHOD,
            request_id,
            message,
            &mut response,
        )
    } else {
        dmesh_server::tagged::encode_numeric_data_response(
            dmesh_server::verified_object::OBJECT_COMPONENT,
            dmesh_server::verified_object::OBJECT_FLASH_METHOD,
            request_id,
            message,
            true,
            &mut response,
        )
    }
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
    association: quic_lite::QuicAssociation,
    stream_id: u64,
    received: u64,
    declared: u64,
    detail: &str,
) {
    let mut line = LogLine::new();
    let _ = write!(
        line,
        "ts_ms={} level=info event=object_flash.{event} request_id={request_id} association={association:?} stream_id={stream_id} received_bytes={received} declared_bytes={declared} {detail}",
        now_ms()
    );
    emit(line);
}

fn log_receiver_error(
    request_id: u64,
    association: Option<quic_lite::QuicAssociation>,
    stream_id: Option<u64>,
    received: u64,
    error: &dmesh_server::verified_object::ImageError,
) {
    let mut line = LogLine::new();
    let _ = write!(
        line,
        "ts_ms={} level=error event=object_flash.receiver_rejected request_id={request_id} association={association:?} stream_id={stream_id:?} received_bytes={received} error={error:?}",
        now_ms(),
    );
    emit(line);
}

struct LogLine {
    bytes: [u8; 240],
    len: usize,
}

impl LogLine {
    const fn new() -> Self {
        Self {
            bytes: [0; 240],
            len: 0,
        }
    }
}

impl Write for LogLine {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let count = value.len().min(self.bytes.len().saturating_sub(self.len));
        self.bytes[self.len..self.len + count].copy_from_slice(&value.as_bytes()[..count]);
        self.len += count;
        Ok(())
    }
}

fn emit(line: LogLine) {
    let _ = crate::uart_esp::send_debug_text(&line.bytes[..line.len]);
}

fn new_receiver(
    request: dmesh_server::verified_object::FlashRequest<'_>,
) -> Result<Box<Receiver>, ()> {
    Receiver::try_new_boxed_with(|| sink_for_request(request).map_err(|_| ())).map_err(|_| ())
}

fn sink_for_request(
    request: dmesh_server::verified_object::FlashRequest<'_>,
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

/// Synchronous ESP-IDF partition sink. The verified-object receiver owns one
/// block at a time, so writes complete before their stream bytes are released.
pub struct EspPartitionSink {
    partition: *const esp_idf_sys::esp_partition_t,
    address: usize,
    capacity: usize,
    target: u8,
    dry_run: bool,
}

impl EspPartitionSink {
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
        })
    }
}

impl ImageSink for EspPartitionSink {
    type Error = ();

    fn begin(&mut self, manifest: &dmesh_server::verified_object::ImageManifest) -> Result<(), ()> {
        if manifest.target != self.target
            || manifest.cpu != local_cpu()
            || manifest.block_size as usize != BLOCK_SIZE
        {
            return Err(());
        }
        let image_len = manifest.image_size as usize;
        let erase_len = image_len.checked_add(BLOCK_SIZE - 1).ok_or(())? / BLOCK_SIZE * BLOCK_SIZE;
        if image_len == 0 || erase_len > self.capacity {
            return Err(());
        }
        if self.dry_run {
            return Ok(());
        }
        let result = unsafe {
            if self.partition.is_null() {
                esp_idf_sys::esp_flash_erase_region(
                    core::ptr::null_mut(),
                    self.address as u32,
                    erase_len as u32,
                )
            } else {
                esp_idf_sys::esp_partition_erase_range(self.partition, self.address, erase_len)
            }
        };
        (result == esp_idf_sys::ESP_OK).then_some(()).ok_or(())
    }

    fn write_block(&mut self, index: u32, bytes: &[u8]) -> Result<(), ()> {
        if self.dry_run {
            return Ok(());
        }
        let offset = self
            .address
            .checked_add(index as usize * BLOCK_SIZE)
            .ok_or(())?;
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
        (result == esp_idf_sys::ESP_OK).then_some(()).ok_or(())
    }

    fn finish(&mut self, _: &dmesh_server::verified_object::ImageManifest) -> Result<(), ()> {
        Ok(())
    }
    fn abort(&mut self) {}
}

impl StreamingImageSink for EspPartitionSink {
    fn poll_completed(&mut self) -> Result<dmesh_server::verified_object::StoragePoll, ()> {
        Ok(dmesh_server::verified_object::StoragePoll::Ready)
    }
}
