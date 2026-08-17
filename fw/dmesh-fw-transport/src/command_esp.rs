// IMPORTANT: This is shared no-std ESP firmware code. If command queueing or
// dispatch can be tested on a host, it belongs in dmesh-server or quic-lite.
// This file is limited to the ESP-IDF/FreeRTOS queue adapter that transfers
// direct records between L2 tasks and the single firmware command owner.

use core::{
    ffi::c_void,
    sync::atomic::{AtomicPtr, Ordering},
};

use crate::uart_esp::UART_MAX_PACKET;

static DIRECT_RECORD_QUEUE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

/// One direct (non-QUIC-lite) record awaiting the firmware command owner.
/// Stage2 selectors and the deliberately narrow emergency controls use this
/// queue. It is bearer-neutral: UART, a temporary raw datagram adapter, or a
/// future wake bearer may enqueue the same record.
#[repr(C)]
struct QueuedDirectRecord {
    len: u16,
    bytes: [u8; UART_MAX_PACKET],
}

pub unsafe fn init_direct_record_queue() -> bool {
    if !DIRECT_RECORD_QUEUE.load(Ordering::Acquire).is_null() {
        return true;
    }
    let queue = esp_idf_sys::xQueueCreateWithCaps(
        2,
        core::mem::size_of::<QueuedDirectRecord>() as _,
        esp_idf_sys::MALLOC_CAP_INTERNAL as _,
    );
    if queue.is_null() {
        return false;
    }
    match DIRECT_RECORD_QUEUE.compare_exchange(
        core::ptr::null_mut(),
        queue.cast(),
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => true,
        Err(_) => {
            esp_idf_sys::vQueueDelete(queue);
            true
        }
    }
}

/// Queue one direct record. A successful return means it is durable for the
/// command owner, not that parsing or a worker start has completed.
pub(crate) fn enqueue_direct_record(packet: &[u8]) -> bool {
    if packet.len() > UART_MAX_PACKET {
        return false;
    }
    let queue = DIRECT_RECORD_QUEUE.load(Ordering::Acquire);
    if queue.is_null() {
        return false;
    }
    let mut queued = QueuedDirectRecord {
        len: packet.len() as u16,
        bytes: [0; UART_MAX_PACKET],
    };
    queued.bytes[..packet.len()].copy_from_slice(packet);
    let accepted = unsafe {
        esp_idf_sys::xQueueGenericSend(
            queue.cast(),
            (&queued as *const QueuedDirectRecord).cast(),
            0,
            0,
        ) == 1
    };
    if accepted {
        crate::state::command_queued();
    }
    accepted
}

pub fn dequeue_direct_record(out: &mut [u8; UART_MAX_PACKET]) -> Option<usize> {
    let queue = DIRECT_RECORD_QUEUE.load(Ordering::Acquire);
    if queue.is_null() {
        return None;
    }
    let mut queued = QueuedDirectRecord {
        len: 0,
        bytes: [0; UART_MAX_PACKET],
    };
    if unsafe {
        esp_idf_sys::xQueueReceive(
            queue.cast(),
            (&mut queued as *mut QueuedDirectRecord).cast(),
            0,
        )
    } != 1
    {
        return None;
    }
    let len = usize::from(queued.len);
    if len > UART_MAX_PACKET {
        return None;
    }
    out[..len].copy_from_slice(&queued.bytes[..len]);
    Some(len)
}
