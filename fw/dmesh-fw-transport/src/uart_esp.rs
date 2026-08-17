use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
// IMPORTANT: This is shared no-std ESP firmware code. PPP marker semantics
// and classification are in quic-lite; this file owns ESP USB/UART queues and
// the nonblocking FreeRTOS L2 task shared by Recovery and Main.

use crate::{classify_ppp_payload, PppIngress};
use uart_codec::codec::{encode_payload, Decoder as UartDecoder};

/// UART is an L2 bearer and therefore uses the transport MTU rather than a
/// separate 512-byte diagnostic limit. PPP escaping is framing overhead, not
/// an additional fragmentation layer.
pub const UART_MAX_PACKET: usize = crate::TRANSPORT_MTU + 1;
const UART_MAX_WIRE: usize = 2 * UART_MAX_PACKET + 2;
pub(crate) const UART_EGRESS_CAPACITY: usize = 8;
// USB-JTAG is a packetized USB transport on C6, not a 115200 UART.  One PPP
// frame can grow to roughly twice the transport MTU through escaping. Retain
// one normal eight-packet transport flight so the FreeRTOS L2 task never
// waits on console-sized 512-byte buffers.
#[cfg(target_arch = "riscv32")]
const USB_JTAG_BUFFER_SIZE: u32 = (8 * (2 * UART_MAX_PACKET + 2)) as u32;
static TRANSPORT_INGRESS_QUEUE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static UART_EGRESS_QUEUE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static UART_EGRESS_QUEUED: AtomicUsize = AtomicUsize::new(0);
pub const COMMAND_GRACE_TICKS: u32 = 8000;

/// A complete PPP-decoded QUIC-lite datagram. The physical UART task queues
/// this without interpreting streams; the shared transport owner supplies
/// DCID routing, callbacks, ACKs, and retransmission.
#[repr(C)]
struct QueuedTransportPacket {
    len: u16,
    bytes: [u8; UART_MAX_PACKET],
}

/// One fully framed PPP record waiting for the dedicated serial task.  No
/// transport worker may block in a USB/UART driver call; a full queue is
/// immediate L2 backpressure and is reported to path selection above it.
#[repr(C)]
struct QueuedUartWire {
    len: u16,
    bytes: [u8; UART_MAX_WIRE],
}

pub unsafe fn init_transport_ingress_queue() -> bool {
    if !TRANSPORT_INGRESS_QUEUE.load(Ordering::Acquire).is_null() {
        return true;
    }
    let queue = esp_idf_sys::xQueueCreateWithCaps(
        // This is receive capacity feedback for the USB L2 path, not a
        // command backlog. Keep enough complete MTU packets for USB bursts
        // while retaining a bounded, explicitly lossy bearer.
        16,
        core::mem::size_of::<QueuedTransportPacket>() as _,
        esp_idf_sys::MALLOC_CAP_INTERNAL as _,
    );
    if queue.is_null() {
        return false;
    }
    match TRANSPORT_INGRESS_QUEUE.compare_exchange(
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

pub unsafe fn init_uart_egress_queue() -> bool {
    if !UART_EGRESS_QUEUE.load(Ordering::Acquire).is_null() {
        return true;
    }
    let queue = esp_idf_sys::xQueueCreateWithCaps(
        UART_EGRESS_CAPACITY as _,
        core::mem::size_of::<QueuedUartWire>() as _,
        esp_idf_sys::MALLOC_CAP_INTERNAL as _,
    );
    if queue.is_null() {
        return false;
    }
    match UART_EGRESS_QUEUE.compare_exchange(
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

/// Immediate egress capacity suitable for `quic_lite::PathCapacity`. This is
/// local L2 feedback, not stream credit: the transport remains responsible
/// for end-to-end ACK, retransmission, and flow control.
pub(crate) fn transport_egress_capacity() -> (usize, usize) {
    (
        UART_EGRESS_QUEUED.load(Ordering::Acquire),
        UART_EGRESS_CAPACITY,
    )
}

fn enqueue_uart_wire(wire: &[u8]) -> bool {
    if wire.is_empty() || wire.len() > UART_MAX_WIRE {
        return false;
    }
    let queue = UART_EGRESS_QUEUE.load(Ordering::Acquire);
    if queue.is_null() {
        return false;
    }
    let mut queued = QueuedUartWire {
        len: wire.len() as u16,
        bytes: [0; UART_MAX_WIRE],
    };
    queued.bytes[..wire.len()].copy_from_slice(wire);
    // Increment before waking the serial task through xQueueGenericSend: the
    // receiver has higher scheduling priority and may dequeue immediately.
    // A failed send rolls the provisional count back below.
    UART_EGRESS_QUEUED.fetch_add(1, Ordering::AcqRel);
    let accepted = unsafe {
        esp_idf_sys::xQueueGenericSend(
            queue.cast(),
            (&queued as *const QueuedUartWire).cast(),
            0,
            0,
        ) == 1
    };
    if !accepted {
        UART_EGRESS_QUEUED.fetch_sub(1, Ordering::AcqRel);
    }
    accepted
}

fn dequeue_uart_wire(out: &mut QueuedUartWire) -> bool {
    let queue = UART_EGRESS_QUEUE.load(Ordering::Acquire);
    if queue.is_null()
        || unsafe {
            esp_idf_sys::xQueueReceive(queue.cast(), (out as *mut QueuedUartWire).cast(), 0)
        } != 1
    {
        return false;
    }
    UART_EGRESS_QUEUED.fetch_sub(1, Ordering::AcqRel);
    let len = usize::from(out.len);
    len != 0 && len <= UART_MAX_WIRE
}

/// Non-blocking ingress from the UART FreeRTOS task. A full queue is an
/// explicit lossy-path drop; it must never wait for stream credit or Wi-Fi.
pub(crate) fn enqueue_transport_packet(packet: &[u8]) -> bool {
    if packet.is_empty() || packet.len() > UART_MAX_PACKET - 1 {
        return false;
    }
    let queue = TRANSPORT_INGRESS_QUEUE.load(Ordering::Acquire);
    if queue.is_null() {
        return false;
    }
    let mut queued = QueuedTransportPacket {
        len: packet.len() as u16,
        bytes: [0; UART_MAX_PACKET],
    };
    queued.bytes[..packet.len()].copy_from_slice(packet);
    unsafe {
        esp_idf_sys::xQueueGenericSend(
            queue.cast(),
            (&queued as *const QueuedTransportPacket).cast(),
            0,
            0,
        ) == 1
    }
}

pub(crate) fn dequeue_transport_packet(out: &mut [u8; UART_MAX_PACKET]) -> Option<usize> {
    let queue = TRANSPORT_INGRESS_QUEUE.load(Ordering::Acquire);
    if queue.is_null() {
        return None;
    }
    let mut queued = QueuedTransportPacket {
        len: 0,
        bytes: [0; UART_MAX_PACKET],
    };
    if unsafe {
        esp_idf_sys::xQueueReceive(
            queue.cast(),
            (&mut queued as *mut QueuedTransportPacket).cast(),
            0,
        )
    } != 1
    {
        return None;
    }
    let len = usize::from(queued.len);
    if len == 0 || len > UART_MAX_PACKET - 1 {
        return None;
    }
    out[..len].copy_from_slice(&queued.bytes[..len]);
    Some(len)
}

/// Emit one complete QUIC-lite packet on the physical UART. This is an ESP32
/// adapter only: the marker and PPP framing are L2 details, while routing and
/// retransmission remain in the shared connection owner.
pub(crate) fn send_transport_packet(packet: &[u8]) -> bool {
    let mut payload = [0u8; UART_MAX_PACKET];
    let Some(used) = crate::encode_uart_transport_payload(packet, &mut payload) else {
        return false;
    };
    let Ok(wire) = encode_payload(&payload[..used], UART_MAX_PACKET) else {
        return false;
    };
    enqueue_uart_wire(&wire)
}

/// Write one opaque non-transport PPP record. The UART adapter does not
/// inspect CBOR, text, service tags, or command responses: those are
/// dispatcher responsibilities.
pub fn send_direct_record(record: &[u8]) -> bool {
    if record.is_empty() || record.len() > UART_MAX_PACKET {
        return false;
    }
    let Ok(wire) = encode_payload(record, UART_MAX_PACKET) else {
        return false;
    };
    enqueue_uart_wire(&wire)
}

#[cfg(target_arch = "riscv32")]
fn write_usb(bytes: &[u8]) -> i32 {
    unsafe {
        // The queue owner never waits for USB. A partial write remains at the
        // head of the task-local frame until it is complete, preserving PPP
        // record order and avoiding a 100-tick transport-worker stall.
        esp_idf_sys::usb_serial_jtag_write_bytes(bytes.as_ptr().cast(), bytes.len(), 0)
    }
}
#[cfg(not(target_arch = "riscv32"))]
fn write_usb(bytes: &[u8]) -> i32 {
    unsafe {
        esp_idf_sys::uart_write_bytes(
            esp_idf_sys::uart_port_t_UART_NUM_0,
            bytes.as_ptr().cast(),
            bytes.len(),
        ) as i32
    }
}

#[cfg(target_arch = "riscv32")]
fn read_usb(bytes: &mut [u8], ticks_to_wait: u32) -> i32 {
    unsafe {
        esp_idf_sys::usb_serial_jtag_read_bytes(
            bytes.as_mut_ptr().cast(),
            bytes.len() as u32,
            ticks_to_wait,
        )
    }
}
#[cfg(not(target_arch = "riscv32"))]
fn read_usb(bytes: &mut [u8], ticks_to_wait: u32) -> i32 {
    unsafe {
        esp_idf_sys::uart_read_bytes(
            esp_idf_sys::uart_port_t_UART_NUM_0,
            bytes.as_mut_ptr().cast(),
            bytes.len() as u32,
            ticks_to_wait,
        )
    }
}

#[cfg(target_arch = "riscv32")]
pub fn install_console() {
    unsafe {
        let mut config = esp_idf_sys::usb_serial_jtag_driver_config_t {
            tx_buffer_size: USB_JTAG_BUFFER_SIZE,
            rx_buffer_size: USB_JTAG_BUFFER_SIZE,
        };
        let _ = esp_idf_sys::usb_serial_jtag_driver_install(&mut config);
    }
}
#[cfg(not(target_arch = "riscv32"))]
pub fn install_console() {}

pub unsafe extern "C" fn task_entry(_argument: *mut c_void) {
    command_task();
}

/// Dedicated nonblocking UART L2 task. It owns only PPP decode and bounded
/// ingress queues; all direct-record and QUIC-lite dispatch happens above it.
fn command_task() {
    let mut decoder = UartDecoder::with_max(UART_MAX_PACKET);
    let mut bytes = [0u8; 256];
    let mut pending = QueuedUartWire {
        len: 0,
        bytes: [0; UART_MAX_WIRE],
    };
    let mut pending_offset = 0usize;
    let mut has_pending = false;
    loop {
        if !has_pending && dequeue_uart_wire(&mut pending) {
            has_pending = true;
            pending_offset = 0;
        }
        if has_pending {
            let pending_len = usize::from(pending.len);
            let written = write_usb(&pending.bytes[pending_offset..pending_len]);
            if written > 0 {
                pending_offset = pending_offset
                    .saturating_add(written as usize)
                    .min(pending_len);
            }
            if pending_offset == pending_len {
                has_pending = false;
            }
        }
        // A pending egress frame must not turn a receive poll into a whole
        // RTOS-tick wait. USB backpressure is driven by a cooperative yield
        // below while USB RX stays responsive.
        let count = read_usb(&mut bytes, if has_pending { 0 } else { 1 });
        if count <= 0 {
            unsafe {
                esp_idf_sys::vTaskDelay(if has_pending { 0 } else { 1 });
            }
            continue;
        }
        if let Ok(records) = decoder.push(&bytes[..count as usize]) {
            for record in records {
                // Stage2 and Recovery's direct maintenance controls remain
                // CBOR-over-PPP. Transport-marked packets are deliberately
                // not fed into that parser: their stream dispatch belongs to
                // the shared transport runtime introduced above this shell.
                match classify_ppp_payload(&record) {
                    Ok(PppIngress::DirectRecord(record)) => {
                        // Direct CBOR (including Stage2 controls) uses the
                        // bearer-neutral bounded dispatcher queue. The UART task
                        // neither decodes a command nor waits for its reply.
                        let _ = crate::command_esp::enqueue_direct_record(record);
                    }
                    Ok(PppIngress::Transport(packet)) => {
                        let _ = enqueue_transport_packet(packet);
                    }
                    Err(_) => {}
                }
            }
        }
    }
}
