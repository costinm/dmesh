use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use dmesh_object_store::cbor::{Decoder as Cbor, Encoder as CborEncoder};
use uart_codec::codec::{encode_payload, Decoder as UartDecoder};

const RECOVERY_METHOD: u64 = 68;
pub(crate) const UART_MAX_PACKET: usize = 512;
static COMMAND_GENERATION: AtomicU32 = AtomicU32::new(0);
static UDP_COMMAND_QUEUE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static mut UDP_LOG_SINK: Option<fn(&[u8])> = None;
pub(crate) const COMMAND_GRACE_TICKS: u32 = 8000;

/// One command record transferred from the raw UDP endpoint to Recovery's
/// main owner.  UDP must never mutate the main command image directly: a
/// command can arrive while the synchronous transport worker is returning.
#[repr(C)]
struct QueuedUdpCommand {
    len: u16,
    bytes: [u8; UART_MAX_PACKET],
}

pub(crate) unsafe fn init_udp_command_queue() -> bool {
    if !UDP_COMMAND_QUEUE.load(Ordering::Acquire).is_null() {
        return true;
    }
    let queue = esp_idf_sys::xQueueCreateWithCaps(
        2,
        core::mem::size_of::<QueuedUdpCommand>() as _,
        esp_idf_sys::MALLOC_CAP_INTERNAL as _,
    );
    if queue.is_null() {
        return false;
    }
    match UDP_COMMAND_QUEUE.compare_exchange(
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

/// Queue a raw-UDP command for the main Recovery owner.  A successful return
/// means the command is durably accepted for parsing, not that a worker has
/// already been started.
pub(crate) fn enqueue_udp_command(packet: &[u8]) -> bool {
    if packet.len() > UART_MAX_PACKET {
        return false;
    }
    let queue = UDP_COMMAND_QUEUE.load(Ordering::Acquire);
    if queue.is_null() {
        return false;
    }
    let mut queued = QueuedUdpCommand {
        len: packet.len() as u16,
        bytes: [0; UART_MAX_PACKET],
    };
    queued.bytes[..packet.len()].copy_from_slice(packet);
    let accepted = unsafe {
        // xQueueSend is a FreeRTOS macro; esp-idf-sys exposes its generated
        // xQueueGenericSend entry point instead. Zero is queueSEND_TO_BACK.
        esp_idf_sys::xQueueGenericSend(
            queue.cast(),
            (&queued as *const QueuedUdpCommand).cast(),
            0,
            0,
        ) == 1
    };
    if accepted {
        // Wake main if it is waiting for the previous benchmark worker to
        // return. Parsing still happens exclusively in main.rs.
        COMMAND_GENERATION.fetch_add(1, Ordering::Release);
    }
    accepted
}

pub(crate) fn dequeue_udp_command(out: &mut [u8; UART_MAX_PACKET]) -> Option<usize> {
    let queue = UDP_COMMAND_QUEUE.load(Ordering::Acquire);
    if queue.is_null() {
        return None;
    }
    let mut queued = QueuedUdpCommand {
        len: 0,
        bytes: [0; UART_MAX_PACKET],
    };
    if unsafe { esp_idf_sys::xQueueReceive(queue.cast(), (&mut queued as *mut QueuedUdpCommand).cast(), 0) } != 1 {
        return None;
    }
    let len = usize::from(queued.len);
    if len > UART_MAX_PACKET {
        return None;
    }
    out[..len].copy_from_slice(&queued.bytes[..len]);
    Some(len)
}

/// Mirror the already-encoded compact UART record to a bearer-specific log
/// sink. The command format remains shared; Wi-Fi only supplies a transport.
pub(crate) unsafe fn set_udp_log_sink(sink: fn(&[u8])) {
    UDP_LOG_SINK = Some(sink);
}

extern "C" {
    fn nvs_flash_init() -> i32;
    fn nvs_open(namespace: *const i8, mode: i32, handle: *mut u32) -> i32;
    fn nvs_get_str(handle: u32, key: *const i8, value: *mut i8, length: *mut usize) -> i32;
    fn nvs_get_u32(handle: u32, key: *const i8, value: *mut u32) -> i32;
    fn nvs_set_u32(handle: u32, key: *const i8, value: u32) -> i32;
    fn nvs_set_str(handle: u32, key: *const i8, value: *const i8) -> i32;
    fn nvs_commit(handle: u32) -> i32;
    fn nvs_close(handle: u32);
}

/// Commit Stage2's persistent default only after Recovery has made a complete
/// authenticated image durable. RTC retained memory is not preserved across
/// every ESP32-C6 `esp_restart()` path, while Stage2 already uses this small
/// `stg2` setting as its boot policy. A managed UART Recovery selector still
/// takes precedence over the Main default for subsequent diagnostics.
pub(crate) fn set_stg2_boot_target(target: u32) -> bool {
    unsafe {
        if nvs_flash_init() != 0 {
            return false;
        }
        let mut handle = 0u32;
        if nvs_open(b"stg2\0".as_ptr().cast(), 1, &mut handle) != 0 {
            return false;
        }
        let ok = nvs_set_u32(handle, b"boot_target\0".as_ptr().cast(), target) == 0
            && nvs_commit(handle) == 0;
        nvs_close(handle);
        ok
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RecoveryParams {
    pub(crate) ssid: [u8; 33],
    pub(crate) ssid_len: usize,
    pub(crate) server: [u8; 64],
    pub(crate) server_len: usize,
    pub(crate) local_ip: [u8; 64],
    pub(crate) local_ip_len: usize,
    pub(crate) gateway: [u8; 64],
    pub(crate) gateway_len: usize,
    pub(crate) mask: [u8; 64],
    pub(crate) mask_len: usize,
    pub(crate) port: u16,
    pub(crate) log_level: u8,
    // One-shot UART diagnostic mode; deliberately never loaded from NVS.
    pub(crate) benchmark: bool,
    /// One-shot raw UDP diagnostic; never loaded from NVS.
    pub(crate) raw_udp: bool,
    /// One-shot transport-only benchmark. It requests SERVICE_IPERF and never
    /// creates an object decoder, hashes a manifest, or touches flash.
    pub(crate) transport_test: bool,
    /// Per-command IPERF application packet size, including its 4-byte ID.
    pub(crate) iperf_packet_size: u16,
    /// Per-command transport IPERF byte count; retained only in RAM.
    pub(crate) iperf_bytes: u32,
    /// 0=count, 1=offset+ID, 2=full byte pattern. Never persisted.
    pub(crate) iperf_validation: u8,
    /// Host-only IPERF sender controls. They are carried to the standalone
    /// listener in the SERVICE_IPERF request and never enter NVS or alter
    /// normal object serving. Zero keeps the listener's unpaced default.
    pub(crate) iperf_pace_us: u32,
    pub(crate) iperf_burst_packets: u8,
    pub(crate) iperf_burst_delay_us: u32,
    /// Receiver-advertised transport packet budget for one diagnostic run.
    /// Zero retains the normal Recovery budget; this never enters NVS.
    pub(crate) iperf_window_packets: u8,
    /// Host-generated correlation ID for one diagnostic run. It is reported
    /// with the final numeric counters, is never persisted, and has no
    /// transport meaning.
    pub(crate) benchmark_run_id: u32,
    /// A profile in NVS describes connectivity only. Starting a transfer is
    /// an explicit UART action, never a side effect of booting Recovery.
    pub(crate) run_requested: bool,
    /// `stg2:boot_target=2` explicitly selected Recovery command mode.
    pub(crate) command_mode: bool,
    // Temporary per-command transport tuning; deliberately never loaded from
    // NVS. Zero means use the wifi.rs default.
    pub(crate) ack_frequency: u8,
    /// Optional per-command delayed-ACK ceiling in milliseconds. It is carried
    /// to the peer in ACK_FREQUENCY for a transport benchmark, never NVS.
    pub(crate) ack_delay_ms: u8,
    // One-shot UART-only deadline for a dry or flash transfer. Never loaded
    // from NVS, so a diagnostic run cannot change a later boot.
    pub(crate) timeout_ms: u32,
}

impl RecoveryParams {
    pub(crate) const fn new() -> Self {
        Self {
            ssid: [0; 33],
            ssid_len: 0,
            server: [0; 64],
            server_len: 0,
            local_ip: [0; 64],
            local_ip_len: 0,
            gateway: [0; 64],
            gateway_len: 0,
            mask: [0; 64],
            mask_len: 0,
            port: 3336,
            log_level: 2,
            benchmark: false,
            raw_udp: false,
            transport_test: false,
            iperf_packet_size: 1200,
            iperf_bytes: 2 * 1024 * 1024,
            iperf_validation: 2,
            iperf_pace_us: 0,
            iperf_burst_packets: 0,
            iperf_burst_delay_us: 0,
            iperf_window_packets: 0,
            benchmark_run_id: 0,
            run_requested: false,
            command_mode: false,
            ack_frequency: 0,
            ack_delay_ms: 0,
            timeout_ms: 300_000,
        }
    }

    unsafe fn load_nvs_text(key: &[u8], destination: &mut [u8], length: &mut usize) -> bool {
        let mut handle = 0u32;
        let namespace = b"dmesh\0";
        if nvs_open(namespace.as_ptr().cast(), 0, &mut handle) != 0 {
            return false;
        }
        let mut capacity = destination.len();
        let result = nvs_get_str(
            handle,
            key.as_ptr().cast(),
            destination.as_mut_ptr().cast(),
            &mut capacity,
        );
        nvs_close(handle);
        if result != 0 || capacity == 0 {
            return false;
        }
        *length = capacity.saturating_sub(1).min(destination.len());
        true
    }

    unsafe fn load_stg2_command_mode() -> bool {
        let mut handle = 0u32;
        if nvs_open(b"stg2\0".as_ptr().cast(), 0, &mut handle) != 0 {
            return false;
        }
        let mut target = 0u32;
        let ok =
            nvs_get_u32(handle, b"boot_target\0".as_ptr().cast(), &mut target) == 0 && target == 2;
        nvs_close(handle);
        ok
    }

    pub(crate) unsafe fn load_from_nvs(&mut self) {
        if nvs_flash_init() != 0 {
            return;
        }
        self.command_mode = Self::load_stg2_command_mode();
        let _ = Self::load_nvs_text(b"ssid\0", &mut self.ssid, &mut self.ssid_len);
        let _ = Self::load_nvs_text(b"server\0", &mut self.server, &mut self.server_len);
        let _ = Self::load_nvs_text(b"ip\0", &mut self.local_ip, &mut self.local_ip_len);
        let _ = Self::load_nvs_text(b"gw\0", &mut self.gateway, &mut self.gateway_len);
        let _ = Self::load_nvs_text(b"mask\0", &mut self.mask, &mut self.mask_len);
        let mut port = [0u8; 8];
        let mut port_len = 0;
        if Self::load_nvs_text(b"port\0", &mut port, &mut port_len) {
            let mut value = 0u16;
            let mut valid = port_len != 0;
            for byte in &port[..port_len] {
                if !byte.is_ascii_digit() {
                    valid = false;
                    break;
                }
                value = value
                    .saturating_mul(10)
                    .saturating_add((byte - b'0') as u16);
            }
            if valid && value != 0 {
                self.port = value;
            }
        }
    }

    pub(crate) fn has_flash_profile(&self) -> bool {
        self.ssid_len != 0 && self.server_len != 0 && self.local_ip_len != 0 && self.port != 0
    }

    /// Update only DMesh's own NVS entries through ESP-IDF.  Unlike a
    /// host-side dump/CSV/regenerate cycle, this leaves opaque Wi-Fi PHY and
    /// calibration entries untouched.
    unsafe fn persist_profile(&self) -> bool {
        let mut handle = 0u32;
        if nvs_open(b"dmesh\0".as_ptr().cast(), 1, &mut handle) != 0 {
            return false;
        }
        let fields = [
            (b"ssid\0".as_slice(), &self.ssid[..self.ssid_len]),
            (b"server\0".as_slice(), &self.server[..self.server_len]),
            (b"ip\0".as_slice(), &self.local_ip[..self.local_ip_len]),
            (b"gw\0".as_slice(), &self.gateway[..self.gateway_len]),
            (b"mask\0".as_slice(), &self.mask[..self.mask_len]),
        ];
        let mut ok = true;
        for (key, value) in fields {
            let mut terminated = [0u8; 65];
            if value.len() >= terminated.len() {
                ok = false;
                break;
            }
            terminated[..value.len()].copy_from_slice(value);
            if nvs_set_str(handle, key.as_ptr().cast(), terminated.as_ptr().cast()) != 0 {
                ok = false;
                break;
            }
        }
        let mut port = [0u8; 6];
        let mut value = self.port;
        let mut digits = 0usize;
        loop {
            port[port.len() - 2 - digits] = b'0' + (value % 10) as u8;
            digits += 1;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        let start = port.len() - 1 - digits;
        if ok
            && nvs_set_str(
                handle,
                b"port\0".as_ptr().cast(),
                port[start..].as_ptr().cast(),
            ) != 0
        {
            ok = false;
        }
        if ok && nvs_commit(handle) != 0 {
            ok = false;
        }
        nvs_close(handle);
        ok
    }
}

fn copy_text(value: &mut Cbor<'_>, destination: &mut [u8], length: &mut usize) -> bool {
    match value.text(destination) {
        Some(size) => {
            *length = size;
            true
        }
        None => false,
    }
}

fn copy_bytes_or_text(value: &mut Cbor<'_>, destination: &mut [u8], length: &mut usize) -> bool {
    let saved = value.position();
    if let Some(size) = value.bytes(destination) {
        *length = size;
        return true;
    }
    value.set_position(saved);
    match value.text(destination) {
        Some(size) => {
            *length = size;
            true
        }
        None => false,
    }
}

fn parse_recovery_packet(packet: &[u8], params: &mut RecoveryParams) -> Option<bool> {
    let mut root = Cbor::new(packet);
    let (major, fields) = root.head()?;
    if major != 5 {
        return None;
    }
    let mut method = false;
    let mut operation = [0u8; 24];
    let mut operation_len = 0;
    let mut payload_seen = false;
    let mut profile_updated = false;
    let mut payload = None;
    let mut remaining = fields;
    while remaining != 0 {
        remaining -= 1;
        let key = root.uint()?;
        if key == 0 {
            let (kind, value) = root.head()?;
            method = if kind == 0 {
                value == RECOVERY_METHOD
            } else if kind == 3 && value != u64::MAX {
                root.take(value as usize)? == b"recovery"
            } else {
                false
            };
        } else if key == 6 {
            let start = root.position();
            payload = Some(start);
            payload_seen = true;
            root.skip()?;
        } else {
            root.skip()?;
        }
    }
    if !method || !payload_seen {
        return None;
    }
    // These are command-scoped. A saved STA profile must not turn a later
    // Recovery boot into a flash or diagnostic run.
    params.benchmark = false;
    params.raw_udp = false;
    params.transport_test = false;
    params.iperf_packet_size = 1200;
    params.iperf_bytes = 2 * 1024 * 1024;
    params.iperf_validation = 2;
    params.iperf_pace_us = 0;
    params.iperf_burst_packets = 0;
    params.iperf_burst_delay_us = 0;
    params.iperf_window_packets = 0;
    params.benchmark_run_id = 0;
    params.ack_frequency = 0;
    params.ack_delay_ms = 0;
    params.timeout_ms = 300_000;
    params.run_requested = false;
    let payload_start = payload?;
    let mut body = Cbor::new(&packet[payload_start..]);
    let (body_major, body_fields) = body.head()?;
    if body_major != 5 {
        return None;
    }
    let mut remaining = body_fields;
    while remaining != 0 {
        remaining -= 1;
        let (key_kind, key_value) = body.head()?;
        let mut key = [0u8; 24];
        let key_len = if key_kind == 3 && key_value != u64::MAX && key_value as usize <= key.len() {
            let bytes = body.take(key_value as usize)?;
            key[..bytes.len()].copy_from_slice(bytes);
            bytes.len()
        } else {
            0
        };
        if (key_len == 2 && &key[..key_len] == b"op") || (key_kind == 0 && key_value == 87) {
            if !copy_text(&mut body, &mut operation, &mut operation_len) {
                return None;
            }
        } else if key_len == 4 && &key[..key_len] == b"ssid" {
            if !copy_bytes_or_text(&mut body, &mut params.ssid, &mut params.ssid_len) {
                return None;
            }
            profile_updated = true;
        } else if (key_len == 6 && &key[..key_len] == b"server")
            || (key_kind == 0 && key_value == 246)
        {
            if !copy_bytes_or_text(&mut body, &mut params.server, &mut params.server_len) {
                return None;
            }
            profile_updated = true;
        } else if key_len == 2 && &key[..key_len] == b"ip" {
            if !copy_bytes_or_text(&mut body, &mut params.local_ip, &mut params.local_ip_len) {
                return None;
            }
            profile_updated = true;
        } else if (key_len == 2 && &key[..key_len] == b"gw")
            || (key_len == 7 && &key[..key_len] == b"gateway")
        {
            if !copy_bytes_or_text(&mut body, &mut params.gateway, &mut params.gateway_len) {
                return None;
            }
            profile_updated = true;
        } else if key_len == 4 && &key[..key_len] == b"mask" {
            if !copy_bytes_or_text(&mut body, &mut params.mask, &mut params.mask_len) {
                return None;
            }
            profile_updated = true;
        } else if (key_len == 4 && &key[..key_len] == b"port")
            || (key_kind == 0 && key_value == 191)
        {
            params.port = body.uint_or_text()? as u16;
            profile_updated = key_len != 0;
        } else if key_len == 9 && &key[..key_len] == b"log_level" {
            params.log_level = body.uint_or_text()?.min(5) as u8;
        } else if (key_len == 9 && &key[..key_len] == b"benchmark")
            || (key_kind == 0 && key_value == 248)
        {
            params.benchmark = body.boolean_or_text()?;
        } else if key_kind == 0 && key_value == 247 {
            let (kind, value) = body.head()?;
            if kind != 7 || (value != 20 && value != 21) {
                return None;
            }
            params.raw_udp = value == 21;
        } else if (key_len == 14 && &key[..key_len] == b"transport_test")
            || (key_kind == 0 && key_value == 251)
        {
            params.transport_test = body.boolean_or_text()?;
        } else if (key_len == 17 && &key[..key_len] == b"iperf_packet_size")
            || (key_kind == 0 && key_value == 252)
        {
            params.iperf_packet_size = body.uint_or_text()?.clamp(8, 1330) as u16;
        } else if (key_len == 11 && &key[..key_len] == b"iperf_bytes")
            || (key_kind == 0 && key_value == 253)
        {
            params.iperf_bytes = body.uint_or_text()?.clamp(8, 64 * 1024 * 1024) as u32;
        } else if (key_len == 16 && &key[..key_len] == b"iperf_validation")
            || (key_kind == 0 && key_value == 254)
        {
            params.iperf_validation = body.uint_or_text()?.min(2) as u8;
        } else if (key_len == 8 && &key[..key_len] == b"pace_us")
            || (key_kind == 0 && key_value == 243)
        {
            params.iperf_pace_us = body.uint_or_text()?.min(1_000_000) as u32;
        } else if (key_len == 5 && &key[..key_len] == b"burst")
            || (key_kind == 0 && key_value == 244)
        {
            params.iperf_burst_packets = body.uint_or_text()?.min(32) as u8;
        } else if (key_len == 8 && &key[..key_len] == b"burst_us")
            || (key_kind == 0 && key_value == 245)
        {
            params.iperf_burst_delay_us = body.uint_or_text()?.min(1_000_000) as u32;
        } else if (key_len == 6 && &key[..key_len] == b"window")
            || (key_kind == 0 && key_value == 242)
        {
            params.iperf_window_packets = body
                .uint_or_text()?
                .min(dmesh_transport::RECOVERY_MAX_DIAGNOSTIC_IN_FLIGHT_PACKETS as u64)
                as u8;
        } else if (key_len == 6 && &key[..key_len] == b"run_id")
            || (key_kind == 0 && key_value == 255)
        {
            params.benchmark_run_id = body.uint_or_text()? as u32;
        } else if (key_len == 3 && &key[..key_len] == b"ack")
            || (key_len == 2 && &key[..key_len] == b"af")
            || (key_kind == 0 && key_value == 249)
        {
            params.ack_frequency =
                body.uint_or_text()?
                    .clamp(1, dmesh_transport::ACK_RANGE_CAPACITY as u64) as u8;
        } else if (key_len == 6 && &key[..key_len] == b"ack_ms")
            || (key_len == 9 && &key[..key_len] == b"ack_delay")
            || (key_kind == 0 && key_value == 241)
        {
            params.ack_delay_ms = body.uint_or_text()?.clamp(1, 25) as u8;
        } else if (key_len == 10 && &key[..key_len] == b"timeout_ms")
            || (key_kind == 0 && key_value == 250)
        {
            params.timeout_ms = body.uint_or_text()?.clamp(1_000, 300_000) as u32;
        } else {
            body.skip()?;
        }
    }
    if profile_updated && params.has_flash_profile() {
        unsafe {
            let _ = params.persist_profile();
        }
    }
    params.run_requested = true;
    Some(
        operation_len == 0
            || &operation[..operation_len] != b"main"
                && &operation[..operation_len] != b"reboot_main",
    )
}

/// Shared command decoder for the UART PPP adapter and the Recovery UDP
/// command endpoint. Both bearers carry the same CBOR packet; neither owns
/// command semantics.
pub(crate) fn accept_packet(packet: &[u8], params: &mut RecoveryParams) -> Option<bool> {
    let reboot_main = parse_recovery_packet(packet, params)?;
    COMMAND_GENERATION.fetch_add(1, Ordering::Release);
    Some(reboot_main)
}

pub(crate) fn send_response(message: &[u8]) {
    let mut cbor = Vec::with_capacity(16 + message.len());
    cbor.extend_from_slice(&[
        0xa3, 0x00, 0x18, 0x44, 0x04, 0x62, b'o', b'k', 0x06, 0xa1, 0x18, 0x20,
    ]);
    if message.len() < 24 {
        cbor.push(0x60 + message.len() as u8);
    } else if message.len() < 256 {
        cbor.extend_from_slice(&[0x78, message.len() as u8]);
    } else {
        return;
    }
    cbor.extend_from_slice(message);
    if let Ok(wire) = encode_payload(&cbor, UART_MAX_PACKET) {
        write_usb(&wire);
    }
    unsafe {
        if let Some(sink) = UDP_LOG_SINK {
            sink(&cbor);
        }
    }
}

pub(crate) fn send_stat(prefix: &[u8], value: u64) {
    let mut message = [0u8; 96];
    if prefix.len() >= message.len() {
        return;
    }
    message[..prefix.len()].copy_from_slice(prefix);
    let mut digits = [0u8; 20];
    let mut number = value;
    let mut count = 0;
    loop {
        digits[count] = b'0' + (number % 10) as u8;
        count += 1;
        number /= 10;
        if number == 0 {
            break;
        }
    }
    for index in 0..count {
        message[prefix.len() + index] = digits[count - index - 1];
    }
    send_response(&message[..prefix.len() + count]);
}

/// Send one compact numeric CBOR map for a benchmark interval. Numeric keys
/// keep UART traffic small; the host owns the key table and decodes values as
/// numbers instead of parsing dozens of verbose text records.
pub(crate) fn send_benchmark_stats(values: &[(u64, u64)]) {
    let Some(cbor) = encode_benchmark_stats(values) else {
        return;
    };
    if let Ok(wire) = encode_payload(&cbor, UART_MAX_PACKET) {
        write_usb(&wire);
    }
    unsafe {
        if let Some(sink) = UDP_LOG_SINK {
            sink(&cbor);
        }
    }
}

/// Encode completion telemetry once for both UART and the UDP log bridge.
/// UDP can carry the full diagnostic map; UART retains its 512-byte frame
/// limit and simply omits an oversized copy instead of truncating CBOR.
fn encode_benchmark_stats(values: &[(u64, u64)]) -> Option<Vec<u8>> {
    if values.len() > u8::MAX as usize {
        return None;
    }
    // A complete Recovery transport result has more than 64 fields and can
    // contain several u64 timing/counter values. UART is limited to 512-byte
    // framed records, but UDP telemetry is MTU-sized; using the UART bound
    // here silently discarded the final result after new diagnostics were
    // added. This runs only on completion, never in the packet loop.
    let mut inner = [0u8; 1024];
    let mut encoder = CborEncoder::new(&mut inner);
    if encoder.map(values.len() as u64).is_none() {
        return None;
    }
    for (key, value) in values {
        if encoder.uint(*key).is_none() || encoder.uint(*value).is_none() {
            return None;
        }
    }
    let mut cbor = Vec::with_capacity(16 + encoder.len());
    cbor.extend_from_slice(&[0xa3, 0x00, 0x18, 0x44, 0x04, 0x62, b'o', b'k', 0x06]);
    let payload_len = encoder.len();
    cbor.extend_from_slice(&inner[..payload_len]);
    Some(cbor)
}

#[cfg(target_arch = "riscv32")]
fn write_usb(bytes: &[u8]) {
    unsafe {
        esp_idf_sys::usb_serial_jtag_write_bytes(bytes.as_ptr().cast(), bytes.len(), 100);
    }
}
#[cfg(not(target_arch = "riscv32"))]
fn write_usb(bytes: &[u8]) {
    unsafe {
        esp_idf_sys::uart_write_bytes(
            esp_idf_sys::uart_port_t_UART_NUM_0,
            bytes.as_ptr().cast(),
            bytes.len(),
        );
    }
}

#[cfg(target_arch = "riscv32")]
fn read_usb(bytes: &mut [u8]) -> i32 {
    unsafe {
        esp_idf_sys::usb_serial_jtag_read_bytes(bytes.as_mut_ptr().cast(), bytes.len() as u32, 1)
    }
}
#[cfg(not(target_arch = "riscv32"))]
fn read_usb(bytes: &mut [u8]) -> i32 {
    unsafe {
        esp_idf_sys::uart_read_bytes(
            esp_idf_sys::uart_port_t_UART_NUM_0,
            bytes.as_mut_ptr().cast(),
            bytes.len() as u32,
            1,
        )
    }
}

#[cfg(target_arch = "riscv32")]
pub(crate) fn install_console() {
    unsafe {
        let mut config = esp_idf_sys::usb_serial_jtag_driver_config_t {
            tx_buffer_size: 512,
            rx_buffer_size: 512,
        };
        let _ = esp_idf_sys::usb_serial_jtag_driver_install(&mut config);
    }
}
#[cfg(not(target_arch = "riscv32"))]
pub(crate) fn install_console() {}

pub(crate) fn send_boot_identity() {
    let payload = [
        0xbf, 0x07, 0x19, 0xea, 0x60, 0x06, 0x9f, 0x02, 0x02, 0xff, 0xff,
    ];
    if let Ok(wire) = encode_payload(&payload, UART_MAX_PACKET) {
        write_usb(&wire);
    }
}

pub(crate) fn command_generation() -> u32 {
    COMMAND_GENERATION.load(Ordering::Acquire)
}

/// A worker must compare against the generation captured before it started.
/// This keeps a command accepted while the worker is emitting final telemetry
/// from being silently discarded when that worker returns.
pub(crate) fn command_generation_changed(observed: u32) -> bool {
    command_generation_changed_from(observed, command_generation())
}

fn command_generation_changed_from(observed: u32, current: u32) -> bool {
    current != observed
}

pub(crate) unsafe extern "C" fn task_entry(argument: *mut c_void) {
    if !argument.is_null() {
        command_task(&mut *(argument as *mut RecoveryParams));
    }
}

fn command_task(params: &mut RecoveryParams) {
    let mut decoder = UartDecoder::with_max(UART_MAX_PACKET);
    let mut bytes = [0u8; 64];
    loop {
        let count = read_usb(&mut bytes);
        if count <= 0 {
            unsafe {
                esp_idf_sys::vTaskDelay(1);
            }
            continue;
        }
        if let Ok(records) = decoder.push(&bytes[..count as usize]) {
            for record in records {
                if let Some(reboot_main) = accept_packet(&record, params) {
                    send_response(if reboot_main {
                        b"transport accepted"
                    } else {
                        b"main rebooting"
                    });
                    if !reboot_main {
                        crate::udp_flash::set_main_handoff();
                        unsafe {
                            esp_idf_sys::vTaskDelay(100);
                        }
                        unsafe {
                            esp_idf_sys::esp_restart();
                        }
                    }
                } else {
                    send_response(b"protocol rejected");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{command_generation_changed_from, encode_benchmark_stats, parse_recovery_packet, RecoveryParams};

    #[test]
    fn command_arrival_during_worker_is_not_missed() {
        let before_worker = 41;
        let after_worker = 42;
        // The worker wait is driven by the pre-worker generation, not a
        // value sampled after the command has already arrived.
        assert!(command_generation_changed_from(before_worker, after_worker));
        assert!(!command_generation_changed_from(after_worker, after_worker));
    }

    #[test]
    fn full_transport_benchmark_map_fits_udp_telemetry_encoder() {
        let values: Vec<(u64, u64)> = (0..84)
            .map(|key| (key, u64::MAX.saturating_sub(key)))
            .collect();
        let encoded = encode_benchmark_stats(&values).expect("full benchmark map encodes");
        assert!(encoded.len() < 1400);
    }

    #[test]
    fn explicit_transport_window_accepts_the_declared_64_packet_ceiling() {
        // {0: 68, 6: {242: 64}}: the same compact command accepted from
        // either UART or the Recovery UDP control endpoint.
        let packet = [0xa2, 0x00, 0x18, 0x44, 0x06, 0xa1, 0x18, 0xf2, 0x18, 0x40];
        let mut params = RecoveryParams::new();
        assert_eq!(parse_recovery_packet(&packet, &mut params), Some(true));
        assert_eq!(
            params.iperf_window_packets,
            dmesh_transport::RECOVERY_MAX_DIAGNOSTIC_IN_FLIGHT_PACKETS as u8
        );
    }

    #[test]
    fn transport_ack_delay_is_command_scoped() {
        // {0: 68, 6: {241: 1}}.  This is a tuning control for one request,
        // not a STA or boot profile field.
        let packet = [0xa2, 0x00, 0x18, 0x44, 0x06, 0xa1, 0x18, 0xf1, 0x01];
        let mut params = RecoveryParams::new();
        assert_eq!(parse_recovery_packet(&packet, &mut params), Some(true));
        assert_eq!(params.ack_delay_ms, 1);
    }

    #[test]
    fn full_host_transport_command_is_accepted() {
        // Exact output from scripts/recovery-udp.py's
        // encode_transport_command(3339, 28800, 1200, 0, 8, 10000, 123).
        // Keeping this cross-language fixture here catches a host encoder or
        // embedded decoder drift before a device benchmark is attempted.
        let packet = [
            0xa2, 0x00, 0x18, 0x44, 0x06, 0xad, 0x18, 0xf8, 0xf5, 0x18, 0xfb, 0xf5,
            0x18, 0xfc, 0x19, 0x04, 0xb0, 0x18, 0xfd, 0x19, 0x70, 0x80, 0x18, 0xfe,
            0x00, 0x18, 0xf9, 0x08, 0x18, 0xfa, 0x19, 0x27, 0x10, 0x18, 0xbf, 0x19,
            0x0d, 0x0b, 0x18, 0xff, 0x18, 0x7b, 0x18, 0xf2, 0x00, 0x18, 0xf3, 0x00,
            0x18, 0xf4, 0x00, 0x18, 0xf5, 0x00,
        ];
        let mut params = RecoveryParams::new();
        assert_eq!(parse_recovery_packet(&packet, &mut params), Some(true));
        assert!(params.benchmark);
        assert!(params.transport_test);
        assert_eq!(params.port, 3339);
        assert_eq!(params.iperf_bytes, 28_800);
        assert_eq!(params.iperf_packet_size, 1200);
        assert_eq!(params.ack_frequency, 8);
        assert_eq!(params.timeout_ms, 10_000);
        assert_eq!(params.benchmark_run_id, 123);
    }
}
