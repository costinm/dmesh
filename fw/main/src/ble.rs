use alloc::vec::Vec;

use dmesh_server::{
    cbor::{Decoder, Encoder},
    services,
    tagged::{self, Name, Record},
};
use dmesh_fw_transport::{
    core_runtime,
    shared_ingress_esp::{self, IngressKind, IngressPacket},
    TRANSPORT_MTU,
};
use dmesh_server::firmware_profile::TransportProfile;
use dmesh_server::main_runtime_state::RadioLifecycle;
use dmesh_server::transport_state::TransportStateObserver;
use quic_lite::PathId;

pub const BLE_COMPONENT: u64 = 104;

struct BleTransportObserver;

static BLE_PROFILE_GENERATION: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
static BLE_PROFILE_ACTIVE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

impl TransportStateObserver for BleTransportObserver {
    fn transport_applied(
        &self,
        requested: &TransportProfile,
        current: RadioLifecycle,
        generation: u32,
    ) {
        let _ = current;
        if generation == BLE_PROFILE_GENERATION.load(core::sync::atomic::Ordering::Acquire) {
            return;
        }
        let snapshot = dmesh_ble::link_snapshot();
        let live = snapshot.advertising || snapshot.connected || snapshot.coc_connected;
        match requested.ble {
            1 => {
                if !live && !dmesh_ble::start_dmesh_service().is_ok() {
                    return;
                }
                BLE_PROFILE_ACTIVE.store(true, core::sync::atomic::Ordering::Release);
                BLE_PROFILE_GENERATION.store(generation, core::sync::atomic::Ordering::Release);
            }
            2 => {
                if live {
                    let _ = dmesh_ble::stop_dmesh_service();
                }
                BLE_PROFILE_ACTIVE.store(false, core::sync::atomic::Ordering::Release);
                BLE_PROFILE_GENERATION.store(generation, core::sync::atomic::Ordering::Release);
            }
            _ => {
                BLE_PROFILE_GENERATION.store(generation, core::sync::atomic::Ordering::Release);
            }
        }
    }
}

static BLE_TRANSPORT_OBSERVER: BleTransportObserver = BleTransportObserver;
const BLE_START: u64 = 80;
const BLE_STOP: u64 = 81;
const BLE_SCAN: u64 = 82;
const BLE_STATUS: u64 = 83;
const BLE_SCAN_STOP: u64 = 84;
const BLE_CONNECT: u64 = 85;
const BLE_COC_SEND: u64 = 86;
const DEFAULT_SCAN_MS: u32 = 10_000;
const MAX_SCAN_MS: u32 = 30_000;

static mut BLE_COC_RESPONSE: [u8; TRANSPORT_MTU] = [0; TRANSPORT_MTU];
static mut BLE_COC_FRAME: [u8; TRANSPORT_MTU + 2] = [0; TRANSPORT_MTU + 2];
static mut BLE_COC_RX: [u8; TRANSPORT_MTU + 2] = [0; TRANSPORT_MTU + 2];
static mut BLE_COC_RX_LEN: usize = 0;
static mut BLE_COC_RX_RECORD: Option<usize> = None;
static BLE_INGRESS_ENQUEUED: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
static BLE_INGRESS_ACCEPTED: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
static BLE_INGRESS_REJECTED: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
static BLE_EGRESS_ATTEMPTS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
static BLE_EGRESS_SENT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
static BLE_EGRESS_SEND_ERRORS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
static BLE_EGRESS_BLOCKED_DISCONNECTED: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
static BLE_EGRESS_BLOCKED_PENDING: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

pub fn register() {
    assert!(services::register_tagged_component(BLE_COMPONENT, handle_ble));
    assert!(dmesh_server::transport_state::register_transport_state_observer(
        &BLE_TRANSPORT_OBSERVER
    ));
}

pub fn install() {
    let _ = shared_ingress_esp::start(IngressKind::BleCoc, receive_ble_coc_ingress);
    dmesh_ble::set_coc_rx_hook(Some(receive_ble_coc_bytes));
    dmesh_ble::set_coc_egress_ready_hook(Some(schedule_ble_coc_egress_ready));
    dmesh_ble::set_coc_state_hook(Some(on_ble_coc_state));
    core_runtime::install_ble_coc_egress_pump(Some(pump_ble_coc_egress));
}

fn ble_coc_path() -> PathId {
    core_runtime::connection_path_id(
        dmesh_server::transport_path::TransportId::BLE.0,
        [0; 6],
    )
}

fn reset_ble_coc_rx() {
    unsafe {
        *core::ptr::addr_of_mut!(BLE_COC_RX_LEN) = 0;
        *core::ptr::addr_of_mut!(BLE_COC_RX_RECORD) = None;
    }
}

fn on_ble_coc_state(_connected: bool) {
    reset_ble_coc_rx();
}

fn receive_ble_coc_bytes(chunk: &[u8]) {
    if !dmesh_ble::coc_connected() {
        reset_ble_coc_rx();
        return;
    }
    let mut consumed = 0;
    while consumed < chunk.len() {
        let record = unsafe { *core::ptr::addr_of!(BLE_COC_RX_RECORD) };
        let record = match record {
            Some(record) if record > 0 && record <= TRANSPORT_MTU => record,
            Some(_) => {
                reset_ble_coc_rx();
                return;
            }
            None => {
                let len = unsafe { *core::ptr::addr_of!(BLE_COC_RX_LEN) };
                if len < 2 {
                    let take = (2 - len).min(chunk.len() - consumed);
                    unsafe {
                        let buffer = &mut *core::ptr::addr_of_mut!(BLE_COC_RX);
                        buffer[len..len + take].copy_from_slice(&chunk[consumed..consumed + take]);
                        *core::ptr::addr_of_mut!(BLE_COC_RX_LEN) = len + take;
                    }
                    consumed += take;
                    continue;
                }
                let value = unsafe {
                    let buffer = &*core::ptr::addr_of!(BLE_COC_RX);
                    u16::from_be_bytes([buffer[0], buffer[1]]) as usize
                };
                if value == 0 || value > TRANSPORT_MTU {
                    reset_ble_coc_rx();
                    return;
                }
                unsafe {
                    *core::ptr::addr_of_mut!(BLE_COC_RX_RECORD) = Some(value);
                    *core::ptr::addr_of_mut!(BLE_COC_RX_LEN) = 0;
                }
                continue;
            }
        };
        let len = unsafe { *core::ptr::addr_of!(BLE_COC_RX_LEN) };
        let take = record.saturating_sub(len).min(chunk.len() - consumed);
        unsafe {
            let buffer = &mut *core::ptr::addr_of_mut!(BLE_COC_RX);
            buffer[len..len + take].copy_from_slice(&chunk[consumed..consumed + take]);
            *core::ptr::addr_of_mut!(BLE_COC_RX_LEN) = len + take;
        }
        consumed += take;
        if len + take == record {
            let payload = unsafe { &*core::ptr::addr_of!(BLE_COC_RX) };
            BLE_INGRESS_ENQUEUED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let _ = shared_ingress_esp::enqueue(IngressKind::BleCoc, [0; 6], &payload[..record]);
            unsafe {
                *core::ptr::addr_of_mut!(BLE_COC_RX_LEN) = 0;
                *core::ptr::addr_of_mut!(BLE_COC_RX_RECORD) = None;
            }
        }
    }
}

fn receive_ble_coc_ingress(_item: IngressPacket, packet: &[u8]) {
    unsafe {
        let response = &mut *core::ptr::addr_of_mut!(BLE_COC_RESPONSE);
        let path = ble_coc_path();
        let ingress = core_runtime::receive_connection_frame_ingress(path, packet, response);
        if ingress.accepted {
            BLE_INGRESS_ACCEPTED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        } else {
            BLE_INGRESS_REJECTED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        pump_ble_coc_egress(path, response, ingress.response);
    }
}

fn pump_ble_coc_egress(
    path: PathId,
    response: &mut [u8; TRANSPORT_MTU],
    immediate: Option<usize>,
) {
    if !dmesh_ble::coc_connected() {
        BLE_EGRESS_BLOCKED_DISCONNECTED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        return;
    }
    if dmesh_ble::coc_tx_pending() {
        BLE_EGRESS_BLOCKED_PENDING.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        return;
    }
    let used = immediate
        .filter(|used| *used > 0 && *used <= TRANSPORT_MTU)
        .unwrap_or_else(|| core_runtime::poll_connection(path, response).unwrap_or(0));
    if used == 0 {
        return;
    }
    unsafe {
        let frame = &mut *core::ptr::addr_of_mut!(BLE_COC_FRAME);
        frame[0] = (used >> 8) as u8;
        frame[1] = used as u8;
        frame[2..2 + used].copy_from_slice(&response[..used]);
        BLE_EGRESS_ATTEMPTS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        match dmesh_ble::send_coc_bytes(&frame[..2 + used]) {
            Ok(()) => {
                BLE_EGRESS_SENT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
            Err(_) => {
                BLE_EGRESS_SEND_ERRORS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

fn schedule_ble_coc_egress_ready() {
    let _ = shared_ingress_esp::schedule_ble_coc_egress_ready(ble_coc_egress_ready_event);
}

fn ble_coc_egress_ready_event() {
    unsafe {
        let response = &mut *core::ptr::addr_of_mut!(BLE_COC_RESPONSE);
        pump_ble_coc_egress(ble_coc_path(), response, None);
    }
}

fn scan_duration(fields: Option<&[u8]>) -> u32 {
    let mut decoder = Decoder::new(fields.unwrap_or(&[]));
    let (major, count) = match decoder.head() {
        Some(value) => value,
        None => return DEFAULT_SCAN_MS,
    };
    if major != 5 {
        return DEFAULT_SCAN_MS;
    }
    for _ in 0..count {
        match decoder.uint() {
            Some(2) => {
                return decoder
                    .uint_or_text()
                    .unwrap_or(DEFAULT_SCAN_MS as u64)
                    .clamp(1_000, MAX_SCAN_MS as u64) as u32;
            }
            Some(_) => {
                if decoder.skip().is_none() {
                    break;
                }
            }
            None => break,
        }
    }
    DEFAULT_SCAN_MS
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn field_bytes(decoder: &mut Decoder<'_>, dst: &mut [u8]) -> Option<usize> {
    let saved = decoder.position();
    let mut raw = [0u8; 512];
    let raw_len = match decoder.bytes(&mut raw) {
        Some(len) => len,
        None => {
            decoder.set_position(saved);
            decoder.text(&mut raw)?
        }
    };
    let raw = &raw[..raw_len];
    match raw.strip_prefix(b"hex:") {
        Some(hex) => {
            if hex.len() > dst.len() * 2 || hex.len() % 2 != 0 {
                return None;
            }
            for (slot, pair) in dst.iter_mut().zip(hex.chunks_exact(2)) {
                *slot = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
            }
            Some(hex.len() / 2)
        }
        None if raw.len() <= dst.len() => {
            dst[..raw.len()].copy_from_slice(raw);
            Some(raw.len())
        }
        None => None,
    }
}

fn connect_request(fields: Option<&[u8]>) -> Option<([u8; 6], u8, u16)> {
    let mut decoder = Decoder::new(fields.unwrap_or(&[]));
    let (major, count) = decoder.head()?;
    if major != 5 {
        return None;
    }
    let mut addr = [0u8; 6];
    let mut addr_type = 0u8;
    let mut psm = dmesh_ble::COC_PSM as u64;
    for _ in 0..count {
        match decoder.uint()? {
            2 => {
                if field_bytes(&mut decoder, &mut addr)? != 6 {
                    return None;
                }
            }
            3 => addr_type = decoder.uint_or_text()?.try_into().ok()?,
            4 => psm = decoder.uint_or_text()?,
            _ => decoder.skip()?,
        }
    }
    let psm: u16 = psm.try_into().ok()?;
    if psm < 0x0080 || psm > 0x00ff {
        return None;
    }
    Some((addr, addr_type, psm))
}

const BLE_COC_SEND_MAX: usize = 250;

fn send_data(fields: Option<&[u8]>) -> Option<([u8; BLE_COC_SEND_MAX], usize)> {
    let mut decoder = Decoder::new(fields.unwrap_or(&[]));
    let (major, count) = decoder.head()?;
    if major != 5 {
        return None;
    }
    for _ in 0..count {
        match decoder.uint()? {
            2 => {
                let mut data = [0u8; BLE_COC_SEND_MAX];
                let len = field_bytes(&mut decoder, &mut data)?;
                if len == 0 {
                    return None;
                }
                let mut result = [0u8; BLE_COC_SEND_MAX];
                result[..len].copy_from_slice(&data[..len]);
                return Some((result, len));
            }
            _ => decoder.skip()?,
        }
    }
    None
}

fn bool_result(record: Record<'_>, ok: bool) -> Option<Vec<u8>> {
    let component = match record.component? {
        Name::Tag(value) if value == BLE_COMPONENT => value,
        _ => return None,
    };
    let method = match record.method? {
        Name::Tag(value) => value,
        _ => return None,
    };
    let id = record.id?;
    let mut result = [0u8; 16];
    let mut encoder = Encoder::new(&mut result);
    let result_len = encoder
        .map(1)
        .and_then(|()| encoder.uint(1))
        .and_then(|()| encoder.boolean(ok))
        .map(|()| encoder.len())?;
    let mut response = [0u8; 64];
    let used = tagged::encode_numeric_response(
        component,
        method,
        id,
        &result[..result_len],
        &mut response,
    )?;
    Some(Vec::from(&response[..used]))
}

fn status_result(record: Record<'_>) -> Option<Vec<u8>> {
    let component = match record.component? {
        Name::Tag(value) if value == BLE_COMPONENT => value,
        _ => return None,
    };
    let method = match record.method? {
        Name::Tag(value) => value,
        _ => return None,
    };
    let id = record.id?;
    let snapshot = dmesh_ble::link_snapshot();
    let mut result = [0u8; 512];
    let mut encoder = Encoder::new(&mut result);
    let result_len = (|| {
        encoder
            .map(26)
            .and_then(|()| encoder.uint(1))
            .and_then(|()| encoder.boolean(snapshot.ready))
            .and_then(|()| encoder.uint(2))
            .and_then(|()| encoder.boolean(snapshot.advertising))
            .and_then(|()| encoder.uint(3))
            .and_then(|()| encoder.boolean(snapshot.connected))
            .and_then(|()| encoder.uint(4))
            .and_then(|()| encoder.boolean(snapshot.coc_connected))
            .and_then(|()| encoder.uint(5))
            .and_then(|()| encoder.uint(snapshot.generation as u64))
            .and_then(|()| encoder.uint(6))
            .and_then(|()| encoder.uint(snapshot.handle as u64))
            .and_then(|()| encoder.uint(7))
            .and_then(|()| encoder.uint(snapshot.coc_rx as u64))
            .and_then(|()| encoder.uint(8))
            .and_then(|()| encoder.uint(snapshot.coc_rx_rejected as u64))
            .and_then(|()| encoder.uint(9))
            .and_then(|()| encoder.boolean(snapshot.scanning))
            .and_then(|()| encoder.uint(10))
            .and_then(|()| encoder.uint(snapshot.scan_reports as u64))
            .and_then(|()| encoder.uint(11))
            .and_then(|()| encoder.uint(snapshot.scan_matches as u64))
            .and_then(|()| encoder.uint(12))
            .and_then(|()| encoder.bytes_value(&snapshot.last_scan_addr))
            .and_then(|()| encoder.uint(13))
            .and_then(|()| encoder.uint(snapshot.last_scan_addr_type as u64))
            .and_then(|()| encoder.uint(14))
            .and_then(|()| encoder.int(snapshot.last_scan_rssi as i64))
            .and_then(|()| encoder.uint(15))
            .and_then(|()| encoder.boolean(snapshot.bonded))
            .and_then(|()| encoder.uint(16))
            .and_then(|()| encoder.boolean(snapshot.coc_tx_pending))
            .and_then(|()| encoder.uint(17))
            .and_then(|()| encoder.bytes_value(&snapshot.local_addr))
            .and_then(|()| encoder.uint(18))
            .and_then(|()| encoder.uint(snapshot.local_addr_type as u64))
            .and_then(|()| encoder.uint(19))
            .and_then(|()| {
                encoder.uint(BLE_INGRESS_ENQUEUED.load(core::sync::atomic::Ordering::Relaxed) as u64)
            })
            .and_then(|()| encoder.uint(20))
            .and_then(|()| {
                encoder.uint(BLE_INGRESS_ACCEPTED.load(core::sync::atomic::Ordering::Relaxed) as u64)
            })
            .and_then(|()| encoder.uint(21))
            .and_then(|()| {
                encoder.uint(BLE_INGRESS_REJECTED.load(core::sync::atomic::Ordering::Relaxed) as u64)
            })
            .and_then(|()| encoder.uint(22))
            .and_then(|()| {
                encoder.uint(BLE_EGRESS_ATTEMPTS.load(core::sync::atomic::Ordering::Relaxed) as u64)
            })
            .and_then(|()| encoder.uint(23))
            .and_then(|()| {
                encoder.uint(BLE_EGRESS_SENT.load(core::sync::atomic::Ordering::Relaxed) as u64)
            })
            .and_then(|()| encoder.uint(24))
            .and_then(|()| {
                encoder.uint(
                    BLE_EGRESS_SEND_ERRORS.load(core::sync::atomic::Ordering::Relaxed) as u64,
                )
            })
            .and_then(|()| encoder.uint(25))
            .and_then(|()| {
                encoder.uint(
                    BLE_EGRESS_BLOCKED_DISCONNECTED.load(core::sync::atomic::Ordering::Relaxed)
                        as u64,
                )
            })
            .and_then(|()| encoder.uint(26))
            .and_then(|()| {
                encoder.uint(
                    BLE_EGRESS_BLOCKED_PENDING.load(core::sync::atomic::Ordering::Relaxed) as u64,
                )
            })
            .map(|()| encoder.len())
    })()?;
    let mut response = [0u8; 576];
    let used = tagged::encode_numeric_response(
        component,
        method,
        id,
        &result[..result_len],
        &mut response,
    )?;
    Some(Vec::from(&response[..used]))
}

fn error_result(record: Record<'_>, message: &[u8]) -> Option<Vec<u8>> {
    let component = match record.component? {
        Name::Tag(value) if value == BLE_COMPONENT => value,
        _ => return None,
    };
    let method = match record.method? {
        Name::Tag(value) => value,
        _ => return None,
    };
    let id = record.id?;
    let mut response = [0u8; 128];
    let used = tagged::encode_numeric_error(component, method, id, message, &mut response)?;
    Some(Vec::from(&response[..used]))
}

fn handle_ble(record: Record<'_>) -> Option<Vec<u8>> {
    if record.to.is_some()
        || record.params.is_some()
        || record.data.is_some()
        || record.result.is_some()
        || record.error.is_some()
    {
        return None;
    }
    if !matches!(record.component, Some(Name::Tag(BLE_COMPONENT))) {
        return None;
    }
    let method = match record.method? {
        Name::Tag(value) => value,
        _ => return None,
    };
    let _id = record.id?;
    match method {
        BLE_START => bool_result(record, dmesh_ble::start_dmesh_service().is_ok()),
        BLE_STOP => bool_result(record, dmesh_ble::stop_dmesh_service().is_ok()),
        BLE_SCAN => {
            let duration = scan_duration(record.fields);
            bool_result(record, dmesh_ble::start_scan(duration).is_ok())
        }
        BLE_STATUS => status_result(record),
        BLE_SCAN_STOP => bool_result(record, dmesh_ble::stop_scan().is_ok()),
        BLE_CONNECT => {
            let (addr, addr_type, psm) = match connect_request(record.fields) {
                Some(value) => value,
                None => return error_result(record, b"bad fields"),
            };
            bool_result(
                record,
                dmesh_ble::connect_coc(&addr, addr_type, psm).is_ok(),
            )
        }
        BLE_COC_SEND => {
            let (data, len) = match send_data(record.fields) {
                Some(value) => value,
                None => return error_result(record, b"empty data"),
            };
            let ok = unsafe {
                let frame = &mut *core::ptr::addr_of_mut!(BLE_COC_FRAME);
                frame[0] = (len >> 8) as u8;
                frame[1] = len as u8;
                frame[2..2 + len].copy_from_slice(&data[..len]);
                dmesh_ble::send_coc_bytes(&frame[..2 + len]).is_ok()
            };
            bool_result(record, ok)
        }
        _ => error_result(record, b"unsupported method"),
    }
}
