//! ESP-IDF NimBLE mechanics for DMesh Main.
//!
//! This crate owns only the native callback boundary while Main wires opaque
//! CoC bytes into its shared QUIC-lite connection service.

#![deny(unsafe_op_in_unsafe_fn)]

use core::ffi::{c_char, c_int, c_uchar, c_ushort};
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};

pub const COC_PSM: u16 = 0x0080;
/// Normal Main QUIC packets are 1100 bytes today.  The native CoC component
/// reserves 1152 bytes, leaving room for byte-stream framing without retaining
/// the old 256-byte test ceiling.
pub const COC_PACKET_CAPACITY: usize = 1152;

static READY: AtomicBool = AtomicBool::new(false);
static CONNECTED: AtomicBool = AtomicBool::new(false);
static COC_CONNECTED: AtomicBool = AtomicBool::new(false);
static CONNECTION_GENERATION: AtomicU32 = AtomicU32::new(0);
static CONNECTION_HANDLE: AtomicU16 = AtomicU16::new(u16::MAX);
static COC_RX: AtomicU32 = AtomicU32::new(0);
static COC_RX_REJECTED: AtomicU32 = AtomicU32::new(0);
static ADVERTISING: AtomicBool = AtomicBool::new(false);
static BOOT_ENABLED: AtomicBool = AtomicBool::new(false);

extern "C" {
    fn dmesh_nimble_init() -> c_int;
    fn dmesh_nimble_start_coc_server(psm: c_ushort) -> c_int;
    fn dmesh_nimble_coc_send(data: *const c_uchar, len: c_ushort) -> c_int;
    fn dmesh_nimble_start_advertising(
        adv: *const c_uchar,
        adv_len: c_uchar,
        min_units: c_ushort,
        max_units: c_ushort,
    ) -> c_int;
    fn dmesh_nimble_stop_advertising() -> c_int;
}

const DMESH_BLE_SERVICE_UUID16: u16 = 0x1820;
const IDLE_EVENT: u8 = 2;
const V2_MARKER: u8 = 0x80;
const EMPTY_PACKET_ID: [u8; 4] = [0xd5, 0x9d, 0x1c, 0x81];
fn idle_advertisement() -> [u8; 18] {
    let uuid = DMESH_BLE_SERVICE_UUID16.to_le_bytes();
    [
        0x02, 0x01, 0x06, 0x0e, 0x16,
        uuid[0], uuid[1],
        0x00, 0x00, 0x00, 0x00,
        EMPTY_PACKET_ID[0], EMPTY_PACKET_ID[1], EMPTY_PACKET_ID[2], EMPTY_PACKET_ID[3],
        V2_MARKER, 0x00, IDLE_EVENT,
    ]
}
const ADVERTISING_INTERVAL_MIN_UNITS: c_ushort = 0x20;
const ADVERTISING_INTERVAL_MAX_UNITS: c_ushort = 0x40;

pub fn configure_boot(enabled: bool) {
    BOOT_ENABLED.store(enabled, Ordering::Release);
}

pub fn boot_enabled() -> bool {
    BOOT_ENABLED.load(Ordering::Acquire)
}

pub fn start_dmesh_service() -> Result<(), i32> {
    if !BOOT_ENABLED.load(Ordering::Acquire) {
        return Err(-22);
    }
    start_coc_server()?;
    let advertisement = idle_advertisement();
    let rc = unsafe {
        dmesh_nimble_start_advertising(
            advertisement.as_ptr(),
            advertisement.len() as c_uchar,
            ADVERTISING_INTERVAL_MIN_UNITS,
            ADVERTISING_INTERVAL_MAX_UNITS,
        )
    };
    if rc != 0 {
        return Err(rc);
    }
    ADVERTISING.store(true, Ordering::Release);
    Ok(())
}

pub fn stop_dmesh_service() -> Result<(), i32> {
    let rc = unsafe { dmesh_nimble_stop_advertising() };
    if rc == 0 {
        ADVERTISING.store(false, Ordering::Release);
    }
    if rc == 0 {
        Ok(())
    } else {
        Err(rc)
    }
}

/// Start NimBLE and publish the CoC server. Main calls this only after its
/// shared connection/egress hooks have been installed.
pub fn start_coc_server() -> Result<(), i32> {
    if !READY.load(Ordering::Acquire) {
        let rc = unsafe { dmesh_nimble_init() };
        if rc != 0 {
            return Err(rc);
        }
    }
    let rc = unsafe { dmesh_nimble_start_coc_server(COC_PSM) };
    if rc == 0 {
        Ok(())
    } else {
        Err(rc)
    }
}

/// Native CoC egress. Packet framing and queue ownership are installed by the
/// Main adapter in a follow-up slice; this only preserves the bounded ABI.
pub fn send_coc_bytes(bytes: &[u8]) -> Result<(), i32> {
    if bytes.is_empty() || bytes.len() > COC_PACKET_CAPACITY {
        return Err(-1);
    }
    let rc = unsafe { dmesh_nimble_coc_send(bytes.as_ptr(), bytes.len() as c_ushort) };
    if rc == 0 {
        Ok(())
    } else {
        Err(rc)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkSnapshot {
    pub ready: bool,
    pub advertising: bool,
    pub connected: bool,
    pub coc_connected: bool,
    pub generation: u32,
    pub handle: u16,
    pub coc_rx: u32,
    pub coc_rx_rejected: u32,
}

pub fn link_snapshot() -> LinkSnapshot {
    LinkSnapshot {
        ready: READY.load(Ordering::Acquire),
        advertising: ADVERTISING.load(Ordering::Acquire),
        connected: CONNECTED.load(Ordering::Acquire),
        coc_connected: COC_CONNECTED.load(Ordering::Acquire),
        generation: CONNECTION_GENERATION.load(Ordering::Acquire),
        handle: CONNECTION_HANDLE.load(Ordering::Acquire),
        coc_rx: COC_RX.load(Ordering::Relaxed),
        coc_rx_rejected: COC_RX_REJECTED.load(Ordering::Relaxed),
    }
}

// The callbacks below are intentionally allocation- and handler-free.  Their
// complete CoC-to-QUIC handoff is introduced with the shared ingress adapter;
// until then inbound payloads are counted and rejected rather than sent to the
// retired command dispatcher.
#[no_mangle]
pub unsafe extern "C" fn dmesh_nimble_on_ready(_addr: *const c_uchar, _addr_type: c_uchar) {
    READY.store(true, Ordering::Release);
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_nimble_on_connect(
    handle: c_ushort,
) {
    CONNECTION_HANDLE.store(handle, Ordering::Release);
    CONNECTION_GENERATION.fetch_add(1, Ordering::AcqRel);
    CONNECTED.store(true, Ordering::Release);
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_nimble_on_disconnect(_reason: c_ushort) {
    CONNECTED.store(false, Ordering::Release);
    COC_CONNECTED.store(false, Ordering::Release);
    CONNECTION_HANDLE.store(u16::MAX, Ordering::Release);
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_nimble_on_coc_state(connected: c_uchar) {
    COC_CONNECTED.store(connected != 0, Ordering::Release);
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_nimble_on_coc_write(_data: *const c_uchar, len: c_ushort) {
    if len == 0 || usize::from(len) > COC_PACKET_CAPACITY {
        COC_RX_REJECTED.fetch_add(1, Ordering::Relaxed);
    } else {
        COC_RX.fetch_add(1, Ordering::Relaxed);
        COC_RX_REJECTED.fetch_add(1, Ordering::Relaxed);
    }
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_nimble_on_log(_line: *const c_char) {}
