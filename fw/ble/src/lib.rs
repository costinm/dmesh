//! ESP-IDF NimBLE mechanics for DMesh Main.
//!
//! This crate owns only the native callback boundary while Main wires opaque
//! CoC bytes into its shared QUIC-lite connection service.

#![deny(unsafe_op_in_unsafe_fn)]

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_ushort};
use core::sync::atomic::{
    AtomicBool, AtomicI32, AtomicU16, AtomicU32, AtomicU8, AtomicUsize, Ordering,
};

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
static SCANNING: AtomicBool = AtomicBool::new(false);
static SCAN_REPORTS: AtomicU32 = AtomicU32::new(0);
static SCAN_MATCHES: AtomicU32 = AtomicU32::new(0);
static LAST_SCAN_ADDR: [AtomicU8; 6] = [const { AtomicU8::new(0) }; 6];
static LAST_SCAN_ADDR_TYPE: AtomicU8 = AtomicU8::new(0);
static LAST_SCAN_RSSI: AtomicI32 = AtomicI32::new(0);
static LOCAL_ADDR: [AtomicU8; 6] = [const { AtomicU8::new(0) }; 6];
static LOCAL_ADDR_TYPE: AtomicU8 = AtomicU8::new(0);
static BONDED: AtomicBool = AtomicBool::new(false);
static COC_RX_HOOK: AtomicUsize = AtomicUsize::new(0);
static COC_EGRESS_READY_HOOK: AtomicUsize = AtomicUsize::new(0);
static COC_STATE_HOOK: AtomicUsize = AtomicUsize::new(0);

extern "C" {
    fn dmesh_nimble_init() -> c_int;
    fn dmesh_nimble_start_coc_server(psm: c_ushort) -> c_int;
    fn dmesh_nimble_connect_coc(
        peer_addr: *const c_uchar,
        peer_addr_type: c_uchar,
        psm: c_ushort,
    ) -> c_int;
    fn dmesh_nimble_coc_send(data: *const c_uchar, len: c_ushort) -> c_int;
    fn dmesh_nimble_coc_tx_pending() -> c_int;
    fn dmesh_nimble_start_scan(duration_ms: c_uint) -> c_int;
    fn dmesh_nimble_stop_scan() -> c_int;
    fn dmesh_nimble_start_advertising(
        adv: *const c_uchar,
        adv_len: c_uchar,
        min_units: c_ushort,
        max_units: c_ushort,
    ) -> c_int;
    fn dmesh_nimble_stop_service() -> c_int;
}

const DMESH_BLE_SERVICE_UUID16: u16 = 0x1820;
/// Android's CompanionDeviceManager filter uses this stable 128-bit UUID. The
/// advertisement also retains the 16-bit DMesh service UUID for ordinary scan
/// compatibility.
const DMESH_BLE_PAIRING_UUID128: [u8; 16] = [
    0x80, 0x6f, 0x6b, 0x5f, 0x2a, 0x4f, 0x4a, 0x6f, 0x8c, 0x42, 0x4d, 0x65, 0x73, 0x68, 0x00, 0x01,
];
fn idle_advertisement() -> [u8; 25] {
    let uuid16 = DMESH_BLE_SERVICE_UUID16.to_le_bytes();
    [
        0x02, 0x01, 0x06,
        0x03, 0x02, uuid16[0], uuid16[1],
        0x11, 0x07,
        DMESH_BLE_PAIRING_UUID128[0], DMESH_BLE_PAIRING_UUID128[1],
        DMESH_BLE_PAIRING_UUID128[2], DMESH_BLE_PAIRING_UUID128[3],
        DMESH_BLE_PAIRING_UUID128[4], DMESH_BLE_PAIRING_UUID128[5],
        DMESH_BLE_PAIRING_UUID128[6], DMESH_BLE_PAIRING_UUID128[7],
        DMESH_BLE_PAIRING_UUID128[8], DMESH_BLE_PAIRING_UUID128[9],
        DMESH_BLE_PAIRING_UUID128[10], DMESH_BLE_PAIRING_UUID128[11],
        DMESH_BLE_PAIRING_UUID128[12], DMESH_BLE_PAIRING_UUID128[13],
        DMESH_BLE_PAIRING_UUID128[14], DMESH_BLE_PAIRING_UUID128[15],
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
    let rc = unsafe { dmesh_nimble_stop_service() };
    if rc == 0 {
        ADVERTISING.store(false, Ordering::Release);
        SCANNING.store(false, Ordering::Release);
    }
    if rc == 0 {
        Ok(())
    } else {
        Err(rc)
    }
}

pub fn start_scan(duration_ms: u32) -> Result<(), i32> {
    if !READY.load(Ordering::Acquire) {
        return Err(-110);
    }
    let rc = unsafe { dmesh_nimble_start_scan(duration_ms) };
    if rc == 0 {
        SCANNING.store(true, Ordering::Release);
    }
    if rc == 0 {
        Ok(())
    } else {
        Err(rc)
    }
}

pub fn stop_scan() -> Result<(), i32> {
    let rc = unsafe { dmesh_nimble_stop_scan() };
    if rc == 0 {
        SCANNING.store(false, Ordering::Release);
    }
    if rc == 0 {
        Ok(())
    } else {
        Err(rc)
    }
}

pub fn coc_tx_pending() -> bool {
    READY.load(Ordering::Acquire) && unsafe { dmesh_nimble_coc_tx_pending() } != 0
}

pub fn coc_connected() -> bool {
    COC_CONNECTED.load(Ordering::Acquire)
}

pub fn set_coc_rx_hook(hook: Option<fn(&[u8])>) {
    COC_RX_HOOK.store(hook.map(|hook| hook as usize).unwrap_or(0), Ordering::Release);
}

pub fn set_coc_egress_ready_hook(hook: Option<fn()>) {
    COC_EGRESS_READY_HOOK.store(
        hook.map(|hook| hook as usize).unwrap_or(0),
        Ordering::Release,
    );
}

pub fn set_coc_state_hook(hook: Option<fn(bool)>) {
    COC_STATE_HOOK.store(hook.map(|hook| hook as usize).unwrap_or(0), Ordering::Release);
}

fn coc_state_hook(connected: bool) {
    let hook = COC_STATE_HOOK.load(Ordering::Acquire);
    if hook != 0 {
        let hook: fn(bool) = unsafe { core::mem::transmute(hook) };
        hook(connected);
    }
}

fn coc_egress_ready() {
    let hook = COC_EGRESS_READY_HOOK.load(Ordering::Acquire);
    if hook != 0 {
        let hook: fn() = unsafe { core::mem::transmute(hook) };
        hook();
    }
}

/// Initiate a central GAP connection and open the requested CoC channel after
/// the link is established.
pub fn connect_coc(peer: &[u8], peer_type: u8, psm: u16) -> Result<(), i32> {
    if !READY.load(Ordering::Acquire) {
        return Err(-110);
    }
    if peer.len() != 6 || psm < 0x0080 || psm > 0x00ff {
        return Err(-22);
    }
    let rc = unsafe { dmesh_nimble_connect_coc(peer.as_ptr(), peer_type, psm) };
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
    pub scanning: bool,
    pub scan_reports: u32,
    pub scan_matches: u32,
    pub last_scan_addr: [u8; 6],
    pub last_scan_addr_type: u8,
    pub last_scan_rssi: i32,
    pub bonded: bool,
    pub coc_tx_pending: bool,
    pub local_addr: [u8; 6],
    pub local_addr_type: u8,
}

pub fn link_snapshot() -> LinkSnapshot {
    let mut last_scan_addr = [0u8; 6];
    for (index, value) in last_scan_addr.iter_mut().enumerate() {
        *value = LAST_SCAN_ADDR[index].load(Ordering::Relaxed);
    }
    let mut local_addr = [0u8; 6];
    for (index, value) in local_addr.iter_mut().enumerate() {
        *value = LOCAL_ADDR[index].load(Ordering::Relaxed);
    }
    LinkSnapshot {
        ready: READY.load(Ordering::Acquire),
        advertising: ADVERTISING.load(Ordering::Acquire),
        connected: CONNECTED.load(Ordering::Acquire),
        coc_connected: COC_CONNECTED.load(Ordering::Acquire),
        generation: CONNECTION_GENERATION.load(Ordering::Acquire),
        handle: CONNECTION_HANDLE.load(Ordering::Acquire),
        coc_rx: COC_RX.load(Ordering::Relaxed),
        coc_rx_rejected: COC_RX_REJECTED.load(Ordering::Relaxed),
        scanning: SCANNING.load(Ordering::Acquire),
        scan_reports: SCAN_REPORTS.load(Ordering::Relaxed),
        scan_matches: SCAN_MATCHES.load(Ordering::Relaxed),
        last_scan_addr,
        last_scan_addr_type: LAST_SCAN_ADDR_TYPE.load(Ordering::Relaxed),
        last_scan_rssi: LAST_SCAN_RSSI.load(Ordering::Relaxed),
        bonded: BONDED.load(Ordering::Acquire),
        coc_tx_pending: coc_tx_pending(),
        local_addr,
        local_addr_type: LOCAL_ADDR_TYPE.load(Ordering::Relaxed),
    }
}

// The callbacks below are intentionally allocation- and handler-free.  Their
// complete CoC-to-QUIC handoff is introduced with the shared ingress adapter;
// until then inbound payloads are counted and rejected rather than sent to the
// retired command dispatcher.
#[no_mangle]
pub unsafe extern "C" fn dmesh_nimble_on_ready(addr: *const c_uchar, addr_type: c_uchar) {
    if !addr.is_null() {
        let bytes = unsafe { core::slice::from_raw_parts(addr, 6) };
        for (index, value) in bytes.iter().enumerate() {
            LOCAL_ADDR[index].store(*value, Ordering::Relaxed);
        }
    }
    LOCAL_ADDR_TYPE.store(addr_type as u8, Ordering::Relaxed);
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
    let was_connected = COC_CONNECTED.load(Ordering::Acquire);
    let connected = connected != 0;
    COC_CONNECTED.store(connected, Ordering::Release);
    if connected != was_connected {
        coc_state_hook(connected);
    }
    if !was_connected && connected {
        coc_egress_ready();
    }
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_nimble_on_coc_write(data: *const c_uchar, len: c_ushort) {
    if len == 0 || usize::from(len) > COC_PACKET_CAPACITY {
        COC_RX_REJECTED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let hook = COC_RX_HOOK.load(Ordering::Acquire);
    if hook == 0 {
        COC_RX_REJECTED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    COC_RX.fetch_add(1, Ordering::Relaxed);
    let hook: fn(&[u8]) = unsafe { core::mem::transmute(hook) };
    hook(unsafe { core::slice::from_raw_parts(data, usize::from(len)) });
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_nimble_on_coc_tx_ready() {
    coc_egress_ready();
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_nimble_on_scan_result(
    addr_type: c_uchar,
    addr: *const c_uchar,
    rssi: c_int,
    matched: c_uchar,
) {
    if !addr.is_null() {
        let bytes = unsafe { core::slice::from_raw_parts(addr, 6) };
        for (index, value) in bytes.iter().enumerate() {
            LAST_SCAN_ADDR[index].store(*value, Ordering::Relaxed);
        }
    }
    LAST_SCAN_ADDR_TYPE.store(addr_type, Ordering::Relaxed);
    LAST_SCAN_RSSI.store(rssi as i32, Ordering::Relaxed);
    SCAN_REPORTS.fetch_add(1, Ordering::Relaxed);
    if matched != 0 {
        SCAN_MATCHES.fetch_add(1, Ordering::Relaxed);
    }
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_nimble_on_scan_state(scanning: c_uchar) {
    SCANNING.store(scanning != 0, Ordering::Release);
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_nimble_on_auth_complete(bonded: c_uchar) {
    BONDED.store(bonded != 0, Ordering::Release);
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_nimble_on_log(_line: *const c_char) {}
