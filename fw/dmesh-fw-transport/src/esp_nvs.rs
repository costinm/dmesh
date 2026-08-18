// IMPORTANT: This is shared no-std ESP firmware code. Host-testable profile
// rules live in dmesh-server/quic-lite; this file is only the ESP-IDF NVS
// adapter used by both Recovery and Main.
//! ESP-IDF NVS adapter for the shared transport profile.
//!
//! The profile layout and command defaults live in `dmesh-fw-transport` so
//! Main and Recovery cannot drift. This file intentionally contains only the
//! Recovery binary's direct NVS calls.

extern "C" {
    fn nvs_flash_init() -> i32;
    fn nvs_open(namespace: *const i8, mode: i32, handle: *mut u32) -> i32;
    fn nvs_get_str(handle: u32, key: *const i8, value: *mut i8, length: *mut usize) -> i32;
    fn nvs_get_u32(handle: u32, key: *const i8, value: *mut u32) -> i32;
    fn nvs_set_str(handle: u32, key: *const i8, value: *const i8) -> i32;
    fn nvs_commit(handle: u32) -> i32;
    fn nvs_close(handle: u32);
}

struct NvsStore {
    handle: u32,
}

impl NvsStore {
    unsafe fn open(mode: i32) -> Option<Self> {
        let mut handle = 0;
        (nvs_open(b"dmesh\0".as_ptr().cast(), mode, &mut handle) == 0).then_some(Self { handle })
    }
}

impl Drop for NvsStore {
    fn drop(&mut self) {
        unsafe { nvs_close(self.handle) }
    }
}

impl crate::TransportSettings for NvsStore {
    fn get_text(&mut self, key: &str, output: &mut [u8]) -> Option<usize> {
        let key = nvs_key(key)?;
        let mut capacity = output.len();
        let result = unsafe {
            nvs_get_str(
                self.handle,
                key.as_ptr().cast(),
                output.as_mut_ptr().cast(),
                &mut capacity,
            )
        };
        (result == 0 && capacity != 0).then_some(capacity.saturating_sub(1).min(output.len()))
    }

    fn set_text(&mut self, key: &str, value: &[u8]) -> bool {
        let Some(key) = nvs_key(key) else {
            return false;
        };
        let mut terminated = [0u8; 65];
        if value.len() >= terminated.len() {
            return false;
        }
        terminated[..value.len()].copy_from_slice(value);
        unsafe { nvs_set_str(self.handle, key.as_ptr().cast(), terminated.as_ptr().cast()) == 0 }
    }

    fn commit(&mut self) -> bool {
        unsafe { nvs_commit(self.handle) == 0 }
    }
}

/// `nvs_get_str`/`nvs_set_str` take C strings.  Never pass a Rust `&str`
/// pointer directly: literals are not required to carry a trailing NUL and a
/// profile read can otherwise depend on adjacent linker data.  Keeping this
/// finite mapping also ensures that shared-profile persistence cannot write
/// arbitrary NVS keys from a transport request.
fn nvs_key(key: &str) -> Option<&'static [u8]> {
    match key {
        "ssid" => Some(b"ssid\0"),
        "server" => Some(b"server\0"),
        "ip" => Some(b"ip\0"),
        "gw" => Some(b"gw\0"),
        "mask" => Some(b"mask\0"),
        "port" => Some(b"port\0"),
        "udp.win" => Some(b"udp.win\0"),
        _ => None,
    }
}

pub unsafe fn load_from_nvs(params: &mut crate::TransportProfile) {
    if nvs_flash_init() != 0 {
        return;
    }
    let mut handle = 0u32;
    if nvs_open(b"stg2\0".as_ptr().cast(), 0, &mut handle) == 0 {
        let mut target = 0u32;
        params.command_mode =
            nvs_get_u32(handle, b"boot_target\0".as_ptr().cast(), &mut target) == 0 && target == 2;
        nvs_close(handle);
    }
    if let Some(mut store) = NvsStore::open(0) {
        crate::load_profile(&mut store, params);
    }
}

/// Update only DMesh-owned entries, leaving ESP calibration and PHY data intact.
pub unsafe fn persist_profile(params: &crate::TransportProfile) -> bool {
    let Some(mut store) = NvsStore::open(1) else {
        return false;
    };
    crate::persist_profile(&mut store, params)
}
