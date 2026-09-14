//! Shared ESP NVS adapter for the provisioned STA profile.
//!
//! This module loads credentials and the optional Recovery server endpoint;
//! it deliberately does not select NAN, NOW, AP, UART, or a product role.
//! Main and Recovery add only their own runtime policy after this succeeds.

extern "C" {
    fn nvs_flash_init() -> i32;
    fn nvs_open(namespace: *const i8, mode: i32, handle: *mut u32) -> i32;
    fn nvs_get_str(handle: u32, key: *const i8, value: *mut u8, length: *mut usize) -> i32;
    fn nvs_close(handle: u32);
}

const NVS_READONLY: i32 = 0;

fn nvs_string(handle: u32, key: &[u8], output: &mut [u8]) -> Option<usize> {
    let mut length = output.len();
    if unsafe {
        nvs_get_str(
            handle,
            key.as_ptr().cast(),
            output.as_mut_ptr(),
            &mut length,
        )
    } != 0
    {
        return None;
    }
    Some(
        output
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(length.min(output.len())),
    )
}

fn parse_port(value: &[u8]) -> Option<u16> {
    let mut port = 0u16;
    for byte in value {
        if !byte.is_ascii_digit() {
            return None;
        }
        port = port.checked_mul(10)?.checked_add(u16::from(*byte - b'0'))?;
    }
    (port != 0).then_some(port)
}

/// Load one complete provisioned STA credential set.
///
/// The optional server address and port are validated as a pair. They remain
/// discovery hints for now; neither this adapter nor the Wi-Fi driver derives
/// transport routing from a BSSID or invents a host scope.
pub(crate) fn load(profile: &mut crate::TransportProfile) -> bool {
    let _ = unsafe { nvs_flash_init() };
    let mut handle = 0_u32;
    if unsafe { nvs_open(b"dmesh\0".as_ptr().cast(), NVS_READONLY, &mut handle) } != 0 {
        return false;
    }
    let mut ssid = [0u8; 33];
    let mut server_ll = [0u8; 40];
    let mut server_port = [0u8; 6];
    let result = (|| {
        let ssid_len = nvs_string(handle, b"sta_ssid\0", &mut ssid)?;
        let server_len = nvs_string(handle, b"sta_server_ll\0", &mut server_ll);
        let port_len = nvs_string(handle, b"sta_server_port\0", &mut server_port);
        if !dmesh_server::firmware_profile::valid_ssid(&ssid[..ssid_len]) {
            return None;
        }
        match (server_len, port_len) {
            (None, None) => {}
            (Some(server_len), Some(port_len))
                if server_ll[..server_len].starts_with(b"fe80:")
                    && !server_ll[..server_len].contains(&b'%')
                    && parse_port(&server_port[..port_len]).is_some() => {}
            _ => return None,
        }
        let mut psk = [0u8; 64];
        let mut secret_handle = 0_u32;
        if unsafe { nvs_open(b"sec\0".as_ptr().cast(), NVS_READONLY, &mut secret_handle) } != 0 {
            return None;
        }
        let psk_len = nvs_string(secret_handle, b"sta\0", &mut psk);
        unsafe { nvs_close(secret_handle) };
        let psk_len = psk_len?;
        if !(8..=63).contains(&psk_len) {
            return None;
        }
        profile.ssid[..ssid_len].copy_from_slice(&ssid[..ssid_len]);
        profile.ssid_len = ssid_len;
        profile.sta_passphrase[..psk_len].copy_from_slice(&psk[..psk_len]);
        profile.sta_passphrase_len = psk_len;
        profile.requested_transport = Some(dmesh_server::control::TransportKind::Sta);
        profile.ap = 0;
        profile.run_requested = true;
        Some(())
    })()
    .is_some();
    unsafe { nvs_close(handle) };
    result
}
