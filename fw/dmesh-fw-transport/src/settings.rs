// IMPORTANT: This crate is for firmware/platform-only glue. If code can be
// host-tested or reused without ESP/FreeRTOS ownership, it probably belongs
// in `quic-lite` (QUIC-lite transport mechanics) or `dmesh-server` (shared
// service/protocol behavior), not here.

//! Shared, allocation-free NVS contract for the STA/transport profile.

use crate::TransportProfile;

pub const NVS_NAMESPACE: &str = "dmesh";
pub const KEY_SSID: &str = "ssid";
pub const KEY_SERVER: &str = "server";
pub const KEY_IP: &str = "ip";
pub const KEY_GATEWAY: &str = "gw";
pub const KEY_MASK: &str = "mask";
pub const KEY_PORT: &str = "port";

/// Thin platform adapter for DMesh's shared NVS namespace.
///
/// Implementations own ESP-IDF/host storage handles and error reporting; the
/// profile rules, key spelling, and bounded conversion stay common.
pub trait TransportSettings {
    fn get_text(&mut self, key: &str, output: &mut [u8]) -> Option<usize>;
    fn set_text(&mut self, key: &str, value: &[u8]) -> bool;
    fn commit(&mut self) -> bool;
}

pub fn load_profile(store: &mut impl TransportSettings, profile: &mut TransportProfile) {
    load_text(store, KEY_SSID, &mut profile.ssid, &mut profile.ssid_len);
    load_text(
        store,
        KEY_SERVER,
        &mut profile.server,
        &mut profile.server_len,
    );
    load_text(
        store,
        KEY_IP,
        &mut profile.local_ip,
        &mut profile.local_ip_len,
    );
    load_text(
        store,
        KEY_GATEWAY,
        &mut profile.gateway,
        &mut profile.gateway_len,
    );
    load_text(store, KEY_MASK, &mut profile.mask, &mut profile.mask_len);
    let mut port = [0u8; 8];
    if let Some(length) = store.get_text(KEY_PORT, &mut port) {
        if let Some(value) = parse_port(&port[..length]) {
            profile.port = value;
        }
    }
}

pub fn persist_profile(store: &mut impl TransportSettings, profile: &TransportProfile) -> bool {
    let fields = [
        (KEY_SSID, &profile.ssid[..profile.ssid_len]),
        (KEY_SERVER, &profile.server[..profile.server_len]),
        (KEY_IP, &profile.local_ip[..profile.local_ip_len]),
        (KEY_GATEWAY, &profile.gateway[..profile.gateway_len]),
        (KEY_MASK, &profile.mask[..profile.mask_len]),
    ];
    for (key, value) in fields {
        if !store.set_text(key, value) {
            return false;
        }
    }
    let mut port = [0u8; 5];
    let length = format_port(profile.port, &mut port);
    store.set_text(KEY_PORT, &port[..length]) && store.commit()
}

fn load_text(store: &mut impl TransportSettings, key: &str, output: &mut [u8], length: &mut usize) {
    if let Some(used) = store.get_text(key, output) {
        *length = used.min(output.len());
    }
}

fn parse_port(value: &[u8]) -> Option<u16> {
    if value.is_empty() {
        return None;
    }
    let mut parsed = 0u16;
    for byte in value {
        if !byte.is_ascii_digit() {
            return None;
        }
        parsed = parsed.checked_mul(10)?.checked_add((byte - b'0') as u16)?;
    }
    (parsed != 0).then_some(parsed)
}

fn format_port(mut value: u16, out: &mut [u8; 5]) -> usize {
    let mut digits = 0;
    loop {
        out[out.len() - 1 - digits] = b'0' + (value % 10) as u8;
        digits += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let start = out.len() - digits;
    out.copy_within(start.., 0);
    digits
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Store {
        values: [Option<(&'static str, [u8; 64], usize)>; 6],
    }
    impl Store {
        fn new() -> Self {
            Self { values: [None; 6] }
        }
    }
    impl TransportSettings for Store {
        fn get_text(&mut self, key: &str, output: &mut [u8]) -> Option<usize> {
            self.values
                .iter()
                .flatten()
                .find(|(stored, _, _)| *stored == key)
                .map(|(_, value, len)| {
                    output[..*len].copy_from_slice(&value[..*len]);
                    *len
                })
        }
        fn set_text(&mut self, key: &str, value: &[u8]) -> bool {
            let index = self
                .values
                .iter()
                .position(|slot| slot.as_ref().is_some_and(|(stored, _, _)| *stored == key))
                .or_else(|| self.values.iter().position(|slot| slot.is_none()));
            let Some(index) = index else {
                return false;
            };
            if value.len() > 64 {
                return false;
            }
            let mut saved = [0u8; 64];
            saved[..value.len()].copy_from_slice(value);
            self.values[index] = Some((
                match key {
                    KEY_SSID => KEY_SSID,
                    KEY_SERVER => KEY_SERVER,
                    KEY_IP => KEY_IP,
                    KEY_GATEWAY => KEY_GATEWAY,
                    KEY_MASK => KEY_MASK,
                    KEY_PORT => KEY_PORT,
                    _ => return false,
                },
                saved,
                value.len(),
            ));
            true
        }
        fn commit(&mut self) -> bool {
            true
        }
    }

    #[test]
    fn profile_round_trips_with_shared_keys() {
        let mut profile = TransportProfile::new();
        profile.ssid[..4].copy_from_slice(b"mesh");
        profile.ssid_len = 4;
        profile.server[..9].copy_from_slice(b"10.0.0.10");
        profile.server_len = 9;
        profile.local_ip[..8].copy_from_slice(b"10.0.0.2");
        profile.local_ip_len = 8;
        profile.port = 3339;
        let mut store = Store::new();
        assert!(persist_profile(&mut store, &profile));
        let mut loaded = TransportProfile::new();
        load_profile(&mut store, &mut loaded);
        assert_eq!(loaded.port, 3339);
        assert_eq!(&loaded.ssid[..loaded.ssid_len], b"mesh");
    }
}
