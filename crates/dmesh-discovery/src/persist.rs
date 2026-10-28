//! Writing the stable part of the inventory to node records.
//!
//! The inventory is RAM: live endpoints per bearer, last-seen, RTT. A node record keeps only what
//! stays a correct hint after a day (identity, name, domain, type, serving port, a stable radio
//! MAC). This turns the inventory's authenticated devices into those records, merged into the
//! node directory without touching an owner's secret; it writes only when something changed.

use dmesh_server::device_record::{DeviceRecord, DeviceStore};

use crate::Device;

/// The radio MAC worth keeping: only an ESP's is stable (a phone's NAN/NOW address is
/// randomized), and only one a NAN or NOW observation reports.
fn stable_mac(device: &Device) -> Option<[u8; 6]> {
    let family = dmesh_server::announce::device_class_name(device.announce.as_ref()?.device_class);
    if !family.starts_with("esp") {
        return None;
    }
    ["nan", "now"].iter().find_map(|bearer| {
        let peer = &device.observations.get(*bearer)?.last_peer;
        let mut mac = [0u8; 6];
        let mut parts = peer.split(':');
        for byte in &mut mac {
            *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
        }
        (parts.next().is_none() && mac != [0; 6] && mac != [0xff; 6]).then_some(mac)
    })
}

/// The record for one device, from its latest announce; `None` unless the announce is signed and
/// verified (an unproven node gets no record).
pub fn record_of(device: &Device) -> Option<DeviceRecord> {
    if !device.authenticated {
        return None;
    }
    DeviceRecord::from_announce(device.announce.as_ref()?, stable_mac(device))
}

/// Merge every authenticated device into `store`. Returns how many files were written.
pub fn persist_devices(store: &DeviceStore, devices: &[Device]) -> Result<usize, String> {
    let mut written = 0;
    for device in devices {
        if let Some(record) = record_of(device)
            && store.observe(&record)?
        {
            written += 1;
        }
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Identity, P256Identity};
    use dmesh_server::announce::{self, Announce};
    use dmesh_server::discovery::{DiscoveryObservation, DiscoveryPacketKind, OBSERVATION_ALL_FIELDS};
    use std::collections::BTreeMap;

    fn device(authenticated: bool, class: u8, peer: &str) -> Device {
        let identity = P256Identity::generate();
        let mut announce = Announce::discovery(identity.device_id(), 16, 5);
        announce.set_device_name("light1");
        announce.device_class = class;
        identity.sign(&mut announce).unwrap();
        let mut observation = DiscoveryObservation::new(10, OBSERVATION_ALL_FIELDS);
        observation.observe(11, DiscoveryPacketKind::ActivePublish, peer, None, None, None, b"a");
        Device {
            id: "d".into(),
            announce: Some(announce),
            record: None, crawled_via: BTreeMap::new(),
            facts: None,
            authenticated,
            first_seen_ms: 1,
            last_seen_ms: 2,
            observations: BTreeMap::from([("nan".to_owned(), observation)]),
            udp_sender: None,
        }
    }

    #[test]
    fn an_authenticated_device_is_written_once_and_an_unproven_one_never() {
        let directory = tempfile::tempdir().unwrap();
        let esp = device(true, announce::DEVICE_CLASS_ESP32C6, "20:6e:f1:13:b1:70");
        let unproven = device(false, announce::DEVICE_CLASS_ESP32C6, "20:6e:f1:13:b1:71");
        assert_eq!(persist_devices(&DeviceStore::new(directory.path()), &[esp.clone(), unproven]).unwrap(), 1);
        // The same inventory again changes nothing on disk.
        assert_eq!(persist_devices(&DeviceStore::new(directory.path()), &[esp.clone()]).unwrap(), 0);
        let records = DeviceStore::new(directory.path()).list().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name.as_deref(), Some("light1"));
        assert_eq!(records[0].mac, Some([0x20, 0x6e, 0xf1, 0x13, 0xb1, 0x70]));
        assert_eq!(records[0].device_type.as_deref(), Some("esp32c6"));
        assert_eq!(records[0].trust.as_deref(), Some("first-seen"));
    }

    #[test]
    fn a_phones_randomized_radio_address_is_not_persisted() {
        let phone = device(true, announce::DEVICE_CLASS_ANDROID, "02:b7:ec:c7:0c:45");
        assert_eq!(record_of(&phone).unwrap().mac, None);
    }
}
