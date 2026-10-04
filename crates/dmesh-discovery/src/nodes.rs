//! The `discovery.nodes` response: one row per discovered device and bearer.
//!
//! The rows are the compact wire shared with the firmware (`API.md`, tags 1 to
//! 15, observation facts) plus the optional tags 16 to 25 that come from the
//! announce. Every platform that has a [`Device`] list builds its response here.

use dmesh_server::announce::{self, ObservedDevice};
use dmesh_server::discovery::DiscoveryObservation;

use crate::inventory::Device;

/// Most rows one response carries.
pub const MAX_ROWS: usize = 64;

struct Row {
    id: Vec<u8>,
    bearer: String,
    observation: DiscoveryObservation,
    name: Option<String>,
    vip6: Option<[u8; 16]>,
    device_class: Option<u8>,
    probe_capabilities: Option<u16>,
    authenticated: bool,
    uptime_secs: Option<u32>,
    udp_endpoint: Option<String>,
    network_name: Option<String>,
}

fn id_bytes(key: &str) -> Option<Vec<u8>> {
    if key.is_empty() || key.len() % 2 != 0 || key.len() > 32 {
        return None;
    }
    (0..key.len() / 2)
        .map(|index| u8::from_str_radix(&key[index * 2..index * 2 + 2], 16).ok())
        .collect()
}

/// Encode the correlated `discovery.nodes` result for request `id`.
///
/// A UDP observation whose link-local scope is no longer a live interface is
/// left out when `live_scopes_only` is set: a scope id is a local kernel
/// object id, and a vanished P2P group must not be offered as a path.
pub fn response(devices: &[Device], request_id: u64, live_scopes_only: bool) -> Option<Vec<u8>> {
    let mut rows = Vec::<Row>::new();
    'devices: for device in devices {
        let Some(id) = id_bytes(device.key()) else {
            continue;
        };
        let announce = device.announce.as_ref();
        let udp_endpoint = device.udp_endpoint().ok().map(|address| address.to_string());
        for (bearer, observation) in &device.observations {
            if rows.len() == MAX_ROWS {
                break 'devices;
            }
            if live_scopes_only
                && bearer == crate::BEARER_UDP
                && device
                    .udp_sender
                    .is_some_and(|sender| !crate::interfaces::has_live_scope(&sender))
            {
                continue;
            }
            rows.push(Row {
                id: id.clone(),
                bearer: bearer.clone(),
                observation: observation.clone(),
                name: device.name().map(str::to_owned),
                vip6: device.vip6().map(|vip| vip.octets()),
                device_class: announce.map(|announce| announce.device_class),
                probe_capabilities: announce.map(|announce| announce.probe_capabilities),
                authenticated: device.authenticated,
                uptime_secs: announce.map(|announce| announce.uptime_secs),
                udp_endpoint: udp_endpoint.clone(),
                network_name: announce
                    .and_then(|announce| announce.network_name())
                    .map(str::to_owned),
            });
        }
    }
    let entries: Vec<ObservedDevice<'_>> = rows
        .iter()
        .map(|row| {
            let observation = &row.observation;
            ObservedDevice {
                device_id: &row.id,
                // A bearer-local handle (an Android PeerHandle, a UDP source) is
                // not a MAC and is never serialized as one; the semantic id is
                // the cross-bearer merge key.
                peer: [0; 6],
                bssid: observation.last_bssid,
                channel: observation.last_channel,
                available_fields: observation.available_fields,
                first_seen_ms: u32::try_from(observation.first_seen_ms).unwrap_or(u32::MAX),
                last_seen_ms: u32::try_from(observation.last_seen_ms).unwrap_or(u32::MAX),
                packets: observation.packets,
                active_publish_rx: observation.active_publish_rx,
                active_subscribe_rx: observation.active_subscribe_rx,
                followup_rx: observation.followup_rx,
                last_kind: observation.last_kind as u8,
                last_payload_len: observation.last_payload_len,
                last_payload_hash: observation.last_payload_hash,
                bearer: Some(&row.bearer),
                rssi_dbm: observation.last_rssi_dbm,
                name: row.name.as_deref(),
                vip6: row.vip6,
                device_class: row.device_class,
                probe_capabilities: row.probe_capabilities,
                authenticated: Some(row.authenticated),
                uptime_secs: row.uptime_secs,
                udp_endpoint: row.udp_endpoint.as_deref(),
                network_name: row.network_name.as_deref(),
            }
        })
        .collect();
    let mut direct = vec![0u8; 128 + entries.len() * 320];
    let direct_len = announce::encode_devices_observed_response(&entries, &mut direct)?;
    let fields = dmesh_server::tagged::decode(&direct[..direct_len])?.fields?;
    let mut wire = vec![0u8; fields.len() + 64];
    let used = dmesh_server::tagged::encode_numeric_response(
        announce::ANNOUNCE_COMPONENT,
        announce::ANNOUNCE_DEVICES_OBSERVED,
        request_id,
        fields,
        &mut wire,
    )?;
    wire.truncate(used);
    Some(wire)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BEARER_UDP, Carrier, Engine, NoFacts, UnsignedIdentity};
    use dmesh_server::announce::{Announce, DEVICE_CLASS_HOST, decode_devices_observed_response};
    use dmesh_server::discovery::DiscoveryPacketKind;
    use std::sync::Arc;

    #[test]
    fn rows_are_per_bearer_with_the_announce_attributes() {
        let engine = Engine::new(Arc::new(UnsignedIdentity::from_seed(b"me")), Arc::new(NoFacts));
        let mut peer = Announce::discovery([0x77; 16], 16, 42);
        assert!(peer.set_device_name("rowpeer"));
        peer.set_probe_descriptor(DEVICE_CLASS_HOST, 0x0f);
        peer.set_udp_link_local_v6("fe80::77".parse::<std::net::Ipv6Addr>().unwrap().octets());
        peer.set_udp_port(3336);
        let mut wire = [0u8; 256];
        let used = announce::encode(peer, &mut wire).unwrap();
        let sender = "[fe80::77%5]:5227".parse().unwrap();
        engine.on_datagram(&Carrier::udp("[fe80::77%5]:5227", sender), &wire[..used]);
        let mut nan = Carrier::radio("nan", "aware:3", DiscoveryPacketKind::ActivePublish);
        nan.rssi_dbm = Some(-58);
        engine.on_datagram(&nan, &wire[..used]);

        let response = response(&engine.devices(), 9, false).unwrap();
        let rows = decode_devices_observed_response(&response).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row.device_id == vec![0x77; 16]));
        let udp = rows.iter().find(|row| row.bearer.as_deref() == Some(BEARER_UDP)).unwrap();
        let nan = rows.iter().find(|row| row.bearer.as_deref() == Some("nan")).unwrap();
        assert_eq!(udp.name.as_deref(), Some("rowpeer"));
        assert_eq!(udp.device_class, Some(DEVICE_CLASS_HOST));
        assert_eq!(udp.uptime_secs, Some(42));
        assert_eq!(udp.authenticated, Some(false));
        assert_eq!(udp.udp_endpoint.as_deref(), Some("[fe80::77%5]:3336"));
        assert_eq!(nan.rssi_dbm, Some(-58));
        assert_eq!(rows[0].peer, None);
    }

    #[test]
    fn a_stale_link_local_scope_is_not_offered_when_asked_to_check() {
        let engine = Engine::new(Arc::new(UnsignedIdentity::from_seed(b"me")), Arc::new(NoFacts));
        let mut peer = Announce::discovery([0x78; 16], 16, 1);
        assert!(peer.set_device_name("gone"));
        let mut wire = [0u8; 256];
        let used = announce::encode(peer, &mut wire).unwrap();
        // Scope 4000000000 cannot be a live interface on any machine.
        let sender = "[fe80::78%4000000000]:5227".parse().unwrap();
        engine.on_datagram(&Carrier::udp("sender", sender), &wire[..used]);
        let kept = decode_devices_observed_response(&response(&engine.devices(), 1, false).unwrap()).unwrap();
        assert_eq!(kept.len(), 1);
        let dropped = decode_devices_observed_response(&response(&engine.devices(), 1, true).unwrap()).unwrap();
        assert!(dropped.is_empty());
    }

    #[test]
    fn no_devices_is_an_empty_list_not_an_error() {
        let engine = Engine::new(Arc::new(UnsignedIdentity::from_seed(b"me")), Arc::new(NoFacts));
        let rows = decode_devices_observed_response(&response(&engine.devices(), 3, false).unwrap()).unwrap();
        assert!(rows.is_empty());
    }
}
