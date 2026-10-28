use anyhow::{Context, Result, bail};
use mesh::message::{
    FIELD_IFACE, FIELD_LEN, FIELD_MEDIUM, FIELD_NODE, FIELD_PAYLOAD, FIELD_RADIO_ID, FIELD_RSSI,
    FIELD_STATUS, MeshMessage, MeshMessageCodec,
};
#[cfg(test)]
use p256::ecdsa::Signature;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[cfg(test)]
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use crate::load_default_infrastructure_credentials;
use dmesh_rawnan::linux::*;
use crate::radio_protocol;
use dmesh_rawnan::{NanActivePublish, NanState};
use dmesh_server::discovery::{
    DiscoveryObservation as CommonDiscoveryObservation, DiscoveryPacketKind, OBSERVATION_BSSID,
    OBSERVATION_PAYLOAD_FINGERPRINT, OBSERVATION_PEER,
};
use dmesh_server::raw_wifi::{
    WifiCaptureCounters, WifiLinkMetrics,
};

const DEFAULT_WIFI_IFACE: &str = "wlan1";
// Firmware raw-NAN peers normally wake every four seconds for a short window.
// A 700 ms probe cadence walks that phase rather than repeatedly landing on a
// fixed 250/500 ms boundary.
const DEFAULT_HCI_DEV: u16 = 0;
const DMESH_P2P_SSID: &str = "DIRECT-dmesh";
const DMESH_P2P_PASSPHRASE: &str = "untrusted-open-mode";
const DMESH_P2P_FREQUENCY_MHZ: u32 = 2437;
const DEFAULT_RAW_WIFI_LISTEN_SECS: u64 = 60;
const DEFAULT_LMESH_CONFIG_FILE: &str = "/home/system/etc/lmesh/lmesh.toml";
// Raw monitor traffic is high volume (especially with an APSTA ESP peer), so
// a short global ring could evict the semantic NAN event before a diagnostic
// client reads it. Keep enough history for one discovery/benchmark interval.
const MAX_HISTORY: usize = 4096;
/// Active NAN subscriptions can arrive anywhere in a beacon period. Keep a
/// small owner-local egress intent list until the next selected discovery
/// window, rather than incorrectly treating a closed DW as a failed request.
const MAX_PENDING_NAN_FOLLOWUPS: usize = 32;
/// One local active-publish descriptor. The radio owns its transmission and
/// releases no driver buffer into this shared, portable state.
const NAN_ACTIVE_PUBLISH_INSTANCE: u8 = 1;
/// One-hour device inventory shared by every discovery ingress handled by
/// this process. NAN is its first source; UDP multicast and control-plane
/// observations use the same registry instead of starting parallel caches.
const DISCOVERED_DEVICE_TTL_MS: u128 = 60 * 60 * 1_000;
const MAX_DISCOVERED_DEVICES: usize = 256;
/// Announcements normally refresh every five minutes. Keep semantic discovery
/// evidence for a new peer or a material change, but never turn periodic SDF
/// receipt into an event-log/trace stream.
const DISCOVERY_EVENT_MIN_INTERVAL_MS: u128 = 15 * 60 * 1_000;
/// Only a bounded tail is needed to restore the at-most-256 live inventory.
/// This keeps a provisioned persistent change log from becoming an unbounded
/// startup read after months of topology churn.
const MAX_DISCOVERY_LOG_RESTORE_BYTES: u64 = 64 * 1_024;
/// The supervised service owns this writable run directory. Operators that
/// need reboot-persistent topology evidence set `LMESH_DISCOVERY_LOG` (or the
/// older `LMESH_WIFI_DISCOVERY_LOG`) to a provisioned durable path; do not
/// silently depend on `/var/log` being writable by the service account.
const DEFAULT_DISCOVERY_CHANGE_LOG: &str = "/run/mesh/lmesh-wifi/discovery.jsonl";




/// Process-local adapter state around the shared, allocation-free capture
/// counters. Each lmesh/lmesh-wifi process has one radio owner, while the
/// counter vocabulary itself is shared with ESP in `dmesh-server`.
#[derive(Default)]
struct HostCaptureCounters {
    capture: WifiCaptureCounters,
    socket_packets: u64,
    socket_bytes: u64,
    socket_max_packet_bytes: u32,
    action_candidates: u64,
}

/// Retained monitor-event counts of one interface.
#[derive(Clone, Copy, Debug, Default)]
pub struct RawEventCounts {
    pub rx: u64,
    pub dispatch: u64,
    pub dispatch_errors: u64,
    pub action_seen: u64,
    pub monitor_frames: u64,
    pub action_candidates: u64,
    pub socket_packets: u64,
}

static HOST_CAPTURE_COUNTERS: std::sync::OnceLock<Mutex<HostCaptureCounters>> =
    std::sync::OnceLock::new();
static DISCOVERY_EVENT_GATE: std::sync::OnceLock<Mutex<BTreeMap<String, (u128, String)>>> =
    std::sync::OnceLock::new();

fn host_capture_counters() -> &'static Mutex<HostCaptureCounters> {
    HOST_CAPTURE_COUNTERS.get_or_init(|| Mutex::new(HostCaptureCounters::default()))
}

fn discovery_event_gate() -> &'static Mutex<BTreeMap<String, (u128, String)>> {
    DISCOVERY_EVENT_GATE.get_or_init(|| Mutex::new(BTreeMap::new()))
}







/// The application side of the raw capture loops: events into the history, announces
/// into the inventory, NOW control records and directed-discovery waiters.
struct RadioHost {
    history: Arc<Mutex<VecDeque<RadioEvent>>>,
    discovered_devices: Arc<Mutex<DiscoveredDeviceRegistry>>,
    espnow_ingress: Arc<Mutex<Option<Arc<dyn crate::espnow_bearer::EspNowIngress>>>>,
}

fn announce_summary(announce: &dmesh_server::announce::Announce) -> Value {
    json!({
        "kind": announce.kind,
        "device_id": hex_bytes(announce.device_id()),
        "uptime_secs": announce.uptime_secs,
        "wifi_channel": (announce.wifi_channel != 0).then_some(announce.wifi_channel),
    })
}

impl CaptureHost for RadioHost {
    fn event(&self, event: dmesh_rawnan::linux::RadioEvent) {
        let message = event.message.as_ref().map(|message| match message {
            EventMessage::RawWifi { iface } => mesh_message_from_raw_wifi(&event.value, iface),
            EventMessage::Mgmt {
                source,
                iface,
                status,
                rssi_dbm,
            } => {
                let mut message = MeshMessage::new(mesh::message::KIND_EVENT, MeshMessageCodec::Text)
                    .field(FIELD_MEDIUM, "wifi")
                    .field(FIELD_RADIO_ID, "sta")
                    .field(FIELD_NODE, source)
                    .field(FIELD_IFACE, iface)
                    .field(FIELD_STATUS, status);
                if let Some(signal) = rssi_dbm {
                    message = message.field(FIELD_RSSI, signal.to_string());
                }
                message
            }
        });
        push_radio_event(
            &self.history,
            RadioEvent {
                ts_millis: event.ts_millis,
                key: event.key,
                source: event.source,
                value: event.value,
                message,
            },
        );
    }

    fn nan_announce(&self, peer: &str, bssid: Option<&str>, payloads: &[&[u8]]) -> NanAnnounce {
        let decoded = payloads
            .iter()
            .filter_map(|payload| dmesh_server::announce::decode_announce(payload).map(|a|(a,*payload)))
            .find(|(item,_)| !is_placeholder_announce_id(item.device_id()));
        let Some((announce,payload)) = decoded else {
            return NanAnnounce::default();
        };
        if announce.has_identity() && !announce_identity_valid(announce) {
            return NanAnnounce {
                invalid_identity: true,
                summary: None,
            };
        }
        if !announce_identity_valid(announce) {
            return NanAnnounce::default();
        }
        self.discovered_devices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .observe_announce_wire("nan", peer.to_owned(), bssid.map(str::to_owned), announce, payload);
        NanAnnounce {
            invalid_identity: false,
            summary: Some(announce_summary(&announce)),
        }
    }

    fn nan_packet(&self, peer: &str, bssid: Option<&str>, kind: NanPacketKind, payload: &[u8]) {
        let kind = match kind {
            NanPacketKind::ActiveSubscribe => DiscoveryPacketKind::ActiveSubscribe,
            NanPacketKind::Followup => DiscoveryPacketKind::Followup,
        };
        self.discovered_devices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .observe_nan_packet(peer, bssid, kind, payload);
    }

    fn now_sync(&self, peer: [u8; 6], cluster_id: [u8; 6], service_info: &[u8]) {
        if let Some(announce) = dmesh_server::announce::decode_announce(service_info)
            && announce_identity_valid(announce)
        {
            self.discovered_devices
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .observe_announce_wire(
                    "now_sync",
                    colon_mac(&peer),
                    Some(colon_mac(&cluster_id)),
                    announce,
                    service_info,
                );
        }
    }

    fn now_discovery(&self, peer: [u8; 6], bssid: Option<[u8; 6]>, payload: &[u8]) -> Option<Vec<u8>> {
        // NOW discovery is NAN's discovery in NOW's envelope: observe it like a NAN
        // descriptor. Whatever is not an announce is not discovery and is ignored.
        let announce = dmesh_server::announce::decode_announce(payload)?;
        if !announce_identity_valid(announce) {
            return None;
        }
        let bssid_text = bssid.map(|mac| colon_mac(&mac));
        self.discovered_devices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .observe_announce_wire("now", colon_mac(&peer), bssid_text.clone(), announce, payload);
        push_radio_event(
            &self.history,
            RadioEvent {
                ts_millis: now_millis(),
                key: "wifi.raw.discovery".to_string(),
                source: "now".to_string(),
                value: json!({
                    "ok": true,
                    "bearer": "now",
                    "peer": colon_mac(&peer),
                    "bssid": bssid_text,
                    "announce": announce_summary(&announce),
                }),
                message: None,
            },
        );
        None
    }

    fn ingress(&self) -> Option<Arc<dyn crate::espnow_bearer::EspNowIngress>> {
        self.espnow_ingress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// Linux radio backend used by the lmesh JSONL methods.
#[derive(Clone)]
pub struct RadioService {
    history: Arc<Mutex<VecDeque<RadioEvent>>>,
    discovered_devices: Arc<Mutex<DiscoveredDeviceRegistry>>,
    radios: Arc<Vec<RadioAdapter>>,
    raw_wifi_listeners: Arc<Mutex<HashSet<String>>>,
    raw_wifi_stop_flags: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
    espnow_ingress: Arc<Mutex<Option<Arc<dyn crate::espnow_bearer::EspNowIngress>>>>,
    /// The application side of the raw capture loops.
    capture_host: Arc<RadioHost>,
    rawnan_subscribers: Arc<Mutex<HashMap<String, usize>>>,
    rawnan_state: Arc<Mutex<NanState>>,
    active_nan_publish: Arc<Mutex<NanActivePublish>>,
    pending_nan_active_subscribe: Arc<Mutex<Option<PendingNanActiveSubscribe>>>,
    pending_nan_followups: Arc<Mutex<dmesh_rawnan::NanFollowupQueue>>,
    wifi_ap_handles: Arc<Mutex<BTreeMap<String, ApRuntime>>>,
    wpa_supplicants: Arc<Mutex<BTreeMap<String, lmesh_wpa::WpaSupplicant>>>,
    // A P2P group has a driver-created VIF and a distinct device address.
    // Raw NAN/NOW action frames are injected through the anchor's monitor
    // fixture, but their address2 must be this group address when a GO is
    // active. Keep the reported VIF name rather than deriving it.
    p2p_group_ifaces: Arc<Mutex<BTreeMap<String, String>>>,
    ap_no_ht_stations: Arc<Mutex<HashSet<[u8; 6]>>>,
}



impl Default for RadioService {
    fn default() -> Self {
        Self::from_environment_inner()
    }
}

/// Semantic discovery record rather than a retained radio frame. `source` is
/// intentionally a string so NAN, UDP multicast, and control-plane adapters
/// share this type without importing each other's socket/radio dependencies.
#[derive(Clone, Debug)]
struct DiscoveredDevice {
    device_id: String,
    last_seen_ms: u128,
    /// Last receiving path for compatibility with older status consumers.
    /// `observations` below retains the corresponding per-bearer evidence.
    source: String,
    peer: String,
    bssid: Option<String>,
    announce: Value,
    observations: BTreeMap<String, CommonDiscoveryObservation>,
}

struct DiscoveredDeviceRegistry {
    devices: BTreeMap<String, DiscoveredDevice>,
    /// Radio-level observations are retained beside semantic DMesh announces.
    /// An AP can be selected before it has emitted a DMesh announce, so its
    /// BSSID is the provisional identity.  Once an announce arrives the
    /// semantic device record remains authoritative; this table retains RF
    /// evidence (including non-DMesh APs) for probe health and selection.
    bss: BTreeMap<String, DiscoveredBss>,
    change_log: PathBuf,
    /// Receives every announce this registry admits, so the shared discovery
    /// engine sees what the NAN/NOW monitor sees.
    sink: Option<AnnounceSink>,
}

/// `(source, peer, announce)` for each announce admitted from a radio bearer.
pub type AnnounceSink = Arc<dyn Fn(&str, &str, dmesh_server::announce::Announce, &[u8]) + Send + Sync>;

#[derive(Clone, Debug)]
struct DiscoveredBss {
    bssid: String,
    ssid: Option<String>,
    channel: Option<u8>,
    frequency_mhz: Option<u32>,
    auth: Option<String>,
    signal_dbm: Option<f64>,
    last_seen_ms: u128,
    observations: BTreeMap<String, u128>,
}

impl DiscoveredDeviceRegistry {
    fn from_environment(default_change_log: impl Into<PathBuf>) -> Self {
        Self::with_change_log(
            std::env::var_os("LMESH_DISCOVERY_LOG")
                .or_else(|| std::env::var_os("LMESH_WIFI_DISCOVERY_LOG"))
                .map(PathBuf::from)
                .unwrap_or_else(|| default_change_log.into()),
        )
    }

    fn with_change_log(change_log: PathBuf) -> Self {
        let mut registry = Self {
            devices: BTreeMap::new(),
            bss: BTreeMap::new(),
            change_log,
            sink: None,
        };
        registry.restore_recent_devices();
        registry
    }

    /// Rebuild the current presence set from this service's own recent change
    /// log. A restart must not manufacture a second `new` record for a node
    /// that is still inside the one-hour observation interval.
    fn restore_recent_devices(&mut self) {
        let Ok(mut file) = OpenOptions::new().read(true).open(&self.change_log) else {
            return;
        };
        let len = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);
        let start = len.saturating_sub(MAX_DISCOVERY_LOG_RESTORE_BYTES);
        if file.seek(SeekFrom::Start(start)).is_err() {
            return;
        }
        let mut text = String::new();
        if file
            .take(MAX_DISCOVERY_LOG_RESTORE_BYTES)
            .read_to_string(&mut text)
            .is_err()
        {
            return;
        }
        let text = if start == 0 {
            text.as_str()
        } else {
            text.split_once('\n').map(|(_, tail)| tail).unwrap_or("")
        };
        let now = now_millis();
        for line in text.lines() {
            let Ok(record) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            if record.get("event").and_then(Value::as_str) != Some("discovery_device") {
                continue;
            }
            let Some(device_id) = record.get("device_id").and_then(Value::as_str) else {
                continue;
            };
            match record.get("change").and_then(Value::as_str) {
                Some("dropped") => {
                    self.devices.remove(device_id);
                }
                Some("new") => {
                    let Some(last_seen_ms) = record.get("at_ms").and_then(Value::as_u64) else {
                        continue;
                    };
                    let last_seen_ms = last_seen_ms as u128;
                    if now.saturating_sub(last_seen_ms) > DISCOVERED_DEVICE_TTL_MS {
                        self.devices.remove(device_id);
                        continue;
                    }
                    let Some(source) = record.get("source").and_then(Value::as_str) else {
                        continue;
                    };
                    let Some(peer) = record.get("peer").and_then(Value::as_str) else {
                        continue;
                    };
                    let Some(announce) = record.get("announce") else {
                        continue;
                    };
                    self.devices.insert(
                        device_id.to_owned(),
                        DiscoveredDevice {
                            device_id: device_id.to_owned(),
                            last_seen_ms,
                            source: source.to_owned(),
                            peer: peer.to_owned(),
                            bssid: record
                                .get("bssid")
                                .and_then(Value::as_str)
                                .map(str::to_owned),
                            announce: announce.clone(),
                            observations: BTreeMap::from([(
                                source.to_owned(),
                                restored_observation(
                                    last_seen_ms,
                                    peer,
                                    record.get("bssid").and_then(Value::as_str),
                                ),
                            )]),
                        },
                    );
                }
                _ => {}
            }
        }
        // Never emit recovery noise while bounding the restored snapshot.
        while self.devices.len() > MAX_DISCOVERED_DEVICES {
            let Some(oldest) = self
                .devices
                .values()
                .min_by_key(|entry| entry.last_seen_ms)
                .map(|entry| entry.device_id.clone())
            else {
                break;
            };
            self.devices.remove(&oldest);
        }
    }

    fn expire(&mut self, now_ms: u128) {
        let dropped = self
            .devices
            .values()
            .filter(|entry| now_ms.saturating_sub(entry.last_seen_ms) > DISCOVERED_DEVICE_TTL_MS)
            .cloned()
            .collect::<Vec<_>>();
        for entry in dropped {
            self.devices.remove(&entry.device_id);
            self.log_change("dropped", &entry, now_ms);
        }
    }

    fn observe(&mut self, mut entry: DiscoveredDevice) {
        let now_ms = entry.last_seen_ms;
        self.expire(now_ms);
        let is_new = !self.devices.contains_key(&entry.device_id);
        if let Some(previous) = self.devices.get(&entry.device_id) {
            // Retain every recent bearer observation while using the newest
            // semantic announce as the active transport/capability state.
            entry.observations = previous.observations.clone();
            // A directed discovery reply deliberately omits its sender-local
            // UDP endpoint: the request's source tuple is the checked path
            // and the responder cannot safely choose an egress interface.
            // It must not erase the interface-specific endpoint advertised
            // by the preceding unsolicited announce.  Preserve only absent
            // route fields; a later complete announce still replaces them.
            preserve_advertised_udp_route(&previous.announce, &mut entry.announce);
        }
        // A cold receiver may first learn a node from its directed discovery
        // reply rather than a multicast announce. The source tuple is then a
        // verified, selected UDP path. Persist its IPv6 address and unicast
        // port as endpoint facts, while keeping the scope in `last_peer` on
        // the receive-side observation where it belongs.
        hydrate_udp_route_from_observed_peer(&entry.source, &entry.peer, &mut entry.announce);
        let bssid = entry
            .bssid
            .as_deref()
            .and_then(|value| parse_mac(Some(value)));
        let available_fields = OBSERVATION_PEER
            | if bssid.is_some() {
                OBSERVATION_BSSID
            } else {
                0
            };
        let kind = if entry.source == "nan" {
            DiscoveryPacketKind::ActivePublish
        } else {
            DiscoveryPacketKind::Other
        };
        let observation = entry
            .observations
            .entry(entry.source.clone())
            .or_insert_with(|| {
                CommonDiscoveryObservation::new(
                    now_ms.min(i64::MAX as u128) as i64,
                    available_fields,
                )
            });
        observation.available_fields = available_fields;
        // The semantic inventory intentionally does not retain the radio
        // frame. Mark fingerprint/channel/RSSI unavailable rather than
        // reporting invented values; raw-NAN history remains the platform
        // diagnostic source for those details.
        observation.observe(
            now_ms.min(i64::MAX as u128) as i64,
            kind,
            &entry.peer,
            bssid,
            None,
            None,
            &[],
        );
        if is_new
            && self.devices.len() >= MAX_DISCOVERED_DEVICES
            && let Some(oldest) = self
                .devices
                .values()
                .min_by_key(|candidate| candidate.last_seen_ms)
                .cloned()
        {
            self.devices.remove(&oldest.device_id);
            self.log_change("dropped", &oldest, now_ms);
        }
        // A refresh may have a newer address/bearer/announce payload but is
        // deliberately silent in the durable change log.
        entry.last_seen_ms = now_ms;
        self.devices.insert(entry.device_id.clone(), entry.clone());
        if is_new {
            self.log_change("new", &entry, now_ms);
        }
    }

    fn observe_announce(
        &mut self,
        source: &str,
        peer: String,
        bssid: Option<String>,
        announce: dmesh_server::announce::Announce,
    ) {
        let mut bytes=[0;512];
        let n=dmesh_server::announce::encode(announce,&mut bytes).unwrap_or(0);
        self.observe_announce_wire(source,peer,bssid,announce,&bytes[..n]);
    }

    fn observe_announce_wire(
        &mut self,
        source: &str,
        peer: String,
        bssid: Option<String>,
        announce: dmesh_server::announce::Announce,
        payload: &[u8],
    ) {
        let device_id = hex_bytes(announce.device_id());
        if let Some(sink) = &self.sink {
            sink(source, &peer, announce, payload);
        }
        self.observe(DiscoveredDevice {
            device_id: device_id.clone(),
            last_seen_ms: now_millis(),
            source: source.to_string(),
            peer,
            bssid,
            announce: json!({
                "kind": announce.kind,
                "device_id": device_id,
                "uptime_secs": announce.uptime_secs,
                "device_class": announce.device_class,
                "probe_capabilities": announce.probe_capabilities,
                "device_name": announce.device_name(),
                // Preserve common announce routing metadata for the generic
                // inventory/UI.  It is advisory (never identity or auth),
                // but lets a controller select a mutually attached UDP6
                // bearer instead of guessing from Android's platform type.
                "network_name": announce.network_name(),
                "wifi_channel": (announce.wifi_channel != 0).then_some(announce.wifi_channel),
                "sta_link_local_v6": announce.sta_link_local_v6().map(Ipv6Addr::from).map(|address| address.to_string()),
                // Endpoint is sender-local address+port only.  `peer` in the
                // observation preserves the receiver's ingress scope, which
                // is what an initiating QUIC route must use for link-local
                // IPv6.
                "udp_port": (announce.udp_port != 0).then_some(announce.udp_port),
                "udp_link_local_v6": announce.udp_link_local_v6().map(Ipv6Addr::from).map(|address| address.to_string()),
                "public_key": (!announce.public_key().is_empty()).then(|| hex_bytes(announce.public_key())),
                "vip6": dmesh_server::announce::virtual_ip6(announce.public_key())
                    .or_else(|| dmesh_server::announce::virtual_ip6_from_identity_hint(announce.device_id()))
                    .map(Ipv6Addr::from).map(|address| address.to_string()),
                // This is the exact discovery identity accepted by the QUIC
                // forwarding handler, not a display-only device id or MAC.
                "route_key": announce.has_identity().then(|| crate::mesh_core::base64_url_encode(announce.public_key())),
            }),
            observations: BTreeMap::new(),
        });
    }

    /// Add raw-NAN packet evidence to an already authenticated semantic
    /// device.  A coalesced Android SDF can contain both an Active Publish
    /// and an Active Subscribe: the publish carries the announce identity,
    /// while this method retains the second packet kind without creating a
    /// platform-specific inventory entry or returning raw radio bytes.
    fn observe_nan_packet(
        &mut self,
        peer: &str,
        bssid: Option<&str>,
        kind: DiscoveryPacketKind,
        payload: &[u8],
    ) {
        let now_ms = now_millis();
        self.expire(now_ms);
        let Some(entry) = self.devices.values_mut().find(|entry| entry.peer == peer) else {
            return;
        };
        let bssid = bssid.and_then(|value| parse_mac(Some(value)));
        let available_fields = OBSERVATION_PEER
            | OBSERVATION_PAYLOAD_FINGERPRINT
            | if bssid.is_some() {
                OBSERVATION_BSSID
            } else {
                0
            };
        let observation = entry
            .observations
            .entry("nan".to_owned())
            .or_insert_with(|| {
                CommonDiscoveryObservation::new(
                    now_ms.min(i64::MAX as u128) as i64,
                    available_fields,
                )
            });
        observation.available_fields |= available_fields;
        observation.observe(
            now_ms.min(i64::MAX as u128) as i64,
            kind,
            peer,
            bssid,
            None,
            None,
            payload,
        );
        entry.last_seen_ms = entry.last_seen_ms.max(now_ms);
    }

    fn snapshot(&mut self) -> Vec<DiscoveredDevice> {
        self.expire(now_millis());
        let mut entries = self.devices.values().cloned().collect::<Vec<_>>();
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.last_seen_ms));
        entries
    }

    fn observe_bss(&mut self, source: &str, entry: &Value, last_seen_ms: u128) {
        let Some(bssid) = entry.get("bssid").and_then(Value::as_str) else {
            return;
        };
        let observation = self
            .bss
            .entry(bssid.to_ascii_lowercase())
            .or_insert_with(|| DiscoveredBss {
                bssid: bssid.to_ascii_lowercase(),
                ssid: None,
                channel: None,
                frequency_mhz: None,
                auth: None,
                signal_dbm: None,
                last_seen_ms,
                observations: BTreeMap::new(),
            });
        observation.ssid = entry
            .get("ssid")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or(observation.ssid.clone());
        observation.channel = entry
            .get("channel")
            .and_then(Value::as_u64)
            .and_then(|value| u8::try_from(value).ok())
            .or(observation.channel);
        observation.frequency_mhz = entry
            .get("frequency_mhz")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .or(observation.frequency_mhz);
        observation.auth = entry
            .get("auth")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or(observation.auth.clone());
        observation.signal_dbm = entry
            .get("signal_dbm")
            .or_else(|| entry.get("rx_signal_dbm"))
            .and_then(Value::as_f64)
            .or(observation.signal_dbm);
        observation.last_seen_ms = observation.last_seen_ms.max(last_seen_ms);
        observation
            .observations
            .insert(source.to_owned(), last_seen_ms);
        while self.bss.len() > MAX_DISCOVERED_DEVICES {
            let Some(oldest) = self
                .bss
                .values()
                .min_by_key(|entry| entry.last_seen_ms)
                .map(|entry| entry.bssid.clone())
            else {
                break;
            };
            self.bss.remove(&oldest);
        }
    }

    fn bss_snapshot(&mut self) -> (Vec<Value>, Vec<Value>) {
        let now_ms = now_millis();
        self.bss.retain(|_, entry| {
            now_ms.saturating_sub(entry.last_seen_ms) <= DISCOVERED_DEVICE_TTL_MS
        });
        let mut bss = self.bss.values().cloned().collect::<Vec<_>>();
        bss.sort_by_key(|entry| std::cmp::Reverse(entry.last_seen_ms));
        let entries = bss
            .iter()
            .map(|entry| {
                json!({
                    "id": format!("bss:{}", entry.bssid),
                    "bssid": entry.bssid,
                    "ssid": entry.ssid,
                    "channel": entry.channel,
                    "frequency_mhz": entry.frequency_mhz,
                    "auth": entry.auth,
                    "signal_dbm": entry.signal_dbm,
                    "last_seen_ms": entry.last_seen_ms,
                    "age_ms": now_ms.saturating_sub(entry.last_seen_ms),
                    "sources": entry.observations,
                })
            })
            .collect::<Vec<_>>();
        let mut channels = BTreeMap::<u8, (u64, u64, u64, u128)>::new();
        for entry in &bss {
            let Some(channel) = entry.channel else {
                continue;
            };
            let values = channels.entry(channel).or_default();
            let dmesh = entry
                .ssid
                .as_deref()
                .is_some_and(|ssid| ssid.to_ascii_lowercase().contains("dmesh"));
            if dmesh {
                values.0 += 1;
            } else {
                values.1 += 1;
            }
            if dmesh && entry.auth.as_deref() == Some("open") {
                values.2 += 1;
            }
            values.3 = values.3.max(entry.last_seen_ms);
        }
        let channels = channels.into_iter().map(|(channel, (dmesh_bss, non_dmesh_bss, open_dmesh_bss, last_seen_ms))| {
            json!({"channel": channel, "dmesh_bss": dmesh_bss, "non_dmesh_bss": non_dmesh_bss, "open_dmesh_bss": open_dmesh_bss, "last_seen_ms": last_seen_ms, "age_ms": now_ms.saturating_sub(last_seen_ms)})
        }).collect();
        (entries, channels)
    }

    fn log_change(&self, change: &str, entry: &DiscoveredDevice, now_ms: u128) {
        let record = json!({
            "event": "discovery_device",
            "change": change,
            "at_ms": now_ms,
            "device_id": entry.device_id,
            "source": entry.source,
            "peer": entry.peer,
            "bssid": entry.bssid,
            "announce": entry.announce,
        });
        let Some(parent) = self.change_log.parent() else {
            return;
        };
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.change_log)
        {
            let _ = writeln!(file, "{record}");
        }
    }
}

/// Retain an interface-specific endpoint across a sparse directed discovery
/// reply. The reply is signed and fresh, but it intentionally has no local
/// interface selector; accepting its `null` fields as a route withdrawal
/// would make a successful check remove the route required for later streams.
fn preserve_advertised_udp_route(previous: &Value, current: &mut Value) {
    let (Some(previous), Some(current)) = (previous.as_object(), current.as_object_mut()) else {
        return;
    };
    for field in ["udp_link_local_v6", "sta_link_local_v6", "udp_port"] {
        if current.get(field).is_none_or(Value::is_null)
            && let Some(value) = previous.get(field).filter(|value| !value.is_null())
        {
            current.insert(field.to_owned(), value.clone());
        }
    }
}

fn hydrate_udp_route_from_observed_peer(source: &str, peer: &str, announce: &mut Value) {
    if source != "udp_multicast" {
        return;
    }
    let Some((host, port)) = peer
        .strip_prefix('[')
        .and_then(|value| value.split_once("]:"))
    else {
        return;
    };
    let Some(address) = host
        .split_once('%')
        .map_or(host, |(address, _)| address)
        .parse::<Ipv6Addr>()
        .ok()
    else {
        return;
    };
    let Ok(port) = port.parse::<u16>() else {
        return;
    };
    // UDP 5227 is receive-only multicast discovery, never a QUIC endpoint.
    if port == crate::mesh_core::DISCOVERY_MULTICAST_PORT {
        return;
    }
    let Some(announce) = announce.as_object_mut() else {
        return;
    };
    if announce.get("udp_link_local_v6").is_none_or(Value::is_null) {
        announce.insert(
            "udp_link_local_v6".to_owned(),
            Value::String(address.to_string()),
        );
    }
    if announce.get("udp_port").is_none_or(Value::is_null) {
        announce.insert("udp_port".to_owned(), Value::Number(u64::from(port).into()));
    }
}

fn restored_observation(
    now_ms: u128,
    peer: &str,
    bssid: Option<&str>,
) -> CommonDiscoveryObservation {
    let bssid = bssid.and_then(|value| parse_mac(Some(value)));
    let available_fields = OBSERVATION_PEER
        | if bssid.is_some() {
            OBSERVATION_BSSID
        } else {
            0
        };
    let now_ms = now_ms.min(i64::MAX as u128) as i64;
    let mut observation = CommonDiscoveryObservation::new(now_ms, available_fields);
    observation.observe(
        now_ms,
        DiscoveryPacketKind::Other,
        peer,
        bssid,
        None,
        None,
        &[],
    );
    observation
}

fn discovered_device_json(entry: &DiscoveredDevice) -> Value {
    let now_ms = now_millis();
    let observations = entry
        .observations
        .iter()
        .map(|(source, observation)| {
            (
                source.clone(),
                json!({
                    "first_seen_ms": observation.first_seen_ms,
                    "last_seen_ms": observation.last_seen_ms,
                    "age_ms": now_ms.saturating_sub(observation.last_seen_ms.max(0) as u128),
                    "available_fields": observation.available_fields,
                    "unavailable_fields": observation.unavailable_fields(),
                    "packets": observation.packets,
                    "active_publish_rx": observation.active_publish_rx,
                    "active_subscribe_rx": observation.active_subscribe_rx,
                    "followup_rx": observation.followup_rx,
                    "last_kind": observation.last_kind.as_str(),
                    // A bearer-scoped path identity.  For NOW this is the
                    // sender MAC required for a directed check; it is kept
                    // beside the bearer evidence so a later NAN/UDP update
                    // cannot overwrite it with a different path.
                    "last_peer": (!observation.last_peer.is_empty()).then_some(&observation.last_peer),
                    "last_bssid": observation.last_bssid.map(|value| colon_mac(&value)),
                    "last_channel": observation.last_channel,
                    "last_rssi_dbm": observation.last_rssi_dbm,
                    "last_payload_len": observation.last_payload_len,
                    "last_payload_hash": observation.last_payload_hash,
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let nan = entry
        .observations
        .get("nan")
        .map(|observation| {
            json!({
                "observed": true,
                "last_seen_ms": observation.last_seen_ms,
                "age_ms": now_ms.saturating_sub(observation.last_seen_ms.max(0) as u128),
                "available_fields": observation.available_fields,
                "unavailable_fields": observation.unavailable_fields(),
            })
        })
        .unwrap_or_else(|| json!({"observed": false}));
    // Older durable inventory entries predate `vip6`. Derive it during
    // presentation as well as at ingress so an existing discovery cache does
    // not hide an advertised identity until the next multicast refresh.
    let mut announce = entry.announce.clone();
    if announce.get("vip6").is_none()
        && let Some(public_key) = announce.get("public_key").and_then(Value::as_str)
        && public_key.len() % 2 == 0
    {
        let key = (0..public_key.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&public_key[offset..offset + 2], 16))
            .collect::<std::result::Result<Vec<_>, _>>();
        if let Ok(key) = key
            && let Some(address) = dmesh_server::announce::virtual_ip6(&key)
        {
            announce["vip6"] = Value::String(Ipv6Addr::from(address).to_string());
        }
    }
    // Key material and the local forwarding key are retained only inside the
    // discovery/route store.  Human-facing inventory identifies a node by
    // name or reachable address; it does not expose security implementation
    // identifiers in normal API/UI output.
    if let Some(announce) = announce.as_object_mut() {
        announce.remove("device_id");
        announce.remove("public_key");
        announce.remove("route_key");
    }
    let identity = announce
        .get("device_name")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .or_else(|| announce.get("vip6").and_then(Value::as_str))
        .map(str::to_owned);
    let transport_mode = announce.get("transport_mode").and_then(Value::as_u64);
    let transport_state = match transport_mode {
        Some(0) => "nan_now",
        Some(1) => "sta",
        Some(2) => "uart_only",
        Some(_) => "unknown",
        None => "unknown",
    };
    let platform = match entry
        .announce
        .get("device_class")
        .and_then(Value::as_u64)
        .and_then(|value| u8::try_from(value).ok())
    {
        Some(class) if dmesh_server::announce::is_esp_device_class(class) => {
            dmesh_server::announce::device_class_name(class)
        }
        Some(dmesh_server::announce::DEVICE_CLASS_ANDROID) => "android",
        Some(dmesh_server::announce::DEVICE_CLASS_HOST) => "host",
        _ => "unknown",
    };
    let mut value = json!({
        "identity_state": "semantic",
        "platform": platform,
        "last_seen_ms": entry.last_seen_ms,
        "source": entry.source,
        "bssid": entry.bssid,
        "announce": announce,
        // `nan` reports local observation, not a claim inferred from the
        // device's desired configuration. A UDP6-only Android therefore
        // remains discoverable with `nan.observed=false`.
        "nan": nan,
        "active_transport": {
            "mode": transport_mode,
            "state": transport_state,
            "observed_bearers": entry.observations.keys().collect::<Vec<_>>(),
        },
        "observations": observations,
    });
    if let Some(identity) = identity {
        value["identity"] = Value::String(identity);
    }
    value
}

/// An announce that includes a public key must prove ownership of it on every
/// ingress, including raw NAN. New ESP, Linux, and Android senders use the
/// same compressed-P256 form; an unsigned announce remains a compatibility
/// observation while older devices are being upgraded. Keeping this check in
/// the radio library prevents UDP, NAN, and local sibling ingress from
/// gradually accepting different identities.
fn announce_identity_valid(announce: dmesh_server::announce::Announce) -> bool {
    dmesh_server::announce::verify_identity(announce)
}

impl RadioService {

    /// Presentation-safe, bearer-neutral discovery inventory. Native peer
    /// handles remain in adapter diagnostics so Android PeerHandle values and
    /// Linux/ESP MAC addresses never become incompatible UI identities.
    pub(crate) fn radio_devices(&self) -> Value {
        let entries = self
            .discovered_devices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .snapshot();
        let devices = entries
            .iter()
            // The common inventory is the complete semantic observation. Do
            // not make the dashboard reconstruct addresses, AP facts, or
            // active transports from a second host-only status response.
            .map(discovered_device_json)
            .collect::<Vec<_>>();
        json!({"devices": devices})
    }

    /// Admit a semantic announcement from any host discovery bearer. This
    /// deliberately takes decoded data rather than a packet: Wi-Fi/UDP/control
    /// adapters retain ownership of their buffers and all update one device
    /// inventory with the same TTL, capacity, and durable change log.
    /// Install the sink that receives every announce the radio admits.
    pub(crate) fn set_announce_sink(&self, sink: AnnounceSink) {
        self.discovered_devices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .sink = Some(sink);
    }

    pub(crate) fn observe_discovered_announce(
        &self,
        source: &str,
        peer: String,
        bssid: Option<String>,
        announce: dmesh_server::announce::Announce,
    ) -> bool {
        if !announce_identity_valid(announce) {
            return false;
        }
        self.discovered_devices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .observe_announce(source, peer, bssid, announce);
        true
    }

    /// Apply the startup TX-rate policy to every interface owned by this
    /// service.  The default is the driver's standard/automatic policy so
    /// Android-compatible NAN management and discovery are not forced to a
    /// DMesh-specific rate.  Targeted frames can opt into 12/24/54 Mbps.
    pub(crate) fn apply_startup_rate_profile(&self, interfaces: &[String]) -> Vec<Value> {
        let profile =
            std::env::var("LMESH_WIFI_RATE_PROFILE").unwrap_or_else(|_| "auto".to_owned());
        let disable_b = std::env::var("LMESH_WIFI_DISABLE_80211B")
            .map(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);
        // Automatic/default rate selection is already the driver's startup
        // state.  Do not issue a SET_TX_BITRATE_MASK while an interface is
        // still down: mt7921u reports ENETDOWN for that request and the
        // failed pre-AP netlink operation can leave the following AP
        // transition stuck.  An explicit 802.11b policy still needs the
        // request even when the rate profile is automatic.
        let normalized_profile = profile.trim().to_ascii_lowercase();
        if matches!(normalized_profile.as_str(), "auto" | "default" | "reset") && !disable_b {
            return interfaces
                .iter()
                .map(|iface| {
                    json!({
                        "ok": true,
                        "backend": "linux_nl80211",
                        "iface": iface,
                        "profile": normalized_profile,
                        "skipped": true,
                        "reason": "driver default rate selection",
                    })
                })
                .collect();
        }
        interfaces
            .iter()
            .map(|iface| self.wifi_rate_profile(Some(iface.clone()), profile.clone(), disable_b))
            .collect()
    }

    /// Apply an owned-interface Linux rate profile for controlled NAN trials.
    /// This is a direct nl80211 request (the same operation as `iw set
    /// bitrates`) so the service does not need to exec a helper or inherit
    /// CAP_NET_* state through a child process. `auto` restores driver rate
    /// selection; `12` and `24` restrict legacy 2.4 GHz rates to the requested
    /// Mbps value, while `ht2`, `ht3`, and `ht4` are temporary exact HT-MCS
    /// diagnostics. `ht3-24` permits MCS3 plus a 24 Mbps OFDM association
    /// fallback, while still excluding lower HT and CCK data rates. Errors
    /// retain the kernel errno/extack text.
    pub(crate) fn wifi_rate_profile(
        &self,
        iface: Option<String>,
        profile: String,
        disable_b: bool,
    ) -> Value {
        let iface = wifi_iface(iface);
        let profile = profile.trim().to_ascii_lowercase();
        let (rate_mbps, ht_mcs) = match profile.as_str() {
            "auto" | "default" | "reset" => (None, None),
            "12" | "12m" => (Some(12_u8), None),
            "24" | "24m" => (Some(24_u8), None),
            "ht2" => (None, Some(2_u8)),
            "ht3" => (None, Some(3_u8)),
            "ht4" => (None, Some(4_u8)),
            "ht3-24" | "ht3_24" => (Some(24_u8), Some(3_u8)),
            _ => {
                return json!({"ok": false, "backend": "linux_nl80211", "iface": iface, "profile": profile, "error": "profile must be auto, 12, 24, ht2, ht3, ht4, or ht3-24"});
            }
        };
        let effective_disable_b = disable_b || rate_mbps.is_some() || ht_mcs.is_some();
        let result = (|| -> Result<()> {
            let ifindex = ifindex(&iface)?;
            let socket = Nl80211Socket::open()?;
            socket.set_tx_rate_profile(ifindex, rate_mbps, ht_mcs, effective_disable_b)
        })();
        let (ok, error) = match result {
            Ok(()) => (true, Value::Null),
            Err(error) => (false, json!(format!("{error:#}"))),
        };
        let value = json!({"ok": ok, "backend": "linux_nl80211", "iface": iface, "profile": profile, "rate_mbps": rate_mbps, "ht_mcs": ht_mcs, "disable_80211b": effective_disable_b, "error": error});
        self.record("wifi.rate.profile", value.clone());
        value
    }





    /// Create a Wi-Fi-only backend. Serial devices are never part of this
    /// service; direct device sessions belong to `dmesh-cli`.
    ///
    /// The full lmesh process and direct-client integration use
    /// [`Self::from_environment`].
    /// The standalone Wi-Fi service uses this constructor so it can own AP,
    /// STA, and NAN interfaces without taking UART devices or serial sockets.
    pub(crate) fn from_environment_without_uart() -> Self {
        Self::from_environment_inner()
    }

    /// Build a Wi-Fi-only instance with a service-specific default discovery
    /// log. The explicit environment override stays shared, while independent
    /// supervised services never append duplicate `new` events to one file.
    pub(crate) fn from_environment_with_discovery_log(default_change_log: impl Into<PathBuf>) -> Self {
        Self::from_environment_inner_with_discovery_log(default_change_log.into())
    }

    fn from_environment_inner() -> Self {
        Self::from_environment_inner_with_discovery_log(PathBuf::from(DEFAULT_DISCOVERY_CHANGE_LOG))
    }

    fn from_environment_inner_with_discovery_log(default_change_log: PathBuf) -> Self {
        let history = Arc::new(Mutex::new(VecDeque::new()));
        let discovered_devices = Arc::new(Mutex::new(DiscoveredDeviceRegistry::from_environment(
            default_change_log,
        )));
        let espnow_ingress = Arc::new(Mutex::new(None));
        let capture_host = Arc::new(RadioHost {
            history: history.clone(),
            discovered_devices: discovered_devices.clone(),
            espnow_ingress: espnow_ingress.clone(),
        });
        let service = Self {
            history,
            discovered_devices,
            capture_host,
            radios: Arc::new(load_radio_adapters()),
            raw_wifi_listeners: Arc::new(Mutex::new(HashSet::new())),
            raw_wifi_stop_flags: Arc::new(Mutex::new(HashMap::new())),
            espnow_ingress,
            rawnan_subscribers: Arc::new(Mutex::new(HashMap::new())),
            rawnan_state: Arc::new(Mutex::new(NanState::new(
                dmesh_rawnan::NAN_CLUSTER_STALE_AFTER_US,
            ))),
            active_nan_publish: Arc::new(Mutex::new(NanActivePublish::new(
                NAN_ACTIVE_PUBLISH_INSTANCE,
            ))),
            pending_nan_active_subscribe: Arc::new(Mutex::new(None)),
            pending_nan_followups: Arc::new(Mutex::new(dmesh_rawnan::NanFollowupQueue::new(
                MAX_PENDING_NAN_FOLLOWUPS,
            ))),
            wifi_ap_handles: Arc::new(Mutex::new(BTreeMap::new())),
            wpa_supplicants: Arc::new(Mutex::new(BTreeMap::new())),
            p2p_group_ifaces: Arc::new(Mutex::new(BTreeMap::new())),
            ap_no_ht_stations: Arc::new(Mutex::new(ap_no_ht_stations())),
        };
        service
    }

    /// Attach the receive side of the executable-owned ESP-NOW bearer.
    pub(crate) fn set_espnow_ingress(&self, ingress: Arc<dyn crate::espnow_bearer::EspNowIngress>) {
        *self
            .espnow_ingress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(ingress);
    }

    /// Return interface, capability, process-capability, and control status.
    pub(crate) fn status(&self) -> Value {
        let iface = wifi_iface(None);
        let link_local_v6 = ready_link_local_address(&iface).map(|address| address.to_string());
        let mac = iface_mac(&iface).ok().map(|address| colon_mac(&address));

        json!({
            "wifi_iface": iface,
            "local_interface": {
                "mac": mac,
                "link_local_v6": link_local_v6,
            },
            "note": "compatibility host diagnostic; use discovery.status, telemetry.nan_status, and discovery.nodes",
        })
    }

    /// Common NAN state.  Device inventory deliberately stays in
    /// `discovery.nodes`: it is cross-bearer and must not be duplicated here.
    pub(crate) fn nan_status(&self, iface: Option<String>) -> Value {
        let raw = self.rawnan_status(iface);
        let mut status = serde_json::Map::new();
        // Monitor ownership and NAN synchronization are different facts: a
        // host can listen successfully while it has no recent cluster beacon
        // and therefore cannot schedule a DW-bound active Subscribe.
        let synced = raw
            .get("cluster_bssid")
            .and_then(Value::as_str)
            .is_some_and(|cluster| !cluster.is_empty())
            && raw
                .get("sync_age_ms")
                .and_then(Value::as_u64)
                .is_some_and(|age_ms| age_ms <= 4_000);
        if let Some(value) = raw.get("cluster_bssid").filter(|value| !value.is_null()) {
            status.insert("cluster_id".to_owned(), value.clone());
        }
        if let Some(value) = raw.get("sync_bssid").filter(|value| !value.is_null()) {
            status.insert("sync_id".to_owned(), value.clone());
        }
        status.insert(
            "active".to_owned(),
            raw.get("listener").cloned().unwrap_or(Value::Bool(false)),
        );
        status.insert("synced".to_owned(), Value::Bool(synced));
        status.insert(
            "sync_age_ms".to_owned(),
            raw.get("sync_age_ms").cloned().unwrap_or(Value::Null),
        );
        if let Some(enabled) = raw
            .get("active_publish")
            .and_then(|value| value.get("enabled"))
            .and_then(Value::as_bool)
        {
            status.insert("publishing".to_owned(), Value::Bool(enabled));
        }
        for (target, source) in [
            ("beacons_received", "nan_beacons"),
            ("service_discovery_received", "sdf_received"),
        ] {
            status.insert(
                target.to_owned(),
                raw.get(source).cloned().unwrap_or(Value::from(0)),
            );
        }
        status.insert(
            "active_cluster_ssid".to_owned(),
            raw.get("active_cluster_ssid")
                .cloned()
                .unwrap_or(Value::Null),
        );
        let nan_devices = raw
            .get("discovered_devices")
            .and_then(Value::as_array)
            .map(|devices| {
                devices
                    .iter()
                    .filter(|device| device.get("source").and_then(Value::as_str) == Some("nan"))
                    .count()
            })
            .unwrap_or(0);
        status.insert("nan_devices".to_owned(), Value::from(nan_devices));
        Value::Object(status)
    }

    /// Return the shared raw-NAN filter state used by the Linux monitor.
    /// This is deliberately independent of any control daemon: the monitor
    /// observes NAN beacons and feeds them to dmesh-rawnan::NanState.
    pub(crate) fn rawnan_status(&self, iface: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let active_publish = self
            .active_nan_publish
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let active_publish_status = json!({
            "enabled": active_publish.enabled(),
            "instance": active_publish.instance(),
            "service_info_len": active_publish.service_info().len(),
            "pending": active_publish.pending(),
            "last_sent_ms": active_publish.last_sent_ms(),
        });
        drop(active_publish);
        let state = self
            .rawnan_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let cluster = state.cluster().map(|mac| colon_mac(&mac.0));
        let last_beacon_local_us = state.last_beacon_local_us();
        let sync_age_ms =
            (now_micros_u64().saturating_sub(last_beacon_local_us) / 1_000).min(u64::MAX);
        let history = self
            .history
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let events = host_capture_counters()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .capture
            .nan_rx;
        // The device inventory survives monitor-history rotation and accepts
        // all discovery bearers. `observed_announces` remains as a compatible
        // NAN-status projection for existing E2E callers.
        let discovered_devices = self
            .discovered_devices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .snapshot();
        let observed_announces = discovered_devices
            .iter()
            .filter(|entry| entry.source == "nan")
            .map(discovered_device_json)
            .collect::<Vec<_>>();
        let discovered_devices = discovered_devices
            .iter()
            .map(discovered_device_json)
            .collect::<Vec<_>>();
        // Follow-ups use the same bounded, newest-first receipt view across
        // host/Android/ESP. Keep the DMesh envelope metadata and payload hash
        // evidence, not raw driver packet storage.
        let followups = history
            .iter()
            .rev()
            .filter(|event| event.key == "wifi.rawnan.discovery")
            .filter_map(|event| {
                event
                    .value
                    .get("followup")
                    .filter(|followup| !followup.is_null())
                    .map(|followup| {
                        json!({
                            "last_seen_ms": event.ts_millis,
                            "peer": event.value.get("peer"),
                            "bssid": event.value.get("bssid"),
                            "followup": followup,
                        })
                    })
            })
            .take(32)
            .collect::<Vec<_>>();
        let sdf_received = history
            .iter()
            .filter(|event| event.key == "wifi.rawnan.discovery")
            .count() as u64;
        // Ordinary AP beacons arrive through the same passive monitor as NAN
        // timing. Keep a bounded, newest-per-BSSID view for STA selection;
        // this is observation only and must never trigger cfg80211 scanning.
        let mut observed_aps = BTreeMap::<String, Value>::new();
        for event in history
            .iter()
            .rev()
            .filter(|event| event.key == "wifi.rawnan.beacon")
        {
            if event.value.get("nan_beacon").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let Some(bssid) = event.value.get("bssid").and_then(Value::as_str) else {
                continue;
            };
            observed_aps.entry(bssid.to_owned()).or_insert_with(|| {
                let capability = event
                    .value
                    .get("fixed")
                    .and_then(|fixed| fixed.get("capability"))
                    .and_then(Value::as_u64);
                json!({
                    "bssid": bssid,
                    "ssid": event.value.get("ssid").cloned().unwrap_or(Value::Null),
                    "channel": event.value.get("channel").cloned().unwrap_or(Value::Null),
                    "signal_dbm": event.value.get("rx_signal_dbm").cloned().unwrap_or(Value::Null),
                    "auth": capability.map(|bits| if bits & (1 << 4) == 0 { "open" } else { "protected" }),
                    "last_seen_ms": event.ts_millis,
                })
            });
        }
        let observed_aps = observed_aps.into_values().collect::<Vec<_>>();
        let active_cluster_ssid = state.sync_bssid().and_then(|sync_bssid| {
            let sync_bssid = colon_mac(&sync_bssid.0);
            observed_aps.iter().find_map(|ap| {
                (ap.get("bssid").and_then(Value::as_str) == Some(sync_bssid.as_str()))
                    .then(|| ap.get("ssid").cloned())
                    .flatten()
                    .filter(|ssid| !ssid.is_null())
            })
        });
        let (radio_bss, channel_discovery) = {
            let mut registry = self
                .discovered_devices
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for ap in &observed_aps {
                let seen = ap
                    .get("last_seen_ms")
                    .and_then(Value::as_u64)
                    .map(u128::from)
                    .unwrap_or_else(now_millis);
                registry.observe_bss("passive_monitor", ap, seen);
            }
            registry.bss_snapshot()
        };
        let listeners = self
            .raw_wifi_listeners
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let monitor_listener = listeners.contains(&format!("{iface}:monitor"));
        let nl80211_beacon_listener = listeners.contains(&format!("{iface}:nl80211_nan_beacon"));
        json!({
            "ok": true,
            "backend": "dmesh-rawnan",
            "iface": iface,
            "listener": monitor_listener,
            "nl80211_beacon_listener": nl80211_beacon_listener,
            "filter_mode": match state.mode() {
                dmesh_rawnan::FilterMode::Discovery => "discovery",
                dmesh_rawnan::FilterMode::Cluster => "cluster_a3",
            },
            "cluster_bssid": cluster,
            "sync_bssid": state.sync_bssid().map(|mac| colon_mac(&mac.0)),
            "last_beacon_tsf_us": state.last_beacon_tsf_us(),
            "last_beacon_local_us": last_beacon_local_us,
            "sync_age_ms": (last_beacon_local_us != 0).then_some(sync_age_ms),
            "beacon_interval_tu": state.beacon_interval_tu(),
            "nan_events": events,
            "nan_beacons": host_capture_counters().lock().unwrap_or_else(|poisoned| poisoned.into_inner()).capture.nan_beacons,
            "sdf_received": sdf_received,
            "active_cluster_ssid": active_cluster_ssid,
            "discovered_devices": discovered_devices,
            "observed_announces": observed_announces,
            "followups": followups,
            "observed_aps": observed_aps,
            // One radio inventory combines provisional BSS observations with
            // the semantic device inventory above.  It is intentionally a
            // status projection: pair probes consume it rather than creating
            // a second discovery RPC.
            "radio_bss": radio_bss,
            "channel_discovery": channel_discovery,
            "active_publish": active_publish_status,
        })
    }

    /// Replace the entire local active-Publish descriptor. Actual emission is
    /// deferred to the next confirmed NAN discovery window, never to a
    /// control request or an arbitrary wall-clock timer.
    pub(crate) fn rawnan_active_publish_configure(
        &self,
        enabled: bool,
        service_info: &[u8],
    ) -> Result<Value> {
        let mut publish = self
            .active_nan_publish
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        publish.configure(enabled, service_info)?;
        Ok(json!({
            "ok": true,
            "enabled": publish.enabled(),
            "instance": publish.instance(),
            "service_info_len": publish.service_info().len(),
            "pending": publish.pending(),
        }))
    }

    /// Schedule one active NAN Subscribe that asks a sleepy peer to restore
    /// its configured STA profile.  The wire payload is deliberately the
    /// same target-checked `transport.set` used by ESP and Android; this
    /// method owns only host monitor scheduling and never changes local STA.
    pub(crate) fn nan_wakeup(&self, target: String) -> Value {
        let Some(target_mac) = parse_mac(Some(&target)) else {
            return json!({"ok": false, "error": "nan.wakeup to must be a MAC", "to": target});
        };
        if target_mac == [0; 6] || target_mac[0] & 1 != 0 {
            return json!({"ok": false, "error": "nan.wakeup to must be a unicast MAC", "to": target});
        }
        let request = dmesh_server::control::Request::TransportSet {
            kind: dmesh_server::control::TransportKind::Sta,
            config: dmesh_server::control::TransportConfig {
                wake_target: Some(target_mac),
                ..dmesh_server::control::TransportConfig::default()
            },
        };
        let mut record = [0u8; 96];
        let Some(used) = dmesh_server::control::encode_request(request, None, &mut record) else {
            return json!({"ok": false, "error": "encode targeted STA activation"});
        };
        let request_id = now_millis_u64();
        *self
            .pending_nan_active_subscribe
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(PendingNanActiveSubscribe {
            service_info: record[..used].to_vec(),
            target: None,
            request_id,
            sent_windows: 0,
            last_slot: None,
        });
        json!({
            "ok": true,
            "operation": "nan.wakeup",
            "to": colon_mac(&target_mac),
            "carrier": "nan_active_subscribe",
            "request_id": request_id,
            "control_len": used,
            "schedule": ["next_dw", "next_dw0_or_dw8"],
        })
    }

    /// Queue a pairing invitation for an unpaired device in the next NAN discovery
    /// window. The direct signed check still has to follow on the chosen
    /// provisioning bearer before any secret is generated or written.
    pub(crate) fn nan_pair_wakeup(&self, target: String) -> Result<Value> {
        let target_mac = parse_mac(Some(&target)).context("pairing wake needs a target MAC")?;
        if target_mac == [0; 6] || target_mac[0] & 1 != 0 {
            anyhow::bail!("pairing wake target must be a unicast MAC");
        }
        let mut record = [0u8; 96];
        let used = dmesh_server::announce::encode_nan_pair_wakeup_request(
            target_mac,
            now_millis_u64(),
            &mut record,
        )
        .context("encode NAN pairing invitation")?;
        let request_id = now_millis_u64();
        *self
            .pending_nan_active_subscribe
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(PendingNanActiveSubscribe {
            service_info: record[..used].to_vec(),
            target: None,
            request_id,
            sent_windows: 0,
            last_slot: None,
        });
        Ok(json!({"queued": true, "to": colon_mac(&target_mac), "request_id": request_id}))
    }

    /// Request current DMesh presence without replacing the selected transport.
    /// An active NAN request is the canonical directed `announce.discovery`
    /// record carried in an SDEA. Peers answer with the same signed announce
    /// used for unsolicited presence.
    fn request_discovery(
        &self,
        iface: Option<String>,
        channel: Option<u8>,
        active: bool,
        nan: bool,
        passive_scan: bool,
        active_scan: bool,
        dns_sd: bool,
        wait_ms: Option<u64>,
    ) -> Value {
        let iface = wifi_iface(iface);
        let channel = raw_wifi_channel(channel);
        let wait_ms = wait_ms.unwrap_or(1_000).clamp(0, 10_000);
        let started_at = now_millis_u64();
        let mut result = json!({"ok": true, "iface": iface, "channel": channel,
            "active": active, "nan": nan, "passive_scan": passive_scan,
            "active_scan": active_scan, "dns_sd": dns_sd});
        if active && nan {
            let mut record = [0u8; 96];
            // One discovery operation keeps one correlation ID across its
            // DW retransmissions. Receivers use it to suppress duplicate
            // replies from Android/host framework Subscribe repetition.
            let Some(used) =
                dmesh_server::announce::encode_discovery_request(started_at, &mut record)
            else {
                return json!({"ok": false, "iface": iface, "error": "encode announce.discovery"});
            };
            // Do not emit this immediately: sleepy firmware only receives in
            // DW0/DW8. The existing beacon-driven monitor sends once in every
            // confirmed DW and stops after the next DW0 or DW8 boundary.
            *self
                .pending_nan_active_subscribe
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                Some(PendingNanActiveSubscribe {
                    service_info: record[..used].to_vec(),
                    target: None,
                    request_id: started_at,
                    sent_windows: 0,
                    last_slot: None,
                });
            result["nan_active_subscribe"] = json!({
                "ok": true,
                "backend": "linux_af_packet_monitor",
                "queued": true,
                "control_len": used,
                "request_id": started_at,
                "schedule": ["next_dw", "next_dw0_or_dw8"],
                "stop_after_dw": "0_or_8",
            });
            // NOW is the always-awake companion to the DW-bound NAN
            // Subscribe. It uses the identical tagged control record and the
            // active P2P GO device address when one exists; the monitor VIF
            // remains only the injection lane. Sleepy peers are still served
            // by the NAN retry above.
            // Discovery remains raw tagged CBOR on both NAN and NOW. Only
            // association traffic is handed to the QUIC bearer.
            let now = self.wifi_raw_send(
                Some(iface.clone()),
                Some(channel),
                Some(1),
                Some("ff:ff:ff:ff:ff:ff".to_owned()),
                None,
                Some("monitor".to_owned()),
                None,
                Some("ff:ff:ff:ff:ff:ff".to_owned()),
                None,
                format!("hex:{}", hex_bytes(&record[..used])),
                Some(6),
            );
            result["now_discovery"] = now;
        }
        if wait_ms != 0 {
            std::thread::sleep(Duration::from_millis(wait_ms));
        }
        // One bounded response. The retained history can hold many observed
        // discovery events across a long DW window (each carrying a full
        // announce projection), so cap the inline events and keep the full
        // stream on the history surface; an unbounded result overflows the
        // 64 KiB seqpacket record limit.
        let fresh = self
            .history
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter(|event| {
                event.ts_millis >= u128::from(started_at)
                    && matches!(
                        event.key.as_str(),
                        "wifi.rawnan.discovery" | "wifi.rawnan.followup"
                    )
            })
            .map(|event| event.value.clone())
            .collect::<Vec<_>>();
        let fresh_len = fresh.len();
        result["fresh_events"] = json!(fresh.into_iter().rev().take(8).collect::<Vec<_>>());
        result["fresh_events_dropped"] = json!(fresh_len.saturating_sub(8));
        result["inventory"] = self.rawnan_status(Some(iface.clone()))["discovered_devices"].clone();
        self.record("announce.discovery", result.clone());
        result
    }

    /// Return the administrative/carrier state without changing the
    /// interface. This is intentionally a small host diagnostic used before
    /// nl80211 frame tests.
    pub(crate) fn wifi_interface_status(&self, iface: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let link = interface_link_status(&iface);
        json!({ "ok": link.get("ok").and_then(Value::as_bool).unwrap_or(false), "iface": iface, "link": link })
    }


    /// Read the host's current netdev inventory through rtnetlink. This is a
    /// diagnostic/recovery surface only: it neither selects nor changes an
    /// interface, and lets a service report a USB radio that returned under a
    /// different kernel-assigned name.
    pub(crate) fn wifi_interface_list(&self) -> Value {
        match list_rtnetlink_interfaces() {
            Ok(interfaces) => json!({"ok": true, "backend": "rtnetlink", "interfaces": interfaces}),
            Err(error) => json!({"ok": false, "backend": "rtnetlink", "error": error}),
        }
    }

    pub(crate) fn wifi_interface_up(&self, iface: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let result = link_state_result(&iface, true);
        json!({ "ok": result.get("ok").and_then(Value::as_bool).unwrap_or(false), "iface": iface, "link": result })
    }


    /// Pin an owned interface to a 2.4 GHz channel using nl80211.  This is
    /// deliberately explicit: it changes only the requested owned interface.
    pub(crate) fn wifi_interface_set_channel(&self, iface: Option<String>, channel: u8) -> Value {
        let iface = wifi_iface(iface);
        let channel = channel.clamp(1, 13);
        let freq = channel_to_freq(channel);
        let mut steps = Vec::new();
        // lmesh owns this interface, so release lmesh's own radio users before
        // asking nl80211 to retune it.  Merely bringing a managed netdev down
        // leaves monitor/NAN/AP state (and their nl80211 registrations) alive,
        // which makes an otherwise valid SET_WIPHY request return EBUSY.
        steps.push(json!({
            "operation": "stop_raw",
            "result": self.wifi_raw_stop(Some(iface.clone())),
        }));
        steps.push(json!({
            "operation": "stop_ap",
            "result": self.wifi_ap_stop(Some(iface.clone())),
        }));
        // Drivers commonly reject SET_WIPHY while a managed VIF is up. Keep
        // the transition bounded and restore administrative-up afterwards.
        steps.push(run_command("ip", &["link", "set", &iface, "down"]));
        let result = if steps
            .last()
            .and_then(|step| step.get("ok"))
            .and_then(Value::as_bool)
            != Some(true)
        {
            json!({
                "ok": false,
                "backend": "linux_nl80211",
                "iface": iface,
                "channel": channel,
                "freq": freq,
                "steps": steps,
                "error": "interface could not be brought up",
            })
        } else {
            let set_result = ifindex(&iface).and_then(|ifindex| {
                let socket = Nl80211Socket::open()?;
                // ath9k_htc rejects SET_WIPHY on a down managed VIF. Match
                // the existing AP setup path's transient AP type while
                // selecting the channel, then restore the lmesh-owned
                // managed interface without starting an AP.
                socket.set_interface_type(ifindex, NL80211_IFTYPE_AP)?;
                let channel_result = socket.set_channel_ht20(ifindex, freq);
                let restore_result = socket.set_interface_type(ifindex, NL80211_IFTYPE_STATION);
                channel_result.and(restore_result)
            });
            steps.push(match &set_result {
                Ok(()) => json!({"program": "nl80211", "ok": true, "channel": channel, "freq": freq}),
                Err(error) => json!({"program": "nl80211", "ok": false, "channel": channel, "freq": freq, "error": format!("{error:#}")}),
            });
            steps.push(run_command("ip", &["link", "set", &iface, "up"]));
            match set_result {
                Ok(()) => {
                    let link = run_command("ip", &["link", "show", &iface]);
                    let result = json!({
                        "ok": true,
                        "backend": "linux_nl80211",
                        "iface": iface,
                        "channel": channel,
                        "freq": freq,
                        "steps": steps,
                        "link": link,
                    });
                    result
                }
                Err(error) => json!({
                    "ok": false,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "channel": channel,
                    "freq": freq,
                    "steps": steps,
                    "error": format!("{error:#}"),
                }),
            }
        };
        self.record("wifi.interface.channel", result.clone());
        result
    }

    /// Stop the monitor VIF owned by lmesh before changing the channel or
    /// switching the interface into AP/IBSS/P2P mode.
    pub(crate) fn wifi_raw_stop(&self, iface: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let monitor = monitor_iface_name(&iface);
        // Stopping one physical path must not retire the logical QUIC
        // association. A later valid packet can migrate the same connection
        // to UDP, UART, or a restarted action adapter while preserving CIDs
        // and stream state. Connection retirement belongs to CLOSE/timeout or
        // explicit connection policy, never bearer teardown.
        self.raw_wifi_listeners
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|key| !key.starts_with(&format!("{iface}:")));
        let iface_prefix = format!("{iface}:");
        let mut stop_flags = self
            .raw_wifi_stop_flags
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for (key, flag) in stop_flags.iter() {
            if key.starts_with(&iface_prefix) {
                flag.store(true, Ordering::Release);
            }
        }
        stop_flags.retain(|key, _| !key.starts_with(&iface_prefix));
        let down = match ifindex(&monitor) {
            Ok(_) => link_state_result(&monitor, false),
            Err(_) => {
                json!({"ok": true, "backend": "nl80211", "iface": monitor, "state": "absent"})
            }
        };
        let delete = match ifindex(&monitor) {
            Ok(ifindex) => Nl80211Socket::open()
                .and_then(|socket| socket.delete_interface(ifindex))
                .map(|_| json!({"ok": true, "backend": "nl80211", "operation": "del_interface", "iface": monitor}))
                .unwrap_or_else(|error| json!({"ok": false, "backend": "nl80211", "operation": "del_interface", "iface": monitor, "error": format!("{error:#}")})),
            Err(_) => json!({"ok": true, "backend": "nl80211", "operation": "del_interface", "iface": monitor, "state": "absent"}),
        };
        let result = json!({
            "ok": delete.get("ok").and_then(Value::as_bool).unwrap_or(false),
            "backend": "linux_nl80211",
            "iface": iface,
            "monitor_iface": monitor,
            "steps": [down, delete],
        });
        self.record("wifi.raw.stop", result.clone());
        result
    }

    /// Count the retained monitor events of `iface`.
    fn raw_event_counts(&self, iface: &str) -> RawEventCounts {
        let history = self
            .history
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut counts = RawEventCounts::default();
        for event in history.iter() {
            if !event.source.contains(iface) {
                continue;
            }
            match event.key.as_str() {
                "wifi.raw.rx" => counts.rx += 1,
                "wifi.raw.dispatch" => {
                    counts.dispatch += 1;
                    if event.value.get("ok").and_then(Value::as_bool) == Some(false) {
                        counts.dispatch_errors += 1;
                    }
                }
                "wifi.raw.action" => counts.action_seen += 1,
                "wifi.raw.monitor" => counts.monitor_frames += 1,
                "wifi.raw.socket" => counts.socket_packets += 1,
                "wifi.raw.action_candidate" => counts.action_candidates += 1,
                _ => {}
            }
        }
        counts
    }

    /// Typed counts for `telemetry.now` (no JSON).
    pub(crate) fn now_counts(&self, iface: Option<String>) -> RawEventCounts {
        self.raw_event_counts(&wifi_iface(iface))
    }

    /// Beacons the raw-NAN monitor captured, for `telemetry.nan`.
    pub(crate) fn nan_beacons(&self) -> u64 {
        host_capture_counters()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .capture
            .nan_beacons
    }

    /// One typed record per AP station, for `telemetry.wifi_link`.
    pub(crate) fn wifi_link_stations(&self, iface: Option<String>) -> Result<Vec<WifiLinkMetrics>> {
        let iface = wifi_iface(iface);
        let interface_index = ifindex(&iface)?;
        let socket = Nl80211Socket::open()?;
        let stations = socket.station_dump(interface_index)?;
        Ok(stations
            .iter()
            .map(|station| station_link_metrics(station, interface_index))
            .collect())
    }

    /// Summarize raw action receive/dispatch activity for E2E diagnostics.
    /// Counters are derived from the bounded history and therefore allocate
    /// nothing per packet or retain a second transport ledger.
    pub(crate) fn wifi_raw_metrics(&self, iface: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let counts = self.raw_event_counts(&iface);
        let RawEventCounts {
            rx,
            dispatch,
            dispatch_errors,
            action_seen,
            monitor_frames,
            action_candidates,
            socket_packets,
        } = counts;
        json!({
            "ok": true,
            "iface": iface,
            "rx": rx,
            "action_seen": action_seen,
            "dispatch": dispatch,
            "dispatch_errors": dispatch_errors,
            "capture": host_capture_metrics_json(),
            // Retained for compatibility. Packet-rate values now live only
            // in `capture`, rather than in the rotating event history.
            "socket_packets": socket_packets,
            "monitor_frames": monitor_frames,
            "action_candidates": action_candidates,
        })
    }


    /// Return recent radio method results and observed notifications.
    pub(crate) fn history(&self, keys: Option<String>, limit: Option<usize>) -> Value {
        let keys = keys
            .unwrap_or_else(|| "messages,net,wifi,BLE,N".to_string())
            .split(',')
            .map(|key| key.trim().to_string())
            .filter(|key| !key.is_empty())
            .collect::<Vec<_>>();
        let limit = limit.unwrap_or(40).max(1);
        let events = self
            .history
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .rev()
            .filter(|event| keys.is_empty() || keys.iter().any(|key| event.key.starts_with(key)))
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        json!({ "events": events })
    }

    /// Reset the process-local capture counters. QUIC-lite and discovery
    /// counters keep their own lifetime; this covers the raw-monitor ledger
    /// exposed through `radio.snapshot`.
    pub(crate) fn reset_capture_counters(&self) -> Value {
        *host_capture_counters()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = HostCaptureCounters::default();
        json!({ "ok": true })
    }

    /// Map the host capture ledger into the shared `radio.snapshot`
    /// vocabulary. Fields the Linux adapter cannot observe are omitted
    /// rather than synthesized as zero.
    pub(crate) fn radio_snapshot(&self) -> Value {
        let raw = self.wifi_raw_metrics(None);
        let capture = raw.get("capture").cloned().unwrap_or(Value::Null);
        let mut snapshot = serde_json::Map::new();
        snapshot.insert("epoch".to_owned(), Value::from(0));
        snapshot.insert(
            "applied_channel".to_owned(),
            Value::from(raw_wifi_channel(None)),
        );
        for (shared, source) in [
            ("rx_driver_dispatch", "dispatch"),
            ("rx_parser_accepted", "rx"),
            ("rx_dropped", "dispatch_errors"),
        ] {
            if let Some(value) = raw.get(source).cloned() {
                snapshot.insert(shared.to_owned(), value);
            }
        }
        if let Some(value) = capture.get("nan_beacons").cloned() {
            snapshot.insert("nan_beacons".to_owned(), value);
        }
        if let Some(value) = capture.get("nan_rx").cloned() {
            snapshot.insert("nan_sdfs".to_owned(), value);
        }
        snapshot.insert("tx_attempted".to_owned(), raw["monitor_frames"].clone());
        snapshot.insert("capture".to_owned(), capture);
        Value::Object(snapshot)
    }





    /// Fan out an active discovery request to the selected media.
    pub(crate) fn discovery_active(&self, medium: Option<String>, to: Option<String>) -> Value {
        // An omitted medium means every currently registered, enabled radio.
        // It must not manufacture errors for optional LoRa/STA adapters that
        // are absent from this service instance.
        let all_available = medium.is_none();
        let radio = medium_to_radio(medium.as_deref().unwrap_or("all"));
        let mut result = json!({
            "ok": true,
            "record": "announce.discovery",
            "mode": "broadcast",
            "radio": radio,
            "submissions": {},
        });
        if let Some(destination) = to {
            // A directed check names the actual bearer address. It must not be
            // silently replaced by a node lookup or a "best" path.
            let mut record = [0u8; 96];
            let request_id = now_millis_u64();
            let Some(used) =
                dmesh_server::announce::encode_discovery_request(request_id, &mut record)
            else {
                return json!({"ok": false, "error": "encode announce.discovery"});
            };
            let sent = if parse_now_peer_address(&destination).is_some() {
                self.wifi_raw_send(
                    None,
                    None,
                    Some(1),
                    Some(now_wire_destination(&destination)),
                    None,
                    Some("monitor".to_owned()),
                    None,
                    Some("ff:ff:ff:ff:ff:ff".to_owned()),
                    None,
                    format!("hex:{}", hex_bytes(&record[..used])),
                    Some(6),
                )
            } else {
                json!({"ok": false, "error": "unsupported explicit discovery address", "to": destination})
            };
            return json!({
                "ok": sent["ok"] == true,
                "record": "announce.discovery",
                "mode": "directed",
                "to": destination,
                "request_id": request_id,
                "submission": sent,
            });
        }
        if all_available {
            result["requested"] = json!("all_available");
            result["unavailable"] = json!([]);
            result["intended_sends"] = json!([
                "nan_active_sd_next_dw",
                "nan_active_sd_next_dw0_or_dw8",
                "udp_multicast_all_scopes",
                "now_broadcast"
            ]);
        }
        // A NAN discovery check is a directed `announce.discovery` request, not
        // merely a local history entry. Android and other common adapters
        // recognize the tagged-CBOR request in the NAN SDEA and immediately
        // re-publish their current presence descriptor.
        if matches!(radio.as_str(), "all" | "nan" | "best") {
            // DW8 endpoints may need almost a complete four-second cadence
            // before receiving the queued active Subscribe. Return the
            // bounded collection instead of a local-TX-only result.
            let active =
                self.request_discovery(None, None, true, true, true, false, false, Some(4_000));
            let active_ok = active["nan_active_subscribe"]["ok"] == true;
            result["submissions"]["nan"] = active;
            result["ok"] = json!(result["ok"] == true && active_ok);
        }
        result
    }



    /// Send a payload over the selected radio, defaulting to current best.
    pub(crate) fn send(
        &self,
        radio: Option<String>,
        payload: String,
        destination: Option<String>,
    ) -> Value {
        let requested_radio = normalize_radio(radio);
        let selected_radio = if requested_radio == "best" {
            "nan".to_string()
        } else {
            requested_radio.clone()
        };
        let result = match selected_radio.as_str() {
            "nan" => {
                let destination = destination.unwrap_or_else(|| "ff:ff:ff:ff:ff:ff".to_string());
                let target = parse_device_id(Some(&destination)).unwrap_or([0xff; 6]);
                match local_device_id().and_then(|source| {
                    radio_protocol::build_nan_followup(
                        "command_text",
                        &source,
                        &target,
                        payload.as_bytes(),
                    )
                }) {
                    Ok(frame) => self.send_nan_followup(target, &frame),
                    Err(error) => json!({
                        "ok": false,
                        "radio": "nan",
                        "error": format!("{error:#}"),
                    }),
                }
            }
            "wifiraw" => self.wifi_raw_send(
                None,
                None,
                None,
                destination,
                None,
                Some("dont_wait_ack".to_string()),
                None,
                None,
                None,
                payload.clone(),
                None,
            ),
            "lora" => self.esp_lora_send(payload.clone(), destination.clone()),
            "sta" | "ble" | "serial" => json!({
                "ok": false,
                "radio": selected_radio,
                "error": "send radio is not implemented in lmesh yet",
            }),
            "all" => json!({
                "ok": false,
                "radio": "all",
                "error": "send requires radio=best or a single radio",
            }),
            other => json!({
                "ok": false,
                "radio": other,
                "error": "unknown radio",
            }),
        };
        let response = json!({
            "ok": result.get("ok").and_then(Value::as_bool).unwrap_or(false),
            "requested_radio": requested_radio,
            "radio": selected_radio,
            "payload_len": payload.len(),
            "result": result,
        });
        self.record("send", response.clone());
        response
    }


    /// Send one DMesh NAN Follow-up during the selected cluster's DW. The
    /// caller supplies the DMesh envelope, while this Wi-Fi owner adds the
    /// NAN public-action/SDF framing and retains packet ownership until the
    /// monitor write completes. A closed or not-yet-known DW queues a bounded
    /// intent for the next observed beacon; it never becomes an always-on
    /// action transport.
    fn send_nan_followup(&self, destination: [u8; 6], payload: &[u8]) -> Value {
        let iface = wifi_iface(None);
        let channel = raw_wifi_channel(None);
        let now_us = now_micros_u64();
        let timing = self
            .rawnan_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .nan_sync_timing();
        let Some((last_beacon_us, _tsf_us, _period_us)) = timing else {
            let queued = queue_nan_followup(
                &self.pending_nan_followups,
                destination,
                1,
                0,
                payload.to_vec(),
            );
            return json!({
                "ok": true,
                "radio": "nan",
                "destination": colon_mac(&destination),
                "queued": queued,
                "error": "NAN cluster timing unavailable; queued for next beacon",
            });
        };
        let dwell_age_us = now_us.saturating_sub(last_beacon_us);
        if !dmesh_rawnan::beacon_dwell_open(dwell_age_us) {
            let queued = queue_nan_followup(
                &self.pending_nan_followups,
                destination,
                1,
                0,
                payload.to_vec(),
            );
            return json!({
                "ok": true,
                "radio": "nan",
                "destination": colon_mac(&destination),
                "dwell_age_us": dwell_age_us,
                "queued": queued,
                "error": "NAN follow-up queued for next discovery window",
            });
        }
        let bssid = self
            .rawnan_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .sync_bssid()
            .map(|mac| mac.0)
            .expect("nan_sync_timing requires BSSID");
        match raw_wifi_source(None, &iface).and_then(|source| {
            let frame = dmesh_rawnan::build_nan_followup_sdf(
                destination,
                source,
                bssid,
                dmesh_rawnan::DMESH_SERVICE_ID,
                1,
                payload,
            );
            let packet = build_radiotap_packet_at_rate(&frame, Some(6))?;
            // The listener is permanent and owns its monitor VIF.  Sending a
            // follow-up must reuse it, never create/restart/reconfigure host
            // radio infrastructure as a side effect of an E2E probe.
            let monitor = monitor_iface_name(&iface);
            let socket = MonitorTxSocket::open(&monitor)?;
            let written = socket.send(&packet)?;
            (written == packet.len())
                .then_some(json!({ "iface": monitor, "packet_len": packet.len() }))
                .ok_or_else(|| anyhow::anyhow!("short NAN follow-up write"))
        }) {
            Ok(monitor) => json!({
                "ok": true,
                "radio": "nan",
                "backend": "linux_af_packet_monitor",
                "destination": colon_mac(&destination),
                "iface": iface,
                "channel": channel,
                "payload_len": payload.len(),
                "dwell_age_us": dwell_age_us,
                "monitor": monitor,
            }),
            Err(error) => json!({
                "ok": false,
                "radio": "nan",
                "destination": colon_mac(&destination),
                "iface": iface,
                "channel": channel,
                "payload_len": payload.len(),
                "error": error.to_string(),
            }),
        }
    }

    fn esp_lora_send(&self, payload: String, destination: Option<String>) -> Value {
        json!({
            "ok": false,
            "radio": "lora",
            "payload_len": payload.len(),
            "destination": destination,
            "error": "ESP LoRa serial gateway is retired; use dmesh-cli for a direct device session",
        })
    }

    /// Return or record an explicit link steering hint.
    pub(crate) fn link_steer(
        &self,
        node: Option<String>,
        radio: Option<String>,
        reason: Option<String>,
    ) -> Value {
        let radio = normalize_radio(radio);
        let result = json!({
            "ok": true,
            "node": node,
            "radio": radio,
            "reason": reason.unwrap_or_else(|| "manual".to_string()),
            "status": "recorded",
        });
        self.record("link.steer", result.clone());
        if let Some(node) = result.get("node").and_then(Value::as_str) {
            let medium = match radio.as_str() {
                "wifiraw" => "wifi",
                "sta" => "wifi",
                other => other,
            };
            self.record_message(
                "link.steer",
                "local",
                MeshMessage::new(mesh::message::KIND_EVENT, MeshMessageCodec::Text)
                    .field(FIELD_NODE, node)
                    .field(FIELD_MEDIUM, medium)
                    .field(FIELD_RADIO_ID, &radio)
                    .field(FIELD_STATUS, "recorded"),
            );
        }
        result
    }



    /// Start an open AP with a runtime beacon interval. Larger intervals are
    /// useful for raw-action throughput experiments because they reduce AP
    /// beacon contention without changing the radio channel or transport.
    pub(crate) fn wifi_ap_start_open_on_channel_with_interval(
        &self,
        iface: Option<String>,
        ssid: Option<String>,
        requested_channel: Option<u8>,
        ht40: Option<bool>,
        beacon_interval_tu: u16,
    ) -> Value {
        self.wifi_ap_start_open_with_width(
            iface,
            ssid,
            requested_channel,
            ht40.unwrap_or(DEFAULT_OPEN_AP_HT40),
            beacon_interval_tu.clamp(10, 1000),
        )
    }

    /// Start an AP as the explicitly service-owned sibling of a persistent
    /// station anchor. The anchor remains a station VIF throughout; callers
    /// can therefore stop/restart the AP without changing primary STA
    /// ownership or leaving AP state on the physical interface.
    pub(crate) fn wifi_ap_start_open_on_child(
        &self,
        anchor_iface: Option<String>,
        ssid: Option<String>,
        requested_channel: Option<u8>,
        ht40: Option<bool>,
        beacon_interval_tu: u16,
    ) -> Value {
        let anchor_iface = wifi_iface(anchor_iface);
        match self.ensure_ap_child_vif(&anchor_iface) {
            Ok((ap_iface, vif)) => {
                let mut result = self.wifi_ap_start_open_on_channel_with_interval(
                    Some(ap_iface.clone()),
                    ssid,
                    requested_channel,
                    ht40,
                    beacon_interval_tu,
                );
                result["anchor_iface"] = json!(anchor_iface);
                result["ap_iface"] = json!(ap_iface);
                result["vif"] = vif;
                result
            }
            Err(error) => json!({
                "ok": false,
                "backend": "linux_nl80211",
                "anchor_iface": anchor_iface,
                "error": format!("create AP VIF: {error:#}"),
            }),
        }
    }

    fn wifi_ap_start_open_with_width(
        &self,
        iface: Option<String>,
        ssid: Option<String>,
        requested_channel: Option<u8>,
        ht40: bool,
        beacon_interval_tu: u16,
    ) -> Value {
        let iface = wifi_iface(iface);
        let ssid = ssid.unwrap_or_else(|| default_open_ap_ssid(&iface));
        let channel = requested_channel.unwrap_or(DEFAULT_RAW_WIFI_CHANNEL);
        if !(1..=13).contains(&channel) || (ht40 && !(1..=9).contains(&channel)) {
            return json!({
                "ok": false,
                "backend": "linux_nl80211",
                "iface": iface,
                "ssid": ssid,
                "channel": channel,
                "error": if ht40 { "HT40+ primary channel must be in 1..=9" } else { "2.4 GHz AP channel must be in 1..=13" },
            });
        }
        let freq = channel_to_freq(channel);
        let ifindex = match ifindex(&iface) {
            Ok(ifindex) => ifindex,
            Err(error) => {
                return json!({
                    "ok": false,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "ssid": ssid,
                    "channel": channel,
                    "error": format!("{error:#}"),
                });
            }
        };
        // AP startup is also the recovery boundary after a failed STA/NAN
        // transition or a supervised restart.  A previous monitor fixture
        // owns the same PHY and can leave the managed parent down; remove it
        // before changing the parent into AP mode.  The operation is
        // intentionally best-effort because the normal AP path has no
        // monitor child yet.
        let _ = self.wifi_raw_stop(Some(iface.clone()));
        self.stop_ap_runtime(&iface);
        let mac = iface_mac(&iface).unwrap_or([0; 6]);
        let template_lengths = open_ap_template_lengths(&ssid, channel)
            .map(|(beacon_head, probe_resp)| {
                json!({
                    "beacon_head": beacon_head,
                    "beacon_tail": esp_open_ap_beacon_tail(channel).len(),
                    "probe_resp": probe_resp,
                    "profile": "esp32_open_ap",
                })
            })
            .unwrap_or_else(|error| json!({ "error": format!("{error:#}") }));
        let mut steps = Vec::new();
        let mut profiles = Vec::new();
        let mut selected_profile = None;
        steps.push(link_state_result(&iface, false));
        let result = Nl80211Socket::open()
            .and_then(|socket| {
                let mgmt_socket = Nl80211Socket::open()?;
                socket.set_interface_type(ifindex, NL80211_IFTYPE_AP)?;
                steps.push(match if ht40 { socket.set_channel_ht40_plus(ifindex, freq) } else { socket.set_channel_ht20(ifindex, freq) } {
                    Ok(()) => json!({
                        "program": "nl80211",
                        "args": ["set_wiphy", if ht40 { "channel_ht40_plus" } else { "channel_ht20" }],
                        "ok": true,
                        "freq": freq,
                    }),
                    Err(error) => json!({
                        "program": "nl80211",
                        "args": ["set_wiphy", if ht40 { "channel_ht40_plus" } else { "channel_ht20" }],
                        "ok": false,
                        "freq": freq,
                        "error": format!("{error:#}"),
                    }),
                });
                steps.push(link_up_confirmed(&iface, 3));
                let registrations = mgmt_socket.register_open_ap_sme_frames(ifindex);
                let registrations_ok = registrations.iter().all(|registration| {
                    registration.get("ok").and_then(Value::as_bool) == Some(true)
                        || registration.get("required").and_then(Value::as_bool) == Some(false)
                });
                steps.push(json!({
                    "program": "nl80211",
                    "args": ["register_frame", "ap_sme"],
                    "ok": registrations_ok,
                    "registrations": registrations,
                }));
                steps.push(match socket.flush_stations(ifindex) {
                    Ok(()) => json!({
                        "program": "nl80211",
                        "args": ["del_station", "all"],
                        "ok": true,
                    }),
                    Err(error) => json!({
                        "program": "nl80211",
                        "args": ["del_station", "all"],
                        "ok": false,
                        "error": format!("{error:#}"),
                    }),
                });
                match socket.start_open_ap(ifindex, mac, &ssid, channel, freq, ht40, beacon_interval_tu) {
                    Ok(report) => {
                        selected_profile = report
                            .get("selected")
                            .and_then(Value::as_str)
                            .map(ToString::to_string);
                        profiles = report
                            .get("attempts")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default();
                    }
                    Err((error, attempts)) => {
                        profiles = attempts;
                        steps.push(link_state_result(&iface, false));
                        let _ = socket.set_interface_type(ifindex, NL80211_IFTYPE_STATION);
                        steps.push(link_state_result(&iface, true));
                        return Err(error);
                    }
                }
                if selected_profile.is_none() {
                    steps.push(link_state_result(&iface, false));
                    let _ = socket.set_interface_type(ifindex, NL80211_IFTYPE_STATION);
                    steps.push(link_state_result(&iface, true));
                    bail!("nl80211 start open AP returned no selected profile");
                }
                let mgmt_iface = iface.clone();
                let history: Arc<dyn CaptureHost> = self.capture_host.clone();
                let rawnan_state = self.rawnan_state.clone();
                let active_nan_publish = self.active_nan_publish.clone();
                let _pending_nan_active_subscribe = self.pending_nan_active_subscribe.clone();
                let pending_nan_followups = self.pending_nan_followups.clone();
                let ap_no_ht_stations = self.ap_no_ht_stations.clone();
                let stop = Arc::new(AtomicBool::new(false));
                let stop_for_thread = stop.clone();
                let join = std::thread::spawn(move || {
                    ap_mgmt_receive_loop(
                        mgmt_socket,
                        &mgmt_iface,
                        ifindex,
                        mac,
                        history,
                        rawnan_state,
                        active_nan_publish,
                        pending_nan_followups,
                        ap_no_ht_stations,
                        channel,
                        ht40,
                        stop_for_thread,
                    );
                });
                self.wifi_ap_handles
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert(
                        iface.clone(),
                        ApRuntime {
                            _owner_socket: socket,
                            ssid: ssid.clone(),
                            channel,
                            ht40,
                            beacon_interval_tu,
                            stop,
                            join: Some(join),
                        },
                    );
                Ok(())
            })
            .map(|_| {
                json!({
                    "ok": true,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "ssid": ssid,
                    "channel": channel,
                    "freq": freq,
                    "bssid": colon_mac(&mac),
                    "auth": "open",
                    "beacon_interval": beacon_interval_tu,
                    "dtim_period": 1,
                    "channel_width": if ht40 { "40_ht" } else { "20_ht" },
                    "template_lengths": template_lengths,
                    "selected_profile": selected_profile,
                    "profiles": profiles,
                    "steps": steps,
                })
            })
            .unwrap_or_else(|error| {
                json!({
                    "ok": false,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "ssid": ssid,
                    "channel": channel,
                    "freq": freq,
                    "bssid": colon_mac(&mac),
                    "auth": "open",
                    "beacon_interval": beacon_interval_tu,
                    "dtim_period": 1,
                    "channel_width": if ht40 { "40_ht" } else { "20_ht" },
                    "template_lengths": template_lengths,
                    "selected_profile": selected_profile,
                    "profiles": profiles,
                    "steps": steps,
                    "error": format!("{error:#}"),
                })
            });
        self.record("wifi.ap.start_open", result.clone());
        result
    }

    /// Stop AP operation on an interface.
    pub(crate) fn wifi_ap_stop(&self, iface: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        self.stop_ap_runtime(&iface);
        let result = ifindex(&iface)
            .and_then(|ifindex| {
                let socket = Nl80211Socket::open()?;
                let mut steps = Vec::new();
                steps.push(match socket.stop_ap(ifindex) {
                    Ok(()) => json!({
                        "program": "nl80211",
                        "args": ["stop_ap"],
                        "ok": true,
                    }),
                    Err(error) => json!({
                        "program": "nl80211",
                        "args": ["stop_ap"],
                        "ok": false,
                        "error": format!("{error:#}"),
                    }),
                });
                steps.push(link_state_result(&iface, false));
                steps.push(
                    match socket.set_interface_type(ifindex, NL80211_IFTYPE_STATION) {
                        Ok(()) => json!({
                            "program": "nl80211",
                            "args": ["set_interface", "station"],
                            "ok": true,
                        }),
                        Err(error) => json!({
                            "program": "nl80211",
                            "args": ["set_interface", "station"],
                            "ok": false,
                            "error": format!("{error:#}"),
                        }),
                    },
                );
                steps.push(link_state_result(&iface, true));
                // STOP_AP may report ENETDOWN after monitor teardown. The
                // meaningful transition proof is that the parent went down
                // and switched back to managed station mode; the supplicant
                // owns the subsequent administrative-up transition.
                let reset_ok = steps
                    .get(1)
                    .and_then(|step| step.get("ok"))
                    .and_then(Value::as_bool)
                    == Some(true)
                    && steps
                        .get(2)
                        .and_then(|step| step.get("ok"))
                        .and_then(Value::as_bool)
                        == Some(true);
                Ok(json!({
                    "ok": reset_ok,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "steps": steps,
                }))
            })
            .unwrap_or_else(|error| {
                json!({
                    "ok": false,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "error": format!("{error:#}"),
                })
            });
        self.record("wifi.ap.stop", result.clone());
        result
    }

    fn stop_ap_runtime(&self, iface: &str) {
        let runtime = self
            .wifi_ap_handles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(iface);
        let Some(mut runtime) = runtime else {
            return;
        };
        runtime.stop.store(true, Ordering::Release);
        if let Some(join) = runtime.join.take() {
            let _ = join.join();
        }
    }

    /// Select address2 for an injected vendor action. The monitor belongs to
    /// the anchor interface, but a running P2P GO owns a distinct device
    /// address. ESP action receive admits the latter; using the dormant anchor
    /// address makes a perfectly transmitted monitor frame invisible to it.
    fn raw_action_source(
        &self,
        value: Option<&str>,
        anchor_iface: &str,
    ) -> Result<([u8; 6], &'static str)> {
        if value.is_some() {
            return raw_wifi_source(value, anchor_iface).map(|mac| (mac, "explicit_mac"));
        }
        let group_iface = self
            .p2p_group_ifaces
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(anchor_iface)
            .cloned();
        if let Some(group_iface) = group_iface {
            if let Ok(mac) = iface_mac(&group_iface) {
                return Ok((mac, "p2p_group_mac"));
            }
        }
        raw_wifi_source(None, anchor_iface).map(|mac| (mac, "interface_mac"))
    }








    /// Join an open AP as a station on its passive-observed channel. A BSSID
    /// constraint avoids an active scan and makes the final association
    /// evidence specific to the requested AP rather than any matching SSID.
    pub(crate) fn wifi_sta_join_open(
        &self,
        iface: Option<String>,
        ssid: String,
        bssid: Option<[u8; 6]>,
        channel: Option<u8>,
    ) -> Value {
        let iface = wifi_iface(iface);
        let channel = channel.unwrap_or(DEFAULT_RAW_WIFI_CHANNEL);
        if !(1..=13).contains(&channel) {
            return json!({"ok": false, "backend": "linux_nl80211", "iface": iface, "ssid": ssid, "channel": channel, "error": "open DMesh STA supports only 2.4 GHz channels 1 through 13"});
        }
        let freq = channel_to_freq(channel);
        let mut steps = Vec::new();
        steps.push(link_state_result(&iface, false));
        let result = ifindex(&iface)
            .and_then(|ifindex| {
                let socket = Nl80211Socket::open()?;
                socket.set_interface_type(ifindex, NL80211_IFTYPE_STATION)?;
                steps.push(link_state_result(&iface, true));
                if steps.last().and_then(|step| step.get("ok")).and_then(Value::as_bool) != Some(true) {
                    bail!("failed to bring {iface} up through rtnetlink");
                }
                socket.connect_open(ifindex, &ssid, freq, bssid)
            })
            .and_then(|_| {
                let deadline = Instant::now() + Duration::from_secs(8);
                let requested_bssid = bssid.map(|mac| colon_mac(&mac));
                loop {
                    let peers = Nl80211Socket::open()?.station_dump(ifindex(&iface)?)?;
                    // A station dump can still describe the previous AP for a
                    // short interval after CONNECT is ACKed.  In particular,
                    // do not turn that stale state into a successful
                    // transition merely because the requested SSID/channel
                    // happen to be valid.  A constrained open connection is
                    // complete only once nl80211 names the requested BSSID.
                    let bssid_matches = requested_bssid.as_ref().is_none_or(|wanted| {
                        peers.iter().any(|peer| {
                            peer.get("mac").and_then(Value::as_str) == Some(wanted)
                                && peer.get("authorized").and_then(Value::as_bool) != Some(false)
                        })
                    });
                    if !peers.is_empty() && bssid_matches {
                        return Ok(peers);
                    }
                    if Instant::now() >= deadline {
                        if let Some(wanted) = requested_bssid {
                            bail!(
                                "timed out waiting for final open STA association to requested BSSID {wanted}; observed station peers: {}",
                                serde_json::to_string(&peers).unwrap_or_else(|_| "<unrenderable>".to_owned())
                            );
                        }
                        bail!("timed out waiting for final open STA association event/station state");
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            })
            .and_then(|peers| {
                let link_local = ensure_link_local_address(&iface)?;
                Ok((peers, link_local))
            })
            .map(|(peers, link_local)| {
                json!({
                    "ok": true,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "ssid": ssid,
                    "channel": channel,
                    "freq": freq,
                    "auth": "open",
                    "bssid": bssid.map(|mac| mac.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(":")),
                    "associated": true,
                    "link_local": link_local,
                    "peers": peers,
                    "steps": steps,
                })
            })
            .unwrap_or_else(|error| {
                json!({
                    "ok": false,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "ssid": ssid,
                    "channel": channel,
                    "freq": freq,
                    "auth": "open",
                    "steps": steps,
                    "error": format!("{error:#}"),
                })
            });
        self.record("wifi.sta.join_open", result.clone());
        result
    }

    /// Execute one STA transition selected by the common `transport.set`
    /// profile.
    ///
    /// A transport transition is an ownership boundary.  Before creating its
    /// requested state it tears down the previous service-owned monitor, AP
    /// STA children, AP runtime, and WPA child.  In particular, a failed WPA
    /// attempt must not leave a managed VIF behind to poison the next AP or
    /// STA transition on the same wiphy.
    pub(crate) fn wifi_sta_transport_start(
        &self,
        iface: Option<String>,
        ssid: String,
        passphrase: Option<String>,
        bssid: Option<[u8; 6]>,
        channel: Option<u8>,
    ) -> Value {
        let iface = wifi_iface(iface);
        // A supplied value is volatile session data from the common
        // transport.set record; it is neither persisted nor included in the
        // result/history.  Without it, retain the deployment-profile lookup
        // and its open-network fallback.
        let supplied_passphrase = passphrase.filter(|value| !value.is_empty());
        if let Some(value) = supplied_passphrase.as_deref() {
            if !(8..=63).contains(&value.len()) || value.contains('\0') {
                return json!({
                    "ok": false,
                    "backend": "validation",
                    "iface": iface,
                    "ssid": ssid,
                    "error": "transport.set passphrase must contain 8 through 63 non-NUL bytes",
                });
            }
        }
        let credentials = if let Some(passphrase) = supplied_passphrase {
            Some((
                passphrase,
                crate::infra_credentials::InfrastructureSecurity::Wpa2Psk,
            ))
        } else {
            match load_default_infrastructure_credentials() {
                Ok(Some(credentials)) => credentials
                    .find_by_ssid(&ssid)
                    .map(|profile| (profile.password().to_owned(), profile.security())),
                Ok(_) => None,
                Err(error) => {
                    return json!({
                        "ok": false,
                        "backend": "configuration",
                        "iface": iface,
                        "ssid": ssid,
                        "error": format!("load infrastructure profile: {error:#}"),
                    });
                }
            }
        };
        // WPA scan/association must own the PHY. Preserve the service-owned
        // AP profile before quiescing it so it can be restored only on the
        // exact frequency reported by the completed WPA association.
        let prior_ap = self
            .wifi_ap_handles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&iface)
            .map(|runtime| {
                (
                    runtime.ssid.clone(),
                    runtime.ht40,
                    runtime.beacon_interval_tu,
                )
            });
        let cleanup = self.clean_transport_state(&iface);
        if cleanup.get("ok").and_then(Value::as_bool) != Some(true) {
            return json!({
                "ok": false,
                "backend": "linux_nl80211",
                "iface": iface,
                "cleanup": cleanup,
                "error": "failed to clean previous transport state",
            });
        }
        // The host-provided anchor is the station VIF.  An AP, when needed,
        // is the service-owned sibling `<anchor>ap`; a transition must never
        // manufacture a second station VIF and leave the primary interface
        // ambiguous or stale.
        let sta_iface = iface.clone();
        // The physical anchor must be administratively up before the new STA
        // transport starts. USB radios can ACK interface operations while
        // refusing RTM_NEWLINK until recovery has completed.
        let anchor_up = link_up_confirmed(&iface, 3);
        if anchor_up.get("ok").and_then(Value::as_bool) != Some(true) {
            return json!({"ok": false, "backend": "rtnetlink", "iface": sta_iface, "anchor_iface": iface, "cleanup": cleanup, "anchor_up": anchor_up, "failure_cleanup": self.clean_transport_state(&iface), "error": "failed to bring STA anchor up through rtnetlink"});
        }
        let Some((passphrase, security)) = credentials else {
            let mut result = self.wifi_sta_join_open(Some(sta_iface.clone()), ssid, bssid, channel);
            result["anchor_iface"] = json!(iface);
            result["cleanup"] = cleanup;
            result["anchor_up"] = anchor_up;
            if result.get("ok").and_then(Value::as_bool) != Some(true) {
                result["failure_cleanup"] = self.clean_transport_state(&iface);
            }
            self.record("transport.set.sta", result.clone());
            return result;
        };
        if let Err(error) = set_link_state(&sta_iface, false) {
            return json!({"ok": false, "backend": "rtnetlink", "iface": sta_iface, "anchor_iface": iface, "cleanup": cleanup, "anchor_up": anchor_up, "failure_cleanup": self.clean_transport_state(&iface), "error": error});
        }
        let setup = ifindex(&sta_iface).and_then(|ifindex| {
            Nl80211Socket::open()?.set_interface_type(ifindex, NL80211_IFTYPE_STATION)
        });
        if let Err(error) = setup {
            return json!({"ok": false, "backend": "linux_nl80211", "iface": sta_iface, "anchor_iface": iface, "cleanup": cleanup, "anchor_up": anchor_up, "failure_cleanup": self.clean_transport_state(&iface), "error": format!("{error:#}")});
        }
        // The only child allowed to own authenticated STA lifecycle is
        // wpa_supplicant. Retain a failed/delayed RTM_NEWLINK ACK as
        // diagnostic evidence but still allow it to raise and scan the VIF.
        let link_up = link_state_result(&sta_iface, true);
        let control_dir = wpa_runtime_dir();
        self.wpa_supplicants
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&sta_iface);
        let supplicant = match lmesh_wpa::WpaSupplicant::start(
            &sta_iface,
            control_dir,
            Duration::from_secs(5),
        ) {
            Ok(supplicant) => supplicant,
            Err(error) => {
                return json!({"ok": false, "backend": "wpa_supplicant", "iface": sta_iface, "anchor_iface": iface, "cleanup": cleanup, "anchor_up": anchor_up, "link_up": link_up, "failure_cleanup": self.clean_transport_state(&iface), "error": format!("{error:#}")});
            }
        };
        let association = match security {
            crate::infra_credentials::InfrastructureSecurity::Wpa2Psk => {
                supplicant.connect_wpa2(ssid.as_bytes(), &passphrase, Duration::from_secs(20))
            }
            crate::infra_credentials::InfrastructureSecurity::Wpa3Sae => {
                supplicant.connect_wpa3_sae(ssid.as_bytes(), &passphrase, Duration::from_secs(20))
            }
        };
        if let Err(error) = association {
            drop(supplicant);
            return json!({"ok": false, "backend": "wpa_supplicant", "iface": sta_iface, "anchor_iface": iface, "auth": security.as_str(), "cleanup": cleanup, "anchor_up": anchor_up, "link_up": link_up, "failure_cleanup": self.clean_transport_state(&iface), "error": format!("{error:#}")});
        }
        let frequency = match supplicant.connected_frequency(Duration::from_secs(2)) {
            Ok(frequency) => frequency,
            Err(error) => {
                drop(supplicant);
                return json!({"ok": false, "backend": "wpa_supplicant", "iface": sta_iface, "anchor_iface": iface, "auth": security.as_str(), "cleanup": cleanup, "anchor_up": anchor_up, "link_up": link_up, "failure_cleanup": self.clean_transport_state(&iface), "error": format!("{error:#}")});
            }
        };
        self.wpa_supplicants
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(sta_iface.clone(), supplicant);
        let ap_restoration = match (prior_ap, freq_to_channel(frequency)) {
            (Some((ap_ssid, ap_ht40, beacon_interval_tu)), Some(channel @ 1..=13)) => {
                match self.ensure_ap_child_vif(&iface) {
                    Ok((ap_iface, vif)) => {
                        let ap = self.wifi_ap_start_open_on_channel_with_interval(
                            Some(ap_iface.clone()),
                            Some(ap_ssid),
                            Some(channel),
                            Some(ap_ht40),
                            beacon_interval_tu,
                        );
                        json!({"ok": ap.get("ok").and_then(Value::as_bool) == Some(true), "iface": ap_iface, "vif": vif, "ap": ap})
                    }
                    Err(error) => {
                        json!({"ok": false, "state": "vif_create_failed", "error": format!("{error:#}")})
                    }
                }
            }
            (Some(_), Some(channel)) => json!({
                "ok": false,
                "state": "not_restored",
                "channel": channel,
                "error": "the current open-AP implementation supports only 2.4 GHz channels 1 through 13",
            }),
            (Some(_), None) => json!({
                "ok": false,
                "state": "not_restored",
                "frequency_mhz": frequency,
                "error": "could not map the WPA association frequency to an AP channel",
            }),
            (None, _) => json!({"ok": true, "state": "not_requested"}),
        };
        let result = json!({
            "ok": true,
            "backend": "wpa_supplicant",
            "iface": sta_iface,
            "anchor_iface": iface,
            "ssid": ssid,
            "auth": security.as_str(),
            "frequency_mhz": frequency,
            "cleanup": cleanup,
            "anchor_up": anchor_up,
            "link_up": link_up,
            "ap_restoration": ap_restoration,
        });
        self.record("transport.set.sta", result.clone());
        result
    }

    /// Start the AP-equivalent half of a common transport epoch. The selected
    /// backend is service policy; a supplied PSK is volatile and otherwise
    /// the common DMesh P2P default is used.
    pub(crate) fn wifi_p2p_transport_start(
        &self,
        iface: Option<String>,
        backend: &str,
        passphrase: Option<&str>,
    ) -> Value {
        let iface = wifi_iface(iface);
        let backend = backend.trim().to_ascii_lowercase();
        if backend != "p2p" && backend != "open" && backend != "wpa2-ap" {
            return json!({
                "ok": false,
                "iface": iface,
                "error": "transport AP backend must be p2p, wpa2-ap, or open",
            });
        }
        let passphrase = passphrase.unwrap_or(DMESH_P2P_PASSPHRASE);
        if (backend == "p2p" || backend == "wpa2-ap")
            && (!(8..=63).contains(&passphrase.len()) || passphrase.contains('\0'))
        {
            return json!({
                "ok": false,
                "iface": iface,
                "error": "transport.set passphrase must contain 8 through 63 non-NUL bytes",
            });
        }
        let cleanup = self.clean_transport_state(&iface);
        if cleanup.get("ok").and_then(Value::as_bool) != Some(true) {
            return json!({
                "ok": false,
                "requested_backend": backend,
                "iface": iface,
                "cleanup": cleanup,
                "error": "failed to clean previous transport state",
            });
        }
        let anchor_up = link_up_confirmed(&iface, 3);
        if anchor_up.get("ok").and_then(Value::as_bool) != Some(true) {
            return json!({
                "ok": false,
                "requested_backend": backend,
                "iface": iface,
                "cleanup": cleanup,
                "anchor_up": anchor_up,
                "error": "failed to bring P2P anchor up through rtnetlink",
            });
        }
        if backend == "open" {
            let open = self.wifi_ap_start_open_on_channel_with_interval(
                Some(iface.clone()),
                Some(DMESH_P2P_SSID.to_owned()),
                Some(DEFAULT_RAW_WIFI_CHANNEL),
                None,
                100,
            );
            let result = json!({
                "ok": open.get("ok").and_then(Value::as_bool) == Some(true),
                "requested_backend": "open",
                "active_backend": "open",
                "iface": iface,
                "ssid": DMESH_P2P_SSID,
                "security": "open-experiment",
                "cleanup": cleanup,
                "anchor_up": anchor_up,
                "ap": open,
            });
            self.record("transport.set.ap", result.clone());
            return result;
        }

        if backend == "wpa2-ap" {
            let control_dir = wpa_runtime_dir();
            let ap = (|| -> Result<()> {
                let supplicant =
                    lmesh_wpa::WpaSupplicant::start(&iface, control_dir, Duration::from_secs(5))?;
                supplicant.start_wpa2_ap(
                    DMESH_P2P_SSID.as_bytes(),
                    passphrase,
                    DMESH_P2P_FREQUENCY_MHZ,
                    Duration::from_secs(15),
                )?;
                self.wpa_supplicants
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert(iface.clone(), supplicant);
                Ok(())
            })();
            return match ap {
                Ok(()) => {
                    let result = json!({
                        "ok": true,
                        "requested_backend": "wpa2-ap",
                        "active_backend": "wpa2-ap",
                        "backend": "wpa_supplicant",
                        "iface": iface,
                        "ssid": DMESH_P2P_SSID,
                        "auth": "wpa2-psk",
                        "frequency_mhz": DMESH_P2P_FREQUENCY_MHZ,
                        "cleanup": cleanup,
                        "anchor_up": anchor_up,
                    });
                    self.record("transport.set.ap", result.clone());
                    result
                }
                Err(error) => {
                    let failure_cleanup = self.clean_transport_state(&iface);
                    let result = json!({
                        "ok": false,
                        "requested_backend": "wpa2-ap",
                        "iface": iface,
                        "ssid": DMESH_P2P_SSID,
                        "cleanup": cleanup,
                        "failure_cleanup": failure_cleanup,
                        "anchor_up": anchor_up,
                        "error": format!("WPA2 AP setup failed: {error:#}"),
                    });
                    self.record("transport.set.ap", result.clone());
                    result
                }
            };
        }

        let control_dir = wpa_runtime_dir();
        let p2p = (|| -> Result<lmesh_wpa::P2pGroup> {
            let supplicant =
                lmesh_wpa::WpaSupplicant::start(&iface, control_dir, Duration::from_secs(5))?;
            supplicant.p2p_capability(Duration::from_secs(2))?;
            let group = supplicant.p2p_start_fixed_go(
                DMESH_P2P_SSID.as_bytes(),
                passphrase,
                DMESH_P2P_FREQUENCY_MHZ,
                Duration::from_secs(15),
            )?;
            self.wpa_supplicants
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(iface.clone(), supplicant);
            self.p2p_group_ifaces
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(iface.clone(), group.iface.clone());
            Ok(group)
        })();
        match p2p {
            Ok(group) => {
                let result = json!({
                    "ok": true,
                    "requested_backend": "p2p",
                    "active_backend": "p2p",
                    "backend": "wpa_supplicant",
                    "iface": iface,
                    "ssid": DMESH_P2P_SSID,
                    "frequency_mhz": group.frequency_mhz,
                    "group_iface": group.iface,
                    "role": match group.role {
                        lmesh_wpa::P2pRole::GroupOwner => "go",
                        lmesh_wpa::P2pRole::Client => "client",
                    },
                    "cleanup": cleanup,
                    "anchor_up": anchor_up,
                });
                self.record("transport.set.ap", result.clone());
                result
            }
            Err(error) => {
                // WpaSupplicant is dropped on error. Never silently replace a
                // requested PSK P2P group with an open AP.
                let failure_cleanup = self.clean_transport_state(&iface);
                let result = json!({
                    "ok": false,
                    "requested_backend": "p2p",
                    "iface": iface,
                    "ssid": DMESH_P2P_SSID,
                    "p2p_failure": format!("{error:#}"),
                    "cleanup": cleanup,
                    "failure_cleanup": failure_cleanup,
                    "anchor_up": anchor_up,
                    "error": "P2P/PSK group creation failed; open AP fallback is disabled",
                });
                self.record("transport.set.ap", result.clone());
                result
            }
        }
    }

    /// Release every service-created transport resource for one anchor. The
    /// host-provided anchor is retained and reset to a down station VIF; the
    /// AP, monitor, and legacy station child are stopped and removed. This is
    /// the mandatory precondition for a replacement transport.
    fn clean_transport_state(&self, anchor_iface: &str) -> Value {
        let sta_iface = match sta_child_iface_name(anchor_iface) {
            Ok(iface) => iface,
            Err(error) => return json!({"ok": false, "error": format!("{error:#}")}),
        };
        let ap_iface = match ap_child_iface_name(anchor_iface) {
            Ok(iface) => iface,
            Err(error) => return json!({"ok": false, "error": format!("{error:#}")}),
        };
        self.stop_ap_runtime(anchor_iface);
        self.stop_ap_runtime(&ap_iface);
        // The normal STA transport owns the anchor itself (for example,
        // `wlan1`), while an older topology could have owned `wlan1sta`.
        // Release both keys.  Removing only the legacy child leaves the
        // retained foreground supplicant alive, allowing it to race a later
        // direct-nl80211 open connection back onto its previous SSID.
        let wpa_owners = wpa_owner_iface_names(anchor_iface, &sta_iface);
        {
            let mut supplicants = self
                .wpa_supplicants
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for owner in &wpa_owners {
                supplicants.remove(owner);
            }
        }
        self.p2p_group_ifaces
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(anchor_iface);

        let raw_stop = self.wifi_raw_stop(Some(anchor_iface.to_owned()));
        let mut children = Vec::new();
        let mut children_ok = true;
        for child in [&ap_iface, &sta_iface] {
            let result = match ifindex(child) {
                Ok(ifindex) => {
                    // DEL_INTERFACE tears down AP state, but stop it first so
                    // the teardown proof distinguishes a stopped AP from an
                    // interface that merely disappeared underneath us.
                    let stop_ap = Nl80211Socket::open()
                        .and_then(|socket| socket.stop_ap(ifindex))
                        .map(|_| json!({"ok": true}))
                        .unwrap_or_else(
                            |error| json!({"ok": false, "error": format!("{error:#}")}),
                        );
                    let down = link_state_result(child, false);
                    let delete = Nl80211Socket::open()
                        .and_then(|socket| socket.delete_interface(ifindex))
                        .map(|_| json!({"ok": true, "operation": "del_interface", "iface": child}))
                        .unwrap_or_else(|error| json!({"ok": false, "operation": "del_interface", "iface": child, "error": format!("{error:#}")}));
                    json!({"iface": child, "stop_ap": stop_ap, "down": down, "delete": delete})
                }
                Err(_) => json!({"iface": child, "state": "absent", "ok": true}),
            };
            if result.pointer("/delete/ok").and_then(Value::as_bool) == Some(false) {
                children_ok = false;
            }
            children.push(result);
        }
        let anchor = ifindex(anchor_iface)
            .and_then(|ifindex| {
                let socket = Nl80211Socket::open()?;
                let stop_ap = socket.stop_ap(ifindex);
                let down = link_state_result(anchor_iface, false);
                let station = socket.set_interface_type(ifindex, NL80211_IFTYPE_STATION);
                Ok(json!({
                    "stop_ap": stop_ap.map(|_| json!({"ok": true})).unwrap_or_else(|error| json!({"ok": false, "error": format!("{error:#}")})),
                    "down": down,
                    "station": station.map(|_| json!({"ok": true})).unwrap_or_else(|error| json!({"ok": false, "error": format!("{error:#}")})),
                }))
            })
            .unwrap_or_else(|error| json!({"ok": false, "error": format!("{error:#}")}));
        let anchor_ok = anchor
            .get("station")
            .and_then(|value| value.get("ok"))
            .and_then(Value::as_bool)
            == Some(true);
        let monitor_iface = monitor_iface_name(anchor_iface);
        let verified_removed = json!({
            "ap": ifindex(&ap_iface).is_err(),
            "legacy_sta": ifindex(&sta_iface).is_err(),
            "monitor": ifindex(&monitor_iface).is_err(),
        });
        let children_removed = verified_removed
            .as_object()
            .is_some_and(|entries| entries.values().all(|value| value.as_bool() == Some(true)));
        json!({
            "ok": children_ok && children_removed && anchor_ok,
            "state": "clean",
            "anchor_iface": anchor_iface,
            "raw_stop": raw_stop,
            "wpa_owners_released": wpa_owners,
            "children": children,
            "anchor": anchor,
            "verified_removed": verified_removed,
        })
    }

    fn ensure_ap_child_vif(&self, sta_iface: &str) -> Result<(String, Value)> {
        let ap_iface = ap_child_iface_name(sta_iface)?;
        if let Ok(ifindex) = ifindex(&ap_iface) {
            return Ok((
                ap_iface.clone(),
                json!({"ok": true, "state": "existing", "iface": ap_iface, "ifindex": ifindex}),
            ));
        }
        let sta_ifindex = ifindex(sta_iface)?;
        let socket = Nl80211Socket::open()?;
        let wiphy = socket.interface_wiphy(sta_ifindex)?;
        socket.new_interface(wiphy, &ap_iface, NL80211_IFTYPE_AP)?;
        let ap_ifindex = ifindex(&ap_iface)?;
        Ok((
            ap_iface.clone(),
            json!({"ok": true, "state": "created", "iface": ap_iface, "ifindex": ap_ifindex, "wiphy": wiphy}),
        ))
    }


    /// Configure a static IPv4 address through the capability-bearing service
    /// using rtnetlink. Callers own route/DHCP policy.
    pub(crate) fn wifi_sta_configure_ipv4(
        &self,
        iface: Option<String>,
        address: String,
        prefix: Option<u8>,
    ) -> Value {
        let iface = wifi_iface(iface);
        let parsed = match address.parse::<Ipv4Addr>() {
            Ok(address) => address,
            Err(error) => {
                return json!({
                    "ok": false,
                    "backend": "ip",
                    "iface": iface,
                    "address": address,
                    "error": format!("invalid IPv4 address: {error}"),
                });
            }
        };
        let prefix = prefix.unwrap_or(24).min(32);
        let address_cidr = format!("{parsed}/{prefix}");
        let link = set_link_up(&iface);
        let configured = set_ipv4_address(&iface, parsed, prefix);
        let result = json!({
            "ok": link.is_ok() && configured.is_ok(),
            "backend": "ip",
            "iface": iface,
            "address": address_cidr,
            "steps": [
                link.map(|step| json!({"ok": true, "stdout": step.stdout}))
                    .unwrap_or_else(|error| json!({"ok": false, "error": error})),
                configured.map(|step| json!({"ok": true, "stdout": step.stdout}))
                    .unwrap_or_else(|error| json!({"ok": false, "error": error})),
            ],
        });
        self.record("wifi.sta.configure_ipv4", result.clone());
        result
    }



    /// Start a direct nl80211 listener for ESP32 DMesh vendor action frames.
    ///
    /// This listener deliberately consumes an existing monitor fixture.  The
    /// managed service prepares that fixture at startup; packet tests must not
    /// change host radio state by asking for a listener.
    pub(crate) fn wifi_raw_listen(
        &self,
        iface: Option<String>,
        channel: Option<u8>,
        listen_sec: Option<u64>,
        rx_variant: Option<String>,
    ) -> Value {
        let iface = wifi_iface(iface);
        let channel = raw_wifi_channel(channel);
        let listen_sec = listen_sec.unwrap_or(DEFAULT_RAW_WIFI_LISTEN_SECS).max(1);
        let rx_variant = rx_variant.unwrap_or_else(|| "nl80211".to_string());
        let channel_setup = json!({"backend": "linux_nl80211", "ok": true});
        let listener_key = format!("{iface}:{rx_variant}");
        {
            let mut listeners = self
                .raw_wifi_listeners
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !listeners.insert(listener_key.clone()) {
                return json!({
                    "ok": true,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "channel": channel,
                    "listen_sec": listen_sec,
                    "rx_variant": rx_variant,
                    "channel_setup": channel_setup,
                    "already_running": true,
                });
            }
        }

        let listen_result = if rx_variant == "monitor" || rx_variant == "monitor_active" {
            let monitor_iface = monitor_iface_name(&iface);
            // E2E listeners are consumers of the long-lived radio fixture.
            // They must never recreate, retune, or administratively change a
            // host interface: that belongs to the operator/service lifecycle
            // which prepared the AP and its permanent monitor.  In particular
            // do not turn a passive monitor into an active one here; fail the
            // request instead of letting an apparently successful AF_PACKET
            // write hide a missing RF fixture.
            require_existing_monitor_iface(&monitor_iface).and_then(|setup| {
                let socket = MonitorRxSocket::open(&monitor_iface)?;
                socket.set_receive_timeout(Duration::from_millis(100))?;
                let history: Arc<dyn CaptureHost> = self.capture_host.clone();
                let listeners = self.raw_wifi_listeners.clone();
                let stop_flags = self.raw_wifi_stop_flags.clone();
                let iface_for_thread = iface.clone();
                let monitor_for_thread = monitor_iface.clone();
                let listener_key_for_thread = listener_key.clone();
                let rawnan_state = self.rawnan_state.clone();
                let active_nan_publish = self.active_nan_publish.clone();
                let _pending_nan_active_subscribe = self.pending_nan_active_subscribe.clone();
                let pending_nan_followups = self.pending_nan_followups.clone();
                let p2p_group_ifaces = self.p2p_group_ifaces.clone();
                let stop_flag = Arc::new(AtomicBool::new(false));
                stop_flags
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert(listener_key.clone(), stop_flag.clone());
                // The discovery windows are served by the shared scheduler, locked to the
                // DW derived from the NAN beacons.
                {
                    let schedule = WindowSchedule {
                        iface: iface.clone(),
                        monitor_iface: monitor_iface.clone(),
                        nan: self.rawnan_state.clone(),
                        publish: self.active_nan_publish.clone(),
                        subscribe: self.pending_nan_active_subscribe.clone(),
                        now_discovery: Arc::new(Mutex::new(None)),
                        now_publish: Arc::new(Mutex::new(None)),
                        followups: self.pending_nan_followups.clone(),
                    };
                    let (host, stop) = (history.clone(), stop_flag.clone());
                    std::thread::spawn(move || run_window_scheduler(schedule, host, stop));
                }
                std::thread::spawn(move || {
                    monitor_receive_loop(
                        socket,
                        &iface_for_thread,
                        &monitor_for_thread,
                        history,
                        rawnan_state,
                        active_nan_publish,
                        pending_nan_followups,
                        p2p_group_ifaces,
                        stop_flag,
                    );
                    listeners
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .remove(&listener_key_for_thread);
                    stop_flags
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .remove(&listener_key_for_thread);
                });
                Ok(json!({
                    "ok": true,
                    "backend": "linux_af_packet_monitor",
                    "iface": iface,
                    "monitor_iface": monitor_iface,
                    "channel": channel,
                    "listen_sec": listen_sec,
                    "rx_variant": rx_variant,
                    "monitor": setup,
                    "channel_setup": channel_setup,
                    "note": "monitor listener records DMesh action and multicast data frames visible on this interface",
                }))
            })
        } else if rx_variant == "nl80211" {
            Nl80211Socket::open()
                .and_then(|socket| {
                    socket.register_dmesh_action(ifindex(&iface)?)?;
                    Ok(socket)
                })
                .map(|socket| {
                    let history: Arc<dyn CaptureHost> = self.capture_host.clone();
                    let listeners = self.raw_wifi_listeners.clone();
                    let iface_for_thread = iface.clone();
                    let listener_key_for_thread = listener_key.clone();
                    std::thread::spawn(move || {
                        nl80211_receive_loop(socket, &iface_for_thread, history);
                        listeners
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .remove(&listener_key_for_thread);
                    });
                    json!({
                        "ok": true,
                        "backend": "linux_nl80211",
                        "iface": iface,
                        "channel": channel,
                        "listen_sec": listen_sec,
                        "rx_variant": rx_variant,
                        "channel_setup": channel_setup,
                        "note": "listener records ESP32 DMesh vendor action frames visible on this interface",
                    })
                })
        } else {
            Err(anyhow::anyhow!(
                "unknown rx_variant {rx_variant:?}; expected nl80211, monitor, or monitor_active"
            ))
        };

        match listen_result {
            Ok(result) => {
                self.record_message(
                    "wifi.raw.listen",
                    "host-wifi",
                    MeshMessage::new(mesh::message::KIND_EVENT, MeshMessageCodec::Text)
                        .field(FIELD_MEDIUM, "wifi")
                        .field(FIELD_IFACE, &iface)
                        .field(FIELD_STATUS, "listening"),
                );
                self.record("wifi.raw.listen", result.clone());
                result
            }
            Err(error) => {
                self.raw_wifi_listeners
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(&listener_key);
                json!({
                    "ok": false,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "error": format!("{error:#}"),
                })
            }
        }
    }

    /// Register the managed interface for beacon delivery without changing
    /// its mode or monitor VIF. Some adapters suppress beacons on an active
    /// monitor used for NOW TX, while nl80211 can still deliver registered
    /// management frames on the managed/AP interface.
    pub(crate) fn wifi_nan_beacon_listen(&self, iface: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let listener_key = format!("{iface}:nl80211_nan_beacon");
        if !self
            .raw_wifi_listeners
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(listener_key.clone())
        {
            return json!({"ok": true, "iface": iface, "backend": "linux_nl80211", "already_running": true});
        }
        let socket = Nl80211Socket::open().and_then(|socket| {
            socket.register_nan_discovery_frames(ifindex(&iface)?)?;
            Ok(socket)
        });
        match socket {
            Ok(socket) => {
                let history: Arc<dyn CaptureHost> = self.capture_host.clone();
                let rawnan_state = self.rawnan_state.clone();
                let pending_nan_followups = self.pending_nan_followups.clone();
                let listeners = self.raw_wifi_listeners.clone();
                let iface_for_thread = iface.clone();
                std::thread::spawn(move || {
                    nl80211_nan_beacon_receive_loop(
                        socket,
                        &iface_for_thread,
                        history,
                        rawnan_state,
                        pending_nan_followups,
                        Arc::new(AtomicBool::new(false)),
                    );
                    listeners
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .remove(&listener_key);
                });
                json!({"ok": true, "iface": iface, "backend": "linux_nl80211", "frame_types": ["0x0080", "0x00d0/public", "0x00d0/vendor"]})
            }
            Err(error) => {
                self.raw_wifi_listeners
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(&listener_key);
                json!({"ok": false, "iface": iface, "backend": "linux_nl80211", "error": format!("{error:#}")})
            }
        }
    }

    /// Establish the long-lived active monitor fixture used by the AP-off
    /// `lmesh` radio.  This is service-startup policy, not a packet-test
    /// operation: it may recreate the service-owned monitor and pin it to the
    /// requested channel before listeners attach.
    pub(crate) fn prepare_raw_monitor_fixture(&self, iface: Option<String>, channel: Option<u8>) -> Value {
        let iface = wifi_iface(iface);
        let channel = raw_wifi_channel(channel);
        let monitor_iface = monitor_iface_name(&iface);
        // Pin the AP-off base interface through nl80211 first.  This uses the
        // same real driver path we want to validate for non-AP operation;
        // monitor setup below only supplies capture/ingress on that channel.
        let channel_setup = self.wifi_interface_set_channel(Some(iface.clone()), channel);
        if !channel_setup
            .get("ok")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return json!({
                "ok": false,
                "backend": "linux_nl80211",
                "iface": iface,
                "monitor_iface": monitor_iface,
                "channel": channel,
                "lifecycle": "service_startup",
                "channel_setup": channel_setup,
                "error": "could not pin AP-off interface to channel",
            });
        }
        // A passive monitor can accept AF_PACKET writes locally without
        // scheduling them on RF. The AP-off NAN+NOW startup personality needs
        // one active monitor VIF instead; nl80211 is the separate beacon RX
        // lane on adapters that cannot create a second monitor child.
        match ensure_monitor_iface(&iface, &monitor_iface, channel, true, true, true) {
            Ok(setup) => json!({
                "ok": true,
                "backend": "linux_af_packet_monitor",
                "iface": iface,
                "monitor_iface": monitor_iface,
                "channel": channel,
                "lifecycle": "service_startup",
                "channel_setup": channel_setup,
                "setup": setup,
            }),
            Err(error) => json!({
                "ok": false,
                "backend": "linux_af_packet_monitor",
                "iface": iface,
                "monitor_iface": monitor_iface,
                "channel": channel,
                "lifecycle": "service_startup",
                "channel_setup": channel_setup,
                "error": format!("{error:#}"),
            }),
        }
    }

    /// Create the same long-lived NAN+NOW monitor alongside an AP. Unlike the
    /// AP-off fixture this retains the managed parent: the AP owns the
    /// channel and the active monitor follows it for on-channel NOW TX.
    pub(crate) fn prepare_ap_raw_monitor_fixture(
        &self,
        iface: Option<String>,
        channel: Option<u8>,
    ) -> Value {
        let iface = wifi_iface(iface);
        let channel = raw_wifi_channel(channel);
        let monitor_iface = monitor_iface_name(&iface);
        match ensure_monitor_iface(&iface, &monitor_iface, channel, true, true, false) {
            Ok(setup) => json!({
                "ok": true,
                "backend": "linux_af_packet_monitor",
                "iface": iface,
                "monitor_iface": monitor_iface,
                "channel": channel,
                "lifecycle": "service_startup_ap",
                "setup": setup,
            }),
            Err(error) => json!({
                "ok": false,
                "backend": "linux_af_packet_monitor",
                "iface": iface,
                "monitor_iface": monitor_iface,
                "channel": channel,
                "lifecycle": "service_startup_ap",
                "error": format!("{error:#}"),
            }),
        }
    }



    /// Send an ESP32-compatible DMesh vendor action frame.
    pub(crate) fn wifi_raw_send(
        &self,
        iface: Option<String>,
        channel: Option<u8>,
        listen_sec: Option<u64>,
        destination: Option<String>,
        source: Option<String>,
        tx_variant: Option<String>,
        tx_duration_ms: Option<u32>,
        bssid: Option<String>,
        llc: Option<String>,
        payload: String,
        tx_rate_mbps: Option<u8>,
    ) -> Value {
        let iface = wifi_iface(iface);
        let channel = raw_wifi_channel(channel);
        let listen_sec = listen_sec.unwrap_or(DEFAULT_RAW_WIFI_LISTEN_SECS).max(1);
        let tx_options =
            match RawWifiTxOptions::from_variant(tx_variant.as_deref(), listen_sec, tx_duration_ms)
            {
                Ok(options) => options,
                Err(error) => {
                    return json!({
                        "ok": false,
                        "backend": "linux_nl80211",
                        "iface": iface,
                        "error": error.to_string(),
                    });
                }
            };
        let channel_setup = json!({"backend": "linux_nl80211", "ok": true});
        let destination_input = destination.as_deref();
        let destination = raw_wifi_destination(destination_input, &tx_options.variant);
        let destination_mode = raw_wifi_destination_mode(destination_input, &tx_options.variant);
        let source_input = source.as_deref();
        let (source, source_mode) = match self.raw_action_source(source_input, &iface) {
            Ok(source) => source,
            Err(error) => {
                return json!({
                    "ok": false,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "error": format!("{error:#}"),
                });
            }
        };
        let payload_bytes = payload
            .strip_prefix("hex:")
            .and_then(|hex| decode_firmware_hex(hex).ok())
            .unwrap_or_else(|| payload.as_bytes().to_vec());
        let nan_bssid = bssid
            .as_deref()
            .and_then(|value| parse_mac(Some(value)))
            .or_else(|| {
                self.rawnan_state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .cluster()
                    .map(|mac| mac.0)
            })
            .or(Some(destination))
            .unwrap_or(destination);
        let llc = parse_experimental_llc(llc.as_deref()).unwrap_or(RAWNAN_LLC_DEFAULT);
        let frame = if tx_options.variant == "multicast_data"
            || tx_options.variant == "multicast_data_active"
        {
            build_dmesh_multicast_data_frame(destination, source, &payload_bytes)
        } else if tx_options.variant == "sta_multicast_llc"
            || tx_options.variant == "sta_multicast_llc_active"
        {
            build_dmesh_sta_multicast_llc_frame(destination, source, &payload_bytes)
        } else if tx_options.variant == "sta_direct_llc"
            || tx_options.variant == "sta_direct_llc_active"
        {
            build_dmesh_sta_direct_llc_frame(destination, source, &payload_bytes)
        } else if tx_options.variant == "nan_data" || tx_options.variant == "nan_data_active" {
            build_dmesh_nan_data_frame(nan_bssid, destination, source, &payload_bytes)
        } else if tx_options.variant == "nan_data_raw"
            || tx_options.variant == "nan_data_raw_active"
            || tx_options.variant == "nan_data_multicast"
            || tx_options.variant == "nan_data_multicast_active"
        {
            let data_destination = if tx_options.variant == "nan_data_multicast"
                || tx_options.variant == "nan_data_multicast_active"
            {
                RAW_WIFI_MULTICAST
            } else {
                destination
            };
            build_dmesh_nan_raw_data_frame(
                nan_bssid,
                data_destination,
                source,
                &llc,
                &payload_bytes,
            )
        } else {
            // Raw NAN action traffic must carry the discovered cluster BSSID
            // in address3. Using the peer MAC here works only before the
            // device arms its hardware cluster filter, and silently drops
            // host-originated transport packets afterwards.
            match build_dmesh_vendor_action_frame_with_bssid(
                destination,
                source,
                nan_bssid,
                &payload_bytes,
            ) {
                Ok(frame) => frame,
                Err(error) => {
                    return json!({"ok": false, "error": format!("raw ESP-NOW frame: {error}")});
                }
            }
        };
        if is_nan_control_frame(&frame)
            && tx_rate_mbps.is_some_and(|rate| !matches!(rate, 6 | 9 | 12 | 18 | 24 | 36 | 48 | 54))
        {
            return json!({
                "ok": false,
                "backend": "linux_nl80211",
                "iface": iface,
                "error": "NAN beacon/action rate must be a mandatory OFDM rate: 6, 9, 12, 18, 24, 36, 48, or 54 Mbps",
            });
        }
        // NAN discovery/synchronization beacons and NAN public action frames
        // have a distinct interoperability rate policy.  The Wi-Fi Aware
        // specification fixes beacons at 6 Mbps and permits SDF/NAF action
        // frames only at mandatory OFDM rates.  Do not let the monitor
        // injector's historical 1 Mbps default leak onto those frames.
        let effective_tx_rate_mbps = tx_rate_mbps.or_else(|| {
            if is_nan_control_frame(&frame) {
                Some(6)
            } else {
                None
            }
        });
        let result = if tx_options.variant == "monitor"
            || tx_options.variant == "monitor_active"
            || tx_options.variant == "multicast_data"
            || tx_options.variant == "multicast_data_active"
            || tx_options.variant == "sta_multicast_llc"
            || tx_options.variant == "sta_multicast_llc_active"
            || tx_options.variant == "sta_direct_llc"
            || tx_options.variant == "sta_direct_llc_active"
            || tx_options.variant == "nan_data"
            || tx_options.variant == "nan_data_active"
            || tx_options.variant == "nan_data_raw"
            || tx_options.variant == "nan_data_raw_active"
            || tx_options.variant == "nan_data_multicast"
            || tx_options.variant == "nan_data_multicast_active"
        {
            match send_monitor_frame(&iface, channel, &frame, effective_tx_rate_mbps) {
                Ok(monitor) => json!({
                    "ok": true,
                    "backend": "linux_af_packet_monitor",
                    "tx_variant": tx_options.variant,
                    "tx_options": tx_options.as_json(),
                    "tx_rate_mbps": effective_tx_rate_mbps,
                    "monitor": monitor,
                    "iface": iface,
                    "channel": channel,
                    "listen_sec": listen_sec,
                    "tx_duration_ms": tx_duration_ms,
                    "channel_setup": channel_setup,
                    "destination": colon_mac(&destination),
                    "destination_mode": destination_mode,
                    "bssid": colon_mac(&nan_bssid),
                    "llc": hex_bytes(&llc),
                    "source": colon_mac(&source),
                    "source_mode": source_mode,
                    "payload_len": payload_bytes.len(),
                    "frame_len": frame.len(),
                }),
                Err(error) => json!({
                    "ok": false,
                    "backend": "linux_af_packet_monitor",
                    "tx_variant": tx_options.variant,
                    "tx_options": tx_options.as_json(),
                    "tx_rate_mbps": effective_tx_rate_mbps,
                    "iface": iface,
                    "error": format!("{error:#}"),
                }),
            }
        } else {
            // Monitor experiments intentionally take the parent down in some
            // drivers. NL80211_CMD_FRAME targets the managed/base interface,
            // so restore only this service-owned interface first.
            let interface_up = link_state_result(&iface, true);
            if !interface_up
                .get("ok")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                return json!({
                    "ok": false,
                    "backend": "linux_nl80211",
                    "tx_variant": tx_options.variant,
                    "iface": iface,
                    "interface_up": interface_up,
                    "error": "failed to bring interface up",
                });
            }
            match Nl80211Socket::open().and_then(|socket| {
                if tx_options.variant == "roc" {
                    socket.remain_on_channel(
                        ifindex(&iface)?,
                        channel_to_freq(channel),
                        tx_options.duration_ms.unwrap_or(10),
                    )?;
                }
                if tx_options.variant == "action" || tx_options.variant == "send_action" {
                    socket.send_mgmt_frame(ifindex(&iface)?, &frame, effective_tx_rate_mbps)
                } else {
                    socket.send_frame(
                        ifindex(&iface)?,
                        channel_to_freq(channel),
                        &tx_options,
                        &frame,
                        effective_tx_rate_mbps,
                    )
                }
            }) {
                Ok(()) => json!({
                    "ok": true,
                    "backend": "linux_nl80211",
                    "tx_variant": tx_options.variant,
                    "tx_options": tx_options.as_json(),
                    "tx_rate_mbps": effective_tx_rate_mbps,
                    "iface": iface,
                    "channel": channel,
                    "listen_sec": listen_sec,
                    "tx_duration_ms": tx_duration_ms,
                    "channel_setup": channel_setup,
                    "interface_up": interface_up,
                    "destination": colon_mac(&destination),
                    "destination_mode": destination_mode,
                    "bssid": colon_mac(&nan_bssid),
                    "source": colon_mac(&source),
                    "source_mode": source_mode,
                    "payload_len": payload_bytes.len(),
                    "frame_len": frame.len(),
                }),
                Err(error) => json!({
                    "ok": false,
                    "backend": "linux_nl80211",
                    "tx_variant": tx_options.variant,
                    "tx_options": tx_options.as_json(),
                    "iface": iface,
                    "interface_up": interface_up,
                    "error": format!("{error:#}"),
                }),
            }
        };
        self.record_message(
            "wifi.raw.tx",
            "host-wifi",
            MeshMessage::new(mesh::message::KIND_EVENT, MeshMessageCodec::Text)
                .field(FIELD_MEDIUM, "wifi")
                .field(FIELD_IFACE, &iface)
                .field(mesh::message::FIELD_PEER, colon_mac(&destination))
                .field(FIELD_LEN, payload_bytes.len())
                .field(FIELD_PAYLOAD, payload),
        );
        self.record("wifi.raw.tx", result.clone());
        result
    }

    /// Inject a caller-supplied 802.11 management or data frame. The input is
    /// the frame beginning at the 802.11 header (no radiotap); lmesh adds the
    /// radiotap wrapper required by the monitor VIF. This deliberately uses
    /// The `monitor` bearer expects an 802.11 frame without radiotap. The
    /// `af_packet` bearer expects a complete Ethernet frame and writes it
    /// directly to the named netdev (useful for AP/STA data-path tests).
    pub(crate) fn wifi_raw_send_frame(
        &self,
        iface: Option<String>,
        channel: Option<u8>,
        tx_variant: Option<String>,
        frame_hex: String,
        tx_rate_mbps: Option<u8>,
    ) -> Value {
        let iface = wifi_iface(iface);
        let channel = raw_wifi_channel(channel);
        let variant = tx_variant.unwrap_or_else(|| "monitor".to_string());
        if variant != "monitor"
            && variant != "monitor_active"
            && variant != "af_packet"
            && variant != "action"
        {
            return json!({
                "ok": false,
                "backend": "linux_af_packet_monitor",
                "iface": iface,
                "tx_variant": variant,
                "error": "arbitrary frame injection requires tx_variant=monitor, monitor_active, action, or af_packet",
            });
        }
        let frame = match decode_firmware_hex(frame_hex.trim_start_matches("hex:")) {
            Ok(frame) if variant == "af_packet" && frame.len() >= 14 => frame,
            Ok(frame) if variant != "af_packet" && frame.len() >= 10 => frame,
            Ok(_) => {
                return json!({"ok": false, "iface": iface, "error": "frame_hex is shorter than an 802.11 header"});
            }
            Err(error) => {
                return json!({"ok": false, "iface": iface, "error": format!("invalid frame_hex: {error:#}")});
            }
        };
        let result = if variant == "af_packet" {
            match DataSocket::open(&iface).and_then(|socket| socket.send(&frame)) {
                Ok(written) => json!({
                    "ok": true,
                    "backend": "linux_af_packet_data",
                    "iface": iface,
                    "channel": channel,
                    "tx_variant": variant,
                    "frame_len": frame.len(),
                    "written": written,
                    "note": "frame_hex is a complete Ethernet frame; no radiotap was added",
                }),
                Err(error) => json!({
                    "ok": false,
                    "backend": "linux_af_packet_data",
                    "iface": iface,
                    "channel": channel,
                    "tx_variant": variant,
                    "frame_len": frame.len(),
                    "error": format!("{error:#}"),
                }),
            }
        } else if variant == "action" {
            // An action injection is a packet operation, never radio setup.
            // The supervised interface must already be up; tests are
            // deliberately not allowed to change that state as a side effect
            // of sending.
            // This is raw ESP-NOW-compatible vendor action, not an AP-SME
            // response.  Keep its CMD_FRAME request minimal: AP-SME's
            // frequency/duration form is rejected with EINVAL by ath9k_htc
            // for an otherwise valid vendor action.
            let options = RawWifiTxOptions::from_variant(Some("action"), 1, None)
                .expect("static raw action TX options are valid");
            let result = Nl80211Socket::open().and_then(|socket| {
                socket.send_frame(
                    ifindex(&iface)?,
                    channel_to_freq(channel),
                    &options,
                    &frame,
                    tx_rate_mbps,
                )
            });
            match result {
                Ok(()) => json!({
                    "ok": true,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "channel": channel,
                    "tx_variant": variant,
                    "tx_rate_mbps": tx_rate_mbps,
                    "frame_len": frame.len(),
                    "lifecycle": "externally_prepared",
                }),
                Err(error) => json!({
                    "ok": false,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "channel": channel,
                    "tx_variant": variant,
                    "frame_len": frame.len(),
                    "lifecycle": "externally_prepared",
                    "error": format!("{error:#}"),
                }),
            }
        } else {
            match send_monitor_frame(&iface, channel, &frame, tx_rate_mbps) {
                Ok(monitor) => json!({
                "ok": true,
                "backend": "linux_af_packet_monitor",
                "iface": iface,
                "channel": channel,
                "tx_variant": variant,
                "tx_rate_mbps": tx_rate_mbps,
                "frame_len": frame.len(),
                "monitor": monitor,
                "note": "frame_hex is an 802.11 header/body; radiotap was added by lmesh",
                }),
                Err(error) => json!({
                "ok": false,
                "backend": "linux_af_packet_monitor",
                "iface": iface,
                "channel": channel,
                "tx_variant": variant,
                "frame_len": frame.len(),
                "error": format!("{error:#}"),
                }),
            }
        };
        self.record("wifi.raw.tx.frame", result.clone());
        result
    }


    fn record(&self, key: &str, value: Value) {
        self.push_event(RadioEvent {
            ts_millis: now_millis(),
            key: key.to_string(),
            source: "local".to_string(),
            value,
            message: None,
        });
    }

    fn record_message(&self, key: &str, source: &str, message: MeshMessage) {
        self.push_event(RadioEvent {
            ts_millis: message.timestamp_ms as u128,
            key: key.to_string(),
            source: source.to_string(),
            value: json!({ "message": message }),
            message: Some(message),
        });
    }

    fn push_event(&self, event: RadioEvent) {
        let mut history = self
            .history
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        history.push_back(event);
        while history.len() > MAX_HISTORY {
            history.pop_front();
        }
    }
}


#[derive(Clone, Debug, Serialize, Deserialize)]
struct RadioEvent {
    ts_millis: u128,
    key: String,
    source: String,
    value: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<MeshMessage>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RadioAdapter {
    id: String,
    kind: String,
    medium: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    baud: Option<u32>,
    enabled: bool,
}



fn normalize_radio(radio: Option<String>) -> String {
    let radio = radio
        .unwrap_or_else(|| "all".to_string())
        .to_ascii_lowercase();
    match radio.as_str() {
        "wifi" | "aware" => "nan".to_string(),
        "raw" | "wifi_raw" | "raw_wifi" => "wifiraw".to_string(),
        "ap" | "assoc" | "associated" | "wifi_assoc" => "sta".to_string(),
        "auto" => "best".to_string(),
        "all" | "best" | "nan" | "wifiraw" | "lora" | "ble" | "serial" | "sta" => radio,
        _ => radio,
    }
}

fn medium_to_radio(medium: &str) -> String {
    match medium {
        "wifi" => "nan".to_string(),
        other => other.to_string(),
    }
}






/// Decode the `hex:` payload accepted by raw Wi-Fi diagnostics.  This is a
/// raw-radio utility, independent of the retired UART forwarding layer.
fn decode_firmware_hex(value: &str) -> Result<Vec<u8>> {
    let value = value.trim();
    if value.len() % 2 != 0 {
        bail!("hex payload has odd length");
    }
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).map_err(Into::into))
        .collect()
}

#[derive(Debug, Deserialize)]
struct LmeshToml {
    #[serde(default)]
    radios: Vec<RadioConfig>,
}

#[derive(Debug, Deserialize)]
struct RadioConfig {
    id: Option<String>,
    kind: String,
    medium: Option<String>,
    path: Option<String>,
    network: Option<String>,
    baud: Option<u32>,
    enabled: Option<bool>,
}

fn load_radio_adapters() -> Vec<RadioAdapter> {
    let mut radios = vec![
        RadioAdapter {
            id: "host-mcast".to_string(),
            kind: "host-mcast".to_string(),
            medium: "mcast".to_string(),
            path: None,
            network: None,
            baud: None,
            enabled: true,
        },
        RadioAdapter {
            id: "host-ble".to_string(),
            kind: "host-ble".to_string(),
            medium: "ble".to_string(),
            path: Some(format!("hci{DEFAULT_HCI_DEV}")),
            network: None,
            baud: None,
            enabled: true,
        },
        RadioAdapter {
            id: "host-nan".to_string(),
            kind: "host-nan".to_string(),
            medium: "nan".to_string(),
            path: Some(format!("rawnan:{}", wifi_iface(None))),
            network: None,
            baud: None,
            enabled: true,
        },
    ];

    if let Some(config) = read_lmesh_config() {
        for radio in config.radios {
            // A dmesh-cli process owns an explicitly selected physical UART
            // for the duration of a device session. lmesh/lmesh-wifi must
            // neither advertise nor select that device as a radio adapter:
            // doing so makes stale lmesh.toml state look like an alternate
            // control transport and invites a second reader.
            if radio.kind == "esp-serial" {
                continue;
            }
            let id = radio.id.unwrap_or_else(|| {
                radio
                    .path
                    .as_deref()
                    .map(sanitize_radio_id)
                    .unwrap_or_else(|| radio.kind.clone())
            });
            radios.push(RadioAdapter {
                id,
                medium: radio
                    .medium
                    .unwrap_or_else(|| default_medium_for_kind(&radio.kind).to_string()),
                kind: radio.kind,
                path: radio.path,
                network: radio.network,
                baud: radio.baud,
                enabled: radio.enabled.unwrap_or(true),
            });
        }
    }

    radios
}

fn read_lmesh_config() -> Option<LmeshToml> {
    let path = lmesh_config_path();
    if !path.exists() {
        return None;
    }
    let data = std::fs::read_to_string(path).ok()?;
    toml::from_str(&data).ok()
}

fn lmesh_config_path() -> PathBuf {
    std::env::var_os("LMESH_CONFIG_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_LMESH_CONFIG_FILE))
}

fn default_medium_for_kind(kind: &str) -> &'static str {
    match kind {
        "host-mcast" => "mcast",
        "host-ble" | "android-ble" => "ble",
        "host-nan" | "android-nan" => "nan",
        "remote-uds" => "remote",
        _ => "unknown",
    }
}

fn sanitize_radio_id(path: &str) -> String {
    path.chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}


/// The station keeps the configured service interface.  A concurrent AP is
/// an explicitly service-owned sibling VIF, never a second configurable name.
fn ap_child_iface_name(sta_iface: &str) -> Result<String> {
    let suffix = "ap";
    if sta_iface.len() + suffix.len() > libc::IFNAMSIZ - 1 {
        bail!("cannot derive AP child name from {sta_iface:?}: Linux IFNAMSIZ limit");
    }
    Ok(format!("{sta_iface}{suffix}"))
}

fn sta_child_iface_name(anchor_iface: &str) -> Result<String> {
    let suffix = "sta";
    if anchor_iface.len() + suffix.len() > libc::IFNAMSIZ - 1 {
        bail!("cannot derive STA child name from {anchor_iface:?}: Linux IFNAMSIZ limit");
    }
    Ok(format!("{anchor_iface}{suffix}"))
}

fn wpa_owner_iface_names(anchor_iface: &str, legacy_sta_iface: &str) -> Vec<String> {
    let mut owners = vec![anchor_iface.to_owned()];
    if legacy_sta_iface != anchor_iface {
        owners.push(legacy_sta_iface.to_owned());
    }
    owners
}





struct ApRuntime {
    _owner_socket: Nl80211Socket,
    ssid: String,
    channel: u8,
    ht40: bool,
    beacon_interval_tu: u16,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}





































































































































fn mesh_message_from_raw_wifi(value: &Value, iface: &str) -> MeshMessage {
    let mut message = MeshMessage::new(mesh::message::KIND_EVENT, MeshMessageCodec::Text)
        .field(FIELD_MEDIUM, "wifi")
        .field(FIELD_IFACE, iface);
    for (field, key) in [
        (FIELD_NODE, "source"),
        (mesh::message::FIELD_PEER, "destination"),
        (FIELD_LEN, "payload_len"),
        (FIELD_PAYLOAD, "payload_text"),
    ] {
        if let Some(value) = value.get(key) {
            message = message.field(field, json_scalar_string(value));
        }
    }
    message
}

/// Fold packet-rate monitor/NAN observations into counters. Returning true
/// means the event must not enter history or tracing; semantic parsing and
/// discovery events take the normal bounded path below.
fn count_high_rate_radio_observation(event: &RadioEvent) -> bool {
    let mut counters = host_capture_counters()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match event.key.as_str() {
        "wifi.raw.socket" => {
            let bytes = event
                .value
                .get("packet_len")
                .and_then(Value::as_u64)
                .unwrap_or_default();
            counters.socket_packets = counters.socket_packets.saturating_add(1);
            counters.socket_bytes = counters.socket_bytes.saturating_add(bytes);
            counters.socket_max_packet_bytes = counters
                .socket_max_packet_bytes
                .max(bytes.min(u64::from(u32::MAX)) as u32);
            true
        }
        "wifi.raw.monitor" => {
            let frame_type = event
                .value
                .get("frame_type")
                .and_then(Value::as_u64)
                .unwrap_or_default() as u8;
            let frame_subtype = event
                .value
                .get("frame_subtype")
                .and_then(Value::as_u64)
                .unwrap_or_default() as u8;
            let bytes = event
                .value
                .get("frame_len")
                .and_then(Value::as_u64)
                .unwrap_or_default() as usize;
            counters
                .capture
                .observe_80211(frame_type, frame_subtype, bytes);
            true
        }
        "wifi.raw.action_candidate" => {
            counters.action_candidates = counters.action_candidates.saturating_add(1);
            true
        }
        "wifi.rawnan.rx" => {
            counters.capture.observe_nan_rx();
            true
        }
        "wifi.rawnan.beacon" => {
            counters.capture.observe_nan_beacon();
            true
        }
        _ => false,
    }
}

fn host_capture_metrics_json() -> Value {
    let counters = host_capture_counters()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let capture = &counters.capture;
    json!({
        "capture": {
            "packets": capture.packets,
            "bytes": capture.bytes,
            "max_packet_bytes": capture.max_packet_bytes,
            "management_frames": capture.management_frames,
            "control_frames": capture.control_frames,
            "data_frames": capture.data_frames,
            "management_subtypes": capture.management_subtypes,
            "nan_rx": capture.nan_rx,
            "nan_beacons": capture.nan_beacons,
        },
        "socket": {
            "packets": counters.socket_packets,
            "bytes": counters.socket_bytes,
            "max_packet_bytes": counters.socket_max_packet_bytes,
            "average_packet_bytes": (counters.socket_packets != 0)
                .then(|| counters.socket_bytes / counters.socket_packets),
        },
        "management_action_candidates": counters.action_candidates,
    })
}

/// Decide whether a semantic discovery observation deserves a retained event.
/// The inventory is updated before this gate, so suppressing a periodic
/// refresh cannot hide a currently reachable peer from status or routing.
fn retain_discovery_event(event: &RadioEvent) -> bool {
    // A directed NAN follow-up is an application receipt, not a periodic
    // presence refresh. Retain it even when it immediately follows a discovery
    // record for the same peer so `telemetry.nan_status` cannot lose the completion.
    if event
        .value
        .get("followup")
        .is_some_and(|followup| !followup.is_null())
    {
        return true;
    }
    let peer = event
        .value
        .get("peer")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let announce = event.value.get("announce");
    let identity = announce
        .and_then(|announce| announce.get("device_id"))
        .and_then(Value::as_str)
        .unwrap_or(peer);
    // Exclude periodic uptime/counter refreshes and raw frame bytes from the
    // comparison. Address, name, transport, and network changes remain
    // meaningful operator evidence.
    let fingerprint = json!({
        "peer": peer,
        "bssid": event.value.get("bssid"),
        "device_id": announce.and_then(|value| value.get("device_id")),
        "device_name": announce.and_then(|value| value.get("device_name")),
        "transport_mode": announce.and_then(|value| value.get("transport_mode")),
        "network_name": announce.and_then(|value| value.get("network_name")),
        "wifi_channel": announce.and_then(|value| value.get("wifi_channel")),
        "sta_link_local_v6": announce.and_then(|value| value.get("sta_link_local_v6")),
        "ap_link_local_v6": announce.and_then(|value| value.get("ap_link_local_v6")),
        "active_subscribe": event.value.get("active_subscribe").is_some(),
        "followup_type": event.value.get("followup").and_then(|value| value.get("msg_type")),
    })
    .to_string();
    let now = event.ts_millis;
    let mut gate = discovery_event_gate()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match gate.get(identity) {
        None => {
            if gate.len() >= MAX_DISCOVERED_DEVICES {
                if let Some(oldest) = gate
                    .iter()
                    .min_by_key(|(_, (seen, _))| *seen)
                    .map(|(key, _)| key.clone())
                {
                    gate.remove(&oldest);
                }
            }
            gate.insert(identity.to_string(), (now, fingerprint));
            true
        }
        Some((last_seen, previous))
            if previous != &fingerprint
                && now.saturating_sub(*last_seen) >= DISCOVERY_EVENT_MIN_INTERVAL_MS =>
        {
            gate.insert(identity.to_string(), (now, fingerprint));
            true
        }
        _ => false,
    }
}

fn push_radio_event(history: &Arc<Mutex<VecDeque<RadioEvent>>>, event: RadioEvent) {
    if count_high_rate_radio_observation(&event) {
        return;
    }
    if event.key == "wifi.rawnan.discovery" && !retain_discovery_event(&event) {
        return;
    }
    // Every event that reaches this point is one the history retains (packet
    // rate observations returned above), so it is also the node's `log.watch`
    // record: `event_type` becomes the record's `kind` and `data` carries the
    // event's value. `trace_prechecked` marks it as retained regardless of the
    // per-type watch selection, which still governs other producers.
    let event_type = event.key.clone();
    let source = &event.source;
    let data = event.value.to_string();
    tracing::info!(
        target: "dmesh.event",
        event_type = %event_type,
        trace_prechecked = true,
        source = %source,
        data = %data,
        message = "event"
    );
    let mut history = history
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    history.push_back(event);
    while history.len() > MAX_HISTORY {
        history.pop_front();
    }
}













































fn wifi_iface(value: Option<String>) -> String {
    value
        .or_else(|| std::env::var("LMESH_WIFI_IFACE").ok())
        .unwrap_or_else(|| DEFAULT_WIFI_IFACE.to_string())
}

fn wpa_runtime_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("LMESH_WPA_RUNTIME_DIR") {
        return PathBuf::from(path);
    }
    if let Some(socket) = std::env::var_os("LMESH_CONTROL_SOCKET") {
        if let Some(parent) = PathBuf::from(socket).parent() {
            return parent.join("wpa");
        }
    }
    PathBuf::from("/run/mesh/lmesh/wpa")
}

fn raw_wifi_channel(value: Option<u8>) -> u8 {
    value.unwrap_or(DEFAULT_RAW_WIFI_CHANNEL).clamp(1, 13)
}


fn local_device_id() -> Result<[u8; 6]> {
    if let Some(value) = std::env::var("LMESH_DEVICE_ID").ok() {
        if let Some(id) = parse_device_id(Some(&value)) {
            return Ok(id);
        }
        bail!("LMESH_DEVICE_ID must be 12 hex chars or colon-separated 6-byte hex");
    }
    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "lmesh".to_string());
    let digest = crate::public_key_sha(&hostname);
    parse_device_id(Some(&digest[..12])).context("failed to derive local DMesh device id")
}

fn parse_device_id(value: Option<&str>) -> Option<[u8; 6]> {
    let value = value?;
    let compact = value.replace(':', "");
    if compact.len() != 12 {
        return None;
    }
    let mut out = [0_u8; 6];
    for (idx, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&compact[idx * 2..idx * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Decode the stable peer address used by the directed NOW API.  `rx:` and
/// `raw:` are accepted for diagnostics, but are framing details rather than a
/// second peer identity: the reply source and association key remain the
/// ordinary MAC supplied after the prefix.
fn parse_now_peer_address(value: &str) -> Option<[u8; 6]> {
    let stable = value
        .strip_prefix("rx:")
        .or_else(|| value.strip_prefix("raw:"))
        .unwrap_or(value);
    parse_device_id(Some(stable))
}

/// Return the action-frame address-1 for a public NOW peer address.
///
/// ESP raw action ingress listens on the derived receive address. Existing
/// explicit `rx:`/`raw:` inputs retain their spelling so a packet-level test
/// can request exactly one conversion, while ordinary callers simply pass a
/// stable catalog/discovery MAC.
fn now_wire_destination(destination: &str) -> String {
    if destination.starts_with("rx:") || destination.starts_with("raw:") {
        destination.to_owned()
    } else {
        format!("rx:{destination}")
    }
}


/// Android's pre-identity NAN callback historically emitted this ASCII
/// placeholder. It is not a stable device identity and must not hide a later
/// announce carrying the framework-provided NAN MAC.
fn is_placeholder_announce_id(device_id: &[u8]) -> bool {
    device_id == b"000000" || device_id.iter().all(|byte| *byte == 0)
}






#[cfg(test)]
mod tests {
    use super::*;
    use dmesh_server::raw_wifi::WIFI_LINK_METRICS_SCHEMA_VERSION;
    use p256::SecretKey;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;

    #[test]
    fn raw_action_submit_classifies_only_nonblocking_socket_pressure_as_retryable() {
        let would_block = anyhow::Error::new(std::io::Error::from(
            std::io::ErrorKind::WouldBlock,
        ))
        .context("failed to send monitor frame");
        let disconnected = anyhow::Error::new(std::io::Error::from(
            std::io::ErrorKind::NotConnected,
        ))
        .context("failed to send monitor frame");
        assert!(raw_action_error_is_would_block(&would_block));
        assert!(!raw_action_error_is_would_block(&disconnected));
    }

    #[test]
    fn now_metrics_exclude_host_reflections_from_peer_action_count() {
        let directory = tempfile::tempdir().unwrap();
        let service = RadioService::from_environment_with_discovery_log(
            directory.path().join("discovery.jsonl"),
        );
        {
            let mut history = service.history.lock().unwrap();
            history.push_back(RadioEvent {
                ts_millis: 1,
                key: "wifi.raw.action.reflection".to_string(),
                source: "wlan1mon".to_string(),
                value: json!({"peer": "local"}),
                message: None,
            });
            history.push_back(RadioEvent {
                ts_millis: 2,
                key: "wifi.raw.action".to_string(),
                source: "wlan1mon".to_string(),
                value: json!({"peer": "remote"}),
                message: None,
            });
        }

        // Only the action frame counts; its reflection is a different key.
        let counts = service.now_counts(Some("wlan1".to_string()));
        assert_eq!(counts.action_seen, 1);
    }

    #[test]
    fn action_filter_admits_a_p2p_go_reply_address() {
        let anchor = [0x9c, 0xef, 0xd5, 0xf6, 0x36, 0x47];
        let group = [0x9a, 0xef, 0xd5, 0xf6, 0x36, 0x47];
        let mut addresses = vec![anchor, raw_receive_mac(anchor), RAW_WIFI_MULTICAST];
        addresses.push(group);
        let mut frame = [0_u8; IEEE80211_BODY];
        frame[IEEE80211_ADDR1..IEEE80211_ADDR1 + 6].copy_from_slice(&group);

        assert!(raw_wifi_receive_address_allowed(&frame, &addresses));
    }

    #[test]
    fn directed_now_quic_keeps_the_advertised_unicast_address() {
        let peer = [0x14, 0xc1, 0x9f, 0xe4, 0x5d, 0x48];
        assert_eq!(directed_now_destination(peer), peer);
        assert_ne!(directed_now_destination(peer), raw_receive_mac(peer));
    }

    #[test]
    fn raw_now_quic_uses_unicast_peer_by_default_and_alias_only_as_diagnostic() {
        let peer = [0x20, 0x6e, 0xf1, 0x13, 0xa4, 0x00];
        assert_eq!(
            raw_action_response_address_with_alias_override(peer, false),
            peer
        );
        assert_eq!(peer[0] & 1, 0, "the announced peer address is unicast");
        let alias = raw_action_response_address_with_alias_override(peer, true);
        assert_eq!(alias, [0x21, 0x6e, 0xf1, 0x13, 0xa4, 0x00]);
        assert_eq!(alias[0] & 1, 1, "the receive alias is a group address");
    }


    #[test]
    fn admitted_announces_reach_the_shared_discovery_sink() {
        let directory = tempfile::tempdir().unwrap();
        let service = RadioService::from_environment_with_discovery_log(
            directory.path().join("discovery.jsonl"),
        );
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink_seen = seen.clone();
        service.set_announce_sink(Arc::new(move |source, peer, announce, _payload| {
            sink_seen
                .lock()
                .unwrap()
                .push((source.to_owned(), peer.to_owned(), announce.uptime_secs));
        }));
        let announce = dmesh_server::announce::Announce::discovery([0x61; 16], 16, 9);
        assert!(service.observe_discovered_announce("nan_sd", "aa:bb:cc:dd:ee:61".to_owned(), None, announce));
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            &[("nan_sd".to_owned(), "aa:bb:cc:dd:ee:61".to_owned(), 9)]
        );
    }

    #[test]
    fn announce_identity_validation_accepts_unsigned_devices_and_rejects_fake_hosts() {
        let unsigned = dmesh_server::announce::Announce::discovery([0x41; 16], 16, 1);
        assert!(announce_identity_valid(unsigned));

        let mut fake = unsigned;
        assert!(fake.set_public_key(b"not-a-p256-spki"));
        assert!(fake.set_signature(&[0x55; dmesh_server::announce::SIGNATURE_LEN]));
        assert!(!announce_identity_valid(fake));
    }

    #[test]
    fn announce_identity_validation_accepts_signed_compressed_p256() {
        let secret = SecretKey::from_slice(&[7_u8; 32]).unwrap();
        let signing_key = SigningKey::from(secret);
        let public_key = signing_key.verifying_key().to_sec1_point(true);
        assert_eq!(public_key.as_bytes().len(), 33);

        let digest = Sha256::digest(public_key.as_bytes());
        let mut device_id = [0_u8; 16];
        device_id.copy_from_slice(&digest[..16]);
        let mut announce = dmesh_server::announce::Announce::discovery(device_id, 16, 1);
        assert!(announce.set_public_key(public_key.as_bytes()));
        let mut signing_bytes = [0_u8; 384];
        let used = dmesh_server::announce::signing_bytes(announce, &mut signing_bytes).unwrap();
        let signature: Signature = signing_key.sign(&signing_bytes[..used]);
        assert!(announce.set_signature(signature.to_bytes().as_ref()));

        assert!(announce_identity_valid(announce));
    }

    #[test]
    fn discovered_device_log_records_only_new_and_dropped_nodes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("discovery.jsonl");
        let mut registry = DiscoveredDeviceRegistry::with_change_log(path.clone());
        let mut id = [0_u8; 16];
        id[..6].copy_from_slice(b"peer-a");
        let announce = dmesh_server::announce::Announce::discovery(id, 6, 1);
        registry.observe_announce(
            "nan",
            "02:00:00:00:00:01".to_string(),
            Some("50:6f:9a:01:a6:2d".to_string()),
            announce,
        );
        // A normal new announcement is a timestamp/payload refresh, not a
        // durable topology change.
        registry.observe_announce(
            "nan",
            "02:00:00:00:00:01".to_string(),
            Some("50:6f:9a:01:a6:2d".to_string()),
            announce,
        );
        let lines = std::fs::read_to_string(&path).unwrap();
        assert_eq!(lines.lines().count(), 1);
        assert!(lines.contains("\"change\":\"new\""));

        // Expiry is checked on the next observation/status pass and records
        // one dropped topology event rather than frequent absence updates.
        registry.devices.insert(
            "stale".to_string(),
            DiscoveredDevice {
                device_id: "stale".to_string(),
                last_seen_ms: 0,
                source: "udp_multicast".to_string(),
                peer: "[fe80::1]:5227".to_string(),
                bssid: None,
                announce: json!({"device_id": "stale"}),
                observations: BTreeMap::new(),
            },
        );
        registry.snapshot();
        let lines = std::fs::read_to_string(&path).unwrap();
        assert_eq!(lines.lines().count(), 2);
        assert!(lines.contains("\"change\":\"dropped\""));
    }

    #[test]
    fn directed_discovery_reply_does_not_erase_advertised_udp_route() {
        let dir = tempfile::tempdir().unwrap();
        let mut registry =
            DiscoveredDeviceRegistry::with_change_log(dir.path().join("nodes.jsonl"));
        let mut id = [0_u8; 16];
        id[..10].copy_from_slice(b"android-p7");
        let mut multicast = dmesh_server::announce::Announce::discovery(id, 10, 1);
        multicast.set_udp_port(3336);
        multicast.set_udp_link_local_v6("fe80::1234".parse::<Ipv6Addr>().unwrap().octets());
        registry.observe_announce(
            "udp_multicast",
            "[fe80::1234%5]:5227".to_owned(),
            None,
            multicast,
        );

        // The generic directed reply has no sender-local endpoint because it
        // cannot know which local interface carried the request.
        let reply = dmesh_server::announce::Announce::discovery(id, 10, 2);
        registry.observe_announce(
            "udp_multicast",
            "[fe80::1234%5]:3336".to_owned(),
            None,
            reply,
        );

        let entry = registry.devices.get(&hex_bytes(&id[..10])).unwrap();
        assert_eq!(entry.announce["udp_link_local_v6"], "fe80::1234");
        assert_eq!(entry.announce["udp_port"], 3336);
        assert_eq!(
            entry.observations["udp_multicast"].last_peer,
            "[fe80::1234%5]:3336"
        );
    }

    #[test]
    fn directed_discovery_reply_seeds_cold_inventory_from_unicast_source() {
        let dir = tempfile::tempdir().unwrap();
        let mut registry =
            DiscoveredDeviceRegistry::with_change_log(dir.path().join("nodes.jsonl"));
        let mut id = [0_u8; 16];
        id[..10].copy_from_slice(b"android-s2");
        registry.observe_announce(
            "udp_multicast",
            "[fe80::5678%5]:3336".to_owned(),
            None,
            dmesh_server::announce::Announce::discovery(id, 10, 1),
        );

        let entry = registry.devices.get(&hex_bytes(&id[..10])).unwrap();
        assert_eq!(entry.announce["udp_link_local_v6"], "fe80::5678");
        assert_eq!(entry.announce["udp_port"], 3336);
    }

    #[test]
    fn discovery_presentation_hides_internal_route_and_key_material() {
        let mut now = CommonDiscoveryObservation::new(1, OBSERVATION_PEER);
        now.observe(
            2,
            DiscoveryPacketKind::Other,
            "02:00:00:00:00:11",
            None,
            None,
            None,
            &[],
        );
        let entry = DiscoveredDevice {
            device_id: "device".to_owned(),
            last_seen_ms: now_millis(),
            source: "nan".to_owned(),
            peer: "internal-route".to_owned(),
            bssid: None,
            announce: json!({
                "device_name": "mesh-device",
                "public_key": "0011",
                "route_key": "internal-route",
                "vip6": "fc00::11",
            }),
            observations: BTreeMap::from([("now".to_owned(), now)]),
        };
        let value = discovered_device_json(&entry);
        assert!(value.get("id").is_none());
        assert!(value.get("peer").is_none());
        assert_eq!(value["identity"], "mesh-device");
        assert_eq!(value["announce"]["vip6"], "fc00::11");
        assert!(value["announce"].get("device_id").is_none());
        assert!(value["announce"].get("public_key").is_none());
        assert!(value["announce"].get("route_key").is_none());
        assert_eq!(
            value["observations"]["now"]["last_peer"],
            "02:00:00:00:00:11"
        );
    }

    #[test]
    fn discovered_device_log_restores_recent_nodes_across_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("discovery.jsonl");
        let mut id = [0_u8; 16];
        id[..6].copy_from_slice(b"peer-r");
        let announce = dmesh_server::announce::Announce::discovery(id, 6, 1);
        DiscoveredDeviceRegistry::with_change_log(path.clone()).observe_announce(
            "nan",
            "02:00:00:00:00:02".to_string(),
            Some("50:6f:9a:01:a6:2d".to_string()),
            announce,
        );
        // The second registry models a supervised service restart. The peer
        // was seen moments ago, so its next announce is a silent refresh.
        let mut restarted = DiscoveredDeviceRegistry::with_change_log(path.clone());
        restarted.observe_announce(
            "nan",
            "02:00:00:00:00:02".to_string(),
            Some("50:6f:9a:01:a6:2d".to_string()),
            announce,
        );
        let lines = std::fs::read_to_string(path).unwrap();
        assert_eq!(lines.lines().count(), 1);
        assert_eq!(restarted.snapshot().len(), 1);
    }

    #[test]
    fn pending_nan_followups_are_deduplicated_and_bounded() {
        let pending = Arc::new(Mutex::new(dmesh_rawnan::NanFollowupQueue::new(
            MAX_PENDING_NAN_FOLLOWUPS,
        )));
        let peer = [2, 0, 0, 0, 0, 1];
        assert!(queue_nan_followup(&pending, peer, 1, 0, vec![1, 2]));
        assert!(!queue_nan_followup(&pending, peer, 1, 0, vec![1, 2]));
        for index in 0..MAX_PENDING_NAN_FOLLOWUPS {
            assert!(queue_nan_followup(
                &pending,
                [2, 0, 0, 0, 1, index as u8],
                1,
                0,
                vec![index as u8],
            ));
        }
        let mut queue = pending.lock().unwrap();
        assert_eq!(queue.len(), MAX_PENDING_NAN_FOLLOWUPS);
        assert!(
            queue
                .take_up_to(MAX_PENDING_NAN_FOLLOWUPS)
                .iter()
                .all(|item| item.destination != peer)
        );
    }

    #[test]
    fn active_publish_configuration_is_pending_until_a_discovery_window() {
        let dir = tempfile::tempdir().unwrap();
        let radio =
            RadioService::from_environment_with_discovery_log(dir.path().join("nodes.jsonl"));
        let configured = radio
            .rawnan_active_publish_configure(true, &[0xa1, 0x01, 0x02])
            .unwrap();
        assert_eq!(configured["enabled"], true);
        assert_eq!(configured["pending"], true);
        let status = radio.rawnan_status(None);
        assert_eq!(status["active_publish"]["service_info_len"], 3);
        assert_eq!(status["active_publish"]["pending"], true);

        let disabled = radio.rawnan_active_publish_configure(false, &[]).unwrap();
        assert_eq!(disabled["enabled"], false);
        assert_eq!(disabled["pending"], false);
    }

    #[test]
    fn followup_status_omits_discovery_events_without_a_followup() {
        let dir = tempfile::tempdir().unwrap();
        let radio =
            RadioService::from_environment_with_discovery_log(dir.path().join("nodes.jsonl"));
        push_radio_event(
            &radio.history,
            RadioEvent {
                ts_millis: 1,
                key: "wifi.rawnan.discovery".to_string(),
                source: "wlan1mon".to_string(),
                value: json!({"followup": null}),
                message: None,
            },
        );
        push_radio_event(
            &radio.history,
            RadioEvent {
                ts_millis: 2,
                key: "wifi.rawnan.discovery".to_string(),
                source: "wlan1mon".to_string(),
                value: json!({"followup": {"seq": 9}}),
                message: None,
            },
        );
        let status = radio.rawnan_status(None);
        assert_eq!(status["followups"].as_array().unwrap().len(), 1);
        assert_eq!(status["followups"][0]["followup"]["seq"], 9);
    }

    #[test]
    fn station_link_metrics_keeps_host_mac_failures_optional_and_named() {
        let station = json!({
            "mac": "14:c1:9f:e5:98:00",
            "rx_bytes": 11,
            "tx_bytes": 22,
            "tx_packets": 3,
            "tx_retries": 4,
            "tx_failed": 5,
            "signal_dbm": -42,
            "tx_bitrate_kbit_s": 19_500,
        });
        let metrics = station_link_metrics(&station, 7);
        assert_eq!(metrics.schema_version, WIFI_LINK_METRICS_SCHEMA_VERSION);
        assert_eq!(metrics.interface_index, Some(7));
        assert_eq!(metrics.peer_mac, Some([0x14, 0xc1, 0x9f, 0xe5, 0x98, 0x00]));
        assert_eq!(metrics.mac_tx_retries, Some(4));
        assert_eq!(metrics.mac_tx_failed, Some(5));
        assert_eq!(metrics.signal_dbm, Some(-42));
        assert_eq!(metrics.raw_tx_completion_failures, None);
        assert_eq!(metrics.bearer_rx_frames, None);
    }

    #[test]
    fn raw_wifi_default_tx_uses_monitor_injection() {
        // An unassociated Linux adapter rejects NL80211_CMD_FRAME.  Keep the
        // no-option operator path aligned with the proven AF_PACKET/radiotap
        // injector used by the host NOW/NAN laboratory.
        let options = RawWifiTxOptions::from_variant(None, 5, None).unwrap();
        assert_eq!(options.variant, "monitor");
        assert!(!options.include_freq);
        assert!(options.duration_ms.is_none());
        assert!(!options.offchannel_tx_ok);
        assert!(options.dont_wait_for_ack);
    }

    #[test]
    fn ap_sme_retires_station_on_disassociation_or_deauthentication() {
        assert!(ap_sme_station_departed(10));
        assert!(ap_sme_station_departed(12));
        assert!(!ap_sme_station_departed(0));
        assert!(!ap_sme_station_departed(11));
    }

    #[test]
    fn open_ap_templates_advertise_ofdm_rates_without_cck() {
        let ies = esp_open_ap_probe_ies("Direct-test", 11).unwrap();
        assert_eq!(
            management_ie_bytes(&ies, 1),
            Some(OPEN_AP_OFDM_BASIC_RATES.as_slice())
        );
        assert_eq!(
            management_ie_bytes(&ies, 50),
            Some(OPEN_AP_OFDM_EXTENDED_RATES.as_slice())
        );

        let assoc = build_open_assoc_response([1; 6], [2; 6], 1, true, 11, false);
        let assoc_ies = &assoc[IEEE80211_BODY + 6..];
        assert_eq!(
            management_ie_bytes(assoc_ies, 1),
            Some(OPEN_AP_OFDM_BASIC_RATES.as_slice())
        );
        assert_eq!(
            management_ie_bytes(assoc_ies, 50),
            Some(OPEN_AP_OFDM_EXTENDED_RATES.as_slice())
        );
        assert_eq!(management_ie_bytes(&ies, 3), Some(&[11][..]));
        assert!(
            dmesh_rawnan::p2p::parse_advertisement(&ies)
                .unwrap()
                .is_some()
        );
        assert_eq!(management_ie_bytes(assoc_ies, 61).map(|ie| ie[0]), Some(11));
        assert_eq!(OPEN_AP_OFDM_BASIC_RATES, [0x8c]);
        assert_eq!(OPEN_AP_OFDM_EXTENDED_RATES, [0x30, 0x48, 0x60, 0x6c]);
        assert_eq!(open_ap_basic_rates(), &[0x8c]);
    }


    #[test]
    fn station_rate_status_distinguishes_ht_from_legacy() {
        let mut status = serde_json::Map::new();
        insert_station_rate_info(
            &mut status,
            "tx",
            &[
                (NL80211_RATE_INFO_BITRATE, &[0x04, 0x01]),
                (NL80211_RATE_INFO_MCS, &[3]),
                (NL80211_RATE_INFO_SHORT_GI, &[]),
            ],
        );
        assert_eq!(status["tx_bitrate_kbit_s"], json!(26_000));
        assert_eq!(status["tx_phy"], json!("ht"));
        assert_eq!(status["tx_mcs"], json!(3));
        assert_eq!(status["tx_width_mhz"], json!(20));
        assert_eq!(status["tx_short_gi"], json!(true));
    }

    #[test]
    fn ht_rate_profile_is_exact_mcs_without_legacy_fallback() {
        assert!(tx_rate_profile_band(None, None, false).is_none());
        let band = tx_rate_profile_band(None, Some(3), true).unwrap();
        let attrs = parse_attrs(&band).unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0], (NL80211_TXRATE_HT, &[3][..]));

        let high_fallback = tx_rate_profile_band(Some(24), Some(3), true).unwrap();
        let attrs = parse_attrs(&high_fallback).unwrap();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0], (NL80211_TXRATE_LEGACY, &[48][..]));
        assert_eq!(attrs[1], (NL80211_TXRATE_HT, &[3][..]));

        let ofdm_only = tx_rate_profile_band(None, None, true).unwrap();
        let attrs = parse_attrs(&ofdm_only).unwrap();
        assert_eq!(attrs[0].0, NL80211_TXRATE_LEGACY);
        assert_eq!(attrs[0].1, &[12, 18, 24, 36, 48, 72, 96, 108]);
    }


    #[test]
    fn raw_nan_transport_action_uses_unicast_a1_a2_and_cluster_a3() {
        let dst = [0x14, 0xc1, 0x9f, 0xe5, 0x98, 0x00];
        let src = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let bssid = [0x50, 0x6f, 0x9a, 0x01, 0x54, 0x6c];
        let frame =
            build_dmesh_vendor_action_frame_with_bssid(dst, src, bssid, b"mesh-test").unwrap();

        assert_eq!(&frame[4..10], &dst); // A1: addressed device
        assert_eq!(&frame[10..16], &src); // A2: host Wi-Fi adapter
        assert_eq!(&frame[16..22], &bssid); // A3: NAN cluster, not broadcast
        assert_ne!(&frame[4..10], &[0xff; 6]);
        assert_ne!(&frame[16..22], &[0xff; 6]);
    }


    #[test]
    fn raw_wifi_legacy_vendor_action_still_parses() {
        let dst = [0xff; 6];
        let src = [0x02, 0x00, 0x00, 0xaa, 0xbb, 0xcc];
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xd0, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&dst);
        frame.extend_from_slice(&src);
        frame.extend_from_slice(&dst);
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&DMESH_LEGACY_VENDOR_ACTION);
        frame.extend_from_slice(b"stats");

        let parsed = parse_dmesh_vendor_action(&frame, "wlan-test").unwrap();
        assert_eq!(parsed["vendor_marker"], "legacy_dmesh");
        assert_eq!(parsed["payload_text"], "stats");
    }



    #[test]
    fn dmesh_now_unicast_radiotap_keeps_no_mac_ack() {
        let packet =
            build_radiotap_packet_at_rate_with_ack(&[0xd0, 0x00, 0x00, 0x00], Some(6), false)
                .unwrap();
        // `0x0008` is radiotap TX_FLAGS NO_ACK. The NOW request and reply
        // builders pass false even when their Address-1 is unicast.
        assert_eq!(&packet[10..12], &[0x08, 0x00]);
    }


    #[test]
    fn nan_radiotap_rate_is_six_mbps() {
        let mut beacon = vec![0x80, 0x00, 0, 0];
        beacon.extend_from_slice(
            &[
                [0xff; 6],
                [2, 0, 0, 0xaa, 0xbb, 0xcc],
                [0x50, 0x6f, 0x9a, 1, 2, 3],
            ]
            .concat(),
        );
        beacon.extend_from_slice(&[0, 0]);
        let packet = build_radiotap_packet_at_rate(&beacon, Some(6)).unwrap();
        assert_eq!(packet[8], 12); // 6 Mbps in 500-kbps radiotap units.
    }

    #[test]
    fn raw_wifi_multicast_data_frame_has_dmesh_body() {
        let src = [0x02, 0x00, 0x00, 0xaa, 0xbb, 0xcc];
        let frame = build_dmesh_multicast_data_frame(RAW_WIFI_MULTICAST, src, b"stats");

        assert_eq!(&frame[..4], &[0x08, 0x00, 0x00, 0x00]);
        assert_eq!(
            &frame[IEEE80211_ADDR1..IEEE80211_ADDR1 + 6],
            &RAW_WIFI_MULTICAST
        );
        assert_eq!(&frame[IEEE80211_ADDR2..IEEE80211_ADDR2 + 6], &src);
        assert_eq!(
            &frame[IEEE80211_BODY..IEEE80211_BODY + DMESH_VENDOR_ACTION_LEN],
            &dmesh_vendor_action_header(RAW_WIFI_MULTICAST)
        );
        assert_eq!(&frame[IEEE80211_BODY + DMESH_VENDOR_ACTION_LEN..], b"stats");
    }

    #[test]
    fn raw_nan_data_frame_keeps_private_llc_and_direct_payload() {
        let bssid = [0x50, 0x6f, 0x9a, 1, 2, 3];
        let src = [0x02, 0x00, 0x00, 0xaa, 0xbb, 0xcc];
        let dst = RAW_WIFI_MULTICAST;
        let payload = b"mesh-test";
        let frame = build_dmesh_nan_raw_data_frame(bssid, dst, src, &RAWNAN_LLC_DEFAULT, payload);
        assert_eq!(&frame[IEEE80211_ADDR1..IEEE80211_ADDR1 + 6], &dst);
        assert_eq!(&frame[IEEE80211_ADDR3..IEEE80211_ADDR3 + 6], &bssid);
        assert_eq!(
            &frame[IEEE80211_BODY..IEEE80211_BODY + IEEE80211_LLC_SNAP_LEN],
            &RAWNAN_LLC_DEFAULT
        );
        let parsed = parse_dmesh_wifi_frame(&frame, "wlan1", "test").unwrap();
        assert_eq!(parsed["layout"], "nan_raw_data");
        assert_eq!(parsed["payload_text"], "mesh-test");
    }

    #[test]
    fn experimental_llc_parser_requires_eight_bytes() {
        assert_eq!(
            parse_experimental_llc(Some("hex:aAaA03d04d455348")),
            Some(RAWNAN_LLC_DEFAULT)
        );
        assert!(parse_experimental_llc(Some("hex:1234")).is_none());
    }

    #[test]
    fn raw_wifi_sta_multicast_llc_frame_maps_to_ethernet_payload() {
        let bssid = [0xa4, 0x2b, 0xb0, 0xbd, 0x00, 0xe3];
        let src = [0x44, 0x94, 0xfc, 0xe4, 0x84, 0x15];
        let frame = build_dmesh_sta_multicast_llc_frame(bssid, src, b"stats");

        assert_eq!(&frame[..4], &[0x08, 0x01, 0x00, 0x00]);
        assert_eq!(&frame[IEEE80211_ADDR1..IEEE80211_ADDR1 + 6], &bssid);
        assert_eq!(&frame[IEEE80211_ADDR2..IEEE80211_ADDR2 + 6], &src);
        assert_eq!(
            &frame[IEEE80211_ADDR3..IEEE80211_ADDR3 + 6],
            &RAW_WIFI_MULTICAST
        );
        assert_eq!(
            &frame[IEEE80211_BODY..IEEE80211_BODY + IEEE80211_LLC_SNAP_LEN],
            &IEEE80211_LLC_SNAP_DMESH
        );

        let parsed = parse_dmesh_wifi_frame(&frame, "wlan-test", "test").unwrap();
        assert_eq!(parsed["encapsulation"], "llc_snap");
        assert_eq!(parsed["payload_text"], "stats");
    }

    #[test]
    fn raw_wifi_sta_direct_llc_frame_targets_peer_mac() {
        let dst = [0xa4, 0x2b, 0xb0, 0xbd, 0x00, 0xe3];
        let src = [0x02, 0x00, 0x00, 0xaa, 0xbb, 0xcc];
        let frame = build_dmesh_sta_direct_llc_frame(dst, src, b"direct");

        assert_eq!(&frame[..4], &[0x08, 0x00, 0x00, 0x00]);
        assert_eq!(&frame[IEEE80211_ADDR1..IEEE80211_ADDR1 + 6], &dst);
        assert_eq!(&frame[IEEE80211_ADDR2..IEEE80211_ADDR2 + 6], &src);
        assert_eq!(&frame[IEEE80211_ADDR3..IEEE80211_ADDR3 + 6], &dst);
        assert_eq!(
            &frame[IEEE80211_BODY..IEEE80211_BODY + IEEE80211_LLC_SNAP_LEN],
            &IEEE80211_LLC_SNAP_DMESH
        );

        let parsed = parse_dmesh_wifi_frame(&frame, "wlan-test", "test").unwrap();
        assert_eq!(parsed["encapsulation"], "llc_snap");
        assert_eq!(parsed["layout"], "multicast_data");
        assert_eq!(parsed["destination"], colon_mac(&dst));
        assert_eq!(parsed["source"], colon_mac(&src));
        assert_eq!(parsed["payload_text"], "direct");
    }

    #[test]
    fn raw_wifi_nan_data_frame_uses_cluster_as_address3() {
        let bssid = [0x50, 0x6f, 0x9a, 0x01, 0x05, 0x01];
        let dst = [0xff; 6];
        let src = [0x02, 0x00, 0x00, 0xaa, 0xbb, 0xcc];
        let frame = build_dmesh_nan_data_frame(bssid, dst, src, b"nan-data");
        assert_eq!(&frame[..4], &[0x08, 0x00, 0x00, 0x00]);
        assert_eq!(&frame[IEEE80211_ADDR1..IEEE80211_ADDR1 + 6], &dst);
        assert_eq!(&frame[IEEE80211_ADDR2..IEEE80211_ADDR2 + 6], &src);
        assert_eq!(&frame[IEEE80211_ADDR3..IEEE80211_ADDR3 + 6], &bssid);
        let parsed = parse_dmesh_wifi_frame(&frame, "wlan-test", "test").unwrap();
        assert_eq!(parsed["payload_text"], "nan-data");
        assert_eq!(parsed["bssid"], colon_mac(&bssid));
    }




    #[test]
    fn radio_inventory_unifies_active_and_passive_bss_by_channel() {
        let mut registry = DiscoveredDeviceRegistry::with_change_log(std::env::temp_dir().join(
            format!("dmesh-radio-inventory-{}.jsonl", std::process::id()),
        ));
        let now = now_millis();
        registry.observe_bss(
            "passive_monitor",
            &json!({
                "bssid": "02:00:00:00:00:06",
                "ssid": "DIRECT-e6-dmesh",
                "channel": 6,
                "auth": "open",
                "rx_signal_dbm": -42,
            }),
            now.saturating_sub(1),
        );
        registry.observe_bss(
            "active_ssid_scan",
            &json!({
                "bssid": "02:00:00:00:00:07",
                "ssid": "costin24",
                "channel": 6,
                "auth": "protected",
                "signal_dbm": -55.0,
            }),
            now,
        );
        let (bss, channels) = registry.bss_snapshot();
        assert_eq!(bss.len(), 2);
        assert_eq!(bss[0]["id"], "bss:02:00:00:00:00:07");
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0]["channel"], 6);
        assert_eq!(channels[0]["dmesh_bss"], 1);
        assert_eq!(channels[0]["non_dmesh_bss"], 1);
        assert_eq!(channels[0]["open_dmesh_bss"], 1);
        assert_eq!(
            channels[0]["last_seen_ms"].as_u64(),
            u64::try_from(now).ok()
        );
    }

    #[test]
    fn raw_wifi_destination_can_derive_firmware_receive_mac() {
        assert_eq!(
            raw_wifi_destination(Some("rx:84:0d:8e:07:42:c5"), "multicast_data"),
            [0x85, 0x0d, 0x8e, 0x07, 0x42, 0xc5]
        );
        assert_eq!(
            raw_wifi_destination(Some("raw:85:0d:8e:07:42:c5"), "multicast_data"),
            [0x84, 0x0d, 0x8e, 0x07, 0x42, 0xc5]
        );
        assert_eq!(
            raw_wifi_destination(None, "multicast_data"),
            RAW_WIFI_MULTICAST
        );
        assert_eq!(raw_wifi_destination(None, "standard"), RAW_WIFI_BROADCAST);
    }

    #[test]
    fn directed_now_keeps_peer_identity_but_uses_receive_alias_on_wire() {
        let peer = [0x14, 0xc1, 0x9f, 0xe4, 0x5d, 0x48];
        assert_eq!(parse_now_peer_address("14:c1:9f:e4:5d:48"), Some(peer));
        assert_eq!(
            now_wire_destination("14:c1:9f:e4:5d:48"),
            "rx:14:c1:9f:e4:5d:48"
        );
        assert_eq!(
            raw_wifi_destination(Some(&now_wire_destination("14:c1:9f:e4:5d:48")), "monitor"),
            [0x15, 0xc1, 0x9f, 0xe4, 0x5d, 0x48]
        );
        assert_eq!(parse_now_peer_address("rx:14:c1:9f:e4:5d:48"), Some(peer));
        assert_eq!(
            now_wire_destination("rx:14:c1:9f:e4:5d:48"),
            "rx:14:c1:9f:e4:5d:48"
        );
    }

    #[test]
    fn transport_cleanup_releases_anchor_and_legacy_wpa_owners() {
        assert_eq!(
            wpa_owner_iface_names("wlan1", "wlan1sta"),
            vec!["wlan1", "wlan1sta"]
        );
        assert_eq!(wpa_owner_iface_names("wlan1", "wlan1"), vec!["wlan1"]);
    }


}

/// Station links of the AP interface `iface`, from an nl80211 station dump, as the common
/// `telemetry.wifi_link` rows.
pub fn station_links(iface: &str) -> Result<Vec<dmesh_server::platform_api::WifiLink>> {
    let interface_index = ifindex(iface)?;
    let socket = Nl80211Socket::open()?;
    Ok(socket
        .station_dump(interface_index)?
        .iter()
        .map(|station| station_link_metrics(station, interface_index))
        .map(|metrics| dmesh_server::platform_api::WifiLink::from(&metrics))
        .collect())
}

/// Convert a raw nl80211 station record into the shared optional link-metrics
/// vocabulary.  The original station JSON remains available for compatibility,
/// but exporters should consume this record so ESP-side observations and host
/// MAC telemetry do not grow separate metric names.
fn station_link_metrics(station: &Value, interface_index: u32) -> WifiLinkMetrics {
    let unsigned = |key| station.get(key).and_then(Value::as_u64);
    let signed = |key| {
        station
            .get(key)
            .and_then(Value::as_i64)
            .and_then(|value| i8::try_from(value).ok())
    };
    let mut metrics = WifiLinkMetrics::new();
    metrics.interface_index = Some(interface_index);
    metrics.peer_mac = station
        .get("mac")
        .and_then(Value::as_str)
        .and_then(|mac| parse_mac(Some(mac)));
    metrics.rx_bytes = unsigned("rx_bytes");
    metrics.tx_bytes = unsigned("tx_bytes");
    metrics.rx_packets = unsigned("rx_packets");
    metrics.tx_packets = unsigned("tx_packets");
    metrics.mac_tx_retries = unsigned("tx_retries");
    metrics.mac_tx_failed = unsigned("tx_failed");
    metrics.rx_dropped = unsigned("rx_drop_misc");
    metrics.rx_airtime_us = unsigned("rx_airtime_us");
    metrics.tx_airtime_us = unsigned("tx_airtime_us");
    metrics.signal_dbm = signed("signal_dbm");
    metrics.signal_avg_dbm = signed("signal_avg_dbm");
    metrics.ack_signal_dbm = signed("ack_signal_dbm");
    metrics.ack_signal_avg_dbm = signed("ack_signal_avg_dbm");
    metrics.rx_bitrate_kbit_s = unsigned("rx_bitrate_kbit_s");
    metrics.tx_bitrate_kbit_s = unsigned("tx_bitrate_kbit_s");
    metrics.expected_throughput_kbit_s = unsigned("expected_throughput_kbit_s");
    metrics
}
