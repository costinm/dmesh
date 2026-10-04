//! Monitor and AP-management capture loops and the NAN engine around them, moved from
//! `lmesh-wifi/src/radio.rs`. Everything the loops hand to the application goes through
//! [`CaptureHost`]; nothing here decodes an announce or touches an inventory.
use super::*;
use crate::{Action as RawNanAction, DiscoveryWindow, NanActivePublish, NanState, RxFrame as RawNanRxFrame};
use crate::service::FollowupDedup;
use std::collections::BTreeMap;

/// How the host should render the mesh message that goes with an event.
#[derive(Clone, Debug)]
pub enum EventMessage {
    /// A parsed raw Wi-Fi frame (`value` carries its fields).
    RawWifi { iface: String },
    /// An AP-mode management frame.
    Mgmt {
        source: String,
        iface: String,
        status: String,
        rssi_dbm: Option<i32>,
    },
}

/// One retained radio event.
#[derive(Clone, Debug)]
pub struct RadioEvent {
    pub ts_millis: u128,
    pub key: String,
    pub source: String,
    pub value: Value,
    pub message: Option<EventMessage>,
}

/// What the NAN descriptors of one frame contained, as the host decoded them.
#[derive(Clone, Debug, Default)]
pub struct NanAnnounce {
    /// A signed announce was present but its identity did not verify.
    pub invalid_identity: bool,
    /// A valid announce was found (and the host has observed it); its summary.
    pub summary: Option<Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NanPacketKind {
    ActiveSubscribe,
    Followup,
}

/// How a NOW action payload is dispatched.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NowClass {
    /// NOW cluster sync: updates the NAN state machine and carries a service info.
    Sync,
    /// An opaque QUIC datagram for the bearer.
    Quic,
    /// Everything else: a discovery payload, handed up as bytes. NOW discovery is
    /// NAN's discovery in NOW's envelope and is processed like NAN; anything that is
    /// not discovery is QUIC.
    Discovery,
}

/// Classify a NOW action payload by its first bytes, as the firmware does: the QUIC
/// fixed bit is the fast path, except for the NOW-sync header that shares it.
/// Nothing is decoded here: a payload is the bearer's (QUIC), the NAN engine's
/// (sync) or the discovery observer's.
pub fn classify_now_payload(payload: &[u8]) -> NowClass {
    const QUIC_FIXED_BIT: u8 = 0x40;
    if payload.first() == Some(&QUIC_FIXED_BIT) && crate::parse_now_sync_body(payload).is_some() {
        NowClass::Sync
    } else if payload.first().is_some_and(|first| first & QUIC_FIXED_BIT != 0) {
        NowClass::Quic
    } else {
        NowClass::Discovery
    }
}

/// What the capture loops need from the application.
pub trait CaptureHost: Send + Sync {
    /// Retain one radio event.
    fn event(&self, event: RadioEvent);
    /// The descriptor payloads of a NAN frame from `peer`: decode and observe any
    /// announce in them.
    fn nan_announce(&self, peer: &str, bssid: Option<&str>, payloads: &[&[u8]]) -> NanAnnounce;
    /// An active Subscribe or follow-up payload from `peer`.
    fn nan_packet(&self, peer: &str, bssid: Option<&str>, kind: NanPacketKind, payload: &[u8]);
    /// A NOW cluster-sync record from `peer`.
    fn now_sync(&self, peer: [u8; 6], cluster_id: [u8; 6], service_info: &[u8]);
    /// A NOW discovery payload (not QUIC, not sync) from `peer`: the same service-info
    /// bytes NAN carries, observed like a NAN descriptor. A request is answered: the
    /// returned bytes go back to `peer` as a NOW discovery payload.
    fn now_discovery(&self, peer: [u8; 6], bssid: Option<[u8; 6]>, payload: &[u8]) -> Option<Vec<u8>>;
    /// The bearer's receive side, once attached.
    fn ingress(&self) -> Option<Arc<dyn super::espnow_bearer::EspNowIngress>>;
}

fn push_radio_event(host: &dyn CaptureHost, event: RadioEvent) {
    host.event(event);
}

/// Send the active discovery Subscribe in every confirmed DW until the next
/// DW0/DW8 boundary. This is deliberately beacon-driven: it gives always-awake
/// peers the first window and guarantees the sleepy DW0/DW8 profile gets one
/// chance, without an unsynchronised retry timer.
/// A discovery request waiting for the next discovery windows. NOW discovery is
/// NAN's discovery in NOW's envelope, so it is sent where NAN's is: immediately, and in
/// each confirmed discovery window until the next DW0 or DW8 (a sleepy peer listens
/// only then).
#[derive(Clone, Debug)]
pub struct PendingNowDiscovery {
    /// The discovery request (the same bytes a NAN active Subscribe carries).
    pub request: Vec<u8>,
    /// One peer, or everyone when absent.
    pub target: Option<[u8; 6]>,
    pub request_id: u64,
    pub sent_windows: u8,
    pub last_slot: Option<u64>,
}

/// The cluster BSSID the transmissions of this window are addressed to.
fn window_bssid(rawnan_state: &Arc<Mutex<NanState>>) -> Option<[u8; 6]> {
    rawnan_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .sync_bssid()
        .map(|mac| mac.0)
}

pub fn drain_pending_now_discovery<F>(
    event_source: &str,
    history: &dyn CaptureHost,
    window: &DiscoveryWindow,
    pending: &Arc<Mutex<Option<PendingNowDiscovery>>>,
    mut send: F,
) where
    F: FnMut(Option<[u8; 6]>, &[u8]) -> Result<()>,
{
    let slot = window.slot;
    let Some(item) = ({
        let guard = pending.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        guard
            .as_ref()
            .filter(|item| item.last_slot != Some(slot))
            .cloned()
    }) else {
        return;
    };
    let result = send(item.target, &item.request);
    let terminal_window = window.dw0_or_dw8();
    let mut guard = pending.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard
        .as_ref()
        .is_some_and(|current| current.request_id == item.request_id)
    {
        if terminal_window {
            *guard = None;
        } else if let Some(current) = guard.as_mut() {
            current.last_slot = Some(slot);
            current.sent_windows = current.sent_windows.saturating_add(1);
        }
    }
    drop(guard);
    push_radio_event(
        history,
        RadioEvent {
            ts_millis: now_millis(),
            key: "wifi.rawnan.now_discovery_tx".to_string(),
            source: event_source.to_string(),
            value: json!({
                "ok": result.is_ok(),
                "request_id": item.request_id,
                "slot": slot,
                "terminal_dw0_or_dw8": terminal_window,
                "sent_windows_before": item.sent_windows,
                "directed": item.target.is_some(),
                "error": result.err().map(|error| format!("{error:#}")),
            }),
            message: None,
        },
    );
}

pub fn drain_pending_nan_active_subscribe<F>(
    local: [u8; 6],
    event_source: &str,
    history: &dyn CaptureHost,
    rawnan_state: &Arc<Mutex<NanState>>,
    window: &DiscoveryWindow,
    pending: &Arc<Mutex<Option<PendingNanActiveSubscribe>>>,
    mut send_subscribe: F,
) where
    F: FnMut(&[u8]) -> Result<()>,
{
    let slot = window.slot;
    let Some(bssid) = window_bssid(rawnan_state) else {
        return;
    };
    let Some(item) = ({
        let guard = pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard
            .as_ref()
            .filter(|item| item.last_slot != Some(slot))
            .cloned()
    }) else {
        return;
    };
    let result = (|| {
        let frame = crate::build_nan_usd_sdf_with_bssid(
            crate::NAN_DISCOVERY_MAC,
            local,
            bssid,
            crate::DMESH_SERVICE_ID,
            9,
            0x11,
            &item.service_info,
        );
        send_subscribe(&frame)
    })();
    let terminal_window = window.dw0_or_dw8();
    let mut guard = pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard
        .as_ref()
        .is_some_and(|current| current.request_id == item.request_id)
    {
        if terminal_window {
            *guard = None;
        } else if let Some(current) = guard.as_mut() {
            current.last_slot = Some(slot);
            current.sent_windows = current.sent_windows.saturating_add(1);
        }
    }
    drop(guard);
    push_radio_event(
        history,
        RadioEvent {
            ts_millis: now_millis(),
            key: "wifi.rawnan.active_subscribe_tx".to_string(),
            source: event_source.to_string(),
            value: json!({
                "ok": result.is_ok(),
                "request_id": item.request_id,
                "directed": item.target.is_some(),
                "control_len": item.service_info.len(),
                "slot": slot,
                "terminal_dw0_or_dw8": terminal_window,
                "sent_windows_before": item.sent_windows,
                "error": result.err().map(|error| format!("{error:#}")),
            }),
            message: None,
        },
    );
}

/// Queue a bounded NAN payload until a beacon confirms that the selected DW
/// is open. `dmesh_rawnan` owns deduplication and replacement semantics;
/// this Wi-Fi adapter supplies the current timestamp and performs frame TX.
pub fn queue_nan_followup(
    pending: &Arc<Mutex<crate::NanFollowupQueue>>,
    destination: [u8; 6],
    instance: u8,
    requestor_instance: u8,
    payload: Vec<u8>,
) -> bool {
    let mut queue = pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    !matches!(
        queue.enqueue(crate::NanFollowupIntent {
            destination,
            instance,
            requestor_instance,
            payload,
            queued_at_us: now_micros_u64(),
        }),
        crate::NanFollowupEnqueue::Duplicate
    )
}

pub fn drain_pending_nan_followups<F>(
    local: [u8; 6],
    event_source: &str,
    history: &dyn CaptureHost,
    rawnan_state: &Arc<Mutex<NanState>>,
    window: &DiscoveryWindow,
    pending: &Arc<Mutex<crate::NanFollowupQueue>>,
    mut send_followup: F,
) where
    F: FnMut(&[u8]) -> Result<()>,
{
    let now_us = now_micros_u64();
    let Some(bssid) = window_bssid(rawnan_state) else {
        return;
    };
    let queued = pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take_up_to(4);
    for item in queued {
        let age_us = now_us.saturating_sub(item.queued_at_us);
        let result = (|| {
            let frame = crate::build_nan_followup_sdf_for_requestor(
                item.destination,
                local,
                bssid,
                crate::DMESH_SERVICE_ID,
                item.instance,
                item.requestor_instance,
                &item.payload,
            );
            send_followup(&frame)
        })();
        push_radio_event(
            history,
            RadioEvent {
                ts_millis: now_millis(),
                key: "wifi.rawnan.followup_tx".to_string(),
                source: event_source.to_string(),
                value: json!({
                    "ok": result.is_ok(),
                    "queued": true,
                    "peer": colon_mac(&item.destination),
                    "bytes": item.payload.len(),
                    "queued_age_us": age_us,
                    "slot": window.slot,
                    "error": result.err().map(|error| format!("{error:#}")),
                }),
                message: None,
            },
        );
    }
}

pub fn drain_active_nan_publish<F>(
    local: [u8; 6],
    event_source: &str,
    history: &dyn CaptureHost,
    rawnan_state: &Arc<Mutex<NanState>>,
    window: &DiscoveryWindow,
    active_publish: &Arc<Mutex<NanActivePublish>>,
    mut send_publish: F,
) where
    F: FnMut(&[u8]) -> Result<()>,
{
    let Some(bssid) = window_bssid(rawnan_state) else {
        return;
    };
    let now_ms = now_millis_u64();
    let (instance, service_info) = {
        let publish = active_publish
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(service_info) = publish.due(now_ms) else {
            return;
        };
        (publish.instance(), service_info.to_vec())
    };
    let result = (|| {
        let frame = crate::build_nan_publish_sdf(
            crate::NAN_DISCOVERY_MAC,
            local,
            bssid,
            crate::DMESH_SERVICE_ID,
            instance,
            &service_info,
        );
        send_publish(&frame)
    })();
    if result.is_ok() {
        active_publish
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .mark_sent(now_ms);
    }
    push_radio_event(
        history,
        RadioEvent {
            ts_millis: now_millis(),
            key: "wifi.rawnan.publish_tx".to_string(),
            source: event_source.to_string(),
            value: json!({
                "ok": result.is_ok(),
                "instance": instance,
                "service_info_len": service_info.len(),
                "slot": window.slot,
                "error": result.err().map(|error| format!("{error:#}")),
            }),
            message: None,
        },
    );
}

/// Emit the bounded, bearer-neutral NAN discovery receipt shared by the
/// permanent monitor and AP-management RX paths. `send_followup` is supplied
/// by the Wi-Fi owner so a received active subscribe is answered through the
/// already-prepared monitor during the current discovery window.
pub fn record_nan_discovery<F>(
    frame: &[u8],
    iface: &str,
    local_mac: Option<[u8; 6]>,
    event_source: &str,
    history: &dyn CaptureHost,
    rawnan_state: &Arc<Mutex<NanState>>,
    active_nan_publish: Option<&Arc<Mutex<NanActivePublish>>>,
    pending_nan_followups: &Arc<Mutex<crate::NanFollowupQueue>>,
    followup_dedup: &mut FollowupDedup,
    mut send_followup: F,
) where
    F: FnMut(&[u8]) -> Result<()>,
{
    if frame_subtype(frame) != 13 {
        return;
    }
    let descriptors = crate::service_descriptors(frame);
    let dmesh = descriptors
        .iter()
        .find(|item| item.service_id == crate::DMESH_SERVICE_ID)
        .map(|item| item.descriptor);
    // The host decodes and validates any announce in the descriptors and observes it;
    // an invalid identity is reported as its own event (an RF delivery failure must
    // stay distinguishable from a crypto failure).
    let payloads: Vec<&[u8]> = descriptors.iter().map(|item| item.descriptor.payload).collect();
    let peer_text = mac_at(frame, IEEE80211_ADDR2).map(|mac| colon_mac(&mac));
    let bssid_text = mac_at(frame, IEEE80211_ADDR3).map(|mac| colon_mac(&mac));
    let seen = match &peer_text {
        Some(peer) => history.nan_announce(peer, bssid_text.as_deref(), &payloads),
        None => NanAnnounce::default(),
    };
    if seen.invalid_identity
        && let Some(source) = mac_at(frame, IEEE80211_ADDR2)
    {
        push_radio_event(
            history,
            RadioEvent {
                ts_millis: now_millis(),
                key: "wifi.rawnan.discovery".to_string(),
                source: iface.to_string(),
                value: json!({
                    "ok": false,
                    "bearer": "nan",
                    "peer": colon_mac(&source),
                    "reason": "invalid_identity",
                }),
                message: None,
            },
        );
    }
    let active_subscribe =
        crate::active_subscribe_service_info(frame, crate::DMESH_SERVICE_ID);
    // The permanent monitor reflects our own active Subscribe. It is not a
    // remote request and must never consume a follow-up slot or be reported
    // as discovery evidence. A real peer has a different address2.
    if active_subscribe.is_some() && mac_at(frame, IEEE80211_ADDR2) == local_mac {
        return;
    }
    if dmesh.is_none() && seen.summary.is_none() && active_subscribe.is_none() {
        return;
    }
    let Some(descriptor) = dmesh.or_else(|| descriptors.first().map(|item| item.descriptor)) else {
        return;
    };
    let followup = crate::followup_service_info(frame, crate::DMESH_SERVICE_ID)
        .and_then(crate::parse_dmesh_nan_followup);
    if let Some(source) = mac_at(frame, IEEE80211_ADDR2) {
        let peer = colon_mac(&source);
        let bssid = mac_at(frame, IEEE80211_ADDR3).map(|mac| colon_mac(&mac));
        let packet = active_subscribe
            .map(|item| (NanPacketKind::ActiveSubscribe, item.service_info))
            .or_else(|| {
                followup
                    .as_ref()
                    .map(|item| (NanPacketKind::Followup, item.payload))
            });
        if let Some((kind, payload)) = packet {
            history.nan_packet(&peer, bssid.as_deref(), kind, payload);
        }
    }
    let duplicate = followup.as_ref().is_some_and(|item| {
        followup_dedup.is_duplicate(item.device_id, item.seq, item.msg_type, item.payload)
    });
    let now_us = now_micros_u64();
    let dw_open = rawnan_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .nan_sync_timing()
        .is_some_and(|(last_beacon_us, _tsf_us, _period_us)| {
            crate::beacon_dwell_open(now_us.saturating_sub(last_beacon_us))
        });
    if let Some(subscription) = active_subscribe {
        let peer = mac_at(frame, IEEE80211_ADDR2);
        let bssid = mac_at(frame, IEEE80211_ADDR3);
        if let (Some(peer), Some(bssid), Some(local)) = (peer, bssid, local_mac) {
            let publish = active_nan_publish.and_then(|publish| {
                let publish = publish
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                (publish.enabled() && !publish.service_info().is_empty())
                    .then(|| (publish.instance(), publish.service_info().to_vec()))
            });
            if let Some((publish_instance, service_info)) = publish {
                let result = crate::build_dmesh_followup_payload(
                    7,
                    now_millis_u64() as u16,
                    local,
                    peer,
                    &service_info,
                )
                .and_then(|payload| {
                    if dw_open {
                        let response = crate::build_nan_followup_sdf_for_requestor(
                            peer,
                            local,
                            bssid,
                            crate::DMESH_SERVICE_ID,
                            publish_instance,
                            subscription.instance,
                            &payload,
                        );
                        send_followup(&response)
                    } else if queue_nan_followup(
                        pending_nan_followups,
                        peer,
                        publish_instance,
                        subscription.instance,
                        payload,
                    ) {
                        Ok(())
                    } else {
                        Ok(())
                    }
                });
                push_radio_event(
                    history,
                    RadioEvent {
                        ts_millis: now_millis(),
                        key: "wifi.rawnan.followup_tx".to_string(),
                        source: event_source.to_string(),
                        value: json!({
                            "ok": result.is_ok(),
                            "queued": result.is_ok() && !dw_open,
                            "peer": colon_mac(&peer),
                            "bytes": service_info.len(),
                            "error": result.err().map(|error| format!("{error:#}")),
                        }),
                        message: None,
                    },
                );
            } else {
                push_radio_event(
                    history,
                    RadioEvent {
                        ts_millis: now_millis(),
                        key: "wifi.rawnan.followup_tx".to_string(),
                        source: event_source.to_string(),
                        value: json!({
                            "ok": false,
                            "peer": colon_mac(&peer),
                            "error": "active NAN discovery has no local announce to return",
                        }),
                        message: None,
                    },
                );
            }
        } else {
            push_radio_event(
                history,
                RadioEvent {
                    ts_millis: now_millis(),
                    key: "wifi.rawnan.followup_tx".to_string(),
                    source: event_source.to_string(),
                    value: json!({
                        "ok": false,
                        "queued": false,
                        "error": "active Subscribe response lacks peer, cluster BSSID, or local interface MAC",
                        "peer": mac_at(frame, IEEE80211_ADDR2).map(|mac| colon_mac(&mac)),
                        "bssid": mac_at(frame, IEEE80211_ADDR3).map(|mac| colon_mac(&mac)),
                    }),
                    message: None,
                },
            );
            // The discovery event below remains the RX proof even if this
            // adapter cannot originate a directed response.
        }
    }
    push_radio_event(
        history,
        RadioEvent {
            ts_millis: now_millis(),
            key: "wifi.rawnan.discovery".to_string(),
            source: event_source.to_string(),
            value: json!({
                "ok": true,
                "backend": "rawnan_host",
                "iface": iface,
                "synchronized": true,
                "peer": mac_at(frame, IEEE80211_ADDR2).map(|mac| colon_mac(&mac)),
                "bssid": mac_at(frame, IEEE80211_ADDR3).map(|mac| colon_mac(&mac)),
                "frame_len": frame.len(),
                "frame_hex": hex_bytes(&frame[..frame.len().min(256)]),
                "control": descriptor.control,
                "services": descriptors.iter().map(|item| json!({
                    "service_id": hex_bytes(&item.service_id),
                    "control": item.descriptor.control,
                    "service_info_hex": hex_bytes(item.descriptor.payload),
                })).collect::<Vec<_>>(),
                "service_info_hex": hex_bytes(descriptor.payload),
                "announce": seen.summary,
                "active_subscribe": active_subscribe.map(|item| json!({
                    "instance": item.instance,
                    "requestor_instance": item.requestor_instance,
                    "service_info_hex": hex_bytes(item.service_info),
                })),
                "duplicate": duplicate,
                "followup": followup.map(|item| json!({
                    "msg_type": item.msg_type,
                    "seq": item.seq,
                    "device_id": colon_mac(&item.device_id),
                    "target_id": colon_mac(&item.target_id),
                    "payload_len": item.payload.len(),
                    "payload_hex": hex_bytes(item.payload),
                })),
                "peer_availability": peer_availability_name(crate::peer_availability(frame)),
                "service_id": hex_bytes(&crate::DMESH_SERVICE_ID),
            }),
            message: None,
        },
    );
}

pub fn monitor_receive_loop(
    socket: MonitorRxSocket,
    iface: &str,
    monitor_iface: &str,
    history: Arc<dyn CaptureHost>,
    rawnan_state: Arc<Mutex<NanState>>,
    active_nan_publish: Arc<Mutex<NanActivePublish>>,
    pending_nan_followups: Arc<Mutex<crate::NanFollowupQueue>>,
    p2p_group_ifaces: Arc<Mutex<BTreeMap<String, String>>>,
    stop_flag: Arc<AtomicBool>,
) {
    let receive_addresses = raw_wifi_receive_addresses(iface);
    let mut local_action_addresses = receive_addresses.clone();
    if let Some(group_iface) = p2p_group_ifaces
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(iface)
        .cloned()
        && let Ok(group_mac) = iface_mac(&group_iface)
    {
        local_action_addresses.push(group_mac);
    }
    // A P2P GO has a distinct group address.  NAN action frames injected
    // through the anchor monitor must use that address2: using the dormant
    // anchor MAC is locally echoed but not admitted by peer NAN engines.
    let nan_tx_mac = p2p_group_ifaces
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(iface)
        .and_then(|group_iface| iface_mac(group_iface).ok())
        .or_else(|| iface_mac(iface).ok());
    let mut followup_dedup = FollowupDedup::new(256);
    let mut buf = [0_u8; 4096];
    let tx_socket = MonitorTxSocket::open(monitor_iface).ok();
    loop {
        if stop_flag.load(Ordering::Acquire) {
            break;
        }
        match socket.recv(&mut buf) {
            Ok(0) => continue,
            Ok(len) => {
                let packet = &buf[..len];
                push_radio_event(
                    &*history,
                    RadioEvent {
                        ts_millis: now_millis(),
                        key: "wifi.raw.socket".to_string(),
                        source: monitor_iface.to_string(),
                        value: json!({"packet_len": len}),
                        message: None,
                    },
                );
                if let Some(frame) = ieee80211_frame(packet) {
                    // Keep bounded receive-path evidence separate from the
                    // parsed DMesh events. This distinguishes a monitor
                    // socket/driver delivery problem from action-parser or
                    // QUIC dispatch rejection without retaining packet data.
                    push_radio_event(
                        &*history,
                        RadioEvent {
                            ts_millis: now_millis(),
                            key: "wifi.raw.monitor".to_string(),
                            source: monitor_iface.to_string(),
                            value: json!({
                                "frame_len": frame.len(),
                                "frame_type": frame_type(frame),
                                "frame_subtype": frame_subtype(frame),
                            }),
                            message: None,
                        },
                    );
                    if frame_subtype(frame) == 13 {
                        push_radio_event(
                            &*history,
                            RadioEvent {
                                ts_millis: now_millis(),
                                key: "wifi.raw.action_candidate".to_string(),
                                source: monitor_iface.to_string(),
                                value: json!({"frame_len": frame.len()}),
                                message: None,
                            },
                        );
                    }
                    // A NAN cluster beacon is preferred, but a normal AP
                    // beacon is the deliberate timing fallback when no
                    // Android NAN publisher is present.  Feed both through
                    // the shared state machine; it selects the NAN cluster
                    // when one appears and otherwise retains the AP TSF.
                    if frame_subtype(frame) == 8 {
                        if let Some(beacon) = handle_beacon_frame(frame, iface, None, &rawnan_state)
                        {
                            push_radio_event(
                                &*history,
                                RadioEvent {
                                    ts_millis: now_millis(),
                                    key: "wifi.rawnan.beacon".to_string(),
                                    source: monitor_iface.to_string(),
                                    value: beacon,
                                    message: None,
                                },
                            );
                        }
                    }
                    let action = rawnan_state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .observe(RawNanRxFrame {
                            bytes: frame,
                            rssi_dbm: 0,
                            timestamp_us: now_micros_u64(),
                        });
                    // AP-management and monitor ingress deliberately share
                    // one semantic path: a packet observed twice is still
                    // marked duplicate at the follow-up layer, instead of
                    // two copies silently evolving different CBOR fields.
                    if frame_subtype(frame) == 13 {
                        record_nan_discovery(
                            frame,
                            iface,
                            nan_tx_mac,
                            monitor_iface,
                            &*history,
                            &rawnan_state,
                            Some(&active_nan_publish),
                            &pending_nan_followups,
                            &mut followup_dedup,
                            |response| {
                                let packet = build_radiotap_packet_at_rate(response, Some(6))?;
                                let socket = tx_socket.as_ref().ok_or_else(|| {
                                    anyhow::anyhow!("monitor TX socket unavailable")
                                })?;
                                socket.send(&packet).and_then(|written| {
                                    (written == packet.len())
                                        .then_some(())
                                        .ok_or_else(|| anyhow::anyhow!("short NAN follow-up write"))
                                })
                            },
                        );
                    }
                    // NAN data frames are selected by the cluster BSSID, not
                    // by the host's ordinary receive MAC.  Admit raw data
                    // payloads as well as the legacy IPv6/UDP diagnostic.
                    let nan_data = is_nan_data_frame(frame);
                    // `local_action_addresses` includes the P2P-GO address
                    // when the monitor is anchored on its parent interface.
                    // A NOW peer replies to the source address it observed,
                    // which is that GO address; filtering only the anchor
                    // aliases here silently dropped the reply before the
                    // bearer-neutral QUIC dispatcher could receive it.
                    if raw_wifi_receive_address_allowed(frame, &local_action_addresses) || nan_data
                    {
                        if let Some(mut value) =
                            parse_dmesh_wifi_frame(frame, iface, "linux_af_packet_monitor")
                        {
                            if let Some(object) = value.as_object_mut() {
                                object.insert(
                                    "nan_action".to_string(),
                                    json!(match action {
                                        RawNanAction::None => "none",
                                        RawNanAction::ArmA3(_) => "arm_a3",
                                        RawNanAction::DropForeign => "drop_foreign",
                                        RawNanAction::Rediscover => "rediscover",
                                    }),
                                );
                            }
                            push_radio_event(
                                &*history,
                                RadioEvent {
                                    ts_millis: now_millis(),
                                    key: "wifi.raw.rx".to_string(),
                                    source: monitor_iface.to_string(),
                                    value,
                                    message: Some(EventMessage::RawWifi { iface: iface.to_string() }),
                                },
                            );
                        }
                    }
                    // ESP-NOW-compatible action frames carry complete
                    // QUIC-lite datagrams. Dispatch them above the radio
                    // adapter, exactly as firmware does, and emit a response
                    // on this same bearer/path. The dispatcher is lazy and
                    // bounded; receiving ambient management traffic does not
                    // allocate a connection or a packet queue.
                    // ESP-NOW-compatible action frames may be delivered by a
                    // monitor driver with Address-1 rewritten (notably for
                    // broadcast action traffic). The vendor-action parser is
                    // the admission check for this bearer; do not apply the
                    // ordinary data-MAC filter before classifying it.
                    let ingress = history.ingress();
                    if let Some(ingress) = ingress {
                        ingress.receive_action_frame(
                            frame,
                            now_micros_u64(),
                            &mut |peer, packet| {
                                // The monitor VIF reflects locally injected frames.
                                // Keep it observable, but separate it from received
                                // peer actions so NOW receive metrics cannot mistake
                                // our own TX echo for evidence of RF delivery.
                                if local_action_addresses.iter().any(|local| *local == peer) {
                                    push_radio_event(
                                        &*history,
                                        RadioEvent {
                                            ts_millis: now_millis(),
                                            key: "wifi.raw.action.reflection".to_string(),
                                            source: monitor_iface.to_string(),
                                            value: json!({
                                                "peer": colon_mac(&peer),
                                                "payload_len": packet.len(),
                                            }),
                                            message: None,
                                        },
                                    );
                                    return false;
                                }
                                let local_source = iface_mac(iface).ok();
                                push_radio_event(
                                    &*history,
                                    RadioEvent {
                                        ts_millis: now_millis(),
                                        key: "wifi.raw.action".to_string(),
                                        source: monitor_iface.to_string(),
                                        value: json!({
                                            "peer": colon_mac(&peer),
                                            "local": local_source.map(|mac| colon_mac(&mac)),
                                            "payload_len": packet.len(),
                                        }),
                                        message: None,
                                    },
                                );
                                match classify_now_payload(packet) {
                                    NowClass::Sync => {
                                        let Some(sync) = crate::parse_now_sync_body(packet) else {
                                            return false;
                                        };
                                        handle_now_sync_as_nan(
                                            local_source.unwrap_or([0; 6]),
                                            peer,
                                            &sync,
                                            now_micros_u64(),
                                            &rawnan_state,
                                        );
                                        history.now_sync(peer, sync.cluster_id, sync.service_info);
                                        false
                                    }
                                    NowClass::Discovery => {
                                        // A request is answered on the same bearer, to
                                        // the sender, as discovery is on every medium.
                                        if let Some(reply) = history.now_discovery(
                                            peer,
                                            mac_at(frame, IEEE80211_ADDR3),
                                            packet,
                                        ) && let Some(socket) = tx_socket.as_ref()
                                        {
                                            let result = send_raw_action_datagram_on_socket(
                                                iface, socket, peer, &reply, 6,
                                            );
                                            push_radio_event(
                                                &*history,
                                                RadioEvent {
                                                    ts_millis: now_millis(),
                                                    key: "wifi.raw.discovery_reply_tx".to_string(),
                                                    source: monitor_iface.to_string(),
                                                    value: json!({
                                                        "ok": result.is_ok(),
                                                        "peer": colon_mac(&peer),
                                                        "bytes": reply.len(),
                                                        "error": result.err().map(|error| format!("{error:#}")),
                                                    }),
                                                    message: None,
                                                },
                                            );
                                        }
                                        false
                                    }
                                    NowClass::Quic => true,
                                }
                            },
                        );
                        continue;
                    }
                    if !matches!(action, RawNanAction::None) {
                        push_radio_event(
                            &*history,
                            RadioEvent {
                                ts_millis: now_millis(),
                                key: "wifi.rawnan.rx".to_string(),
                                source: monitor_iface.to_string(),
                                value: json!({
                                    "ok": true,
                                    "backend": "rawnan_host",
                                    "frame_len": frame.len(),
                                    "frame_hex": hex_bytes(&frame[..frame.len().min(256)]),
                                    "addr1": mac_at(frame, IEEE80211_ADDR1).map(|mac| colon_mac(&mac)),
                                    "addr2": mac_at(frame, IEEE80211_ADDR2).map(|mac| colon_mac(&mac)),
                                    "addr3": mac_at(frame, IEEE80211_ADDR3).map(|mac| colon_mac(&mac)),
                                    "cluster_bssid": rawnan_state
                                        .lock()
                                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                                        .cluster()
                                        .map(|mac| colon_mac(&mac.0)),
                                    "nan_action": match action {
                                        RawNanAction::ArmA3(_) => "arm_a3",
                                        RawNanAction::DropForeign => "drop_foreign",
                                        RawNanAction::Rediscover => "rediscover",
                                        RawNanAction::None => "none",
                                    },
                                }),
                                message: None,
                            },
                        );
                    }
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(error) => {
                push_radio_event(
                    &*history,
                    RadioEvent {
                        ts_millis: now_millis(),
                        key: "wifi.raw.listen.error".to_string(),
                        source: monitor_iface.to_string(),
                        value: json!({
                            "ok": false,
                            "iface": iface,
                            "monitor_iface": monitor_iface,
                            "error": error.to_string()
                        }),
                        message: None,
                    },
                );
                break;
            }
        }
    }
}

pub fn ap_mgmt_receive_loop(
    socket: Nl80211Socket,
    iface: &str,
    ifindex: u32,
    ap_mac: [u8; 6],
    history: Arc<dyn CaptureHost>,
    rawnan_state: Arc<Mutex<NanState>>,
    active_nan_publish: Arc<Mutex<NanActivePublish>>,
    pending_nan_followups: Arc<Mutex<crate::NanFollowupQueue>>,
    ap_no_ht_stations: Arc<Mutex<HashSet<[u8; 6]>>>,
    channel: u8,
    ht40: bool,
    stop: Arc<AtomicBool>,
) {
    let _ = socket.set_receive_timeout(Duration::from_millis(100));
    // AP-mode management RX is a real NAN ingress lane on adapters that do
    // not mirror public actions to the monitor child. Keep the same bounded
    // follow-up deduplication as the monitor path so AP and unassociated
    // hosts expose one discovery contract.
    let mut followup_dedup = FollowupDedup::new(256);
    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }
        match socket.recv_frame_with_signal() {
            Ok((frame, rx_signal_dbm)) => {
                let mut value = parse_management_frame(&frame, iface, "linux_nl80211_ap_sme");
                if frame_subtype(&frame) == 8
                    && let Some(beacon) =
                        handle_beacon_frame(&frame, iface, rx_signal_dbm, &rawnan_state)
                    && let Some(object) = value.as_object_mut()
                {
                    object.insert("beacon_sync".to_string(), beacon);
                }
                if frame_subtype(&frame) == 13 {
                    if let Some(action) =
                        handle_action_frame(&frame, iface, rx_signal_dbm, &rawnan_state)
                        && let Some(object) = value.as_object_mut()
                    {
                        object.insert("action_frame".to_string(), action);
                    }
                    if let Some(response) = build_dmesh_p2p_sd_response(ap_mac, &frame) {
                        let tx =
                            send_open_ap_mgmt_response(&socket, iface, ifindex, channel, &response);
                        if let Some(object) = value.as_object_mut() {
                            // This proves that a validated DMesh GAS request
                            // reached shared host ingress and its matching
                            // DNS-SD/CBOR public-action response was emitted.
                            object.insert(
                                "p2p_sd_response".to_string(),
                                json!({
                                    "kind": "gas_initial_response_dmesh",
                                    "frame_len": response.len(),
                                    "tx": tx,
                                }),
                            );
                        }
                    }
                    // The AP management socket may be the only receiver to
                    // see a host-generated SDF. Feed it through the same
                    // semantic event/follow-up path as monitor ingress;
                    // sending a response reuses the permanent monitor and
                    // never changes AP or interface state.
                    record_nan_discovery(
                        &frame,
                        iface,
                        Some(ap_mac),
                        iface,
                        &*history,
                        &rawnan_state,
                        Some(&active_nan_publish),
                        &pending_nan_followups,
                        &mut followup_dedup,
                        |response| {
                            send_monitor_frame(iface, channel, response, Some(6)).map(|_| ())
                        },
                    );
                }
                if ap_sme_station_departed(frame_subtype(&frame))
                    && let Some(sta_mac) = mac_at(&frame, IEEE80211_ADDR2)
                    && let Some(object) = value.as_object_mut()
                {
                    // nl80211's AP SME does not remove a userspace-added
                    // station entry when the STA sends disassoc/deauth.  A
                    // retained entry made the next ESP association unreliable
                    // until an operator manually removed it.  The operation
                    // is idempotent, and association still replaces any
                    // remaining entry as its separate recovery path.
                    let removed = Nl80211Socket::open()
                        .and_then(|socket| socket.remove_station(ifindex, sta_mac))
                        .is_ok();
                    object.insert("station_removed".to_string(), json!(removed));
                }
                if let Some(response) = handle_open_ap_sme_frame(
                    &socket,
                    iface,
                    ifindex,
                    ap_mac,
                    &frame,
                    &ap_no_ht_stations,
                    channel,
                    ht40,
                ) && let Some(object) = value.as_object_mut()
                {
                    object.insert("sme_response".to_string(), response);
                }
                if let Some(signal) = rx_signal_dbm
                    && let Some(object) = value.as_object_mut()
                {
                    object.insert("rx_signal_dbm".to_string(), json!(signal));
                }
                let source = value
                    .get("source")
                    .and_then(Value::as_str)
                    .unwrap_or(iface)
                    .to_string();
                let message = EventMessage::Mgmt {
                    source: source.clone(),
                    iface: iface.to_string(),
                    status: value
                        .get("kind")
                        .and_then(Value::as_str)
                        .unwrap_or("mgmt")
                        .to_string(),
                    rssi_dbm: rx_signal_dbm,
                };
                let beacon_sync = (frame_subtype(&frame) == 8)
                    .then(|| value.get("beacon_sync").cloned())
                    .flatten();
                push_radio_event(
                    &*history,
                    RadioEvent {
                        ts_millis: now_millis(),
                        key: "wifi.ap.mgmt".to_string(),
                        source: iface.to_string(),
                        value,
                        message: Some(message),
                    },
                );
                if crate::is_nan_beacon(&frame) {
                    if let Some(beacon_sync) = beacon_sync {
                        push_radio_event(
                            &*history,
                            RadioEvent {
                                ts_millis: now_millis(),
                                key: "wifi.rawnan.beacon".to_string(),
                                source: iface.to_string(),
                                value: beacon_sync,
                                message: None,
                            },
                        );
                    }
                }
            }
            Err(error) => {
                if stop.load(Ordering::Acquire)
                    || error.downcast_ref::<std::io::Error>().is_some_and(|error| {
                        error.kind() == std::io::ErrorKind::WouldBlock
                            || error.kind() == std::io::ErrorKind::TimedOut
                    })
                {
                    continue;
                }
                push_radio_event(
                    &*history,
                    RadioEvent {
                        ts_millis: now_millis(),
                        key: "wifi.ap.mgmt.error".to_string(),
                        source: iface.to_string(),
                        value: json!({ "ok": false, "iface": iface, "error": error.to_string() }),
                        message: None,
                    },
                );
                break;
            }
        }
    }
}

/// One caller-requested active NAN Subscribe. It retains only portable
/// Service Info; the monitor builds a fresh frame at each confirmed DW using
/// the current local MAC and cluster BSSID. Repeating through the next DW0 or
/// DW8 lets sleepy peers see the same correlation ID without a timer or a
/// second radio owner.
#[derive(Clone, Debug)]
pub struct PendingNanActiveSubscribe {
    pub service_info: Vec<u8>,
    /// The peer this request is about, for reporting. A NAN Subscribe is always addressed
    /// to the NAN discovery address, as the firmware's is and as Android's NAN stack
    /// accepts it; a request that concerns one device names it inside its own record
    /// (a wake carries `wake_target`), and every peer sees the Subscribe.
    pub target: Option<[u8; 6]>,
    pub request_id: u64,
    pub sent_windows: u8,
    pub last_slot: Option<u64>,
}

pub fn nl80211_receive_loop(
    socket: Nl80211Socket,
    iface: &str,
    history: Arc<dyn CaptureHost>,
) {
    loop {
        match socket.recv_frame() {
            Ok(frame) => {
                if let Some(value) = parse_dmesh_vendor_action(&frame, iface) {
                    push_radio_event(
                        &*history,
                        RadioEvent {
                            ts_millis: now_millis(),
                            key: "wifi.raw.rx".to_string(),
                            source: iface.to_string(),
                            value,
                            message: Some(EventMessage::RawWifi { iface: iface.to_string() }),
                        },
                    );
                }
            }
            Err(error) => {
                push_radio_event(
                    &*history,
                    RadioEvent {
                        ts_millis: now_millis(),
                        key: "wifi.raw.listen.error".to_string(),
                        source: iface.to_string(),
                        value: json!({ "ok": false, "iface": iface, "error": error.to_string() }),
                        message: None,
                    },
                );
                break;
            }
        }
    }
}

/// Feed registered management beacons into the same NAN state machine as the
/// monitor path. This owns no interface lifecycle and is intentionally a
/// fallback for adapters whose active monitor VIF drops beacon RX.
pub fn nl80211_nan_beacon_receive_loop(
    socket: Nl80211Socket,
    iface: &str,
    history: Arc<dyn CaptureHost>,
    rawnan_state: Arc<Mutex<NanState>>,
    pending_nan_followups: Arc<Mutex<crate::NanFollowupQueue>>,
    stop: Arc<AtomicBool>,
) {
    let _ = socket.set_receive_timeout(Duration::from_millis(250));
    let mut followup_dedup = FollowupDedup::new(256);
    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }
        match socket.recv_frame_with_signal() {
            Ok((frame, rx_signal_dbm)) => {
                match frame_subtype(&frame) {
                    8 => {
                        if let Some(beacon) =
                            handle_beacon_frame(&frame, iface, rx_signal_dbm, &rawnan_state)
                        {
                            push_radio_event(
                                &*history,
                                RadioEvent {
                                    ts_millis: now_millis(),
                                    key: "wifi.rawnan.beacon".to_string(),
                                    source: iface.to_string(),
                                    value: beacon,
                                    message: None,
                                },
                            );
                        }
                    }
                    13 => {
                        // This is the base-interface fallback for adapters
                        // that do not mirror NAN SDFs to the monitor VIF.
                        // It shares the semantic registry/deduplication path
                        // with monitor and AP-SME ingress.  The fallback does
                        // not transmit follow-ups: a received active request
                        // is reported as such instead of claiming a response
                        // from a monitor that did not receive the frame.
                        record_nan_discovery(
                            &frame,
                            iface,
                            iface_mac(iface).ok(),
                            iface,
                            &*history,
                            &rawnan_state,
                            None,
                            &pending_nan_followups,
                            &mut followup_dedup,
                            |_| Err(anyhow::anyhow!("nl80211 NAN fallback has no TX lane")),
                        );
                        if let Some(action) =
                            handle_action_frame(&frame, iface, rx_signal_dbm, &rawnan_state)
                        {
                            push_radio_event(
                                &*history,
                                RadioEvent {
                                    ts_millis: now_millis(),
                                    key: "wifi.rawnan.action".to_string(),
                                    source: iface.to_string(),
                                    value: action,
                                    message: None,
                                },
                            );
                        }
                    }
                    _ => {}
                }
            }
            Err(error)
                if error
                    .to_string()
                    .contains("Resource temporarily unavailable") =>
            {
                continue;
            }
            Err(error) => {
                push_radio_event(
                    &*history,
                    RadioEvent {
                        ts_millis: now_millis(),
                        key: "wifi.rawnan.beacon_listener.error".to_string(),
                        source: iface.to_string(),
                        value: json!({"ok": false, "error": error.to_string()}),
                        message: None,
                    },
                );
                break;
            }
        }
    }
}

/// What the window scheduler transmits, and from where.
pub struct WindowSchedule {
    pub iface: String,
    pub monitor_iface: String,
    pub nan: Arc<Mutex<NanState>>,
    pub publish: Arc<Mutex<NanActivePublish>>,
    pub subscribe: Arc<Mutex<Option<PendingNanActiveSubscribe>>>,
    pub now_discovery: Arc<Mutex<Option<PendingNowDiscovery>>>,
    /// The local announce, broadcast on NOW like the NAN publish (firmware does both).
    pub now_publish: Arc<Mutex<Option<PendingNowDiscovery>>>,
    pub followups: Arc<Mutex<crate::NanFollowupQueue>>,
}

/// Run one discovery window's transmissions, in order: the periodic publish, the
/// active Subscribe, the NOW request, then follow-ups. NAN frames go out as 802.11
/// management frames, NOW requests as NOW actions; both through `nan_tx` / `now_tx`.
fn unix_micros() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_micros() as u64)
}

pub fn run_discovery_window(
    schedule: &WindowSchedule,
    host: &dyn CaptureHost,
    window: &DiscoveryWindow,
    local: [u8; 6],
    nan_tx: &mut dyn FnMut(&[u8]) -> Result<()>,
    now_tx: &mut dyn FnMut(Option<[u8; 6]>, &[u8]) -> Result<()>,
) {
    let source = &schedule.monitor_iface;
    drain_active_nan_publish(local, source, host, &schedule.nan, window, &schedule.publish, |frame| nan_tx(frame));
    drain_pending_nan_active_subscribe(
        local, source, host, &schedule.nan, window, &schedule.subscribe, |frame| nan_tx(frame),
    );
    drain_pending_now_discovery(source, host, window, &schedule.now_publish, |target, request| {
        now_tx(target, request)
    });
    drain_pending_now_discovery(source, host, window, &schedule.now_discovery, |target, request| {
        now_tx(target, request)
    });
    drain_pending_nan_followups(local, source, host, &schedule.nan, window, &schedule.followups, |frame| nan_tx(frame));
    let _ = send_now_sync(local, &schedule.nan, &schedule.publish, |body| now_tx(None, body));
}

/// Send this device's NOW sync record, the beacon-equivalent every NOW-capable device
/// emits in each window so the others can follow the same cluster: the followed
/// cluster's (the NAN cluster's, when one is followed), or this device's own when it is the
/// anchor master. The local announce rides in it, as it does in a NAN beacon's service.
fn send_now_sync(
    local: [u8; 6],
    nan: &Arc<Mutex<NanState>>,
    publish: &Arc<Mutex<crate::NanActivePublish>>,
    send: impl FnOnce(&[u8]) -> Result<()>,
) -> Result<()> {
    let now = now_micros_u64();
    let out = {
        let mut state = nan.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // The master's own sync is refreshed by being sent; a follower is left alone.
        state.become_now_master(crate::MacAddr(local), now, unix_micros());
        state.now_sync_outgoing(now)
    };
    let Some(out) = out else {
        return Ok(());
    };
    let info = publish
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .service_info()
        .to_vec();
    let info = &info[..info.len().min(crate::NOW_SYNC_SERVICE_INFO_MAX_LEN)];
    send(&crate::build_now_sync_body(
        out.cluster_id,
        out.anchor_master,
        out.tsf_us,
        out.interval_tu,
        out.flags,
        info,
    )?)
}

/// Sync on the discovery window and transmit in it. The window is extrapolated from the
/// last NAN beacon (or NOW sync): every 512 TU from its local receive time, numbered by
/// its TSF, so each window is served once, at its start, whether or not a beacon
/// happens to arrive then, and DW0/DW8 are known. A lost sync (no beacon for the
/// cluster staleness limit) means no window and nothing is sent. Runs until `stop`.
pub fn run_window_scheduler(schedule: WindowSchedule, host: Arc<dyn CaptureHost>, stop: Arc<AtomicBool>) {
    let tx = loop {
        if stop.load(Ordering::Acquire) {
            return;
        }
        match MonitorTxSocket::open(&schedule.monitor_iface) {
            Ok(socket) => break socket,
            Err(_) => std::thread::sleep(Duration::from_secs(1)),
        }
    };
    let mut last_slot = None;
    let mut listening_since: Option<u64> = None;
    while !stop.load(Ordering::Acquire) {
        let now = now_micros_u64();
        let window = schedule
            .nan
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .window_at_or_after(now);
        let Some(window) = window else {
            // Nothing to follow: listen for one reselect interval (a NAN beacon or a NOW
            // record ends this), then form the NOW cluster with this device as its anchor
            // master, the way a lone NAN device becomes its own anchor master.
            let since = *listening_since.get_or_insert(now);
            if now.saturating_sub(since) >= crate::NAN_CLUSTER_RESELECT_AFTER_US
                && let Ok(local) = iface_mac(&schedule.iface)
            {
                schedule
                    .nan
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .become_now_master(crate::MacAddr(local), now, unix_micros());
                listening_since = None;
            }
            std::thread::sleep(Duration::from_millis(250));
            continue;
        };
        listening_since = None;
        if window.start_local_us > now {
            let wait = (window.start_local_us - now).min(250_000);
            std::thread::sleep(Duration::from_micros(wait));
            continue;
        }
        if last_slot == Some(window.slot) {
            // Already served; the dwell is over soon, then the next window is ahead.
            std::thread::sleep(Duration::from_millis(5));
            continue;
        }
        last_slot = Some(window.slot);
        let Ok(local) = iface_mac(&schedule.iface) else {
            continue;
        };
        let mut nan_tx = |frame: &[u8]| -> Result<()> {
            let packet = build_radiotap_packet_at_rate(frame, Some(6))?;
            tx.send(&packet).and_then(|written| {
                (written == packet.len())
                    .then_some(())
                    .ok_or_else(|| anyhow::anyhow!("short NAN write"))
            })
        };
        let mut now_tx = |target: Option<[u8; 6]>, request: &[u8]| -> Result<()> {
            send_raw_action_datagram_on_socket(
                &schedule.iface,
                &tx,
                target.unwrap_or([0xff; 6]),
                request,
                6,
            )
        };
        run_discovery_window(&schedule, &*host, &window, local, &mut nan_tx, &mut now_tx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder {
        events: Mutex<Vec<(String, Value)>>,
        announces: Mutex<Vec<(String, Option<String>, Vec<Vec<u8>>)>>,
        packets: Mutex<Vec<(String, NanPacketKind, Vec<u8>)>>,
        valid_announce: bool,
    }

    impl CaptureHost for Recorder {
        fn event(&self, event: RadioEvent) {
            self.events.lock().unwrap().push((event.key, event.value));
        }
        fn nan_announce(&self, peer: &str, bssid: Option<&str>, payloads: &[&[u8]]) -> NanAnnounce {
            self.announces.lock().unwrap().push((
                peer.to_owned(),
                bssid.map(str::to_owned),
                payloads.iter().map(|payload| payload.to_vec()).collect(),
            ));
            NanAnnounce {
                invalid_identity: false,
                summary: self.valid_announce.then(|| json!({"kind": 1})),
            }
        }
        fn nan_packet(&self, peer: &str, _: Option<&str>, kind: NanPacketKind, payload: &[u8]) {
            self.packets.lock().unwrap().push((peer.to_owned(), kind, payload.to_vec()));
        }
        fn now_sync(&self, _: [u8; 6], _: [u8; 6], _: &[u8]) {}
        fn now_discovery(&self, _: [u8; 6], _: Option<[u8; 6]>, _: &[u8]) -> Option<Vec<u8>> {
            None
        }
        fn ingress(&self) -> Option<Arc<dyn super::super::espnow_bearer::EspNowIngress>> {
            None
        }
    }

    fn state() -> (Arc<Mutex<NanState>>, Arc<Mutex<crate::NanFollowupQueue>>) {
        (
            Arc::new(Mutex::new(NanState::new(crate::NAN_CLUSTER_STALE_AFTER_US))),
            Arc::new(Mutex::new(crate::NanFollowupQueue::new(8))),
        )
    }

    #[test]
    fn now_payloads_split_into_sync_quic_and_discovery() {
        // QUIC fixed bit set: an opaque datagram.
        assert_eq!(classify_now_payload(&[0x41, 1, 2, 3]), NowClass::Quic);
        // A discovery payload has the fixed bit clear; rawnan does not decode it.
        assert_eq!(classify_now_payload(&[0xa1, 0x01, 0x02]), NowClass::Discovery);
        assert_eq!(classify_now_payload(&[]), NowClass::Discovery);
    }

    #[test]
    fn a_published_descriptor_reaches_the_host_with_its_payload_and_a_discovery_event() {
        let (nan, followups) = state();
        let peer = [0x02, 1, 2, 3, 4, 5];
        let frame = crate::build_nan_publish_sdf(
            crate::NAN_DISCOVERY_MAC,
            peer,
            [0x50, 0x6f, 0x9a, 0x01, 0xff, 0xff],
            crate::DMESH_SERVICE_ID,
            1,
            b"announce-bytes",
        );
        let host = Recorder {
            valid_announce: true,
            ..Default::default()
        };
        let mut dedup = FollowupDedup::new(8);
        record_nan_discovery(
            &frame,
            "wlan0",
            Some([0x02, 9, 9, 9, 9, 9]),
            "wlan0mon",
            &host,
            &nan,
            None,
            &followups,
            &mut dedup,
            |_| Ok(()),
        );
        let announces = host.announces.lock().unwrap();
        assert_eq!(announces.len(), 1);
        assert_eq!(announces[0].0, "02:01:02:03:04:05");
        assert!(announces[0].2.iter().any(|payload| payload == b"announce-bytes"));
        let events = host.events.lock().unwrap();
        let discovery = events
            .iter()
            .find(|(key, _)| key == "wifi.rawnan.discovery")
            .expect("a discovery event");
        assert_eq!(discovery.1["announce"]["kind"], 1);
        assert_eq!(discovery.1["peer"], "02:01:02:03:04:05");
    }

    #[test]
    fn our_own_active_subscribe_is_not_discovery_evidence() {
        let (nan, followups) = state();
        let local = [0x02, 9, 9, 9, 9, 9];
        let frame = crate::build_nan_usd_sdf_with_bssid(
            crate::NAN_DISCOVERY_MAC,
            local,
            [0x50, 0x6f, 0x9a, 0x01, 0xff, 0xff],
            crate::DMESH_SERVICE_ID,
            9,
            0x11,
            b"control",
        );
        let host = Recorder::default();
        let mut dedup = FollowupDedup::new(8);
        record_nan_discovery(
            &frame, "wlan0", Some(local), "wlan0mon", &host, &nan, None, &followups, &mut dedup,
            |_| Ok(()),
        );
        assert!(host.packets.lock().unwrap().is_empty());
        assert!(host.events.lock().unwrap().iter().all(|(key, _)| key != "wifi.rawnan.discovery"));
    }

    #[test]
    fn a_remote_active_subscribe_is_reported_to_the_host_as_a_packet() {
        let (nan, followups) = state();
        let frame = crate::build_nan_usd_sdf_with_bssid(
            crate::NAN_DISCOVERY_MAC,
            [0x02, 1, 2, 3, 4, 5],
            [0x50, 0x6f, 0x9a, 0x01, 0xff, 0xff],
            crate::DMESH_SERVICE_ID,
            9,
            0x11,
            b"control",
        );
        let host = Recorder::default();
        let mut dedup = FollowupDedup::new(8);
        record_nan_discovery(
            &frame,
            "wlan0",
            Some([0x02, 9, 9, 9, 9, 9]),
            "wlan0mon",
            &host,
            &nan,
            None,
            &followups,
            &mut dedup,
            |_| Ok(()),
        );
        let packets = host.packets.lock().unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].1, NanPacketKind::ActiveSubscribe);
        // With no local publish configured there is nothing to answer with, and the
        // event says so rather than pretending.
        let events = host.events.lock().unwrap();
        assert!(events.iter().any(|(key, value)| key == "wifi.rawnan.followup_tx" && value["ok"] == false));
    }

    /// A NAN beacon (the cluster BSSID, TSF and interval at fixed offsets).
    fn nan_beacon(bssid: [u8; 6], tsf_us: u64) -> Vec<u8> {
        let mut frame = vec![0_u8; 34];
        frame[0] = 0x80;
        frame[16..22].copy_from_slice(&bssid);
        frame[24..32].copy_from_slice(&tsf_us.to_le_bytes());
        frame[32..34].copy_from_slice(&100u16.to_le_bytes());
        frame
    }

    /// A state that has seen a beacon: it has a cluster, so frames can be addressed.
    fn synced() -> Arc<Mutex<NanState>> {
        let (nan, _) = state();
        let beacon = nan_beacon([0x50, 0x6f, 0x9a, 0x01, 0x00, 0x01], crate::NAN_DISCOVERY_PERIOD_US + 1);
        nan.lock().unwrap().observe(RawNanRxFrame {
            bytes: &beacon,
            rssi_dbm: 0,
            timestamp_us: now_micros_u64(),
        });
        nan
    }

    fn window(slot: u64) -> DiscoveryWindow {
        DiscoveryWindow {
            slot,
            start_local_us: 0,
        }
    }

    fn pending(target: Option<[u8; 6]>) -> Arc<Mutex<Option<PendingNowDiscovery>>> {
        Arc::new(Mutex::new(Some(PendingNowDiscovery {
            request: b"request".to_vec(),
            target,
            request_id: 7,
            sent_windows: 0,
            last_slot: None,
        })))
    }

    #[test]
    fn a_now_request_goes_out_once_per_discovery_window_and_stops_after_dw0_or_dw8() {
        let host = Recorder::default();
        let sent = Mutex::new(Vec::new());
        let queue = pending(None);
        let mut send = |target: Option<[u8; 6]>, request: &[u8]| -> Result<()> {
            sent.lock().unwrap().push((target, request.to_vec()));
            Ok(())
        };
        // Window 3: sent, and kept for the next window; a second pass in it sends nothing.
        for _ in 0..2 {
            drain_pending_now_discovery("wlan0mon", &host, &window(3), &queue, &mut send);
        }
        assert_eq!(sent.lock().unwrap().len(), 1, "once per window");
        assert_eq!(sent.lock().unwrap()[0], (None, b"request".to_vec()));
        assert_eq!(queue.lock().unwrap().as_ref().unwrap().sent_windows, 1);
        drain_pending_now_discovery("wlan0mon", &host, &window(4), &queue, &mut send);
        assert_eq!(sent.lock().unwrap().len(), 2);
        // Window 8 is DW0/DW8 for a sleepy peer: sent, and then the request is done.
        drain_pending_now_discovery("wlan0mon", &host, &window(8), &queue, &mut send);
        assert_eq!(sent.lock().unwrap().len(), 3);
        assert!(queue.lock().unwrap().is_none());
        let events = host.events.lock().unwrap();
        assert_eq!(events.iter().filter(|(_, value)| value["terminal_dw0_or_dw8"] == true).count(), 1);
    }

    #[test]
    fn a_directed_now_request_keeps_its_target() {
        let host = Recorder::default();
        let peer = [0x02, 1, 2, 3, 4, 5];
        let queue = pending(Some(peer));
        let sent = Mutex::new(Vec::new());
        drain_pending_now_discovery("wlan0mon", &host, &window(3), &queue, |target, _| {
            sent.lock().unwrap().push(target);
            Ok(())
        });
        assert_eq!(*sent.lock().unwrap(), [Some(peer)]);
    }

    #[test]
    fn a_failed_send_is_reported_in_the_event_and_retried_next_window() {
        let host = Recorder::default();
        let queue = pending(None);
        drain_pending_now_discovery("wlan0mon", &host, &window(3), &queue, |_, _| bail!("monitor TX socket unavailable"));
        let events = host.events.lock().unwrap();
        assert_eq!(events[0].1["ok"], false);
        assert!(events[0].1["error"].as_str().unwrap().contains("unavailable"));
        assert!(queue.lock().unwrap().is_some());
    }

    #[test]
    fn a_nan_subscribe_is_always_addressed_to_the_nan_discovery_address() {
        let host = Recorder::default();
        let peer = [0x02, 1, 2, 3, 4, 5];
        for target in [Some(peer), None] {
            let expected = crate::NAN_DISCOVERY_MAC;
            let queue = Arc::new(Mutex::new(Some(PendingNanActiveSubscribe {
                service_info: b"request".to_vec(),
                target,
                request_id: 5,
                sent_windows: 0,
                last_slot: None,
            })));
            let sent = Mutex::new(Vec::new());
            drain_pending_nan_active_subscribe(
                [0x02, 9, 9, 9, 9, 9],
                "wlan0mon",
                &host,
                &synced(),
                &window(3),
                &queue,
                |frame| {
                    sent.lock().unwrap().push(frame.to_vec());
                    Ok(())
                },
            );
            let sent = sent.lock().unwrap();
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0][4..10], expected);
        }
    }

    #[test]
    fn one_window_sends_publish_subscribe_the_now_request_and_followups_in_that_order() {
        let host = Recorder::default();
        let nan = synced();
        let publish = Arc::new(Mutex::new(NanActivePublish::new(1)));
        publish.lock().unwrap().configure(true, b"announce").unwrap();
        let subscribe = Arc::new(Mutex::new(Some(PendingNanActiveSubscribe {
            service_info: b"subscribe".to_vec(),
            target: None,
            request_id: 1,
            sent_windows: 0,
            last_slot: None,
        })));
        let followups = Arc::new(Mutex::new(crate::NanFollowupQueue::new(8)));
        followups.lock().unwrap().enqueue(crate::NanFollowupIntent {
            destination: [0x02, 1, 2, 3, 4, 5],
            instance: 1,
            requestor_instance: 9,
            payload: b"followup".to_vec(),
            queued_at_us: now_micros_u64(),
        });
        let schedule = WindowSchedule {
            iface: "wlan0".to_owned(),
            monitor_iface: "wlan0mon".to_owned(),
            nan,
            publish,
            subscribe,
            now_discovery: pending(None),
            now_publish: Arc::new(Mutex::new(None)),
            followups,
        };
        let order = Mutex::new(Vec::new());
        let mut nan_tx = |frame: &[u8]| -> Result<()> {
            let tag = if frame.windows(8).any(|w| w == b"announce") {
                "publish"
            } else if frame.windows(9).any(|w| w == b"subscribe") {
                "subscribe"
            } else {
                "followup"
            };
            order.lock().unwrap().push(tag);
            Ok(())
        };
        let sync = Mutex::new(None);
        let mut now_tx = |_: Option<[u8; 6]>, body: &[u8]| -> Result<()> {
            if crate::is_now_sync(body) {
                order.lock().unwrap().push("sync");
                *sync.lock().unwrap() = Some(body.to_vec());
            } else {
                order.lock().unwrap().push("now");
            }
            Ok(())
        };
        run_discovery_window(&schedule, &host, &window(3), [0x02, 9, 9, 9, 9, 9], &mut nan_tx, &mut now_tx);
        // The NOW sync record closes the window; it carries the announce.
        assert_eq!(*order.lock().unwrap(), ["publish", "subscribe", "now", "followup", "sync"]);
        let body = sync.lock().unwrap().clone().unwrap();
        let record = crate::parse_now_sync_body(&body).unwrap();
        assert_eq!(record.service_info, b"announce");
        // The cluster followed is a NAN one (the test state is synced on a NAN beacon).
        assert!(record.is_nan_aligned() && !record.is_master());
    }
}
