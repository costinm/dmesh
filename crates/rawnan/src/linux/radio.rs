//! The raw Wi-Fi bearer as one object: an interface that is an open AP on the shared
//! channel plus a monitor VIF, carrying NOW (the QUIC bearer and its NAN-like
//! discovery) and NAN. There is no `wpa_supplicant` and no separate AP API.
//!
//! [`Radio::new`] returns the QUIC [`EspNowBearer`] and a [`Radio`] handle.
//! [`Radio::start`] runs the start chain ([`start_chain`]) and the capture threads;
//! everything the capture sees that is discovery goes to the caller's [`Observer`] as
//! bytes with its radio facts, so the discovery engine decides what it means. Nothing
//! here decodes an announce or knows an inventory.

use super::*;
use crate::{NanActivePublish, NanState};
use super::espnow_bearer::{EspNowBearer, EspNowIngress};
use std::collections::BTreeMap;
use std::sync::atomic::AtomicU64;

/// The single local active-publish descriptor.
pub const NAN_ACTIVE_PUBLISH_INSTANCE: u8 = 1;
const MAX_PENDING_NAN_FOLLOWUPS: usize = 32;
/// The SSID of the open AP.
pub const DEFAULT_SSID: &str = "DIRECT-dmesh";
/// A NAN sync older than this is not a sync.
const SYNC_FRESH_MS: u64 = 4_000;

/// What to run on.
#[derive(Clone, Debug)]
pub struct RadioConfig {
    pub iface: String,
    pub monitor: String,
    pub ssid: String,
    pub channel: u8,
}

impl RadioConfig {
    /// The interface on the shared channel, its conventional monitor VIF, default SSID.
    pub fn for_interface(iface: &str) -> Self {
        Self {
            iface: iface.to_owned(),
            monitor: monitor_iface_name(iface),
            ssid: DEFAULT_SSID.to_owned(),
            channel: SHARED_CHANNEL,
        }
    }
}

/// What kind of NOW discovery payload arrived.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NowKind {
    /// A cluster-sync record carrying a service info.
    Sync,
    /// A discovery payload (the same bytes NAN carries as service info).
    Discovery,
}

/// The discovery side of the bearer. Implemented by whoever owns the inventory.
pub trait Observer: Send + Sync {
    /// The service-descriptor payloads of one NAN frame from `peer`.
    fn nan(&self, peer: [u8; 6], bssid: Option<[u8; 6]>, payloads: &[&[u8]]) -> NanAnnounce;
    /// An active Subscribe or follow-up payload from `peer`.
    fn nan_packet(&self, peer: [u8; 6], bssid: Option<[u8; 6]>, kind: NanPacketKind, payload: &[u8]);
    /// A NOW discovery payload from `peer`.
    /// A request is answered: return the bytes to send back to `peer`.
    fn now(
        &self,
        peer: [u8; 6],
        bssid: Option<[u8; 6]>,
        kind: NowKind,
        payload: &[u8],
    ) -> Option<Vec<u8>>;
}

/// Capture counters since start (or the last reset).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Counters {
    /// 802.11 frames the monitor delivered, and their bytes.
    pub frames: u64,
    pub bytes: u64,
    pub management_frames: u64,
    pub control_frames: u64,
    pub data_frames: u64,
    /// NAN beacons and NAN service frames seen.
    pub nan_beacons: u64,
    pub nan_service_frames: u64,
    /// NOW action frames from a peer, and those handed to the QUIC bearer.
    pub now_actions: u64,
    pub now_quic: u64,
    /// Our own injected frames reflected by the monitor.
    pub now_reflections: u64,
    /// Management action frames that could have been NOW.
    pub action_candidates: u64,
    /// NOW transmissions attempted, accepted by the monitor socket, and failed.
    pub now_tx_attempted: u64,
    pub now_tx_accepted: u64,
    pub now_tx_failed: u64,
}

#[derive(Default)]
struct AtomicCounters {
    frames: AtomicU64,
    bytes: AtomicU64,
    management: AtomicU64,
    control: AtomicU64,
    data: AtomicU64,
    nan_beacons: AtomicU64,
    nan_service_frames: AtomicU64,
    now_actions: AtomicU64,
    now_quic: AtomicU64,
    now_reflections: AtomicU64,
    action_candidates: AtomicU64,
}

impl AtomicCounters {
    fn snapshot(&self) -> Counters {
        let load = |value: &AtomicU64| value.load(Ordering::Relaxed);
        Counters {
            frames: load(&self.frames),
            bytes: load(&self.bytes),
            management_frames: load(&self.management),
            control_frames: load(&self.control),
            data_frames: load(&self.data),
            nan_beacons: load(&self.nan_beacons),
            nan_service_frames: load(&self.nan_service_frames),
            now_actions: load(&self.now_actions),
            now_quic: load(&self.now_quic),
            now_reflections: load(&self.now_reflections),
            action_candidates: load(&self.action_candidates),
            now_tx_attempted: super::frames::NOW_TX_ATTEMPTED.load(Ordering::Relaxed),
            now_tx_accepted: super::frames::NOW_TX_ACCEPTED.load(Ordering::Relaxed),
            now_tx_failed: super::frames::NOW_TX_FAILED.load(Ordering::Relaxed),
        }
    }

    fn reset(&self) {
        for value in [
            &self.frames,
            &self.bytes,
            &self.management,
            &self.control,
            &self.data,
            &self.nan_beacons,
            &self.nan_service_frames,
            &self.now_actions,
            &self.now_quic,
            &self.now_reflections,
            &self.action_candidates,
        ] {
            value.store(0, Ordering::Relaxed);
        }
        for value in [
            &super::frames::NOW_TX_ATTEMPTED,
            &super::frames::NOW_TX_ACCEPTED,
            &super::frames::NOW_TX_FAILED,
        ] {
            value.store(0, Ordering::Relaxed);
        }
    }
}

/// NAN synchronization and publish state, for status.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NanStatus {
    /// The capture is running.
    pub active: bool,
    pub cluster_id: Option<[u8; 6]>,
    pub sync_id: Option<[u8; 6]>,
    pub sync_age_ms: Option<u64>,
    pub publishing: bool,
}

impl NanStatus {
    /// A cluster is known and its last beacon is recent enough to schedule a
    /// discovery-window transmission.
    pub fn synced(&self) -> bool {
        self.cluster_id.is_some() && self.sync_age_ms.is_some_and(|age| age <= SYNC_FRESH_MS)
    }
}

struct Core {
    config: RadioConfig,
    observer: Arc<dyn Observer>,
    nan: Arc<Mutex<NanState>>,
    publish: Arc<Mutex<NanActivePublish>>,
    subscribe: Arc<Mutex<Option<PendingNanActiveSubscribe>>>,
    followups: Arc<Mutex<crate::NanFollowupQueue>>,
    now_discovery: Arc<Mutex<Option<PendingNowDiscovery>>>,
    now_publish: Arc<Mutex<Option<PendingNowDiscovery>>>,
    tx: Mutex<Option<MonitorTxSocket>>,
    ingress: Arc<Mutex<Option<Arc<dyn EspNowIngress>>>>,
    counters: AtomicCounters,
}

fn peer_array(peer: &str) -> Option<[u8; 6]> {
    parse_mac(Some(peer))
}

impl CaptureHost for Core {
    fn event(&self, event: RadioEvent) {
        let load = |value: &AtomicU64| value.fetch_add(1, Ordering::Relaxed);
        let counters = &self.counters;
        // Packet-rate observations are counted, not retained.
        match event.key.as_str() {
            "wifi.raw.socket" => return,
            "wifi.raw.monitor" => {
                let number = |name: &str| event.value.get(name).and_then(Value::as_u64).unwrap_or(0);
                load(&counters.frames);
                counters.bytes.fetch_add(number("frame_len"), Ordering::Relaxed);
                match number("frame_type") {
                    0 => load(&counters.management),
                    1 => load(&counters.control),
                    2 => load(&counters.data),
                    _ => 0,
                };
                return;
            }
            "wifi.raw.action_candidate" => {
                load(&counters.action_candidates);
                return;
            }
            "wifi.rawnan.beacon" => {
                load(&counters.nan_beacons);
                return;
            }
            "wifi.raw.action" => {
                load(&counters.now_actions);
            }
            "wifi.raw.action.reflection" => {
                load(&counters.now_reflections);
            }
            "wifi.rawnan.discovery" => {
                load(&counters.nan_service_frames);
            }
            _ => {}
        }
        // The event is also the node's `log.watch` record.
        tracing::info!(
            target: "dmesh.event",
            event_type = %event.key,
            trace_prechecked = true,
            source = %event.source,
            data = %event.value,
            message = "event"
        );
    }

    fn nan_announce(&self, peer: &str, bssid: Option<&str>, payloads: &[&[u8]]) -> NanAnnounce {
        match peer_array(peer) {
            Some(peer) => self
                .observer
                .nan(peer, bssid.and_then(peer_array), payloads),
            None => NanAnnounce::default(),
        }
    }

    fn nan_packet(&self, peer: &str, bssid: Option<&str>, kind: NanPacketKind, payload: &[u8]) {
        if let Some(peer) = peer_array(peer) {
            self.observer
                .nan_packet(peer, bssid.and_then(peer_array), kind, payload);
        }
    }

    fn now_sync(&self, peer: [u8; 6], cluster_id: [u8; 6], service_info: &[u8]) {
        let _ = self
            .observer
            .now(peer, Some(cluster_id), NowKind::Sync, service_info);
    }

    fn now_discovery(&self, peer: [u8; 6], bssid: Option<[u8; 6]>, payload: &[u8]) -> Option<Vec<u8>> {
        self.observer.now(peer, bssid, NowKind::Discovery, payload)
    }

    fn ingress(&self) -> Option<Arc<dyn EspNowIngress>> {
        self.ingress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// What is running after [`Radio::start`].
struct Running {
    stop: Arc<AtomicBool>,
    /// Keeps START_AP alive: the kernel stops an AP when its owner socket closes.
    _owner: Option<Nl80211Socket>,
}

/// The handle to the raw Wi-Fi bearer.
#[derive(Clone)]
pub struct Radio {
    core: Arc<Core>,
    running: Arc<Mutex<Option<Running>>>,
}

impl Radio {
    /// The QUIC bearer for NOW and the control handle. Attach the bearer to the node,
    /// then call [`Self::start`].
    pub fn new<P>(config: RadioConfig, observer: Arc<dyn Observer>) -> (EspNowBearer<P>, Self)
    where
        P: quic_lite::bearer::PacketPool + Sync + 'static,
        P::Buffer: Send,
    {
        let (bearer, ingress) = EspNowBearer::<P>::new(config.iface.clone());
        let core = Arc::new(Core {
            config,
            observer,
            nan: Arc::new(Mutex::new(NanState::new(crate::NAN_CLUSTER_STALE_AFTER_US))),
            publish: Arc::new(Mutex::new(NanActivePublish::new(NAN_ACTIVE_PUBLISH_INSTANCE))),
            subscribe: Arc::new(Mutex::new(None)),
            followups: Arc::new(Mutex::new(crate::NanFollowupQueue::new(MAX_PENDING_NAN_FOLLOWUPS))),
            now_discovery: Arc::new(Mutex::new(None)),
            now_publish: Arc::new(Mutex::new(None)),
            tx: Mutex::new(None),
            ingress: Arc::new(Mutex::new(Some(ingress))),
            counters: AtomicCounters::default(),
        });
        (
            bearer,
            Self {
                core,
                running: Arc::new(Mutex::new(None)),
            },
        )
    }

    pub fn config(&self) -> &RadioConfig {
        &self.core.config
    }

    /// Bring the interface to open AP + monitor on the shared channel and start the
    /// capture threads. Blocking (netlink); call it from a blocking task. Starting
    /// again while it runs and the interface is already in the target state does
    /// nothing.
    pub fn start(&self) -> Result<ChainOutcome> {
        let mut running = self
            .running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let config = &self.core.config;
        let chain = ChainConfig {
            iface: &config.iface,
            monitor: &config.monitor,
            ssid: &config.ssid,
            channel: config.channel,
        };
        let mut ops = SysOps::default();
        let outcome = start_chain_with_retries(&mut ops, &chain, 3, |attempt| {
            std::thread::sleep(Duration::from_secs(2 * attempt as u64));
        })?;
        if outcome == ChainOutcome::AlreadyRunning && running.is_some() {
            return Ok(outcome);
        }
        // A restart of the chain (or of this process) replaces the capture threads.
        if let Some(previous) = running.take() {
            previous.stop.store(true, Ordering::Release);
        }
        let stop = Arc::new(AtomicBool::new(false));
        if let Err(error) = self.spawn_capture(&mut ops, &stop) {
            // Threads already launched must not outlive a failed startup or
            // accumulate on the next maintenance retry.
            stop.store(true, Ordering::Release);
            return Err(error);
        }
        *running = Some(Running {
            stop,
            _owner: ops.owner.take(),
        });
        Ok(outcome)
    }

    fn spawn_capture(&self, ops: &mut SysOps, stop: &Arc<AtomicBool>) -> Result<()> {
        let core = &self.core;
        let config = &core.config;
        let host: Arc<dyn CaptureHost> = core.clone();

        let monitor = MonitorRxSocket::open(&config.monitor)?;
        monitor.set_receive_timeout(Duration::from_millis(100))?;
        {
            let (host, iface, monitor_iface) = (host.clone(), config.iface.clone(), config.monitor.clone());
            let (nan, publish, followups) = (
                core.nan.clone(),
                core.publish.clone(),
                core.followups.clone(),
            );
            let stop = stop.clone();
            std::thread::Builder::new()
                .name("rawnan-monitor".to_owned())
                .spawn(move || {
                    monitor_receive_loop(
                        monitor,
                        &iface,
                        &monitor_iface,
                        host,
                        nan,
                        publish,
                        followups,
                        Arc::new(Mutex::new(BTreeMap::new())),
                        stop,
                    );
                })?;
        }
        // The discovery windows: transmissions are locked to the DW derived from the NAN
        // beacons (or NOW sync), not to whichever beacon arrives.
        {
            let schedule = WindowSchedule {
                iface: config.iface.clone(),
                monitor_iface: config.monitor.clone(),
                nan: core.nan.clone(),
                publish: core.publish.clone(),
                subscribe: core.subscribe.clone(),
                now_discovery: core.now_discovery.clone(),
                now_publish: core.now_publish.clone(),
                followups: core.followups.clone(),
            };
            let (host, stop) = (host.clone(), stop.clone());
            std::thread::Builder::new()
                .name("rawnan-dw".to_owned())
                .spawn(move || run_window_scheduler(schedule, host, stop))?;
        }
        // The AP's management socket answers authentication and association for
        // stations, and is a second NAN ingress on adapters that do not mirror public
        // actions to the monitor.
        if let Some(mgmt) = ops.mgmt.take() {
            let index = ifindex(&config.iface)?;
            let mac = iface_mac(&config.iface)?;
            let (host, iface, channel) = (host.clone(), config.iface.clone(), config.channel);
            let (nan, publish, followups) = (
                core.nan.clone(),
                core.publish.clone(),
                core.followups.clone(),
            );
            let no_ht = Arc::new(Mutex::new(ap_no_ht_stations()));
            let stop = stop.clone();
            std::thread::Builder::new()
                .name("rawnan-ap".to_owned())
                .spawn(move || {
                    ap_mgmt_receive_loop(
                        mgmt, &iface, index, mac, host, nan, publish, followups, no_ht, channel, false,
                        stop,
                    );
                })?;
        }
        // NAN beacons on the base interface, for adapters that do not mirror them.
        let beacons = Nl80211Socket::open().and_then(|socket| {
            socket.register_nan_discovery_frames(ifindex(&config.iface)?)?;
            Ok(socket)
        });
        if let Ok(beacons) = beacons {
            let (host, iface) = (host.clone(), config.iface.clone());
            let (nan, followups) = (core.nan.clone(), core.followups.clone());
            let stop = stop.clone();
            std::thread::Builder::new()
                .name("rawnan-nan-beacon".to_owned())
                .spawn(move || {
                    nl80211_nan_beacon_receive_loop(beacons, &iface, host, nan, followups, stop);
                })?;
        } else if let Err(error) = beacons {
            // Monitor RX is already active. This second ingress is optional:
            // many drivers cannot register beacon management frames at all.
            tracing::warn!(%error, iface = %config.iface, "nan_beacon_registration_unavailable_using_monitor");
        }
        Ok(())
    }

    /// Stop the capture threads. The AP stops when the interface is next released.
    pub fn stop(&self) {
        if let Some(running) = self
            .running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            running.stop.store(true, Ordering::Release);
        }
    }

    pub fn is_running(&self) -> bool {
        self.running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }

    /// Publish the local announce: as the NAN active Publish (sent in the next discovery
    /// windows, refreshed at the shared 5-minute interval) and broadcast on NOW, now
    /// and in the following windows until DW0/DW8, as the firmware does. Call it when
    /// the announce is first available and then at that interval, not more often: every
    /// call restarts the burst.
    pub fn set_publish(&self, service_info: &[u8]) -> Result<()> {
        self.core
            .publish
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .configure(true, service_info)?;
        if let Err(error) = self.send_now([0xff; 6], service_info) {
            tracing::warn!(error = %format!("{error:#}"), "rawnan_now_publish_not_sent_immediately");
        }
        *self
            .core
            .now_publish
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(PendingNowDiscovery {
            request: service_info.to_vec(),
            target: None,
            request_id: now_millis_u64(),
            sent_windows: 0,
            last_slot: None,
        });
        Ok(())
    }

    /// Send one NAN service-discovery request on every medium the interface has, the
    /// way UDP multicast would be sent: on NOW now, and again in each confirmed
    /// discovery window until the next DW0 or DW8 (a sleepy peer listens only then); on
    /// NAN as an active Subscribe in the same windows (NAN transmits only inside a
    /// window). `target` addresses one peer on both media, otherwise everyone.
    ///
    /// `request` is the record the medium carries: a discovery request, or a wake
    /// request (a NAN service-discovery request too). Replies come through the
    /// [`Observer`]. Returns the request id; a failed immediate NOW send is logged, as
    /// the window sends still follow.
    pub fn request(&self, request: Vec<u8>, target: Option<[u8; 6]>, nan: bool) -> u64 {
        let request_id = now_millis_u64();
        if let Err(error) = self.send_now(target.unwrap_or([0xff; 6]), &request) {
            tracing::warn!(error = %format!("{error:#}"), "rawnan_now_request_not_sent_immediately");
        }
        *self
            .core
            .now_discovery
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(PendingNowDiscovery {
            request: request.clone(),
            target,
            request_id,
            sent_windows: 0,
            last_slot: None,
        });
        if nan {
            *self
                .core
                .subscribe
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(PendingNanActiveSubscribe {
                service_info: request,
                target,
                request_id,
                sent_windows: 0,
                last_slot: None,
            });
        }
        request_id
    }

    /// One NOW action to `peer` (everyone for the broadcast address).
    fn send_now(&self, peer: [u8; 6], payload: &[u8]) -> Result<()> {
        let mut tx = self
            .core
            .tx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if tx.is_none() {
            *tx = Some(MonitorTxSocket::open(&self.core.config.monitor)?);
        }
        send_raw_action_datagram_on_socket(
            &self.core.config.iface,
            tx.as_ref().expect("opened above"),
            peer,
            payload,
            6,
        )
    }

    pub fn nan_status(&self) -> NanStatus {
        let state = self
            .core
            .nan
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let last_beacon_us = state.last_beacon_local_us();
        let publishing = self
            .core
            .publish
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .enabled();
        NanStatus {
            active: self.is_running(),
            cluster_id: state.cluster().map(|mac| mac.0),
            sync_id: state.sync_bssid().map(|mac| mac.0),
            sync_age_ms: (last_beacon_us != 0)
                .then(|| now_micros_u64().saturating_sub(last_beacon_us) / 1_000),
            publishing,
        }
    }

    pub fn counters(&self) -> Counters {
        self.core.counters.snapshot()
    }

    pub fn reset_counters(&self) {
        self.core.counters.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Quiet;
    impl Observer for Quiet {
        fn nan(&self, _: [u8; 6], _: Option<[u8; 6]>, _: &[&[u8]]) -> NanAnnounce {
            NanAnnounce::default()
        }
        fn nan_packet(&self, _: [u8; 6], _: Option<[u8; 6]>, _: NanPacketKind, _: &[u8]) {}
        fn now(&self, _: [u8; 6], _: Option<[u8; 6]>, _: NowKind, _: &[u8]) -> Option<Vec<u8>> {
            None
        }
    }

    type TestPool = quic_lite::packet_pool::PacketPool<4, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;

    fn radio() -> Radio {
        Radio::new::<TestPool>(RadioConfig::for_interface("wlan0"), Arc::new(Quiet)).1
    }

    #[test]
    fn the_defaults_are_the_shared_channel_and_the_conventional_monitor() {
        let config = RadioConfig::for_interface("wlan0");
        assert_eq!(config.channel, 6);
        assert_eq!(config.monitor, "wlan0mon");
        assert_eq!(config.ssid, DEFAULT_SSID);
    }

    #[test]
    fn a_new_radio_is_not_running_and_has_no_sync() {
        let radio = radio();
        let status = radio.nan_status();
        assert!(!status.active && !status.synced() && !status.publishing);
        assert_eq!(radio.counters(), Counters::default());
    }

    #[test]
    fn publishing_needs_service_info_and_queues_the_nan_publish_and_the_now_broadcast() {
        let radio = radio();
        assert!(radio.set_publish(&[]).is_err());
        radio.set_publish(b"announce").unwrap();
        assert!(radio.nan_status().publishing);
        let now = radio.core.now_publish.lock().unwrap();
        assert_eq!(now.as_ref().unwrap().request, b"announce");
        assert_eq!(now.as_ref().unwrap().target, None);
    }

    #[test]
    fn counters_count_packet_rate_events_without_retaining_them_and_reset() {
        let radio = radio();
        let host: &dyn CaptureHost = &*radio.core;
        host.event(RadioEvent {
            ts_millis: 0,
            key: "wifi.raw.monitor".to_owned(),
            source: "wlan0mon".to_owned(),
            value: json!({"frame_len": 100, "frame_type": 0, "frame_subtype": 8}),
            message: None,
        });
        host.event(RadioEvent {
            ts_millis: 0,
            key: "wifi.rawnan.beacon".to_owned(),
            source: "wlan0mon".to_owned(),
            value: json!({}),
            message: None,
        });
        let counters = radio.counters();
        assert_eq!((counters.frames, counters.bytes, counters.management_frames), (1, 100, 1));
        assert_eq!(counters.nan_beacons, 1);
        radio.reset_counters();
        assert_eq!(radio.counters(), Counters::default());
    }

    #[test]
    fn a_request_is_queued_for_both_media_and_a_directed_one_keeps_its_target() {
        let radio = radio();
        let peer = [0x02, 1, 2, 3, 4, 5];
        let id = radio.request(vec![1, 2, 3], Some(peer), true);
        assert_ne!(id, 0);
        let now = radio.core.now_discovery.lock().unwrap();
        let now = now.as_ref().unwrap();
        assert_eq!((now.request.as_slice(), now.target, now.request_id), (&[1u8, 2, 3][..], Some(peer), id));
        let nan = radio.core.subscribe.lock().unwrap();
        let nan = nan.as_ref().unwrap();
        assert_eq!((nan.service_info.as_slice(), nan.target, nan.request_id), (&[1u8, 2, 3][..], Some(peer), id));
    }

    #[test]
    fn a_nan_less_request_queues_only_the_now_side() {
        let radio = radio();
        radio.request(vec![9], None, false);
        assert!(radio.core.now_discovery.lock().unwrap().is_some());
        assert!(radio.core.subscribe.lock().unwrap().is_none());
    }
}
