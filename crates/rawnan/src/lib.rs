//! Shared wire-level NAN definitions for Linux, ESP32, and Android adapters.
//!
//! The important boundary is intentional: this crate owns bytes on the air
//! (802.11 offsets, NAN attributes, SDF layout, service descriptors, and
//! availability classification).  Hardware adapters own channel selection,
//! TSF/clock sampling, driver calls, queues, and power policy.  Keeping these
//! concerns separate prevents a timing workaround in one adapter from
//! silently changing the Android/ESP interoperability format.

use anyhow::{anyhow, bail, Result};
pub mod espnow;
pub use espnow::{
    action_header as espnow_action_header, build_action_frame as build_espnow_action_frame,
};

pub mod service;
pub use service::{
    active_ack_for_service, build_dmesh_followup_payload, build_dmesh_service_info,
    build_nan_followup_sdf, build_nan_publish_sdf, build_nan_publish_sdf_with_sdea,
    build_nan_service_extension, build_nan_usd_sdf, is_dmesh_service_info,
    parse_dmesh_nan_followup, parse_dmesh_service_info, wake_request_for_service, DmeshNanFollowup,
    DmeshServiceInfo,
};

pub const FRAME_DST: usize = 4;
pub const FRAME_SRC: usize = 10;
pub const FRAME_BSSID: usize = 16;
pub const FRAME_DATA: usize = 24;
pub const NAN_ACTION_START: usize = 30;
pub const NAN_BSSID_OUI: [u8; 3] = [0x50, 0x6f, 0x9a];
pub const NAN_DISCOVERY_MAC: [u8; 6] = [0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00];
pub const NAN_CLUSTER_BSSID_DEFAULT: [u8; 6] = [0x50, 0x6f, 0x9a, 0x01, 0x05, 0x01];
pub const NAN_DEFAULT_CHANNEL: u8 = 6;
pub const NAN_COMMAND_MAX_LEN: usize = 231;
pub const NAN_DW_CONTROL_KEY: u16 = 332;
pub const NAN_COMMAND_TIMEOUT_KEY: u16 = 41;
pub const NAN_REQUEST_ID_KEY: u16 = 333;
pub const NAN_DW_MORE: u8 = 1;
pub const NAN_DW_DONE: u8 = 1 << 1;
pub const NAN_DW_UNITS_SHIFT: u8 = 2;
pub const NAN_RX_FRAME_MAX: usize = 1536;
pub const NAN_CLUSTER_RESELECT_AFTER_US: u64 = 3 * 512 * 1024;
pub const NAN_DISCOVERY_PERIOD_US: u64 = 512 * 1024;
/// One IEEE 802.11 time unit in microseconds.
pub const NAN_TU_US: u32 = 1024;
/// Availability bitmaps use 16-TU units (NAN specification tables 85-91).
pub const NAN_AVAILABILITY_BITMAP_TU: u32 = 16;
/// Maximum post-beacon transmit dwell shared by host and firmware schedulers.
/// A frame outside this interval cannot be assumed to reach a sleepy peer.
pub const NAN_TX_DWELL_US: u64 = 32_000;
pub const DMESH_SERVICE_ID: [u8; 6] = [0x75, 0x94, 0x31, 0x93, 0xea, 0xc9];
pub const DMESH_MAGIC: [u8; 2] = *b"DM";
pub const DMESH_VERSION: u8 = 1;
pub const DMESH_NAN_FOLLOWUP_HEADER_LEN: usize = 24;
pub const NAN_SERVICE_INFO_LEN: usize = 21;
pub const NAN_SERVICE_FLAG_UART_WAKE: u8 = 0x80;
pub const NAN_SERVICE_FLAG_BLE_WAKE: u8 = 0x40;
pub const NAN_SERVICE_FLAG_ACTIVE_ACK: u8 = 0x20;
pub const NAN_SDEA_SERVICE_UPDATE_CONTROL: [u8; 2] = [0x00, 0x02];
pub const IEEE80211_HEADER_LEN: usize = 24;
pub const IEEE80211_LLC_SNAP_LEN: usize = 8;
pub const IEEE80211_LLC_SNAP_IPV6: [u8; IEEE80211_LLC_SNAP_LEN] =
    [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x86, 0xdd];
pub const IEEE80211_LLC_SNAP_DMESH: [u8; IEEE80211_LLC_SNAP_LEN] =
    [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0xb5];
pub const NAN_UDP_SOURCE_PORT: u16 = 4242;
pub const NAN_UDP_DEST_PORT: u16 = 4243;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SoftNanSyncSource {
    NanCluster,
    DirectAp,
    InfrastructureAp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SoftNanSyncBeacon {
    pub source: SoftNanSyncSource,
    pub local_us: u64,
    pub tsf_us: u64,
    pub interval_tu: u32,
    pub bssid: [u8; 6],
}

/// Select the soft-NAN timing authority. A fresh NAN cluster always wins;
/// otherwise a fresh AP beacon is a valid anchor for the same DW scheduler.
pub fn select_soft_nan_sync(
    nan: Option<SoftNanSyncBeacon>,
    ap: Option<SoftNanSyncBeacon>,
    now_us: u64,
    nan_max_age_us: u64,
    ap_max_age_us: u64,
) -> Option<SoftNanSyncBeacon> {
    if let Some(value) = nan.filter(|value| {
        value.local_us != 0 && now_us.saturating_sub(value.local_us) <= nan_max_age_us
    }) {
        return Some(value);
    }
    ap.filter(|value| value.local_us != 0 && now_us.saturating_sub(value.local_us) <= ap_max_age_us)
}

/// Cross-adapter NAN counters and bounded timing evidence.
///
/// These atomics deliberately live with the shared protocol rather than in
/// an ESP callback module. Linux, ESP32, and Android diagnostics can therefore
/// expose the same names and meanings; adapters only decide how a sample is
/// collected and how it is rendered on their debug socket.
pub mod metrics {
    /// Cross-adapter NAN counters. Values are deliberately plain integers so
    /// ESP32, Linux, recovery, and embedded users can populate the same
    /// snapshot without sharing an allocator, logger, or atomic type.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct NanMetricsSnapshot {
        pub dispatch: u64,
        pub accepted: u64,
        pub rx_mgmt: u64,
        pub rx_data: u64,
        pub rx_matched: u64,
        pub rx_action: u64,
        pub rx_beacon: u64,
        pub rx_sdf: u64,
        pub rx_other: u64,
        pub rx_bytes: u64,
        pub sync_beacon_tx: u64,
        pub ap_beacon: u64,
        pub command_rx: u64,
        pub command_tx: u64,
        pub command_drops: u64,
        pub response_rx: u64,
        pub response_tx: u64,
        pub outgoing_drops: u64,
        pub service_rx: u64,
        pub followup_rx: u64,
        pub followup_tx: u64,
        pub prefilter_drops: u64,
        pub queue_drops: u64,
        pub oversize_drops: u64,
        pub ipv6_udp_rx: u64,
        pub ipv6_udp_bytes: u64,
        pub cluster_foreign_drops: u64,
        pub cluster_reselects: u64,
        pub hw_filter_arms: u64,
        pub hw_filter_reprobes: u64,
        pub hw_filter_errors: u64,
        pub publish_dw_tx: u64,
        pub publish_dw_skipped: u64,
        pub publish_guard_drops: u64,
        pub queue_len: u64,
        pub publish_queue_len: u64,
        pub last_beacon_local_us: u64,
        pub last_beacon_tsf_us: u64,
        pub last_raw_tx_offset_us: u64,
        pub last_raw_tx_slot: u64,
        pub last_publish_beacon: u64,
        pub last_publish_slot: u64,
        pub last_publish_offset_us: u64,
    }

    /// Stable machine-readable text for debug sockets. Adapters may wrap this
    /// in JSON/CBOR, but the field names remain identical across platforms.
    pub fn format_nan_metrics(metrics: &NanMetricsSnapshot) -> String {
        format!(
            "nan_metrics dispatch={} accepted={} rx_mgmt={} rx_data={} rx_matched={} rx_action={} rx_beacon={} rx_sdf={} rx_other={} rx_bytes={} sync_beacon_tx={} ap_beacon={} command_rx={} command_tx={} command_drops={} response_rx={} response_tx={} outgoing_drops={} service_rx={} followup_rx={} followup_tx={} prefilter_drops={} queue_drops={} oversize_drops={} ipv6_udp_rx={} ipv6_udp_bytes={} cluster_foreign_drops={} cluster_reselects={} hw_filter_arms={} hw_filter_reprobes={} hw_filter_errors={} publish_dw_tx={} publish_dw_skipped={} publish_guard_drops={} queue_len={} publish_queue_len={} last_beacon_local_us={} last_beacon_tsf_us={} last_raw_tx_offset_us={} last_raw_tx_slot={} last_publish_beacon={} last_publish_slot={} last_publish_offset_us={}",
            metrics.dispatch, metrics.accepted, metrics.rx_mgmt, metrics.rx_data,
            metrics.rx_matched, metrics.rx_action, metrics.rx_beacon, metrics.rx_sdf,
            metrics.rx_other, metrics.rx_bytes, metrics.sync_beacon_tx, metrics.ap_beacon,
            metrics.command_rx, metrics.command_tx, metrics.command_drops, metrics.response_rx,
            metrics.response_tx, metrics.outgoing_drops, metrics.service_rx, metrics.followup_rx,
            metrics.followup_tx, metrics.prefilter_drops, metrics.queue_drops,
            metrics.oversize_drops, metrics.ipv6_udp_rx, metrics.ipv6_udp_bytes,
            metrics.cluster_foreign_drops, metrics.cluster_reselects, metrics.hw_filter_arms,
            metrics.hw_filter_reprobes, metrics.hw_filter_errors, metrics.publish_dw_tx,
            metrics.publish_dw_skipped, metrics.publish_guard_drops, metrics.queue_len,
            metrics.publish_queue_len, metrics.last_beacon_local_us, metrics.last_beacon_tsf_us,
            metrics.last_raw_tx_offset_us, metrics.last_raw_tx_slot, metrics.last_publish_beacon,
            metrics.last_publish_slot, metrics.last_publish_offset_us,
        )
    }

    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

    pub static NAN_RX_MGMT: AtomicU32 = AtomicU32::new(0);
    pub static NAN_RX_ACTION: AtomicU32 = AtomicU32::new(0);
    pub static NAN_RX_BEACON: AtomicU32 = AtomicU32::new(0);
    pub static NAN_RX_SDF: AtomicU32 = AtomicU32::new(0);
    pub static NAN_RX_OTHER: AtomicU32 = AtomicU32::new(0);
    pub static NAN_RX_DATA: AtomicU32 = AtomicU32::new(0);
    pub static NAN_RX_BYTES: AtomicU32 = AtomicU32::new(0);
    pub static NAN_RX_MATCHED: AtomicU32 = AtomicU32::new(0);
    pub static NAN_RAW_COMMAND_RX: AtomicU32 = AtomicU32::new(0);
    pub static NAN_RAW_COMMAND_TX: AtomicU32 = AtomicU32::new(0);
    pub static NAN_RAW_RESPONSE_RX: AtomicU32 = AtomicU32::new(0);
    pub static NAN_RAW_RESPONSE_TX: AtomicU32 = AtomicU32::new(0);
    pub static NAN_RAW_COMMAND_PENDING: AtomicU32 = AtomicU32::new(0);
    pub static NAN_RAW_RESPONSE_PENDING: AtomicU32 = AtomicU32::new(0);
    pub static NAN_OBJECT_ACTION_DISPATCH: AtomicU32 = AtomicU32::new(0);
    pub static NAN_OBJECT_ACTION_ACCEPTED: AtomicU32 = AtomicU32::new(0);
    pub static NAN_LAST_RAW_TX_OFFSET_US: AtomicU32 = AtomicU32::new(0);
    pub static NAN_LAST_RAW_TX_SLOT_LO: AtomicU32 = AtomicU32::new(0);
    pub static NAN_LAST_RAW_TX_SLOT_HI: AtomicU32 = AtomicU32::new(0);
    pub static NAN_RAW_COMMAND_DROPS: AtomicU32 = AtomicU32::new(0);
    pub static NAN_RAW_OUTGOING_DROPS: AtomicU32 = AtomicU32::new(0);
    pub static NAN_DMESH_SERVICE_RX: AtomicU32 = AtomicU32::new(0);
    pub static NAN_DMESH_FOLLOWUP_RX: AtomicU32 = AtomicU32::new(0);
    pub static NAN_DMESH_FOLLOWUP_TX: AtomicU32 = AtomicU32::new(0);
    pub static NAN_SYNC_BEACON_TX: AtomicU32 = AtomicU32::new(0);
    pub static NAN_LAST_PUBLISH_BEACON: AtomicU32 = AtomicU32::new(0);
    pub static NAN_DISCOVERY_ROLE: AtomicU8 = AtomicU8::new(0);
    pub static NAN_PUBLISH_DW_TX: AtomicU32 = AtomicU32::new(0);
    pub static NAN_PUBLISH_DW_LAST_OFFSET_US: AtomicU32 = AtomicU32::new(0);
    pub static NAN_PUBLISH_DW_SKIPPED_SLOT: AtomicU32 = AtomicU32::new(0);
    pub static NAN_LAST_PUBLISH_SLOT: AtomicU32 = AtomicU32::new(0);
    pub static NAN_LAST_PUBLISH_LOCAL_LO: AtomicU32 = AtomicU32::new(0);
    pub static NAN_LAST_PUBLISH_LOCAL_HI: AtomicU32 = AtomicU32::new(0);
    pub static NAN_PUBLISH_DW_LOCAL_GUARD_DROPS: AtomicU32 = AtomicU32::new(0);
    pub static NAN_LAST_INFRA_AUTO_PUBLISH_LO: AtomicU32 = AtomicU32::new(0);
    pub static NAN_LAST_INFRA_AUTO_PUBLISH_HI: AtomicU32 = AtomicU32::new(0);
    pub static NAN_LAST_SERVICE_LOCAL_LO: AtomicU32 = AtomicU32::new(0);
    pub static NAN_LAST_SERVICE_LOCAL_HI: AtomicU32 = AtomicU32::new(0);
    pub static NAN_LAST_ACTION_LOCAL_LO: AtomicU32 = AtomicU32::new(0);
    pub static NAN_LAST_ACTION_LOCAL_HI: AtomicU32 = AtomicU32::new(0);
    pub static NAN_RX_QUEUE_DROPS: AtomicU32 = AtomicU32::new(0);
    pub static NAN_RX_PREFILTER_DROPS: AtomicU32 = AtomicU32::new(0);
    pub static NAN_RX_OVERSIZE_DROPS: AtomicU32 = AtomicU32::new(0);
    pub static NAN_LAST_BEACON_LOCAL_LO: AtomicU32 = AtomicU32::new(0);
    pub static NAN_LAST_BEACON_LOCAL_HI: AtomicU32 = AtomicU32::new(0);
    pub static NAN_LAST_BEACON_TSF_LO: AtomicU32 = AtomicU32::new(0);
    pub static NAN_LAST_BEACON_TSF_HI: AtomicU32 = AtomicU32::new(0);
    pub static NAN_BEACON_HISTORY_SEQ: [AtomicU32; 64] = [const { AtomicU32::new(0) }; 64];
    pub static NAN_BEACON_HISTORY_TSF_LO: [AtomicU32; 64] = [const { AtomicU32::new(0) }; 64];
    pub static NAN_BEACON_HISTORY_TSF_HI: [AtomicU32; 64] = [const { AtomicU32::new(0) }; 64];
    pub static NAN_BEACON_HISTORY_LOCAL_LO: [AtomicU32; 64] = [const { AtomicU32::new(0) }; 64];
    pub static NAN_BEACON_HISTORY_LOCAL_HI: [AtomicU32; 64] = [const { AtomicU32::new(0) }; 64];
    pub static NAN_BEACON_HISTORY_SOURCE: [[AtomicU8; 6]; 64] =
        [const { [const { AtomicU8::new(0) }; 6] }; 64];
    pub static NAN_CLUSTER_LOCKED: AtomicBool = AtomicBool::new(false);
    pub static NAN_CLUSTER_FOREIGN_DROPS: AtomicU32 = AtomicU32::new(0);
    pub static NAN_CLUSTER_RESELECTS: AtomicU32 = AtomicU32::new(0);
    pub static BEACON_STATS_SOURCE: AtomicU32 = AtomicU32::new(0);
    pub static BEACON_STATS_BSSID: [AtomicU8; 6] = [const { AtomicU8::new(0) }; 6];
    pub static BEACON_STATS_INTERVAL_TU: AtomicU32 = AtomicU32::new(512);
    pub static BEACON_STATS_STRIDE: AtomicU32 = AtomicU32::new(8);
    pub static BEACON_STATS_FIRST_TSF_LO: AtomicU32 = AtomicU32::new(0);
    pub static BEACON_STATS_FIRST_TSF_HI: AtomicU32 = AtomicU32::new(0);
    pub static BEACON_STATS_LAST_TSF_LO: AtomicU32 = AtomicU32::new(0);
    pub static BEACON_STATS_LAST_TSF_HI: AtomicU32 = AtomicU32::new(0);
    pub static BEACON_STATS_LAST_LOCAL_LO: AtomicU32 = AtomicU32::new(0);
    pub static BEACON_STATS_LAST_LOCAL_HI: AtomicU32 = AtomicU32::new(0);
    pub static BEACON_STATS_LAST_SLOT_LO: AtomicU32 = AtomicU32::new(0);
    pub static BEACON_STATS_LAST_SLOT_HI: AtomicU32 = AtomicU32::new(0);
    pub static BEACON_STATS_LAST_SELECTED_SLOT_LO: AtomicU32 = AtomicU32::new(0);
    pub static BEACON_STATS_LAST_SELECTED_SLOT_HI: AtomicU32 = AtomicU32::new(0);
    pub static BEACON_STATS_LAST_PHASE: AtomicU32 = AtomicU32::new(0);
    pub static BEACON_STATS_ACCEPTED: AtomicU32 = AtomicU32::new(0);
    pub static BEACON_STATS_SELECTED_SEEN: AtomicU32 = AtomicU32::new(0);
    pub static BEACON_STATS_SELECTED_MISSED: AtomicU32 = AtomicU32::new(0);
    pub static BEACON_STATS_DUPLICATES: AtomicU32 = AtomicU32::new(0);
    pub static BEACON_STATS_TSF_REGRESSIONS: AtomicU32 = AtomicU32::new(0);
    pub static BEACON_STATS_PHASE_MIN: AtomicU32 = AtomicU32::new(u32::MAX);
    pub static BEACON_STATS_PHASE_MAX: AtomicU32 = AtomicU32::new(0);
    pub static BEACON_STATS_LOCAL_DELTA_MIN: AtomicU32 = AtomicU32::new(u32::MAX);
    pub static BEACON_STATS_LOCAL_DELTA_MAX: AtomicU32 = AtomicU32::new(0);
    pub static BEACON_STATS_TSF_DELTA_MIN: AtomicU32 = AtomicU32::new(u32::MAX);
    pub static BEACON_STATS_TSF_DELTA_MAX: AtomicU32 = AtomicU32::new(0);
    pub static AP_LAST_BEACON_LOCAL_LO: AtomicU32 = AtomicU32::new(0);
    pub static AP_LAST_BEACON_LOCAL_HI: AtomicU32 = AtomicU32::new(0);
    pub static AP_LAST_BEACON_TSF_LO: AtomicU32 = AtomicU32::new(0);
    pub static AP_LAST_BEACON_TSF_HI: AtomicU32 = AtomicU32::new(0);
    pub static AP_LAST_BEACON_INTERVAL_TU: AtomicU32 = AtomicU32::new(0);
    pub static AP_LAST_BEACON_RSSI: AtomicU32 = AtomicU32::new(0);
    pub static AP_LAST_BEACON_BSSID: [AtomicU8; 6] = [const { AtomicU8::new(0) }; 6];
    pub static AP_LAST_BEACON_DIRECT: AtomicBool = AtomicBool::new(false);
    pub static AP_RX_BEACON: AtomicU32 = AtomicU32::new(0);

    /// Stable cross-adapter view of beacon timing evidence. Adapters may add
    /// hardware counters around this, but this is the common NAN timing
    /// contract exposed by ESP32 and Linux debug services.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct BeaconStatsSnapshot {
        pub source: u32,
        pub bssid: [u8; 6],
        pub interval_tu: u32,
        pub stride: u32,
        pub accepted: u32,
        pub selected_seen: u32,
        pub selected_missed: u32,
        pub duplicates: u32,
        pub tsf_regressions: u32,
        pub phase_min_us: u32,
        pub phase_max_us: u32,
        pub last_phase_us: u32,
        pub tsf_delta_min_us: u32,
        pub tsf_delta_max_us: u32,
        pub local_delta_min_us: u32,
        pub local_delta_max_us: u32,
        pub first_tsf_us: u64,
        pub last_tsf_us: u64,
    }

    fn load_u64(low: &AtomicU32, high: &AtomicU32) -> u64 {
        let hi = u64::from(high.load(Ordering::Acquire));
        let lo = u64::from(low.load(Ordering::Acquire));
        (hi << 32) | lo
    }

    fn min_or_zero(value: u32) -> u32 {
        if value == u32::MAX {
            0
        } else {
            value
        }
    }

    /// Snapshot the shared atomics without taking an adapter-specific lock.
    pub fn beacon_stats_snapshot() -> BeaconStatsSnapshot {
        let mut bssid = [0; 6];
        for (index, byte) in bssid.iter_mut().enumerate() {
            *byte = BEACON_STATS_BSSID[index].load(Ordering::Relaxed);
        }
        BeaconStatsSnapshot {
            source: BEACON_STATS_SOURCE.load(Ordering::Relaxed),
            bssid,
            interval_tu: BEACON_STATS_INTERVAL_TU.load(Ordering::Relaxed),
            stride: BEACON_STATS_STRIDE.load(Ordering::Relaxed),
            accepted: BEACON_STATS_ACCEPTED.load(Ordering::Relaxed),
            selected_seen: BEACON_STATS_SELECTED_SEEN.load(Ordering::Relaxed),
            selected_missed: BEACON_STATS_SELECTED_MISSED.load(Ordering::Relaxed),
            duplicates: BEACON_STATS_DUPLICATES.load(Ordering::Relaxed),
            tsf_regressions: BEACON_STATS_TSF_REGRESSIONS.load(Ordering::Relaxed),
            phase_min_us: min_or_zero(BEACON_STATS_PHASE_MIN.load(Ordering::Relaxed)),
            phase_max_us: BEACON_STATS_PHASE_MAX.load(Ordering::Relaxed),
            last_phase_us: BEACON_STATS_LAST_PHASE.load(Ordering::Relaxed),
            tsf_delta_min_us: min_or_zero(BEACON_STATS_TSF_DELTA_MIN.load(Ordering::Relaxed)),
            tsf_delta_max_us: BEACON_STATS_TSF_DELTA_MAX.load(Ordering::Relaxed),
            local_delta_min_us: min_or_zero(BEACON_STATS_LOCAL_DELTA_MIN.load(Ordering::Relaxed)),
            local_delta_max_us: BEACON_STATS_LOCAL_DELTA_MAX.load(Ordering::Relaxed),
            first_tsf_us: load_u64(&BEACON_STATS_FIRST_TSF_LO, &BEACON_STATS_FIRST_TSF_HI),
            last_tsf_us: load_u64(&BEACON_STATS_LAST_TSF_LO, &BEACON_STATS_LAST_TSF_HI),
        }
    }

    /// Render the stable text form used by both debug sockets. Hardware-only
    /// counters are intentionally excluded so Linux and ESP32 reports remain
    /// directly comparable.
    pub fn format_beacon_stats(stats: &BeaconStatsSnapshot) -> String {
        let source = match stats.source {
            1 => "nan",
            2 => "ap",
            3 => "raw",
            _ => "none",
        };
        format!(
            "beacon_stats source={} bssid={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} interval_tu={} stride={} accepted={} selected_seen={} selected_missed={} duplicates={} tsf_regressions={} phase_min_us={} phase_max_us={} phase_span_us={} last_phase_us={} tsf_delta_min_us={} tsf_delta_max_us={} local_delta_min_us={} local_delta_max_us={} first_tsf_us={} last_tsf_us={}",
            source,
            stats.bssid[0], stats.bssid[1], stats.bssid[2], stats.bssid[3], stats.bssid[4], stats.bssid[5],
            stats.interval_tu, stats.stride, stats.accepted, stats.selected_seen,
            stats.selected_missed, stats.duplicates, stats.tsf_regressions,
            stats.phase_min_us, stats.phase_max_us,
            stats.phase_max_us.saturating_sub(stats.phase_min_us), stats.last_phase_us,
            stats.tsf_delta_min_us, stats.tsf_delta_max_us,
            stats.local_delta_min_us, stats.local_delta_max_us,
            stats.first_tsf_us, stats.last_tsf_us,
        )
    }

    pub fn reset_beacon_stats() {
        BEACON_STATS_SOURCE.store(0, Ordering::Relaxed);
        for byte in &BEACON_STATS_BSSID {
            byte.store(0, Ordering::Relaxed);
        }
        BEACON_STATS_INTERVAL_TU.store(512, Ordering::Relaxed);
        BEACON_STATS_STRIDE.store(8, Ordering::Relaxed);
        for cell in [
            &BEACON_STATS_FIRST_TSF_LO,
            &BEACON_STATS_FIRST_TSF_HI,
            &BEACON_STATS_LAST_TSF_LO,
            &BEACON_STATS_LAST_TSF_HI,
            &BEACON_STATS_LAST_LOCAL_LO,
            &BEACON_STATS_LAST_LOCAL_HI,
            &BEACON_STATS_LAST_SLOT_LO,
            &BEACON_STATS_LAST_SLOT_HI,
            &BEACON_STATS_LAST_SELECTED_SLOT_LO,
            &BEACON_STATS_LAST_SELECTED_SLOT_HI,
        ] {
            cell.store(0, Ordering::Relaxed);
        }
        BEACON_STATS_LAST_PHASE.store(0, Ordering::Relaxed);
        for cell in [
            &BEACON_STATS_ACCEPTED,
            &BEACON_STATS_SELECTED_SEEN,
            &BEACON_STATS_SELECTED_MISSED,
            &BEACON_STATS_DUPLICATES,
            &BEACON_STATS_TSF_REGRESSIONS,
        ] {
            cell.store(0, Ordering::Relaxed);
        }
        BEACON_STATS_PHASE_MIN.store(u32::MAX, Ordering::Relaxed);
        BEACON_STATS_PHASE_MAX.store(0, Ordering::Relaxed);
        BEACON_STATS_LOCAL_DELTA_MIN.store(u32::MAX, Ordering::Relaxed);
        BEACON_STATS_LOCAL_DELTA_MAX.store(0, Ordering::Relaxed);
        BEACON_STATS_TSF_DELTA_MIN.store(u32::MAX, Ordering::Relaxed);
        BEACON_STATS_TSF_DELTA_MAX.store(0, Ordering::Relaxed);
    }

    /// Record one accepted beacon. `source` is the common source code (NAN,
    /// AP, or raw); adapters supply the already-sampled local and TSF clocks.
    pub fn record_beacon_stats(
        source: u32,
        bssid: [u8; 6],
        tsf_us: u64,
        local_us: u64,
        interval_tu: u32,
        stride: u32,
    ) {
        let mut current = [0; 6];
        for (i, byte) in current.iter_mut().enumerate() {
            *byte = BEACON_STATS_BSSID[i].load(Ordering::Acquire);
        }
        if BEACON_STATS_SOURCE.load(Ordering::Acquire) != source || current != bssid {
            reset_beacon_stats();
            BEACON_STATS_SOURCE.store(source, Ordering::Release);
            for (i, byte) in bssid.iter().enumerate() {
                BEACON_STATS_BSSID[i].store(*byte, Ordering::Relaxed);
            }
        }
        let interval_tu = interval_tu.max(1);
        let stride = stride.max(1);
        BEACON_STATS_INTERVAL_TU.store(interval_tu, Ordering::Relaxed);
        BEACON_STATS_STRIDE.store(stride, Ordering::Relaxed);
        let period_us = u64::from(interval_tu) * 1024;
        let slot = tsf_us / period_us;
        let phase = (tsf_us % period_us).min(u64::from(u32::MAX)) as u32;
        let last_tsf = load_u64(&BEACON_STATS_LAST_TSF_LO, &BEACON_STATS_LAST_TSF_HI);
        let last_local = load_u64(&BEACON_STATS_LAST_LOCAL_LO, &BEACON_STATS_LAST_LOCAL_HI);
        if last_tsf == 0 {
            store_u64(
                &BEACON_STATS_FIRST_TSF_LO,
                &BEACON_STATS_FIRST_TSF_HI,
                tsf_us,
            );
        } else if tsf_us < last_tsf {
            BEACON_STATS_TSF_REGRESSIONS.fetch_add(1, Ordering::Relaxed);
        } else {
            let d = tsf_us.saturating_sub(last_tsf).min(u64::from(u32::MAX)) as u32;
            BEACON_STATS_TSF_DELTA_MIN.fetch_min(d, Ordering::Relaxed);
            BEACON_STATS_TSF_DELTA_MAX.fetch_max(d, Ordering::Relaxed);
        }
        if last_local != 0 {
            let d = local_us.saturating_sub(last_local).min(u64::from(u32::MAX)) as u32;
            BEACON_STATS_LOCAL_DELTA_MIN.fetch_min(d, Ordering::Relaxed);
            BEACON_STATS_LOCAL_DELTA_MAX.fetch_max(d, Ordering::Relaxed);
        }
        BEACON_STATS_PHASE_MIN.fetch_min(phase, Ordering::Relaxed);
        BEACON_STATS_PHASE_MAX.fetch_max(phase, Ordering::Relaxed);
        BEACON_STATS_ACCEPTED.fetch_add(1, Ordering::Relaxed);
        if slot % u64::from(stride) == 0 {
            let last_selected = load_u64(
                &BEACON_STATS_LAST_SELECTED_SLOT_LO,
                &BEACON_STATS_LAST_SELECTED_SLOT_HI,
            );
            if last_selected == slot {
                BEACON_STATS_DUPLICATES.fetch_add(1, Ordering::Relaxed);
            } else {
                if last_selected != 0 && slot > last_selected + 1 {
                    BEACON_STATS_SELECTED_MISSED.fetch_add(
                        ((slot - last_selected) / u64::from(stride))
                            .saturating_sub(1)
                            .min(u64::from(u32::MAX)) as u32,
                        Ordering::Relaxed,
                    );
                }
                BEACON_STATS_SELECTED_SEEN.fetch_add(1, Ordering::Relaxed);
                store_u64(
                    &BEACON_STATS_LAST_SELECTED_SLOT_LO,
                    &BEACON_STATS_LAST_SELECTED_SLOT_HI,
                    slot,
                );
            }
        }
        store_u64(&BEACON_STATS_LAST_TSF_LO, &BEACON_STATS_LAST_TSF_HI, tsf_us);
        store_u64(
            &BEACON_STATS_LAST_LOCAL_LO,
            &BEACON_STATS_LAST_LOCAL_HI,
            local_us,
        );
        store_u64(&BEACON_STATS_LAST_SLOT_LO, &BEACON_STATS_LAST_SLOT_HI, slot);
        BEACON_STATS_LAST_PHASE.store(phase, Ordering::Relaxed);
    }

    fn store_u64(low: &AtomicU32, high: &AtomicU32, value: u64) {
        low.store(value as u32, Ordering::Release);
        high.store((value >> 32) as u32, Ordering::Release);
    }
}

const NAN_AVAILABILITY_ATTR_ID: u8 = 0x12;

/// Encode the shared NAN Availability attribute for a 2.4-GHz duty schedule.
/// Adapter code supplies timing policy; this function owns the wire layout.
/// `dw_tu` is the local discovery-window period, `stride` is the committed
/// DW cadence, and `offset_tu` is the first active 16-TU bitmap slot.  The
/// resulting attribute is consumed by Android WifiAware and by the ESP raw
/// parser; do not replace it with an adapter-specific shorthand.
pub fn build_nan_availability_attribute(
    dw_tu: u32,
    offset_tu: u32,
    stride: u32,
    active_ms: u32,
    map_id: u8,
) -> Result<Vec<u8>> {
    if map_id > 15 {
        bail!("NAN Availability Map ID must be in 0..=15; got {map_id}");
    }
    let period_tu = dw_tu
        .checked_mul(stride)
        .ok_or_else(|| anyhow!("NAN availability period overflow"))?;
    let period_code = match period_tu {
        128 => 1,
        256 => 2,
        512 => 3,
        1_024 => 4,
        2_048 => 5,
        4_096 => 6,
        8_192 => 7,
        _ => bail!("NAN availability period must be 128..=8192 TU power-of-two; got {period_tu}"),
    };
    if offset_tu % NAN_AVAILABILITY_BITMAP_TU != 0 || offset_tu >= period_tu {
        bail!("NAN availability offset must be a 16-TU multiple below the period; got {offset_tu}");
    }
    let active_tu = active_ms
        .saturating_mul(1_000)
        .saturating_add(NAN_TU_US - 1)
        / NAN_TU_US;
    let active_slots =
        active_tu.saturating_add(NAN_AVAILABILITY_BITMAP_TU - 1) / NAN_AVAILABILITY_BITMAP_TU;
    let start_slot = offset_tu / NAN_AVAILABILITY_BITMAP_TU;
    let max_slots = period_tu / NAN_AVAILABILITY_BITMAP_TU;
    if active_slots == 0 || start_slot.saturating_add(active_slots) > max_slots {
        bail!("NAN active interval does not fit the availability period");
    }
    let bitmap_len = ((start_slot + active_slots).saturating_add(7) / 8) as usize;
    let mut bitmap = vec![0_u8; bitmap_len];
    for bit in start_slot..start_slot + active_slots {
        bitmap[(bit / 8) as usize] |= 1 << (bit % 8);
    }
    let entry_len = 2 + 2 + 1 + bitmap.len() + 2;
    let attr_len = 1 + 2 + 2 + entry_len;
    let mut attr = Vec::with_capacity(3 + attr_len);
    attr.push(NAN_AVAILABILITY_ATTR_ID);
    attr.extend_from_slice(&(attr_len as u16).to_le_bytes());
    attr.push(1);
    attr.extend_from_slice(&u16::from(map_id).to_le_bytes());
    attr.extend_from_slice(&(entry_len as u16).to_le_bytes());
    attr.extend_from_slice(&0x1101_u16.to_le_bytes());
    let bitmap_control: u16 =
        ((period_code << 3) | ((offset_tu / NAN_AVAILABILITY_BITMAP_TU) << 6)) as u16;
    attr.extend_from_slice(&bitmap_control.to_le_bytes());
    attr.push(bitmap.len() as u8);
    attr.extend_from_slice(&bitmap);
    attr.extend_from_slice(&[0x10, 0x02]);
    Ok(attr)
}

/// Encode the shared 2.4-GHz ESP/Android Device Capability attribute.
pub fn build_nan_device_capability_attribute(stride: u32) -> Result<Vec<u8>> {
    let dw_code = match stride {
        1 => 1,
        2 => 2,
        4 => 3,
        8 => 4,
        16 => 5,
        _ => bail!("NAN committed DW stride must be 1, 2, 4, 8, or 16; got {stride}"),
    };
    Ok(vec![
        0x0f, 0x09, 0x00, 0x00, dw_code, 0x00, 0x04, 0x00, 0x11, 0x00, 0x00, 0x00,
    ])
}

pub fn build_nan_ipv6_udp_frame(
    cluster_bssid: [u8; 6],
    destination: [u8; 6],
    source: [u8; 6],
    payload: &[u8],
) -> Vec<u8> {
    let body_len = payload.len().min(1200);
    let udp_len = 8 + body_len;
    let mut ip = vec![0u8; 40 + udp_len];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    ip[6] = 17;
    ip[7] = 1;
    let src = nan_link_local(source);
    let dst = nan_link_local(destination);
    ip[8..24].copy_from_slice(&src);
    ip[24..40].copy_from_slice(&dst);
    ip[40..42].copy_from_slice(&NAN_UDP_SOURCE_PORT.to_be_bytes());
    ip[42..44].copy_from_slice(&NAN_UDP_DEST_PORT.to_be_bytes());
    ip[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
    ip[48..48 + body_len].copy_from_slice(&payload[..body_len]);
    let mut sum = 0u32;
    checksum_add(&mut sum, &src);
    checksum_add(&mut sum, &dst);
    checksum_add(&mut sum, &(udp_len as u32).to_be_bytes());
    checksum_add(&mut sum, &[0, 0, 0, 17]);
    checksum_add(&mut sum, &ip[40..48 + body_len]);
    ip[46..48].copy_from_slice(&checksum_finalize(sum).to_be_bytes());

    let mut frame = Vec::with_capacity(IEEE80211_HEADER_LEN + IEEE80211_LLC_SNAP_LEN + ip.len());
    frame.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&cluster_bssid);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&IEEE80211_LLC_SNAP_IPV6);
    frame.extend_from_slice(&ip);
    frame
}

/// Build a raw NAN data frame with an explicit LLC/SNAP protocol marker.
pub fn build_nan_raw_data_frame(
    cluster_bssid: [u8; 6],
    destination: [u8; 6],
    source: [u8; 6],
    llc: [u8; IEEE80211_LLC_SNAP_LEN],
    payload: &[u8],
) -> Vec<u8> {
    let body_len = payload.len().min(1400);
    let mut frame = Vec::with_capacity(IEEE80211_HEADER_LEN + llc.len() + body_len);
    frame.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&cluster_bssid);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&llc);
    frame.extend_from_slice(&payload[..body_len]);
    frame
}

fn nan_link_local(mac: [u8; 6]) -> [u8; 16] {
    [
        0xfe,
        0x80,
        0,
        0,
        0,
        0,
        0,
        0,
        mac[0] ^ 0x02,
        mac[1],
        mac[2],
        0xff,
        0xfe,
        mac[3],
        mac[4],
        mac[5],
    ]
}

fn checksum_add(sum: &mut u32, bytes: &[u8]) {
    let mut index = 0;
    while index + 1 < bytes.len() {
        *sum += u32::from(u16::from_be_bytes([bytes[index], bytes[index + 1]]));
        index += 2;
    }
    if index < bytes.len() {
        *sum += u32::from(bytes[index]) << 8;
    }
}

fn checksum_finalize(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nan_beacon(bssid: [u8; 6], tsf_us: u64, interval_tu: u16) -> Vec<u8> {
        let mut frame = vec![0_u8; 34];
        frame[0] = 0x80;
        frame[16..22].copy_from_slice(&bssid);
        frame[24..32].copy_from_slice(&tsf_us.to_le_bytes());
        frame[32..34].copy_from_slice(&interval_tu.to_le_bytes());
        frame
    }

    #[test]
    fn nan_usd_sdf_matches_raw_action_prefix_and_attributes() {
        let frame = build_nan_usd_sdf(
            NAN_DISCOVERY_MAC,
            [1, 2, 3, 4, 5, 6],
            [7, 8, 9, 10, 11, 12],
            1,
            0,
            b"ssi",
        );
        assert_eq!(
            &frame[..24],
            &[
                0xd0, 0, 0, 0, 0x51, 0x6f, 0x9a, 1, 0, 0, 1, 2, 3, 4, 5, 6, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0, 0
            ]
        );
        assert_eq!(&frame[24..30], &[0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13]);
        assert_eq!(frame[30], 0x03);
        assert_eq!(u16::from_le_bytes([frame[31], frame[32]]), 9);
        assert_eq!(&frame[33..39], &[7, 8, 9, 10, 11, 12]);
        assert_eq!(frame[39], 1);
        assert_eq!(frame[41], 0);
        assert_eq!(classify(&frame), FrameKind::Sdf);
        let descriptor = service_descriptor(&frame, [7, 8, 9, 10, 11, 12]).expect("USD SDA");
        assert_eq!(descriptor.control, 0);
        assert_eq!(peer_availability(&frame), PeerAvailability::Dw0Dw8);
    }

    #[test]
    fn nan_state_arms_cluster_then_drops_foreign_until_stale() {
        let cluster = [0x50, 0x6f, 0x9a, 1, 5, 1];
        let foreign = [0x50, 0x6f, 0x9a, 1, 5, 2];
        let mut state = NanState::new(5_000_000);
        assert_eq!(
            state.observe(RxFrame {
                bytes: &nan_beacon(cluster, 100, 512),
                rssi_dbm: -20,
                timestamp_us: 1_000
            }),
            Action::ArmA3(MacAddr(cluster))
        );
        assert_eq!(state.mode(), FilterMode::Cluster);
        assert_eq!(
            state.observe(RxFrame {
                bytes: &nan_beacon(foreign, 200, 512),
                rssi_dbm: -30,
                timestamp_us: 2_000
            }),
            Action::DropForeign
        );
        assert_eq!(
            state.observe(RxFrame {
                bytes: &nan_beacon(cluster, 300, 512),
                rssi_dbm: -20,
                timestamp_us: 3_000
            }),
            Action::None
        );
        assert_eq!(state.tick(5_003_000), Action::Rediscover);
        assert_eq!(state.mode(), FilterMode::Discovery);
    }

    #[test]
    fn shared_beacon_wait_and_slot_policy_is_deterministic() {
        assert!(!beacon_seen_since(7, 7));
        assert!(beacon_seen_since(7, 8));
        assert!(beacon_dwell_open(NAN_TX_DWELL_US));
        assert!(!beacon_dwell_open(NAN_TX_DWELL_US + 1));
        assert_eq!(beacon_slot(1_048_576, NAN_DISCOVERY_PERIOD_US), Some(2));
        assert_eq!(beacon_slot(1, 0), None);
    }

    #[test]
    fn availability_encoding_rejects_nonstandard_period_and_offset() {
        assert!(build_nan_availability_attribute(512, 0, 3, 64, 1).is_err());
        assert!(build_nan_availability_attribute(512, 8, 1, 64, 1).is_err());
        assert!(build_nan_availability_attribute(512, 0, 1, 64, 16).is_err());
        let attribute = build_nan_availability_attribute(512, 0, 8, 250, 1).unwrap();
        assert_eq!(attribute[0], 0x12);
        assert_eq!(attribute[3], 1); // one availability-map entry
    }

    #[test]
    fn synchronized_publish_and_followup_builders_keep_nan_addresses_and_attributes() {
        let destination = NAN_DISCOVERY_MAC;
        let source = [1, 2, 3, 4, 5, 6];
        let cluster = NAN_CLUSTER_BSSID_DEFAULT;
        let service = DMESH_SERVICE_ID;
        let info = build_dmesh_service_info([9, 8, 7, 6, 5, 4], 1, None);
        let publish = build_nan_publish_sdf_with_sdea(
            destination,
            source,
            cluster,
            service,
            1,
            &info,
            Some(3),
        );
        assert_eq!(&publish[4..10], &destination);
        assert_eq!(&publish[10..16], &source);
        assert_eq!(&publish[16..22], &cluster);
        assert!(publish
            .windows(7)
            .any(|window| window == [0x0e, 0x04, 0x00, 1, 0, 2, 3]));

        let followup = build_nan_followup_sdf(destination, source, cluster, service, 1, b"hello");
        assert_eq!(&followup[4..10], &destination);
        assert_eq!(followup[41], 0x12);
        assert_eq!(&followup[43..48], b"hello");
    }

    #[test]
    fn beacon_stats_use_one_common_snapshot_and_renderer() {
        metrics::reset_beacon_stats();
        metrics::record_beacon_stats(1, NAN_CLUSTER_BSSID_DEFAULT, 0, 10, 512, 8);
        metrics::record_beacon_stats(1, NAN_CLUSTER_BSSID_DEFAULT, 512 * 1024 * 8, 20, 512, 8);
        let snapshot = metrics::beacon_stats_snapshot();
        assert_eq!(snapshot.accepted, 2);
        assert_eq!(snapshot.selected_seen, 1);
        assert!(metrics::format_beacon_stats(&snapshot).contains("source=nan"));
    }

    #[test]
    fn nan_metrics_field_names_are_stable() {
        let metrics = metrics::NanMetricsSnapshot {
            rx_beacon: 3,
            followup_rx: 2,
            ..Default::default()
        };
        let rendered = metrics::format_nan_metrics(&metrics);
        assert!(rendered.contains("rx_beacon=3"));
        assert!(rendered.contains("followup_rx=2"));
        assert!(rendered.contains("publish_guard_drops=0"));
    }

    #[test]
    fn soft_nan_prefers_fresh_nan_then_ap_anchor() {
        let ap = SoftNanSyncBeacon {
            source: SoftNanSyncSource::DirectAp,
            local_us: 900,
            tsf_us: 9,
            interval_tu: 500,
            bssid: [2; 6],
        };
        let nan = SoftNanSyncBeacon {
            source: SoftNanSyncSource::NanCluster,
            local_us: 800,
            tsf_us: 8,
            interval_tu: 512,
            bssid: [1; 6],
        };
        assert_eq!(
            select_soft_nan_sync(Some(nan), Some(ap), 1_000, 300, 300),
            Some(nan)
        );
        assert_eq!(
            select_soft_nan_sync(Some(nan), Some(ap), 1_200, 300, 300),
            Some(ap)
        );
    }

    #[test]
    fn availability_and_capability_wire_contract_is_shared() {
        let availability = build_nan_availability_attribute(512, 0, 8, 250, 1).unwrap();
        assert_eq!(&availability[3..6], &[1, 1, 0]);
        assert_eq!(&availability[13..15], &[0xff, 0xff]);
        assert!(build_nan_availability_attribute(512, 0, 4, 250, 16).is_err());
        let map_zero = build_nan_availability_attribute(512, 0, 4, 250, 0).unwrap();
        let map_fifteen = build_nan_availability_attribute(512, 0, 4, 250, 15).unwrap();
        assert_eq!(&map_zero[4..6], &0_u16.to_le_bytes());
        assert_eq!(&map_fifteen[4..6], &15_u16.to_le_bytes());
        let two_second = build_nan_availability_attribute(512, 0, 4, 64, 1).unwrap();
        let one_second = build_nan_availability_attribute(512, 0, 2, 64, 1).unwrap();
        let two_control = u16::from_le_bytes([two_second[10], two_second[11]]);
        let one_control = u16::from_le_bytes([one_second[10], one_second[11]]);
        assert_eq!((two_control >> 3) & 0x07, 5); // 2048 TU period
        assert_eq!((one_control >> 3) & 0x07, 4); // 1024 TU period
        assert_eq!(&two_second[12..14], &one_second[12..14]);
        assert_eq!(
            build_nan_device_capability_attribute(4).unwrap(),
            [0x0f, 0x09, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00, 0x11, 0x00, 0x00, 0x00]
        );
        assert!(build_nan_device_capability_attribute(3).is_err());
        assert_eq!(
            build_nan_service_extension(4),
            [0x0e, 0x04, 0x00, 1, 0x00, 0x02, 4]
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceDescriptor<'a> {
    pub instance: u8,
    pub requestor_instance: u8,
    pub control: u8,
    pub payload: &'a [u8],
}

/// Coarse peer availability used for follow-up scheduling.  We deliberately
/// do not expose the complete NAN availability bitmap here: validation only
/// needs to distinguish continuously powered infrastructure from the common
/// DW0/DW8 sleepy cadence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerAvailability {
    Infra,
    Dw0Dw8,
}

pub fn peer_availability(frame: &[u8]) -> PeerAvailability {
    let mut offset = NAN_ACTION_START;
    while offset + 3 <= frame.len() {
        let attr_id = frame[offset];
        let len = u16::from_le_bytes([frame[offset + 1], frame[offset + 2]]) as usize;
        let start = offset + 3;
        let Some(end) = start.checked_add(len) else {
            break;
        };
        let Some(body) = frame.get(start..end) else {
            break;
        };
        // Device Capability: map id, committed DW cadence, bands, ...
        if attr_id == 0x0f && body.len() >= 2 {
            return if body[1] == 1 {
                PeerAvailability::Infra
            } else {
                PeerAvailability::Dw0Dw8
            };
        }
        offset = end;
    }
    PeerAvailability::Dw0Dw8
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameKind {
    Other,
    Beacon,
    Sdf,
    Followup,
}

pub fn bssid(frame: &[u8]) -> Option<[u8; 6]> {
    frame.get(FRAME_BSSID..FRAME_BSSID + 6)?.try_into().ok()
}
pub fn source(frame: &[u8]) -> Option<[u8; 6]> {
    frame.get(FRAME_SRC..FRAME_SRC + 6)?.try_into().ok()
}
pub fn is_nan_bssid(frame: &[u8]) -> bool {
    bssid(frame)
        .map(|b| b[..3] == NAN_BSSID_OUI)
        .unwrap_or(false)
}
pub fn is_beacon(frame: &[u8]) -> bool {
    frame.first() == Some(&0x80)
}
pub fn is_nan_beacon(frame: &[u8]) -> bool {
    is_beacon(frame) && is_nan_bssid(frame)
}
pub fn is_direct_dmesh_ssid(frame: &[u8]) -> bool {
    let mut offset = FRAME_DATA + 12;
    while offset + 2 <= frame.len() {
        let id = frame[offset];
        let len = frame[offset + 1] as usize;
        let start = offset + 2;
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        if end > frame.len() {
            return false;
        }
        if id == 0 && frame[start..end].starts_with(b"DIRECT-DMESH-") {
            return true;
        }
        offset = end;
    }
    false
}
pub fn beacon_tsf_us(frame: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(
        frame.get(FRAME_DATA..FRAME_DATA + 8)?.try_into().ok()?,
    ))
}
pub fn beacon_interval_tu(frame: &[u8]) -> Option<u32> {
    let value = u16::from_le_bytes(
        frame
            .get(FRAME_DATA + 8..FRAME_DATA + 10)?
            .try_into()
            .ok()?,
    ) as u32;
    (value != 0).then_some(value)
}
pub fn is_nan_sdf(frame: &[u8]) -> bool {
    frame.len() > NAN_ACTION_START
        && frame.get(FRAME_DATA..FRAME_DATA + 6) == Some(&[0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13])
}
pub fn classify(frame: &[u8]) -> FrameKind {
    if is_nan_beacon(frame) {
        FrameKind::Beacon
    } else if is_nan_followup(frame) {
        FrameKind::Followup
    } else if is_nan_sdf(frame) {
        FrameKind::Sdf
    } else {
        FrameKind::Other
    }
}
pub fn is_nan_followup(frame: &[u8]) -> bool {
    service_descriptor(frame, DMESH_SERVICE_ID)
        .map(|d| matches!(d.control, 0x02 | 0x12))
        .unwrap_or(false)
}

pub fn fnv1a32(data: &[u8]) -> u32 {
    data.iter().fold(0x811c9dc5u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
    })
}

pub fn service_descriptor_payload<'a>(frame: &'a [u8], service_id: [u8; 6]) -> Option<&'a [u8]> {
    service_descriptor(frame, service_id).map(|descriptor| descriptor.payload)
}

pub fn service_descriptor<'a>(
    frame: &'a [u8],
    service_id: [u8; 6],
) -> Option<ServiceDescriptor<'a>> {
    if !is_nan_sdf(frame) {
        return None;
    }
    let mut offset = NAN_ACTION_START;
    while offset + 3 <= frame.len() {
        let attr_id = frame[offset];
        let len = u16::from_le_bytes([frame[offset + 1], frame[offset + 2]]) as usize;
        let start = offset + 3;
        let end = start.checked_add(len)?;
        let body = frame.get(start..end)?;
        if attr_id == 0x03 {
            if let Some(descriptor) = service_descriptor_body(body, service_id) {
                return Some(descriptor);
            }
        }
        offset = end;
    }
    None
}

pub fn service_descriptor_body<'a>(
    body: &'a [u8],
    service_id: [u8; 6],
) -> Option<ServiceDescriptor<'a>> {
    if body.len() < 9 || body[..6] != service_id {
        return None;
    }
    if matches!(body[8], 0x10..=0x12) {
        let payload_len = *body.get(9)? as usize;
        return Some(ServiceDescriptor {
            instance: body[6],
            requestor_instance: body[7],
            control: body[8],
            payload: body.get(10..10 + payload_len)?,
        });
    }
    // NAN USD puts service information in SDEA, so SDA is the
    // nine-byte descriptor without the DMesh payload-length byte.
    if matches!(body[8], 0..=2) {
        return Some(ServiceDescriptor {
            instance: body[6],
            requestor_instance: body[7],
            control: body[8],
            payload: &[],
        });
    }
    None
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacAddr(pub [u8; 6]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RxFrame<'a> {
    pub bytes: &'a [u8],
    pub rssi_dbm: i8,
    pub timestamp_us: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilterMode {
    Discovery,
    Cluster,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    None,
    ArmA3(MacAddr),
    DropForeign,
    Rediscover,
}

/// Return whether a receive-side beacon counter advanced.  Adapters use this
/// as the event predicate after waking their task; the counter itself is kept
/// in the adapter because ISR/driver ownership differs between ESP and Linux.
pub const fn beacon_seen_since(previous: u32, current: u32) -> bool {
    current != previous
}

/// A synchronized transmit is valid only during the short interval following
/// the selected cluster beacon.  This policy is shared; clock sampling and
/// event delivery remain adapter-specific.
pub const fn beacon_dwell_open(age_us: u64) -> bool {
    age_us <= NAN_TX_DWELL_US
}

/// Stable slot identity for duplicate suppression across host and firmware.
pub const fn beacon_slot(tsf_us: u64, period_us: u64) -> Option<u64> {
    if period_us == 0 {
        None
    } else {
        Some(tsf_us / period_us)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NanState {
    mode: FilterMode,
    cluster: Option<MacAddr>,
    sync_bssid: Option<MacAddr>,
    last_beacon_tsf_us: u64,
    beacon_interval_tu: u32,
    last_beacon_us: u64,
    stale_after_us: u64,
}

impl NanState {
    pub const fn new(stale_after_us: u64) -> Self {
        Self {
            mode: FilterMode::Discovery,
            cluster: None,
            sync_bssid: None,
            last_beacon_tsf_us: 0,
            beacon_interval_tu: 0,
            last_beacon_us: 0,
            stale_after_us,
        }
    }
    pub const fn mode(&self) -> FilterMode {
        self.mode
    }
    pub const fn cluster(&self) -> Option<MacAddr> {
        self.cluster
    }
    pub const fn sync_bssid(&self) -> Option<MacAddr> {
        self.sync_bssid
    }
    pub const fn last_beacon_tsf_us(&self) -> u64 {
        self.last_beacon_tsf_us
    }
    pub const fn beacon_interval_tu(&self) -> u32 {
        self.beacon_interval_tu
    }
    /// Latest selected NAN beacon timing: local receive time, beacon TSF,
    /// and the expected NAN interval in microseconds.
    pub fn nan_sync_timing(&self) -> Option<(u64, u64, u64)> {
        match (self.cluster, self.last_beacon_us, self.last_beacon_tsf_us) {
            (Some(_), local_us, tsf_us) if local_us != 0 && tsf_us != 0 => {
                Some((local_us, tsf_us, NAN_DISCOVERY_PERIOD_US))
            }
            _ => None,
        }
    }

    /// Record a normal AP beacon as a timing fallback.  A selected NAN
    /// cluster remains preferred; the AP beacon is only an anchor when no NAN
    /// cluster beacon has been seen.
    pub fn observe_ap_beacon(&mut self, frame: RxFrame<'_>) {
        if !is_beacon(frame.bytes) || self.cluster.is_some() {
            return;
        }
        if let Some(a3) = bssid(frame.bytes) {
            self.sync_bssid = Some(MacAddr(a3));
            self.last_beacon_tsf_us = beacon_tsf_us(frame.bytes).unwrap_or(0);
            self.beacon_interval_tu = beacon_interval_tu(frame.bytes).unwrap_or(0);
            self.last_beacon_us = frame.timestamp_us;
        }
    }

    pub fn observe(&mut self, frame: RxFrame<'_>) -> Action {
        let Some(a3) = bssid(frame.bytes) else {
            return Action::None;
        };
        let a3 = MacAddr(a3);
        if is_nan_beacon(frame.bytes) {
            if self.cluster.is_none() {
                self.cluster = Some(a3);
                self.sync_bssid = Some(a3);
                self.last_beacon_tsf_us = beacon_tsf_us(frame.bytes).unwrap_or(0);
                self.beacon_interval_tu = beacon_interval_tu(frame.bytes).unwrap_or(0);
                self.mode = FilterMode::Cluster;
                self.last_beacon_us = frame.timestamp_us;
                return Action::ArmA3(a3);
            }
            if self.cluster == Some(a3) {
                self.last_beacon_us = frame.timestamp_us;
                return Action::None;
            }
            if frame.timestamp_us.saturating_sub(self.last_beacon_us)
                >= NAN_CLUSTER_RESELECT_AFTER_US
            {
                self.cluster = Some(a3);
                self.sync_bssid = Some(a3);
                self.last_beacon_tsf_us = beacon_tsf_us(frame.bytes).unwrap_or(0);
                self.beacon_interval_tu = beacon_interval_tu(frame.bytes).unwrap_or(0);
                self.last_beacon_us = frame.timestamp_us;
                return Action::ArmA3(a3);
            }
            return Action::DropForeign;
        }
        if self.mode == FilterMode::Cluster && self.cluster != Some(a3) {
            return Action::DropForeign;
        }
        Action::None
    }

    pub fn tick(&mut self, now_us: u64) -> Action {
        if self.mode == FilterMode::Cluster
            && now_us.saturating_sub(self.last_beacon_us) >= self.stale_after_us
        {
            self.mode = FilterMode::Discovery;
            self.cluster = None;
            self.sync_bssid = None;
            self.last_beacon_tsf_us = 0;
            self.beacon_interval_tu = 0;
            return Action::Rediscover;
        }
        Action::None
    }
}

impl Default for NanState {
    fn default() -> Self {
        Self::new(5_000_000)
    }
}
