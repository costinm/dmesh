//! NOW (ESP-NOW) discovery cluster: a broadcast, beacon-equivalent sync frame.
//!
//! This is the ESP-NOW fallback for NAN discovery on devices that cannot
//! transmit NAN beacons (ESP32) or in areas where NAN beacons are not visible.
//! It reuses NAN's cluster-selection algorithm and 512-TU discovery-window
//! math, but carries a lean, NOW-native payload instead of replicating the NAN
//! SDA/SDEA attribute format. NOW is a broadcast medium, so the frame is a
//! plain beacon-equivalent struct wrapped in the shared ESP-NOW vendor-action
//! envelope with broadcast address-1/address-3; it deliberately does not
//! attempt to fit a NAN-specific packet format, carrying only the beacon fields.
//!
//! There are two distinct identities, mirroring NAN:
//!   * `anchor_master` - the cluster head / time authority, i.e. the beacon
//!     source a device follows. This is the *selection key*, exactly as NAN
//!     selects on the cluster BSSID. In a NAN cluster it is the anchor master
//!     Android's NAN stack elected; in a NOW-only cluster it is the master
//!     elected among the NOW peers.
//!   * `cluster_id` - the cluster identity. When following a NAN cluster it is
//!     the NAN cluster ID (respected as-is); in a NOW-only cluster it is the
//!     anchor master's MAC.
//!
//! The payload also carries:
//!   * `tsf_us`      - the anchor master's cluster-wide time reference (the
//!                     beacon TSF). It is cluster-wide, and followers forward
//!                     it so the whole cluster shares one time reference. This
//!                     is distinct from a receiver's *local anchor* (its own
//!                     receive time of the beacon), which is what schedules
//!                     that receiver's radio window.
//!   * `interval_tu` - the discovery-window period (normally 512 TU).
//!   * `flags`       - master / NAN-alignment bits.
//!   * `service_info`- the same DMesh Service Info NAN Publish carries.
//!
//! Operation matches the two real cases:
//!   * A NAN cluster exists: send NOW packets immediately after the NAN DW,
//!     carrying the NAN anchor master and cluster ID (NAN-aligned). Followers
//!     respect the Android anchor master.
//!   * No NAN cluster: form a cluster over NOW and elect an anchor master on
//!     NOW (strongest beacon, tie-break to the smallest MAC, the same
//!     convergence rule NAN documents). The anchor master's MAC is the cluster
//!     ID.
//!   * If a NAN cluster is later discovered, join it and revert to the first
//!     case.
//!
//! Master (anchor) selection follows NAN's exact rules (see
//! [`crate::NanState`]): the first observed anchor master is adopted, the
//! selection is sticky, a foreign anchor is dropped while the selected one is
//! live, reselection happens only after [`NOW_SYNC_RESELECT_AFTER_US`], and
//! the selection goes stale after [`NOW_SYNC_STALE_AFTER_US`]. NAN-aligned
//! clusters take priority over NOW-only ones, so discovering a NAN cluster
//! immediately joins it (the "revert" case). NAN's stronger-beacon convergence
//! tie-break (measured RSSI/hysteresis) is the same unimplemented TODO as on
//! the ESP, so RSSI is carried on an observation only as a diagnostic and never
//! drives the follower selection; it is used only by the NOW-only anchor
//! election when the bearer actually reports it.

use crate::espnow;
use alloc::vec;
use alloc::vec::Vec;
use anyhow::{bail, Result};

/// First byte of the NOW-sync magic prefix. It is shaped like the first byte
/// of a QUIC long header (form=01) only so a NOW-sync record can coexist with
/// QUIC datagrams on the same ESP-NOW bearer. rawnan owns these bytes and has
/// no dependency on the QUIC crate; how a shared bearer routes the two is an
/// integration detail of the projects that use both (see the module docs).
pub const NOW_SYNC_PREFIX_BYTE: u8 = 0x40;
/// The four-byte reserved magic following the prefix byte. This is a rawnan
/// value, not a real protocol version. An integrating project may treat it as
/// a "version" to dispatch a shared bearer (for example to coexist with
/// QUIC-lite), but rawnan only ever checks it for equality.
pub const NOW_SYNC_MAGIC_VERSION: u32 = 0x4e53_5931; // "NSY1"
/// Fixed body prefix before the opaque Service Info.
/// `first_byte(1) + magic_version(4) + cluster_id(6) + anchor_master(6)
///  + tsf_us(8) + interval_tu(4) + flags(1)`.
pub const NOW_SYNC_HEADER_LEN: usize = 30;
/// The sender is the anchor master and its `tsf_us` advances the cluster time.
pub const NOW_SYNC_FLAG_MASTER: u8 = 0x01;
/// The cluster is a NAN cluster: the anchor master and cluster ID come from
/// the NAN cluster Android selected, and the time reference is NAN-derived so
/// the NOW window stays phase-aligned with the NAN discovery window.
/// NAN-aligned clusters take priority over NOW-only ones.
pub const NOW_SYNC_FLAG_NAN_ALIGNED: u8 = 0x02;
/// Default NOW discovery-window period, in TU. One NAN 512-TU discovery window.
pub const NOW_SYNC_DEFAULT_INTERVAL_TU: u32 = 512;
/// Maximum Service Info carried by a NOW-sync record. Matches the NAN active
/// Publish bound so host, Android, and ESP inventories share one record.
pub const NOW_SYNC_SERVICE_INFO_MAX_LEN: usize = crate::NAN_ACTIVE_PUBLISH_MAX_LEN;

// The NOW cluster applies NAN's identical reselection/staleness policy so a
// peer that migrates between the two clusters sees the same timing behavior.
pub const NOW_SYNC_RESELECT_AFTER_US: u64 = crate::NAN_CLUSTER_RESELECT_AFTER_US;
pub const NOW_SYNC_STALE_AFTER_US: u64 = crate::NAN_CLUSTER_STALE_AFTER_US;
pub const NOW_SYNC_DISCOVERY_PERIOD_US: u64 = crate::NAN_DISCOVERY_PERIOD_US;

/// A decoded NOW-sync beacon-equivalent record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NowSyncFrame<'a> {
    /// Cluster identity: the NAN cluster ID, or the anchor master's MAC in a
    /// NOW-only cluster.
    pub cluster_id: [u8; 6],
    /// The anchor master (cluster head / time authority) MAC: the beacon a
    /// device follows. This is the selection key.
    pub anchor_master: [u8; 6],
    /// The anchor master's cluster-wide time reference (beacon TSF), µs.
    pub tsf_us: u64,
    /// Discovery-window period in TU (normally 512).
    pub interval_tu: u32,
    pub flags: u8,
    /// Opaque DMesh Service Info (the same record NAN Publish carries).
    pub service_info: &'a [u8],
}

impl NowSyncFrame<'_> {
    pub const fn is_master(&self) -> bool {
        self.flags & NOW_SYNC_FLAG_MASTER != 0
    }
    pub const fn is_nan_aligned(&self) -> bool {
        self.flags & NOW_SYNC_FLAG_NAN_ALIGNED != 0
    }
    /// Selection priority: NAN-aligned clusters outrank NOW-only clusters so a
    /// discovered NAN cluster is always joined.
    pub const fn priority(&self) -> u8 {
        if self.is_nan_aligned() {
            1
        } else {
            0
        }
    }
}

/// A received NOW-sync observation with the radio's local facts. The adapter
/// supplies `rssi_dbm` (diagnostic only; the bearer may not report it) and
/// `local_us` (monotonic receive time = the local anchor); the rest come from
/// the frame body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NowSyncObservation {
    /// The anchor master MAC (selection key).
    pub anchor_master: [u8; 6],
    /// The cluster identity (NAN cluster ID or anchor master MAC).
    pub cluster_id: [u8; 6],
    pub tsf_us: u64,
    pub interval_tu: u32,
    pub flags: u8,
    /// Diagnostic only; never drives follower selection.
    pub rssi_dbm: i8,
    /// Local monotonic receive time of this beacon (the local anchor).
    pub local_us: u64,
}

impl NowSyncObservation {
    /// Build an observation from a decoded frame plus the adapter's local facts.
    pub fn from_frame(frame: &NowSyncFrame<'_>, rssi_dbm: i8, local_us: u64) -> Self {
        Self {
            anchor_master: frame.anchor_master,
            cluster_id: frame.cluster_id,
            tsf_us: frame.tsf_us,
            interval_tu: frame.interval_tu,
            flags: frame.flags,
            rssi_dbm,
            local_us,
        }
    }
    pub const fn is_nan_aligned(&self) -> bool {
        self.flags & NOW_SYNC_FLAG_NAN_ALIGNED != 0
    }
    pub const fn priority(&self) -> u8 {
        if self.is_nan_aligned() {
            1
        } else {
            0
        }
    }
}

/// Build the NOW-sync body (without the 802.11/ESP-NOW envelope). Adapters wrap
/// it with [`crate::espnow::build_action_frame`] to get a complete frame.
pub fn build_now_sync_body(
    cluster_id: [u8; 6],
    anchor_master: [u8; 6],
    tsf_us: u64,
    interval_tu: u32,
    flags: u8,
    service_info: &[u8],
) -> Result<Vec<u8>> {
    if service_info.len() > NOW_SYNC_SERVICE_INFO_MAX_LEN {
        bail!("NOW-sync Service Info exceeds {NOW_SYNC_SERVICE_INFO_MAX_LEN} bytes");
    }
    let mut body = vec![0u8; NOW_SYNC_HEADER_LEN + service_info.len()];
    body[0] = NOW_SYNC_PREFIX_BYTE;
    body[1..5].copy_from_slice(&NOW_SYNC_MAGIC_VERSION.to_be_bytes());
    body[5..11].copy_from_slice(&cluster_id);
    body[11..17].copy_from_slice(&anchor_master);
    body[17..25].copy_from_slice(&tsf_us.to_le_bytes());
    body[25..29].copy_from_slice(&interval_tu.to_le_bytes());
    body[29] = flags;
    body[NOW_SYNC_HEADER_LEN..].copy_from_slice(service_info);
    Ok(body)
}

/// Build a complete NOW-sync action frame: broadcast address-1/address-3, the
/// shared ESP-NOW vendor-action envelope, carrying the beacon-equivalent body.
pub fn build_now_sync_frame(
    source: [u8; 6],
    cluster_id: [u8; 6],
    anchor_master: [u8; 6],
    tsf_us: u64,
    interval_tu: u32,
    flags: u8,
    service_info: &[u8],
) -> Result<Vec<u8>> {
    let body = build_now_sync_body(
        cluster_id,
        anchor_master,
        tsf_us,
        interval_tu,
        flags,
        service_info,
    )?;
    espnow::build_action_frame([0xff; 6], source, [0xff; 6], &body)
}

/// Whether a reassembled bearer body is a well-formed NOW-sync record. This is
/// a pure byte check on rawnan's own magic prefix (no dependency on the QUIC
/// crate); a shared-bearer integrator uses it to route NOW-sync off the
/// connection path before handing anything else to its QUIC stack.
pub fn is_now_sync(body: &[u8]) -> bool {
    if body.len() < NOW_SYNC_HEADER_LEN || body[0] != NOW_SYNC_PREFIX_BYTE {
        return false;
    }
    u32::from_be_bytes([body[1], body[2], body[3], body[4]]) == NOW_SYNC_MAGIC_VERSION
}

/// Parse a reassembled ESP-NOW vendor body into a NOW-sync record (borrowed).
/// Returns `None` for any body that is not a well-formed NOW-sync record, so a
/// caller can use this as the bearer routing predicate.
pub fn parse_now_sync_body(body: &[u8]) -> Option<NowSyncFrame<'_>> {
    if !is_now_sync(body) {
        return None;
    }
    let cluster_id: [u8; 6] = body[5..11].try_into().ok()?;
    let anchor_master: [u8; 6] = body[11..17].try_into().ok()?;
    let tsf_us = u64::from_le_bytes(body[17..25].try_into().ok()?);
    let interval_tu = u32::from_le_bytes(body[25..29].try_into().ok()?);
    let flags = body[29];
    Some(NowSyncFrame {
        cluster_id,
        anchor_master,
        tsf_us,
        interval_tu,
        flags,
        service_info: &body[NOW_SYNC_HEADER_LEN..],
    })
}

/// Parse a complete NOW-sync action frame (802.11 header + ESP-NOW envelope)
/// into caller-owned reassembly storage, returning the source MAC and the
/// decoded record. This is the no-std-friendly entry used by firmware; `out`
/// must be at least [`NOW_SYNC_HEADER_LEN`] + [`NOW_SYNC_SERVICE_INFO_MAX_LEN`].
pub fn parse_now_sync_frame<'a>(
    frame: &[u8],
    out: &'a mut [u8],
) -> Option<([u8; 6], NowSyncFrame<'a>)> {
    let (source, used) = espnow::parse_action_frame_into(frame, out)?;
    let record = parse_now_sync_body(&out[..used])?;
    Some((source, record))
}

/// Elect the NOW anchor master over the set of currently-present NOW-only
/// candidates, emulating NAN's documented stronger-beacon convergence rule:
/// the candidate with the strongest beacon (highest RSSI) wins, ties breaking
/// to the lexicographically smallest MAC. `local` is always a candidate.
///
/// RSSI is optional: the ESP-NOW bearer has no public RSSI fact on this
/// receive path, so candidates whose RSSI is `None` rank below any candidate
/// that reports one, and among the `None` candidates the smallest MAC wins.
/// That makes the election symmetric and convergent in the common all-`None`
/// (ESP) case, while still following the stronger-beacon rule when a bearer
/// does report RSSI.
pub fn elect_now_anchor_master(local: [u8; 6], peers: &[([u8; 6], Option<i8>)]) -> [u8; 6] {
    let mut best: ([u8; 6], Option<i8>) = (local, None);
    for &(mac, rssi) in peers {
        let winner = stronger_candidate(best, (mac, rssi));
        best = winner;
    }
    best.0
}

/// Return the stronger of two candidates: higher (less negative) RSSI wins; a
/// reported RSSI outranks a missing one; equal/absent RSSI breaks to the
/// lexicographically smaller MAC.
fn stronger_candidate(a: ([u8; 6], Option<i8>), b: ([u8; 6], Option<i8>)) -> ([u8; 6], Option<i8>) {
    let (a_mac, a_rssi) = a;
    let (b_mac, b_rssi) = b;
    let a_wins = match (a_rssi, b_rssi) {
        (Some(ar), Some(br)) if ar != br => ar > br,
        (Some(_), Some(_)) => a_mac < b_mac,
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (None, None) => a_mac < b_mac,
    };
    if a_wins {
        a
    } else {
        b
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NowSyncAction {
    None,
    /// First cluster observed; adopt it.
    Adopt {
        anchor_master: [u8; 6],
        cluster_id: [u8; 6],
        tsf_us: u64,
    },
    /// Same anchor master; timing refreshed.
    Refresh {
        tsf_us: u64,
    },
    /// A higher-priority cluster (a NAN cluster) is discovered while following
    /// a lower-priority (NOW-only) one; join it immediately (the revert case).
    Join {
        anchor_master: [u8; 6],
        cluster_id: [u8; 6],
        tsf_us: u64,
    },
    /// A same-or-lower-priority foreign anchor is seen after the reselect guard;
    /// switch to it.
    Reselect {
        anchor_master: [u8; 6],
        cluster_id: [u8; 6],
        tsf_us: u64,
    },
    /// A foreign anchor is seen while the selected one is still live.
    DropForeign,
    /// The selected cluster went silent; rediscover.
    Rediscover,
}

/// NOW-cluster follower state. Mirrors [`crate::NanState`] so the NOW cluster
/// applies NAN's identical sticky/reselect/stale policy, keyed on the anchor
/// master (the NAN cluster-BSSID equivalent) with the local receive time of the
/// last in-cluster beacon as the anchor, plus NAN > NOW priority so a discovered
/// NAN cluster is always joined.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NowSyncState {
    mode: crate::FilterMode,
    anchor_master: Option<[u8; 6]>,
    cluster_id: [u8; 6],
    last_tsf_us: u64,
    interval_tu: u32,
    /// Local monotonic receive time of the latest in-cluster beacon; the DW
    /// anchor, exactly as NAN uses the beacon's local receive time.
    last_local_us: u64,
    /// Whether the followed cluster is NAN-aligned (its priority).
    nan_aligned: bool,
    stale_after_us: u64,
}

impl NowSyncState {
    pub const fn new(stale_after_us: u64) -> Self {
        Self {
            mode: crate::FilterMode::Discovery,
            anchor_master: None,
            cluster_id: [0; 6],
            last_tsf_us: 0,
            interval_tu: NOW_SYNC_DEFAULT_INTERVAL_TU,
            last_local_us: 0,
            nan_aligned: false,
            stale_after_us,
        }
    }

    pub const fn mode(&self) -> crate::FilterMode {
        self.mode
    }
    /// The followed anchor master MAC, when one is selected.
    pub const fn anchor_master(&self) -> Option<[u8; 6]> {
        self.anchor_master
    }
    /// The followed cluster's identity (NAN cluster ID or anchor master MAC).
    pub const fn cluster_id(&self) -> [u8; 6] {
        self.cluster_id
    }
    pub const fn last_tsf_us(&self) -> u64 {
        self.last_tsf_us
    }
    pub const fn interval_tu(&self) -> u32 {
        self.interval_tu
    }
    /// Local monotonic receive time of the latest in-cluster beacon; the DW
    /// anchor, exactly as NAN uses the beacon's local receive time.
    pub const fn last_local_us(&self) -> u64 {
        self.last_local_us
    }
    /// Whether the followed cluster is a NAN cluster.
    pub const fn is_nan_aligned(&self) -> bool {
        self.nan_aligned
    }
}

impl Default for NowSyncState {
    fn default() -> Self {
        Self::new(NOW_SYNC_STALE_AFTER_US)
    }
}

fn adopt(mut state: NowSyncState, obs: &NowSyncObservation) -> NowSyncState {
    state.mode = crate::FilterMode::Cluster;
    state.anchor_master = Some(obs.anchor_master);
    state.cluster_id = obs.cluster_id;
    state.last_tsf_us = obs.tsf_us;
    state.interval_tu = obs.interval_tu.max(1);
    state.last_local_us = obs.local_us;
    state.nan_aligned = obs.is_nan_aligned();
    state
}

fn refresh(mut state: NowSyncState, obs: &NowSyncObservation) -> NowSyncState {
    state.last_tsf_us = obs.tsf_us;
    state.interval_tu = obs.interval_tu.max(1);
    state.last_local_us = obs.local_us;
    state
}

/// Observe one NOW-sync frame and return the decision plus the updated state.
/// This is the pure, host-testable core of the NOW cluster follower selection
/// and is the same algorithm shape as [`crate::NanState::observe`], keyed on
/// the anchor master: first anchor adopted, same anchor refreshes timing, a
/// foreign anchor is dropped while the selected one is live, and reselection
/// happens only after [`NOW_SYNC_RESELECT_AFTER_US`] (or immediately when the
/// foreign anchor is a higher-priority NAN cluster). Staleness is handled by
/// [`now_sync_tick`].
pub fn now_sync_observe(
    state: NowSyncState,
    obs: &NowSyncObservation,
) -> (NowSyncAction, NowSyncState) {
    // A record with no anchor master carries no selection information.
    if obs.anchor_master == [0; 6] {
        return (NowSyncAction::None, state);
    }
    match state.anchor_master {
        None => (
            NowSyncAction::Adopt {
                anchor_master: obs.anchor_master,
                cluster_id: obs.cluster_id,
                tsf_us: obs.tsf_us,
            },
            adopt(state, obs),
        ),
        Some(current) if current == obs.anchor_master => (
            NowSyncAction::Refresh { tsf_us: obs.tsf_us },
            refresh(state, obs),
        ),
        Some(_) => {
            if obs.priority() > state.priority() {
                // A NAN cluster was discovered while following a NOW-only one:
                // join it immediately and revert.
                (
                    NowSyncAction::Join {
                        anchor_master: obs.anchor_master,
                        cluster_id: obs.cluster_id,
                        tsf_us: obs.tsf_us,
                    },
                    adopt(state, obs),
                )
            } else if obs.local_us.saturating_sub(state.last_local_us) >= NOW_SYNC_RESELECT_AFTER_US
            {
                (
                    NowSyncAction::Reselect {
                        anchor_master: obs.anchor_master,
                        cluster_id: obs.cluster_id,
                        tsf_us: obs.tsf_us,
                    },
                    adopt(state, obs),
                )
            } else {
                (NowSyncAction::DropForeign, state)
            }
        }
    }
}

/// Advance staleness. Returns [`NowSyncAction::Rediscover`] (and a cleared
/// state) once no in-cluster frame has arrived for `stale_after_us`, mirroring
/// [`crate::NanState::tick`].
pub fn now_sync_tick(state: NowSyncState, now_us: u64) -> (NowSyncAction, NowSyncState) {
    if state.mode == crate::FilterMode::Cluster
        && now_us.saturating_sub(state.last_local_us) >= state.stale_after_us
    {
        (
            NowSyncAction::Rediscover,
            NowSyncState::new(state.stale_after_us),
        )
    } else {
        (NowSyncAction::None, state)
    }
}

/// The next NOW discovery-window start, derived from the observed cluster's
/// local receive anchor. Delegates to NAN's shared 512-TU math so the NOW and
/// NAN windows share one phase calculation.
pub const fn next_now_dw_start_us(anchor_local_us: u64, now_us: u64) -> u64 {
    crate::next_nan_dw_start_us(anchor_local_us, now_us)
}

/// The cluster TSF a new NOW-only master starts from: the Unix time in microseconds when the
/// clock is set (any time after 2020), so independent clusters on synchronized clocks number
/// their windows the same way and DW0 is whichever slot is a multiple of 8 (the low bits of
/// `tsf / 512 TU` are zero), as in a NAN cluster. Without a set clock, the local monotonic
/// time: the cluster is still consistent, only its slot numbers are its own.
pub const fn now_master_tsf_us(unix_us: Option<u64>, local_us: u64) -> u64 {
    const UNIX_2020_US: u64 = 1_577_836_800_000_000;
    match unix_us {
        Some(unix) if unix >= UNIX_2020_US => unix,
        _ => local_us.saturating_add(1),
    }
}

/// What this device sends as its NOW sync record: the fields of
/// [`build_now_sync_frame`], from [`crate::NanState::now_sync_outgoing`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NowSyncOutgoing {
    pub cluster_id: [u8; 6],
    pub anchor_master: [u8; 6],
    pub tsf_us: u64,
    pub interval_tu: u32,
    pub flags: u8,
}

/// The NOW cluster is formed in the one [`crate::NanState`] that also follows real NAN
/// beacons, so the discovery-window scheduler of every platform has a single source of
/// timing. A NOW record plays the part of a beacon: its cluster id is the selection key,
/// its TSF places the window boundary, and the same sticky/3-DW/5-s rules apply. A real
/// NAN cluster always wins over a NOW-only one.
/// The selected cluster, as far as the NOW selection rules need it. A platform that keeps
/// its selection in its own fields (the firmware's atomics) builds one of these and calls
/// [`now_sync_decide`]; [`crate::NanState`] does the same from its own.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NowSelection {
    /// The followed cluster id, `[0; 6]` when none.
    pub cluster: [u8; 6],
    /// It is a real NAN cluster (a NAN beacon or an aligned NOW record selected it).
    pub nan_cluster: bool,
    /// This device is its NOW-only anchor master.
    pub master: bool,
    /// Local receive time of the last record that kept it alive.
    pub last_local_us: u64,
}

/// What an observed NOW sync record does to the selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NowSyncDecision {
    /// Not a usable record (names this device, or nobody).
    Ignore,
    /// Select this record's cluster (a first cluster, a NAN cluster replacing a NOW-only
    /// one, a lower MAC replacing a master, or a reselection after the guard).
    Join,
    /// The followed cluster's timing is refreshed.
    Refresh,
    /// A different cluster while the selected one stays.
    Drop,
}

/// The NOW cluster selection rules, in one place for every platform: the same sticky /
/// 3-DW / 5-s rules as NAN beacons, a real NAN cluster outranking a NOW-only one, and,
/// among NOW-only masters, the lowest MAC winning. With nothing selected a NOW-only
/// cluster is joined only when its id is below `local`; otherwise the caller becomes the
/// master, so two isolated devices cannot adopt each other.
pub fn now_sync_decide(
    selection: NowSelection,
    local: [u8; 6],
    cluster: [u8; 6],
    nan_aligned: bool,
    local_us: u64,
) -> NowSyncDecision {
    use NowSyncDecision::{Drop, Ignore, Join, Refresh};
    if cluster == [0; 6] || cluster == local {
        return Ignore;
    }
    if selection.cluster == [0; 6] {
        return if nan_aligned || cluster < local { Join } else { Ignore };
    }
    if selection.cluster == cluster {
        return Refresh;
    }
    if nan_aligned && !selection.nan_cluster {
        Join
    } else if !nan_aligned && selection.nan_cluster {
        Drop
    } else if selection.master {
        if cluster < selection.cluster { Join } else { Drop }
    } else if local_us.saturating_sub(selection.last_local_us) >= crate::NAN_CLUSTER_RESELECT_AFTER_US {
        Join
    } else {
        Drop
    }
}

impl crate::NanState {
    /// Observe one NOW sync record. `Action::ArmA3(cluster)` reports that this record
    /// selected (or replaced) the followed cluster, exactly as a NAN beacon would; see
    /// [`now_sync_decide`] for the rules.
    pub fn observe_now_sync(
        &mut self,
        local: crate::MacAddr,
        cluster: [u8; 6],
        tsf_us: u64,
        interval_tu: u32,
        nan_aligned: bool,
        local_us: u64,
    ) -> crate::Action {
        use crate::{Action, FilterMode, MacAddr};
        let selection = NowSelection {
            cluster: self.cluster.map_or([0; 6], |mac| mac.0),
            nan_cluster: self.nan_cluster,
            master: self.now_master,
            last_local_us: self.last_beacon_us,
        };
        match now_sync_decide(selection, local.0, cluster, nan_aligned, local_us) {
            NowSyncDecision::Ignore => Action::None,
            NowSyncDecision::Drop => Action::DropForeign,
            NowSyncDecision::Refresh => {
                self.last_beacon_tsf_us = tsf_us;
                self.beacon_interval_tu = interval_tu.max(1);
                self.last_beacon_us = local_us;
                if nan_aligned {
                    self.nan_cluster = true;
                }
                Action::None
            }
            NowSyncDecision::Join => {
                self.cluster = Some(MacAddr(cluster));
                self.sync_bssid = Some(MacAddr(cluster));
                self.last_beacon_tsf_us = tsf_us;
                self.beacon_interval_tu = interval_tu.max(1);
                self.mode = FilterMode::Cluster;
                self.last_beacon_us = local_us;
                self.nan_cluster = nan_aligned;
                self.now_master = false;
                Action::ArmA3(MacAddr(cluster))
            }
        }
    }

    /// Form (or keep) a NOW-only cluster with this device as its anchor master: its own
    /// clock is the cluster TSF, so its windows are the 512-TU multiples of `now_us`.
    /// Does nothing while another cluster is followed. Returns true while master.
    /// Call it when about to send a sync record with nothing selected, and at every
    /// record, so the master's own sync does not go stale.
    pub fn become_now_master(
        &mut self,
        local: crate::MacAddr,
        now_us: u64,
        unix_us: Option<u64>,
    ) -> bool {
        if self.cluster.is_some() && !self.now_master {
            return false;
        }
        // A master already running keeps its phase: its TSF is carried forward, not reset.
        let tsf_us = match (self.now_master, self.now_sync_outgoing(now_us)) {
            (true, Some(out)) => out.tsf_us,
            _ => now_master_tsf_us(unix_us, now_us),
        };
        self.cluster = Some(local);
        self.sync_bssid = Some(local);
        self.last_beacon_tsf_us = tsf_us;
        self.beacon_interval_tu = NOW_SYNC_DEFAULT_INTERVAL_TU;
        self.mode = crate::FilterMode::Cluster;
        self.last_beacon_us = now_us;
        self.nan_cluster = false;
        self.now_master = true;
        true
    }

    pub const fn is_now_master(&self) -> bool {
        self.now_master
    }

    /// The record to send now for the followed cluster, with the cluster TSF carried
    /// forward to `now_us`. `None` when no cluster is selected.
    pub fn now_sync_outgoing(&self, now_us: u64) -> Option<NowSyncOutgoing> {
        let cluster = self.cluster?;
        let mut flags = 0;
        if self.now_master {
            flags |= NOW_SYNC_FLAG_MASTER;
        }
        if self.nan_cluster {
            flags |= NOW_SYNC_FLAG_NAN_ALIGNED;
        }
        Some(NowSyncOutgoing {
            cluster_id: cluster.0,
            anchor_master: cluster.0,
            tsf_us: self
                .last_beacon_tsf_us
                .saturating_add(now_us.saturating_sub(self.last_beacon_us)),
            interval_tu: self.beacon_interval_tu.max(1),
            flags,
        })
    }
}

impl NowSyncState {
    const fn priority(&self) -> u8 {
        if self.nan_aligned {
            1
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(anchor: [u8; 6], tsf_us: u64, local_us: u64, flags: u8) -> NowSyncObservation {
        NowSyncObservation {
            anchor_master: anchor,
            cluster_id: anchor,
            tsf_us,
            interval_tu: 512,
            flags,
            rssi_dbm: -50,
            local_us,
        }
    }

    fn obs_with_cluster(
        anchor: [u8; 6],
        cluster_id: [u8; 6],
        tsf_us: u64,
        local_us: u64,
        flags: u8,
    ) -> NowSyncObservation {
        NowSyncObservation {
            anchor_master: anchor,
            cluster_id,
            tsf_us,
            interval_tu: 512,
            flags,
            rssi_dbm: -50,
            local_us,
        }
    }

    #[test]
    fn now_sync_body_round_trips_and_rejects_a_foreign_magic() {
        let info = build_dmesh_service_info_for_test();
        let body = build_now_sync_body(
            [9, 8, 7, 6, 5, 4],
            [0x30, 0x20, 0x10, 0, 0, 0],
            123_456_789,
            512,
            0x03,
            &info,
        )
        .unwrap();
        assert!(is_now_sync(&body));
        let parsed = parse_now_sync_body(&body).unwrap();
        assert_eq!(parsed.cluster_id, [9, 8, 7, 6, 5, 4]);
        assert_eq!(parsed.anchor_master, [0x30, 0x20, 0x10, 0, 0, 0]);
        assert_eq!(parsed.tsf_us, 123_456_789);
        assert_eq!(parsed.interval_tu, 512);
        assert!(parsed.is_master());
        assert!(parsed.is_nan_aligned());
        assert_eq!(parsed.service_info, info.as_slice());
        // A body with the same prefix byte but a foreign magic value must not
        // be mistaken for a NOW-sync record: only the reserved magic routes to
        // the sync path. This is what lets a shared-bearer integrator tell
        // NOW-sync apart from whatever else uses the prefix shape.
        let mut foreign = [0u8; NOW_SYNC_HEADER_LEN];
        foreign[0] = NOW_SYNC_PREFIX_BYTE;
        foreign[1..5].copy_from_slice(&0x0000_0001u32.to_be_bytes());
        assert!(!is_now_sync(&foreign));
        // A body without the prefix byte is never NOW-sync.
        assert!(!is_now_sync(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]));
    }

    #[test]
    fn now_sync_frame_round_trips_through_the_espnow_envelope() {
        let info = build_dmesh_service_info_for_test();
        let frame = build_now_sync_frame(
            [1, 2, 3, 4, 5, 6],
            [9, 8, 7, 6, 5, 4],
            [0x30, 0x20, 0x10, 0, 0, 0],
            42,
            512,
            NOW_SYNC_FLAG_MASTER | NOW_SYNC_FLAG_NAN_ALIGNED,
            &info,
        )
        .unwrap();
        assert!(crate::is_action_frame(&frame));
        // Broadcast address-1 and address-3.
        assert_eq!(&frame[4..10], &[0xff; 6]);
        assert_eq!(&frame[16..22], &[0xff; 6]);
        let mut out = [0u8; NOW_SYNC_HEADER_LEN + NOW_SYNC_SERVICE_INFO_MAX_LEN];
        let (source, record) = parse_now_sync_frame(&frame, &mut out).unwrap();
        assert_eq!(source, [1, 2, 3, 4, 5, 6]);
        assert_eq!(record.cluster_id, [9, 8, 7, 6, 5, 4]);
        assert_eq!(record.anchor_master, [0x30, 0x20, 0x10, 0, 0, 0]);
        assert_eq!(record.tsf_us, 42);
        assert!(record.is_nan_aligned());
        assert_eq!(record.service_info, info.as_slice());
    }

    #[test]
    fn oversize_service_info_is_rejected() {
        let mut info = [0u8; NOW_SYNC_SERVICE_INFO_MAX_LEN + 1];
        info[..2].copy_from_slice(&crate::DMESH_MAGIC);
        assert!(build_now_sync_body([0; 6], [0; 6], 0, 512, 0, &info).is_err());
    }

    #[test]
    fn anchor_master_election_all_missing_rssi_is_symmetric_and_convergent() {
        let a = [1; 6];
        let b = [2; 6];
        // No RSSI (the ESP-NOW case): the smallest MAC wins and the election is
        // symmetric, so both isolated peers elect the same master.
        assert_eq!(elect_now_anchor_master(a, &[(b, None)]), a);
        assert_eq!(elect_now_anchor_master(b, &[(a, None)]), a);
        // An isolated device is its own master.
        assert_eq!(elect_now_anchor_master(a, &[]), a);
    }

    #[test]
    fn anchor_master_election_with_rssi_prefers_reported_peer() {
        let a = [1; 6]; // local has no self-RSSI
        let b = [2; 6];
        // A peer that reports an RSSI outranks local, which has none.
        assert_eq!(elect_now_anchor_master(a, &[(b, Some(-50))]), b);
    }

    #[test]
    fn anchor_master_stronger_candidate_rules() {
        let a = [1; 6];
        let b = [2; 6];
        // Stronger (higher, less negative) RSSI wins regardless of MAC.
        assert_eq!(stronger_candidate((a, Some(-70)), (b, Some(-50))).0, b);
        // A reported RSSI outranks a missing one.
        assert_eq!(stronger_candidate((a, None), (b, Some(-90))).0, b);
        assert_eq!(stronger_candidate((a, Some(-90)), (b, None)).0, a);
        // Equal RSSI breaks to the smaller MAC.
        assert_eq!(stronger_candidate((a, Some(-60)), (b, Some(-60))).0, a);
        // Both missing breaks to the smaller MAC.
        assert_eq!(stronger_candidate((a, None), (b, None)).0, a);
    }

    #[test]
    fn now_sync_state_adopts_then_refreshes_then_drops_foreign() {
        let state = NowSyncState::default();
        let (action, state) = now_sync_observe(state, &obs([1; 6], 100, 1_000, 0));
        assert_eq!(
            action,
            NowSyncAction::Adopt {
                anchor_master: [1; 6],
                cluster_id: [1; 6],
                tsf_us: 100
            }
        );
        assert_eq!(state.anchor_master(), Some([1; 6]));
        assert_eq!(state.mode(), crate::FilterMode::Cluster);

        let (action, state) = now_sync_observe(state, &obs([1; 6], 200, 2_000, 0));
        assert_eq!(action, NowSyncAction::Refresh { tsf_us: 200 });

        // A foreign anchor is dropped while the selected one is still live.
        let (action, _) = now_sync_observe(state, &obs([2; 6], 300, 2_500, 0));
        assert_eq!(action, NowSyncAction::DropForeign);
    }

    #[test]
    fn now_sync_state_reselects_after_reselect_guard_and_rediscover_on_stale() {
        let state = NowSyncState::default();
        let (_, state) = now_sync_observe(state, &obs([1; 6], 100, 1_000, 0));
        // After the reselect guard elapses, a same-priority foreign anchor is
        // adopted.
        let reselect_at = 1_000 + NOW_SYNC_RESELECT_AFTER_US + 1;
        let (action, state) = now_sync_observe(state, &obs([2; 6], 300, reselect_at, 0));
        assert_eq!(
            action,
            NowSyncAction::Reselect {
                anchor_master: [2; 6],
                cluster_id: [2; 6],
                tsf_us: 300
            }
        );
        assert_eq!(state.anchor_master(), Some([2; 6]));

        // Staleness clears the selection.
        let (action, state) = now_sync_tick(state, reselect_at + NOW_SYNC_STALE_AFTER_US + 1);
        assert_eq!(action, NowSyncAction::Rediscover);
        assert_eq!(state.anchor_master(), None);
        assert_eq!(state.mode(), crate::FilterMode::Discovery);
    }

    #[test]
    fn nan_aligned_cluster_joins_immediately_over_now_only() {
        // Following a NOW-only cluster.
        let state = NowSyncState::default();
        let (_, state) = now_sync_observe(state, &obs([1; 6], 100, 1_000, 0));
        assert!(!state.is_nan_aligned());
        // A NAN-aligned beacon from a different anchor is joined immediately,
        // before the reselect guard (the "revert to NAN" case).
        let (action, state) = now_sync_observe(
            state,
            &obs_with_cluster([5; 6], [7; 6], 900, 1_100, NOW_SYNC_FLAG_NAN_ALIGNED),
        );
        assert_eq!(
            action,
            NowSyncAction::Join {
                anchor_master: [5; 6],
                cluster_id: [7; 6],
                tsf_us: 900
            }
        );
        assert!(state.is_nan_aligned());
        assert_eq!(state.cluster_id(), [7; 6]);
        assert_eq!(state.anchor_master(), Some([5; 6]));
    }

    #[test]
    fn now_only_cannot_displace_nan_aligned() {
        // Following a NAN cluster; a NOW-only beacon must not displace it
        // before the reselect guard.
        let state = NowSyncState::default();
        let (_, state) = now_sync_observe(
            state,
            &obs_with_cluster([5; 6], [7; 6], 100, 1_000, NOW_SYNC_FLAG_NAN_ALIGNED),
        );
        assert!(state.is_nan_aligned());
        let (action, state) = now_sync_observe(state, &obs([2; 6], 300, 1_500, 0));
        assert_eq!(action, NowSyncAction::DropForeign);
        assert!(state.is_nan_aligned());
        assert_eq!(state.anchor_master(), Some([5; 6]));
    }

    #[test]
    fn now_dw_reuses_nan_phase_math() {
        let anchor = 7_123_456;
        assert_eq!(
            next_now_dw_start_us(anchor, anchor + 1),
            anchor + NOW_SYNC_DISCOVERY_PERIOD_US
        );
        assert_eq!(
            next_now_dw_start_us(anchor, anchor + 2 * NOW_SYNC_DISCOVERY_PERIOD_US + 7),
            anchor + 3 * NOW_SYNC_DISCOVERY_PERIOD_US
        );
    }

    fn build_dmesh_service_info_for_test() -> Vec<u8> {
        crate::build_dmesh_service_info([9, 8, 7, 6, 5, 4], 1, None).to_vec()
    }

    mod cluster {
        use super::*;
        use crate::{Action, MacAddr, NanState, NAN_DISCOVERY_PERIOD_US as P};

        const A: MacAddr = MacAddr([2, 0, 0, 0, 0, 1]);
        const B: MacAddr = MacAddr([2, 0, 0, 0, 0, 2]);
        const C: MacAddr = MacAddr([2, 0, 0, 0, 0, 3]);

        fn state() -> NanState {
            NanState::new(crate::NAN_CLUSTER_STALE_AFTER_US)
        }

        #[test]
        fn two_isolated_devices_converge_on_the_lowest_mac_and_never_adopt_each_other() {
            let (mut a, mut b) = (state(), state());
            assert!(a.become_now_master(A, 1_000_000, None));
            assert!(b.become_now_master(B, 2_000_000, None));
            let from_a = a.now_sync_outgoing(1_100_000).unwrap();
            let from_b = b.now_sync_outgoing(2_100_000).unwrap();
            assert!(from_a.flags & NOW_SYNC_FLAG_MASTER != 0);
            // The higher MAC follows; the lower one ignores it.
            assert_eq!(a.observe_now_sync(A, from_b.cluster_id, from_b.tsf_us, 512, false, 1_100_000), Action::DropForeign);
            assert_eq!(b.observe_now_sync(B, from_a.cluster_id, from_a.tsf_us, 512, false, 2_100_000), Action::ArmA3(A));
            assert_eq!(b.cluster(), Some(A));
            assert!(!b.is_now_master() && a.is_now_master());
            // B now forwards A's cluster, not its own, with A's TSF carried forward.
            let forwarded = b.now_sync_outgoing(2_200_000).unwrap();
            assert_eq!(forwarded.cluster_id, A.0);
            assert_eq!(forwarded.tsf_us, from_a.tsf_us + 100_000);
            assert_eq!(forwarded.flags & NOW_SYNC_FLAG_MASTER, 0);
        }

        #[test]
        fn a_follower_places_its_windows_on_the_masters_clock() {
            let mut b = state();
            let tsf = 5 * P + 1_000;
            assert_eq!(b.observe_now_sync(B, A.0, tsf, 512, false, 9_000_000), Action::ArmA3(A));
            let open = b.window_at_or_after(9_000_000).unwrap();
            assert_eq!((open.slot, open.start_local_us), (5, 9_000_000 - 1_000));
            let next = b.window_at_or_after(9_000_000 + crate::NAN_TX_DWELL_US).unwrap();
            assert_eq!((next.slot, next.start_local_us), (6, 9_000_000 - 1_000 + P));
        }

        #[test]
        fn nothing_selected_and_a_higher_mac_leaves_the_caller_to_become_master() {
            let mut a = state();
            assert_eq!(a.observe_now_sync(A, B.0, 10, 512, false, 1), Action::None);
            assert!(a.cluster().is_none());
            assert_eq!(a.observe_now_sync(B, A.0, 10, 512, false, 1), Action::ArmA3(A));
            // A record naming this device itself, or nobody, is ignored.
            assert_eq!(state().observe_now_sync(A, A.0, 10, 512, false, 1), Action::None);
            assert_eq!(state().observe_now_sync(A, [0; 6], 10, 512, false, 1), Action::None);
        }

        #[test]
        fn a_follower_is_sticky_until_the_guard_and_the_master_never_follows_a_higher_mac() {
            let mut s = state();
            assert_eq!(s.observe_now_sync(C, B.0, 10, 512, false, 1_000), Action::ArmA3(B));
            // A lower MAC does not take over inside the guard, only after 3 DWs.
            assert_eq!(s.observe_now_sync(C, A.0, 10, 512, false, 2_000), Action::DropForeign);
            let late = 1_000 + crate::NAN_CLUSTER_RESELECT_AFTER_US;
            assert_eq!(s.observe_now_sync(C, A.0, 10, 512, false, late), Action::ArmA3(A));
            let mut m = state();
            m.become_now_master(A, 1_000, None);
            assert_eq!(m.observe_now_sync(A, C.0, 10, 512, false, 2_000), Action::DropForeign);
            assert_eq!(m.cluster(), Some(A));
        }

        #[test]
        fn a_nan_cluster_replaces_a_now_only_one_at_once_and_is_never_replaced_by_one() {
            let mut s = state();
            s.become_now_master(A, 1_000, None);
            // A NOW record reporting a NAN cluster joins it (the revert case).
            let nan = [0x50, 0x6f, 0x9a, 1, 2, 3];
            assert_eq!(s.observe_now_sync(A, nan, 7 * P, 512, true, 2_000), Action::ArmA3(MacAddr(nan)));
            assert!(!s.is_now_master());
            assert_eq!(s.now_sync_outgoing(2_000).unwrap().flags, NOW_SYNC_FLAG_NAN_ALIGNED);
            // A NOW-only record, even with a lower MAC, is dropped while a NAN cluster is live.
            assert_eq!(s.observe_now_sync(B, [1; 6], 1, 512, false, 3_000), Action::DropForeign);
            // And a NOW-only follower is replaced by a real NAN beacon at once.
            let mut f = state();
            f.observe_now_sync(C, B.0, 1, 512, false, 1_000);
            assert!(!f.nan_cluster);
        }

        #[test]
        fn a_master_numbers_its_windows_by_unix_time_so_dw0_is_a_multiple_of_8() {
            let unix = 1_790_000_000_000_000u64 / P * P + 1_000;
            let mut a = state();
            a.become_now_master(A, 5_000_000, Some(unix));
            let slot = a.window_at_or_after(5_000_000).unwrap().slot;
            assert_eq!(slot, unix / P);
            // Refreshing keeps the phase; an unset clock falls back to local time.
            a.become_now_master(A, 5_100_000, Some(unix + 999_999_999));
            assert_eq!(a.now_sync_outgoing(5_100_000).unwrap().tsf_us, unix + 100_000);
            assert_eq!(now_master_tsf_us(Some(12345), 777), 778);
            // A follower in another clock domain lands on the same slots.
            let out = a.now_sync_outgoing(5_300_000).unwrap();
            let mut b = state();
            b.observe_now_sync(B, out.cluster_id, out.tsf_us, 512, false, 900_000_000);
            let w = b.window_at_or_after(900_000_000).unwrap();
            // The master's window 301 ms ago is over; the follower's next one is the next slot.
            assert_eq!(w.slot, out.tsf_us / P + 1);
        }

        #[test]
        fn the_master_goes_stale_without_refreshing_itself_and_follows_none() {
            let mut m = state();
            m.become_now_master(A, 1_000, None);
            assert_eq!(m.tick(1_000 + crate::NAN_CLUSTER_STALE_AFTER_US), Action::Rediscover);
            assert!(m.cluster().is_none() && !m.is_now_master());
            assert!(m.now_sync_outgoing(0).is_none());
            // A follower is not turned into a master.
            let mut f = state();
            f.observe_now_sync(C, B.0, 1, 512, false, 1);
            assert!(!f.become_now_master(C, 100, None));
            assert_eq!(f.cluster(), Some(B));
        }
    }
}
