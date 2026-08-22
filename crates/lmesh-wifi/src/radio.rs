use anyhow::{Context, Result, bail};
use mesh::message::{
    FIELD_IFACE, FIELD_LEN, FIELD_MEDIUM, FIELD_NETWORK, FIELD_NODE, FIELD_PAYLOAD, FIELD_RADIO_ID,
    FIELD_RSSI, FIELD_SNR, FIELD_STATUS, MeshMessage, MeshMessageCodec,
};
use minicbor::Encoder;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::radio_protocol;
use dmesh_rawnan::service::FollowupDedup;
use dmesh_rawnan::{Action as RawNanAction, NanActivePublish, NanState, RxFrame as RawNanRxFrame};
use dmesh_server::raw_wifi::{WIFI_LINK_METRICS_SCHEMA_VERSION, WifiLinkMetrics};

const DEFAULT_WIFI_IFACE: &str = "wlan1";
// Firmware raw-NAN peers normally wake every four seconds for a short window.
// A 700 ms probe cadence walks that phase rather than repeatedly landing on a
// fixed 250/500 ms boundary.
const DEFAULT_HCI_DEV: u16 = 0;
const DEFAULT_RAW_WIFI_CHANNEL: u8 = 6;
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
/// Only a bounded tail is needed to restore the at-most-256 live inventory.
/// This keeps a provisioned persistent change log from becoming an unbounded
/// startup read after months of topology churn.
const MAX_DISCOVERY_LOG_RESTORE_BYTES: u64 = 64 * 1_024;
/// The supervised service owns this writable run directory. Operators that
/// need reboot-persistent topology evidence set `LMESH_DISCOVERY_LOG` (or the
/// older `LMESH_WIFI_DISCOVERY_LOG`) to a provisioned durable path; do not
/// silently depend on `/var/log` being writable by the service account.
const DEFAULT_DISCOVERY_CHANGE_LOG: &str = "/run/mesh/lmesh-wifi/discovery.jsonl";
const ETH_P_ALL: u16 = 0x0003;
const ETH_P_DMESH: u16 = 0x88b5;
const ETHERNET_HEADER_LEN: usize = 14;
const IEEE80211_LLC_SNAP_LEN: usize = 8;
const PACKET_ADD_MEMBERSHIP: libc::c_int = 1;
const PACKET_MR_MULTICAST: libc::c_ushort = 0;

/// Complete-datagram client contract shared by the bounded IPERF benchmark
/// and the small production status check.  Raw 802.11 injection/capture stays
/// below this boundary; service clients stay in `dmesh-server`.
trait RawActionClient {
    fn start(
        &mut self,
        output: &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE],
    ) -> Result<usize, quic_lite::Error>;
    fn receive_at(
        &mut self,
        input: &[u8],
        now_ms: u64,
        output: &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE],
    ) -> Result<Option<usize>, quic_lite::Error>;
    fn is_complete(&self) -> bool;
    /// Poll delayed ACK/window control.  Action bearers have no socket task
    /// to drive the QUIC clock, so the adapter must explicitly service this
    /// timer path between received frames.
    fn poll_transmit(
        &mut self,
        output: &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE],
    ) -> Result<Option<usize>, quic_lite::Error>;
    fn poll_retransmit(
        &mut self,
        now_us: u64,
        pto_us: u64,
        output: &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE],
    ) -> Result<Option<usize>, quic_lite::Error>;
}

/// A monitor VIF receives every matching action frame, including delayed
/// packets from a previous association and unrelated NAN/management traffic.
/// These errors mean that a frame is not for this client CID and must not
/// poison the active request; actual transport/codec failures remain fatal.
fn raw_action_receive_error_is_ambient(error: quic_lite::Error) -> bool {
    matches!(
        error,
        quic_lite::Error::WrongConnectionId
            | quic_lite::Error::BootstrapInvalid
            | quic_lite::Error::Invalid
    )
}

impl RawActionClient
    for dmesh_server::raw_iperf::RawIperfClient<16, { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE }>
{
    fn start(
        &mut self,
        output: &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE],
    ) -> Result<usize, quic_lite::Error> {
        Self::start(self, output)
    }

    fn is_complete(&self) -> bool {
        Self::is_complete(self)
    }

    fn receive_at(
        &mut self,
        input: &[u8],
        now_ms: u64,
        output: &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE],
    ) -> Result<Option<usize>, quic_lite::Error> {
        Self::receive_at(self, input, now_ms, output)
    }

    fn poll_transmit(
        &mut self,
        output: &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE],
    ) -> Result<Option<usize>, quic_lite::Error> {
        <dmesh_server::raw_iperf::RawIperfClient<16, { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE }>>::poll_transmit_at(self, now_millis_u64(), output)
    }
    fn poll_retransmit(
        &mut self,
        now_us: u64,
        pto_us: u64,
        output: &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE],
    ) -> Result<Option<usize>, quic_lite::Error> {
        <dmesh_server::raw_iperf::RawIperfClient<16, { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE }>>::poll_retransmit(self, now_us, pto_us, output)
    }
}

impl RawActionClient
    for dmesh_server::raw_iperf::RawCheckClient<16, { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE }>
{
    fn start(
        &mut self,
        output: &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE],
    ) -> Result<usize, quic_lite::Error> {
        Self::start(self, output)
    }

    fn is_complete(&self) -> bool {
        Self::is_complete(self)
    }

    fn receive_at(
        &mut self,
        input: &[u8],
        now_ms: u64,
        output: &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE],
    ) -> Result<Option<usize>, quic_lite::Error> {
        Self::receive_at(self, input, now_ms, output)
    }

    fn poll_transmit(
        &mut self,
        output: &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE],
    ) -> Result<Option<usize>, quic_lite::Error> {
        <dmesh_server::raw_iperf::RawCheckClient<16, { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE }>>::poll_transmit(self, output)
    }
    fn poll_retransmit(
        &mut self,
        now_us: u64,
        pto_us: u64,
        output: &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE],
    ) -> Result<Option<usize>, quic_lite::Error> {
        <dmesh_server::raw_iperf::RawCheckClient<16, { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE }>>::poll_retransmit(self, now_us, pto_us, output)
    }
}

#[derive(Debug)]
struct RawActionRun {
    elapsed_us: u128,
    tx_packets: u64,
    /// Driver/socket transmission failures. A successful local write is not
    /// proof that the frame reached the peer (especially for monitor inject).
    tx_errors: u64,
    /// Structured result of the most recent raw frame submission. This keeps
    /// adapter errors (for example nl80211 EINVAL) visible to automated tests
    /// without retaining packet bytes.
    last_tx: Option<Value>,
    rx_packets: u64,
    retransmit_packets: u64,
    error: Option<String>,
}

const NETLINK_GENERIC: libc::c_int = 16;
const NETLINK_EXT_ACK: libc::c_int = 11;
const GENL_ID_CTRL: u16 = 16;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const NLMSGERR_ATTR_MSG: u16 = 1;
const NLMSGERR_ATTR_OFFS: u16 = 2;
const NLMSGERR_ATTR_MISS_TYPE: u16 = 5;
const NL80211_GENL_VERSION: u8 = 1;
const NL80211_CMD_SET_WIPHY: u8 = 2;
// `NL80211_ATTR_TX_RATES` is interpreted only by this command.  Sending the
// attribute in SET_WIPHY can ACK without constraining per-interface data TX.
const NL80211_CMD_SET_TX_BITRATE_MASK: u8 = 57;
const NL80211_CMD_SET_INTERFACE: u8 = 6;
const NL80211_CMD_SET_POWER_SAVE: u8 = 61;
const NL80211_CMD_REMAIN_ON_CHANNEL: u8 = 55;
const NL80211_CMD_REGISTER_FRAME: u8 = 58;
const NL80211_CMD_FRAME: u8 = 59;
const NL80211_CMD_START_AP: u8 = 15;
const NL80211_CMD_STOP_AP: u8 = 16;
const NL80211_CMD_GET_STATION: u8 = 17;
const NL80211_CMD_NEW_STATION: u8 = 19;
const NL80211_CMD_DEL_STATION: u8 = 20;
const NL80211_CMD_CONNECT: u8 = 46;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFTYPE: u16 = 5;
const NL80211_ATTR_PS_STATE: u16 = 93;
const NL80211_ATTR_WIPHY_TX_POWER_SETTING: u16 = 97;
const NL80211_ATTR_WIPHY_TX_POWER_LEVEL: u16 = 98;
// NL80211_ATTR_TX_RATES is the nested per-band rate policy used by `iw
// set bitrates`.  Keep the values local rather than depending on libnl/iw.
const NL80211_ATTR_TX_RATES: u16 = 90;
const NL80211_ATTR_MAC: u16 = 6;
const NL80211_ATTR_BEACON_INTERVAL: u16 = 12;
const NL80211_ATTR_DTIM_PERIOD: u16 = 13;
const NL80211_ATTR_BEACON_HEAD: u16 = 14;
const NL80211_ATTR_BEACON_TAIL: u16 = 15;
const NL80211_ATTR_STA_AID: u16 = 16;
const NL80211_ATTR_STA_FLAGS2: u16 = 67;
const NL80211_ATTR_STA_LISTEN_INTERVAL: u16 = 18;
const NL80211_ATTR_STA_SUPPORTED_RATES: u16 = 19;
const NL80211_ATTR_STA_INFO: u16 = 21;
const NL80211_ATTR_HT_CAPABILITY: u16 = 31;
const NL80211_ATTR_BSS_BASIC_RATES: u16 = 36;
const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
const NL80211_ATTR_WIPHY_CHANNEL_TYPE: u16 = 39;
const NL80211_ATTR_IE: u16 = 42;
const NL80211_ATTR_FREQ_FIXED: u16 = 60;
const NL80211_ATTR_FRAME: u16 = 51;
const NL80211_ATTR_SSID: u16 = 52;
const NL80211_ATTR_AUTH_TYPE: u16 = 53;
const NL80211_ATTR_CIPHER_SUITE_GROUP: u16 = 74;
const NL80211_ATTR_DURATION: u16 = 87;
const NL80211_ATTR_FRAME_MATCH: u16 = 91;
const NL80211_ATTR_FRAME_TYPE: u16 = 101;
const NL80211_ATTR_BSS_HT_OPMODE: u16 = 109;
const NL80211_ATTR_OFFCHANNEL_TX_OK: u16 = 108;
const NL80211_ATTR_HIDDEN_SSID: u16 = 126;
const NL80211_ATTR_IE_PROBE_RESP: u16 = 127;
const NL80211_ATTR_IE_ASSOC_RESP: u16 = 128;
const NL80211_ATTR_STA_WME: u16 = 129;
const NL80211_ATTR_STA_CAPABILITY: u16 = 171;
const NL80211_ATTR_STA_EXT_CAPABILITY: u16 = 172;
const NL80211_ATTR_TX_NO_CCK_RATE: u16 = 135;
const NL80211_ATTR_DONT_WAIT_FOR_ACK: u16 = 142;
const NL80211_ATTR_PROBE_RESP: u16 = 145;
const NL80211_ATTR_RX_SIGNAL_DBM: u16 = 151;
const NL80211_ATTR_CHANNEL_WIDTH: u16 = 159;
const NL80211_ATTR_CENTER_FREQ1: u16 = 160;
const NL80211_ATTR_SOCKET_OWNER: u16 = 204;
const NL80211_ATTR_COOKIE: u16 = 88;
const NL80211_AUTHTYPE_OPEN_SYSTEM: u32 = 0;
const NL80211_HIDDEN_SSID_NOT_IN_USE: u32 = 0;
const NL80211_PS_DISABLED: u32 = 0;
const NL80211_PS_ENABLED: u32 = 1;
const NL80211_CHAN_NO_HT: u32 = 0;
const NL80211_CHAN_HT20: u32 = 1;
const NL80211_CHAN_HT40PLUS: u32 = 3;
const NL80211_CHAN_WIDTH_20_NOHT: u32 = 0;
const NL80211_CHAN_WIDTH_20: u32 = 1;
const NL80211_CHAN_WIDTH_40: u32 = 2;
const WLAN_CIPHER_SUITE_WEP40: u32 = 0x000f_ac01;
const NL80211_STA_INFO_INACTIVE_TIME: u16 = 1;
const NL80211_STA_INFO_RX_BYTES: u16 = 2;
const NL80211_STA_INFO_TX_BYTES: u16 = 3;
const NL80211_STA_INFO_SIGNAL: u16 = 7;
const NL80211_STA_INFO_TX_BITRATE: u16 = 8;
const NL80211_STA_INFO_RX_PACKETS: u16 = 9;
const NL80211_STA_INFO_TX_PACKETS: u16 = 10;
const NL80211_STA_INFO_TX_RETRIES: u16 = 11;
const NL80211_STA_INFO_TX_FAILED: u16 = 12;
const NL80211_STA_INFO_SIGNAL_AVG: u16 = 13;
const NL80211_STA_INFO_RX_BITRATE: u16 = 14;
const NL80211_STA_INFO_CONNECTED_TIME: u16 = 16;
const NL80211_STA_INFO_STA_FLAGS: u16 = 17;
const NL80211_STA_INFO_RX_BYTES64: u16 = 23;
const NL80211_STA_INFO_TX_BYTES64: u16 = 24;
const NL80211_STA_INFO_EXPECTED_THROUGHPUT: u16 = 28;
const NL80211_STA_INFO_RX_DROP_MISC: u16 = 29;
const NL80211_STA_INFO_RX_DURATION: u16 = 32;
const NL80211_STA_INFO_ACK_SIGNAL: u16 = 34;
const NL80211_STA_INFO_ACK_SIGNAL_AVG: u16 = 35;
const NL80211_STA_INFO_RX_MPDUS: u16 = 36;
const NL80211_STA_INFO_FCS_ERROR_COUNT: u16 = 37;
const NL80211_STA_INFO_TX_DURATION: u16 = 39;
const NL80211_RATE_INFO_BITRATE: u16 = 1;
const NL80211_RATE_INFO_MCS: u16 = 2;
const NL80211_RATE_INFO_40_MHZ_WIDTH: u16 = 3;
const NL80211_RATE_INFO_SHORT_GI: u16 = 4;
const NL80211_RATE_INFO_BITRATE32: u16 = 5;
const NL80211_RATE_INFO_VHT_MCS: u16 = 6;
const NL80211_RATE_INFO_VHT_NSS: u16 = 7;
const NL80211_TXRATE_LEGACY: u16 = 1;
const NL80211_TXRATE_HT: u16 = 2;
const NL80211_IFTYPE_STATION: u32 = 2;
const NL80211_IFTYPE_AP: u32 = 3;
const NL80211_IFTYPE_OCB: u32 = 11;
const NL80211_STA_FLAG_AUTHORIZED: u32 = 1 << 1;
const NL80211_STA_FLAG_SHORT_PREAMBLE: u32 = 1 << 2;
const NL80211_STA_FLAG_WME: u32 = 1 << 3;
const NL80211_STA_FLAG_AUTHENTICATED: u32 = 1 << 5;
const NL80211_STA_FLAG_ASSOCIATED: u32 = 1 << 7;
// The stable Recovery AP is a bulk-data HT20 network.  Do not admit CCK or
// low OFDM fallbacks. The ESP C6 refuses association when 24 Mbps is present
// in this AP's basic-rate set, so retain mandatory 6 Mbps solely for
// BSS/control compatibility while excluding 9/12/18 Mbps and all CCK rates.
// Optional data rates remain 24/36/48/54 plus HT. This rate set applies to
// beacon, probe, association, and the nl80211 AP profile.
const OPEN_AP_OFDM_BASIC_RATES: [u8; 1] = [0x8c];
const OPEN_AP_OFDM_EXTENDED_RATES: [u8; 4] = [0x30, 0x48, 0x60, 0x6c];
// The AP driver selects HT short-GI data rates when the peer supports them.
// Advertise SGI-20 in the management IE as well: sending short-GI frames
// after advertising no SGI leaves an ESP STA with a contradictory negotiated
// PHY profile. HT40 additionally enables the matching SGI-40 bit below.
const HOSTAPD_HT20_CAPABILITY: [u8; 28] = [
    0x2d, 26, 0x2c, 0x00, 0x1b, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// The manual AP SME must advertise the same width in beacon, probe, and
// association response as nl80211 operates. Keep the shared channel-6 lab
// and production default at HT20: NAN/NOW, STA, and AP must all share the
// same 20 MHz channel without occupying the adjacent channel. HT40 is an
// explicit opt-in for a dedicated AP experiment only.
const DEFAULT_OPEN_AP_HT40: bool = false;

fn open_ap_basic_rates() -> &'static [u8] {
    &OPEN_AP_OFDM_BASIC_RATES
}

const NLM_F_DUMP: u16 = 0x300;
// Netlink attributes reserve the high two type bits for NLA_F_NESTED and
// NLA_F_NET_BYTEORDER.  Match the attribute number independently of those
// flags; station/rate information is commonly nested.
const NLA_TYPE_MASK: u16 = 0x3fff;
const DMESH_ESPNOW_PREFIX: [u8; 4] = [0x7f, 0x18, 0xfe, 0x34];
// rawnan owns the ESP-NOW-compatible action prefix.  Its current envelope is
// category/OUI plus four random bytes; the vendor type lives in the first IE,
// not after this prefix.
const DMESH_VENDOR_ACTION_LEN: usize = 8;
const DMESH_VENDOR_IE_LEN: usize = 7;
const DMESH_MESH_DST4_BROADCAST: [u8; 4] = [0xff; 4];
const DMESH_LEGACY_VENDOR_ACTION: [u8; 5] = [0x7f, 0x50, 0x6f, 0x9a, 0x42];
const IEEE80211_ADDR1: usize = 4;
const IEEE80211_ADDR2: usize = 10;
const IEEE80211_ADDR3: usize = 16;
const IEEE80211_BODY: usize = 24;
const IEEE80211_ACTION_FRAME_TYPE: u16 = 0x00d0;
const RAW_WIFI_BROADCAST: [u8; 6] = [0xff; 6];
const RAW_WIFI_MULTICAST: [u8; 6] = [0x33, 0x33, 0x00, 0x00, 0x52, 0x27];
const IEEE80211_LLC_SNAP_DMESH: [u8; IEEE80211_LLC_SNAP_LEN] = [
    0xaa,
    0xaa,
    0x03,
    0x00,
    0x00,
    0x00,
    (ETH_P_DMESH >> 8) as u8,
    ETH_P_DMESH as u8,
];
const IEEE80211_LLC_SNAP_IPV6: [u8; IEEE80211_LLC_SNAP_LEN] =
    [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x86, 0xdd];
// Private experimental marker for raw NAN data tests.  The payload after
// this eight-byte LLC value is quic-lite directly, not IPv6/UDP.
const RAWNAN_LLC_DEFAULT: [u8; IEEE80211_LLC_SNAP_LEN] =
    [0xaa, 0xaa, 0x03, 0xd0, 0x4d, 0x45, 0x53, 0x48];
const RAW_ACTION_RESPONSE_REPETITIONS: usize = 1;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const IFF_UP: u32 = 0x1;

/// Linux radio backend used by the lmesh JSONL methods.
#[derive(Clone)]
pub struct RadioService {
    history: Arc<Mutex<VecDeque<RadioEvent>>>,
    discovered_devices: Arc<Mutex<DiscoveredDeviceRegistry>>,
    radios: Arc<Vec<RadioAdapter>>,
    raw_wifi_listeners: Arc<Mutex<HashSet<String>>>,
    raw_wifi_stop_flags: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
    // The host raw-action receiver uses the same bounded QUIC-lite service
    // dispatcher as firmware. It is created lazily only after the first
    // valid NOW packet, so normal AP/NAN operation reserves no transport RAM.
    raw_action_dispatcher: Arc<
        Mutex<
            Option<
                dmesh_server::raw_iperf::RawIperfDispatcher<
                    16,
                    { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE },
                >,
            >,
        >,
    >,
    rawnan_subscribers: Arc<Mutex<HashMap<String, usize>>>,
    rawnan_state: Arc<Mutex<NanState>>,
    active_nan_publish: Arc<Mutex<NanActivePublish>>,
    pending_nan_followups: Arc<Mutex<dmesh_rawnan::NanFollowupQueue>>,
    wifi_ap_handles: Arc<Mutex<BTreeMap<String, ApRuntime>>>,
    ap_no_ht_stations: Arc<Mutex<HashSet<[u8; 6]>>>,
    object_udp_started: Arc<AtomicBool>,
    transport_control: Arc<dmesh_server::udp::TransportControl>,
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
    source: String,
    peer: String,
    bssid: Option<String>,
    announce: Value,
}

struct DiscoveredDeviceRegistry {
    devices: BTreeMap<String, DiscoveredDevice>,
    change_log: PathBuf,
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
            change_log,
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
        let device_id = hex_bytes(announce.device_id());
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
                "transport_mode": announce.transport_mode,
                "counters": announce.counters,
            }),
        });
    }

    fn snapshot(&mut self) -> Vec<DiscoveredDevice> {
        self.expire(now_millis());
        let mut entries = self.devices.values().cloned().collect::<Vec<_>>();
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.last_seen_ms));
        entries
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

fn discovered_device_json(entry: &DiscoveredDevice) -> Value {
    json!({
        "id": entry.device_id,
        "last_seen_ms": entry.last_seen_ms,
        "source": entry.source,
        "peer": entry.peer,
        "bssid": entry.bssid,
        "announce": entry.announce,
    })
}

/// A host/Android announce that includes a public key must prove ownership of
/// it on every ingress, including raw NAN. ESP32 deliberately omits both
/// fields and remains the sole accepted unsigned form. Keeping this check in
/// the radio library prevents UDP, NAN, and local sibling ingress from
/// gradually accepting different identities.
fn announce_identity_valid(announce: dmesh_server::announce::Announce) -> bool {
    if !announce.has_identity() {
        return true;
    }
    let digest = Sha256::digest(announce.public_key());
    if announce.device_id() != &digest[..announce.device_id().len()] {
        return false;
    }
    let Ok(signature) = Signature::from_slice(announce.signature()) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_public_key_der(announce.public_key()) else {
        return false;
    };
    let mut signed = [0u8; 384];
    let Some(used) = dmesh_server::announce::signing_bytes(announce, &mut signed) else {
        return false;
    };
    key.verify(&signed[..used], &signature).is_ok()
}

impl RadioService {
    /// Admit a semantic announcement from any host discovery bearer. This
    /// deliberately takes decoded data rather than a packet: Wi-Fi/UDP/control
    /// adapters retain ownership of their buffers and all update one device
    /// inventory with the same TTL, capacity, and durable change log.
    pub fn observe_discovered_announce(
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
    pub fn apply_startup_rate_profile(&self, interfaces: &[String]) -> Vec<Value> {
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
    pub fn wifi_rate_profile(
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

    /// Set the driver power-save policy through the same nl80211 owner that
    /// starts the AP.  AP throughput tests must never depend on an
    /// out-of-band `iw` command with different privileges.
    pub fn wifi_power_save(&self, iface: Option<String>, enabled: bool) -> Value {
        let iface = wifi_iface(iface);
        let result = (|| -> Result<()> {
            let ifindex = ifindex(&iface)?;
            Nl80211Socket::open()?.set_power_save(ifindex, enabled)
        })();
        let (ok, error) = match result {
            Ok(()) => (true, Value::Null),
            Err(error) => (false, json!(format!("{error:#}"))),
        };
        let value = json!({
            "ok": ok,
            "backend": "linux_nl80211",
            "iface": iface,
            "power_save": enabled,
            "error": error,
        });
        self.record("wifi.power_save", value.clone());
        value
    }

    /// Limit AP transmit power through the Wi-Fi owner. `None` restores the
    /// driver's automatic/regulatory choice; a requested limit is in dBm and
    /// cannot raise it above that ceiling. This is intentionally separate
    /// from STA power-save: it is a PHY diagnostic for near-field AP tests.
    pub fn wifi_tx_power(&self, iface: Option<String>, dbm: Option<i16>) -> Value {
        let iface = wifi_iface(iface);
        let result = (|| -> Result<()> {
            if let Some(dbm) = dbm
                && !(-20..=30).contains(&dbm)
            {
                bail!("tx power must be between -20 and 30 dBm");
            }
            let ifindex = ifindex(&iface)?;
            Nl80211Socket::open()?.set_tx_power_limit(ifindex, dbm)
        })();
        let (ok, error) = match result {
            Ok(()) => (true, Value::Null),
            Err(error) => (false, json!(format!("{error:#}"))),
        };
        let value = json!({
            "ok": ok,
            "backend": "linux_nl80211",
            "iface": iface,
            "limit_dbm": dbm,
            "automatic": dbm.is_none(),
            "error": error,
        });
        self.record("wifi.tx_power", value.clone());
        value
    }

    /// Select HT or legacy association parameters for one AP station. The
    /// setting takes effect on that station's next association.
    pub fn wifi_ap_station_profile(&self, mac: String, ht: bool) -> Value {
        let Some(mac) = parse_mac(Some(mac.trim())) else {
            return json!({"ok": false, "error": "invalid station MAC"});
        };
        let mut stations = self
            .ap_no_ht_stations
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if ht {
            stations.remove(&mac);
        } else {
            stations.insert(mac);
        }
        let value = json!({"ok": true, "station": colon_mac(&mac), "ht": ht,
            "reassociate_required": true});
        self.record("wifi.ap.station.profile", value.clone());
        value
    }

    /// Create a Wi-Fi/NAN-only radio service from environment and optional
    /// MESH_HOME/lmesh.toml config.
    ///
    /// Direct UART ownership belongs to `dmesh-cli`.  Keep this constructor
    /// equivalent to the Wi-Fi-only form so a future caller cannot recreate
    /// an extra physical-TTY reader merely by choosing a different factory.
    pub fn from_environment() -> Self {
        Self::from_environment_without_uart()
    }

    /// Create a Wi-Fi-only backend. Serial devices are never part of this
    /// service; direct device sessions belong to `dmesh-cli`.
    ///
    /// The full lmesh process and direct-client integration use
    /// [`Self::from_environment`].
    /// The standalone Wi-Fi service uses this constructor so it can own AP,
    /// STA, and NAN interfaces without taking UART devices or serial sockets.
    pub fn from_environment_without_uart() -> Self {
        Self::from_environment_inner()
    }

    /// Build a Wi-Fi-only instance with a service-specific default discovery
    /// log. The explicit environment override stays shared, while independent
    /// supervised services never append duplicate `new` events to one file.
    pub fn from_environment_with_discovery_log(default_change_log: impl Into<PathBuf>) -> Self {
        Self::from_environment_inner_with_discovery_log(default_change_log.into())
    }

    fn from_environment_inner() -> Self {
        Self::from_environment_inner_with_discovery_log(PathBuf::from(DEFAULT_DISCOVERY_CHANGE_LOG))
    }

    fn from_environment_inner_with_discovery_log(default_change_log: PathBuf) -> Self {
        let service = Self {
            history: Arc::new(Mutex::new(VecDeque::new())),
            discovered_devices: Arc::new(Mutex::new(DiscoveredDeviceRegistry::from_environment(
                default_change_log,
            ))),
            radios: Arc::new(load_radio_adapters()),
            raw_wifi_listeners: Arc::new(Mutex::new(HashSet::new())),
            raw_wifi_stop_flags: Arc::new(Mutex::new(HashMap::new())),
            raw_action_dispatcher: Arc::new(Mutex::new(None)),
            rawnan_subscribers: Arc::new(Mutex::new(HashMap::new())),
            rawnan_state: Arc::new(Mutex::new(NanState::new(5_000_000))),
            active_nan_publish: Arc::new(Mutex::new(NanActivePublish::new(
                NAN_ACTIVE_PUBLISH_INSTANCE,
            ))),
            pending_nan_followups: Arc::new(Mutex::new(dmesh_rawnan::NanFollowupQueue::new(
                MAX_PENDING_NAN_FOLLOWUPS,
            ))),
            wifi_ap_handles: Arc::new(Mutex::new(BTreeMap::new())),
            ap_no_ht_stations: Arc::new(Mutex::new(ap_no_ht_stations())),
            object_udp_started: Arc::new(AtomicBool::new(false)),
            transport_control: Arc::new(dmesh_server::udp::TransportControl::default()),
        };
        service
    }

    /// Start the object-store UDP bearer without restarting lmesh-wifi. UDP
    /// terminates here, while quic-lite and dmesh-server remain
    /// separate layers inside the adapter.
    pub fn object_udp_start(
        &self,
        bind: Option<String>,
        port: Option<u16>,
        root: Option<String>,
    ) -> Value {
        if self.object_udp_started.swap(true, Ordering::AcqRel) {
            return json!({"ok": true, "already_running": true, "bearer": "udp"});
        }
        let bind = bind.unwrap_or_else(|| "0.0.0.0".to_owned());
        // lmesh-wifi owns the stable wlan0 AP by default.  The development
        // lmesh/wlan1 service selects its separate listener through
        // LMESH_OBJECT_SERVER_PORT, so both can run on the same host.
        let port = port.unwrap_or_else(|| {
            std::env::var("LMESH_OBJECT_SERVER_PORT")
                .ok()
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(dmesh_server::udp::STABLE_WIFI_UDP_PORT)
        });
        let address = match format!("{bind}:{port}").parse::<SocketAddr>() {
            Ok(address) => address,
            Err(error) => {
                self.object_udp_started.store(false, Ordering::Release);
                return json!({"ok": false, "bearer": "udp", "error": format!("invalid bind address: {error}")});
            }
        };
        if let Err(error) = std::net::UdpSocket::bind(address) {
            self.object_udp_started.store(false, Ordering::Release);
            return json!({"ok": false, "bearer": "udp", "bind": address.ip().to_string(), "port": address.port(), "error": format!("UDP bind failed: {error}")});
        }
        let root = root
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("DMESH_REPO")
                    .map(PathBuf::from)
                    .map(|path| path.join("target/flash"))
            })
            // The managed service does not necessarily run with the checkout
            // as its cwd. Keep the default usable for the source-tree build
            // and let deployments override it with DMESH_REPO or `root=`.
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/flash")
            });
        let started = self.object_udp_started.clone();
        let mut udp_config = dmesh_server::udp::UdpConfig {
            bind: address,
            artifact_root: root,
            // The host retains the sender window. Recovery processes receive
            // callbacks immediately and does not mirror this payload ledger,
            // so use a window large enough to cover Wi-Fi ACK latency. Four
            // slots accidentally imposed one round trip per 4 KiB block.
            history_capacity: std::env::var("DMESH_UDP_HISTORY_CAPACITY")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .filter(|value| (1..=quic_lite::RECOVERY_MAX_HISTORY_PACKETS).contains(value))
                .unwrap_or(quic_lite::RECOVERY_MAX_HISTORY_PACKETS),
            // 512 bytes remains in the host fault matrix, but production
            // Recovery uses a near-MTU application chunk. This reduces the
            // number of transport/ACK cycles while staying below the 1400
            // byte bearer MTU.
            object_chunk: std::env::var("DMESH_UDP_OBJECT_CHUNK")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(quic_lite::DEFAULT_MAX_DATAGRAM_SIZE - 64),
            control: Some(self.transport_control.clone()),
            ..dmesh_server::udp::UdpConfig::default()
        };
        // Keep deployment tuning outside the transport implementation while
        // allowing operators to select an explicit host ledger or leave it at
        // the memory-aware automatic policy (zero).
        if let Ok(value) = std::env::var("DMESH_UDP_MAX_ACTIVE_CONNECTIONS") {
            if let Ok(limit) = value.parse::<usize>() {
                udp_config.max_active_connections = limit.max(1);
            }
        }
        tokio::spawn(async move {
            let result = dmesh_server::udp::run(udp_config).await;
            started.store(false, Ordering::Release);
            if let Err(error) = result {
                tracing::warn!(%error, "object_udp_stopped");
            }
        });
        json!({"ok": true, "bearer": "udp", "bind": address.ip().to_string(), "port": address.port(), "transport": "quic-lite", "object_store": "dmesh-server", "services": ["object", "echo", "status", "handlers", "iperf", "metrics", "events", "control", "log-watch"]})
    }

    /// Transport-owned aggregates for the stable object listener.  This is
    /// intentionally a status snapshot, not an ACK/frame debugging API.
    pub fn object_udp_status(&self) -> Value {
        let stats = self.transport_control.server_stats();
        json!({
            "ok": self.object_udp_started.load(Ordering::Acquire),
            "transport": stats.map(|value| json!({
                "history": value.history_len,
                "history_capacity": value.history_capacity,
                "peer_max_in_flight": value.peer_max_in_flight_packets,
                "inflight": value.bytes_in_flight,
                "cwnd": value.congestion_window,
                "rx": value.transport.received_datagrams,
                "rx_stream": value.transport.stream_datagrams,
                "rx_control": value.transport.control_datagrams,
                "tx": value.transport.sent_datagrams,
                "tx_stream": value.transport.sent_stream_datagrams,
                "tx_control": value.transport.sent_control_datagrams,
                "retx": value.transport.retransmitted_datagrams,
                "duplicate": value.transport.duplicate_datagrams,
                "out_of_order": value.transport.out_of_order_datagrams,
                "missing": value.transport.inferred_missing_packets,
                "loss_packet": value.transport.loss_packet_threshold_datagrams,
                "loss_time": value.transport.loss_time_threshold_datagrams,
                "loss_events": value.transport.loss_events,
                "pto": value.transport.pto_retransmitted_datagrams,
            })),
            "events": self.transport_control.events(),
            "errors": self.transport_control.errors(),
        })
    }

    /// Return interface, capability, process-capability, and control status.
    pub fn status(&self) -> Value {
        let iface = wifi_iface(None);

        json!({
            "wifi_iface": iface,
            "radios": self.radios.as_ref(),
            "capabilities": process_caps(),
            "hci": json!({"ok": false, "backend": "lmesh-wifi", "reason": "BLE is owned by lmesh"}),
            "rawnan": self.rawnan_status(Some(iface)),
        })
    }

    /// Return the shared raw-NAN filter state used by the Linux monitor.
    /// This is deliberately independent of any control daemon: the monitor
    /// observes NAN beacons and feeds them to dmesh-rawnan::NanState.
    pub fn rawnan_status(&self, iface: Option<String>) -> Value {
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
        let history = self
            .history
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let events = history
            .iter()
            .filter(|event| event.key == "wifi.rawnan.rx")
            .count();
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
            "beacon_interval_tu": state.beacon_interval_tu(),
            "nan_events": events,
            "discovered_devices": discovered_devices,
            "observed_announces": observed_announces,
            "followups": followups,
            "active_publish": active_publish_status,
        })
    }

    /// Replace the entire local active-Publish descriptor. Actual emission is
    /// deferred to the next confirmed NAN discovery window, never to a
    /// control request or an arbitrary wall-clock timer.
    pub fn rawnan_active_publish_configure(
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

    /// Return the administrative/carrier state without changing the
    /// interface. This is intentionally a small host diagnostic used before
    /// nl80211 frame tests.
    pub fn wifi_interface_status(&self, iface: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let link = run_command("ip", &["link", "show", &iface]);
        json!({ "ok": link.get("ok").and_then(Value::as_bool).unwrap_or(false), "iface": iface, "link": link })
    }

    pub fn wifi_interface_up(&self, iface: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let result = run_command("ip", &["link", "set", &iface, "up"]);
        json!({ "ok": result.get("ok").and_then(Value::as_bool).unwrap_or(false), "iface": iface, "link": result })
    }

    /// Replace the owned interface with an 802.11 OCB (outside-context-of-a-
    /// BSS) interface and join the requested frequency.  OCB has no AP,
    /// association, WPA, or BSSID; it is useful for the shared open-medium
    /// experiments.  This intentionally operates only on the lmesh-owned
    /// interface.
    pub fn wifi_ocb_start(
        &self,
        iface: Option<String>,
        freq: Option<u32>,
        bandwidth: Option<String>,
    ) -> Value {
        let iface = wifi_iface(iface);
        let freq = freq.unwrap_or_else(|| channel_to_freq(DEFAULT_RAW_WIFI_CHANNEL));
        let bandwidth = bandwidth.unwrap_or_else(|| "10MHz".to_owned());
        let mut steps = Vec::new();
        steps.push(run_command("ip", &["link", "set", &iface, "down"]));
        let set_type = ifindex(&iface).and_then(|ifindex| {
            let socket = Nl80211Socket::open()?;
            socket.set_interface_type(ifindex, NL80211_IFTYPE_OCB)
        });
        steps.push(match &set_type {
            Ok(()) => json!({"program": "nl80211", "operation": "set_interface", "type": "ocb", "ok": true}),
            Err(error) => json!({"program": "nl80211", "operation": "set_interface", "type": "ocb", "ok": false, "error": format!("{error:#}")}),
        });
        if set_type.is_ok() {
            // Some drivers require JOIN_OCB while the netdev is administratively
            // down, while others require it up. Try the documented iw operation
            // first and only then raise the carrier.
            let freq_text = freq.to_string();
            let args = [
                "dev",
                iface.as_str(),
                "ocb",
                "join",
                freq_text.as_str(),
                bandwidth.as_str(),
            ];
            let join = run_command("iw", &args);
            let joined = join.get("ok").and_then(Value::as_bool).unwrap_or(false);
            steps.push(join);
            steps.push(run_command("ip", &["link", "set", &iface, "up"]));
            if !joined {
                // Preserve the failed join and leave the interface state
                // visible to the caller; do not silently fall back to AP/STA.
            }
        }
        let ok = set_type.is_ok()
            && steps
                .iter()
                .all(|step| step.get("ok").and_then(Value::as_bool).unwrap_or(false));
        let result = json!({
            "ok": ok,
            "backend": "linux_nl80211",
            "iface": iface,
            "type": "ocb",
            "freq": freq,
            "bandwidth": bandwidth,
            "steps": steps,
        });
        self.record("wifi.ocb.start", result.clone());
        result
    }

    /// Pin an owned interface to a 2.4 GHz channel using nl80211.  This is
    /// deliberately explicit: it changes only the requested lmesh interface
    /// and does not touch wlan0 or the lmesh-wifi service.
    pub fn wifi_interface_set_channel(&self, iface: Option<String>, channel: u8) -> Value {
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

    /// Stop the experimental monitor VIF owned by lmesh. This never touches
    /// wlan0 or the lmesh-wifi service; it is needed before changing the
    /// channel or switching wlan1 into AP/IBSS/P2P mode.
    pub fn wifi_raw_stop(&self, iface: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let monitor = monitor_iface_name(&iface);
        // The action dispatcher owns one association ledger for this radio
        // service. Stopping its monitor listener is an explicit bearer
        // lifecycle boundary, so discard that ledger as well; otherwise a
        // later automated check/IPERF run can inherit an old CID and report
        // misleading reverse-direction dispatch errors.
        if let Ok(mut dispatcher) = self.raw_action_dispatcher.lock() {
            *dispatcher = None;
        }
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
        let down = run_command("ip", &["link", "set", &monitor, "down"]);
        let delete = run_command("/sbin/iw", &["dev", &monitor, "del"]);
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

    /// Summarize raw action receive/dispatch activity for E2E diagnostics.
    /// Counters are derived from the bounded history and therefore allocate
    /// nothing per packet or retain a second transport ledger.
    pub fn wifi_raw_metrics(&self, iface: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let history = self
            .history
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut rx = 0_u64;
        let mut dispatch = 0_u64;
        let mut dispatch_errors = 0_u64;
        let mut action_seen = 0_u64;
        let mut monitor_frames = 0_u64;
        let mut action_candidates = 0_u64;
        let mut socket_packets = 0_u64;
        for event in history.iter() {
            if !event.source.contains(&iface) {
                continue;
            }
            match event.key.as_str() {
                "wifi.raw.rx" => rx += 1,
                "wifi.raw.dispatch" => {
                    dispatch += 1;
                    if event.value.get("ok").and_then(Value::as_bool) == Some(false) {
                        dispatch_errors += 1;
                    }
                }
                "wifi.raw.action" => action_seen += 1,
                "wifi.raw.monitor" => monitor_frames += 1,
                "wifi.raw.socket" => socket_packets += 1,
                "wifi.raw.action_candidate" => action_candidates += 1,
                _ => {}
            }
        }
        json!({"ok": true, "iface": iface, "rx": rx, "socket_packets": socket_packets, "monitor_frames": monitor_frames, "action_candidates": action_candidates, "action_seen": action_seen, "dispatch": dispatch, "dispatch_errors": dispatch_errors})
    }

    /// Return recent radio method results and observed notifications.
    pub fn history(&self, keys: Option<String>, limit: Option<usize>) -> Value {
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

    /// Return the configured local, remote, and future adapter inventory.
    pub fn list_radios(&self) -> Value {
        json!({ "radios": self.radios.as_ref() })
    }

    /// Return the current link table derived from recent radio observations.
    pub fn links_list(&self, seen_within_sec: Option<u64>) -> Value {
        let seen_within_sec = seen_within_sec.unwrap_or(21_600);
        let neighbors = self.collect_neighbors(seen_within_sec);
        let links = neighbors
            .into_values()
            .map(|neighbor| {
                let radio = neighbor
                    .medium
                    .as_deref()
                    .map(mesh_radio_name)
                    .unwrap_or("unknown");
                json!({
                    "node": neighbor.node,
                    "last_seen_ms": neighbor.last_seen_ms,
                    "radio": radio,
                    "medium": neighbor.medium,
                    "network": neighbor.network,
                    "radio_id": neighbor.radio_id,
                    "rssi": neighbor.rssi,
                    "snr": neighbor.snr,
                    "source": neighbor.source,
                    "last_event": neighbor.last_event,
                    "selected": radio,
                    "quality": link_quality(neighbor.rssi, neighbor.snr),
                })
            })
            .collect::<Vec<_>>();
        json!({
            "ok": true,
            "seen_within_sec": seen_within_sec,
            "default_send_radio": "best",
            "links": links,
        })
    }

    /// Return recently observed neighbors from normalized radio messages.
    pub fn neighbors(&self, seen_within_sec: Option<u64>) -> Value {
        let seen_within_sec = seen_within_sec.unwrap_or(21_600);
        let neighbors = self.collect_neighbors(seen_within_sec);
        json!({
            "seen_within_sec": seen_within_sec,
            "neighbors": neighbors.into_values().collect::<Vec<_>>(),
        })
    }

    fn collect_neighbors(&self, seen_within_sec: u64) -> BTreeMap<String, NeighborInfo> {
        let window_ms = seen_within_sec.saturating_mul(1000);
        let cutoff = now_millis_u64().saturating_sub(window_ms);
        let mut neighbors: BTreeMap<String, NeighborInfo> = BTreeMap::new();
        for event in self
            .history
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
        {
            if event.key == "wifi.raw.tx" {
                continue;
            }
            if event.key == "wifi.raw.rx"
                && event
                    .value
                    .get("payload_text")
                    .and_then(Value::as_str)
                    .is_some_and(|payload| payload.contains("source=lmesh"))
            {
                continue;
            }
            let Some(message) = &event.message else {
                continue;
            };
            if message.timestamp_ms < cutoff {
                continue;
            }
            let Some(node) = message
                .field_value(FIELD_NODE)
                .or_else(|| message.field_value(mesh::message::FIELD_PEER))
            else {
                continue;
            };
            if is_group_mac(node) {
                continue;
            }
            let entry = neighbors
                .entry(node.to_string())
                .or_insert_with(|| NeighborInfo::new(node));
            if message.timestamp_ms >= entry.last_seen_ms {
                entry.last_seen_ms = message.timestamp_ms;
                entry.medium = message.field_value(FIELD_MEDIUM).map(str::to_string);
                entry.network = message.field_value(FIELD_NETWORK).map(str::to_string);
                entry.radio_id = message.field_value(FIELD_RADIO_ID).map(str::to_string);
                entry.rssi = message
                    .field_value(FIELD_RSSI)
                    .and_then(|value| value.parse().ok());
                entry.snr = message
                    .field_value(FIELD_SNR)
                    .and_then(|value| value.parse().ok());
                entry.source = Some(event.source.clone());
                entry.last_event = Some(event.key.clone());
            }
        }
        neighbors
    }

    /// Fan out a discovery ping request to the selected media and record the intent.
    pub fn discovery_ping(&self, medium: Option<String>) -> Value {
        self.ping(
            Some(medium_to_radio(medium.as_deref().unwrap_or("all"))),
            None,
            None,
        )
    }

    /// Ping/discover peers over one radio or all radios.
    pub fn ping(
        &self,
        radio: Option<String>,
        _wait_ms: Option<u64>,
        _nonce: Option<String>,
    ) -> Value {
        let radio = normalize_radio(radio);
        let selected = self
            .radios
            .iter()
            .filter(|adapter| {
                radio == "all"
                    || radio == mesh_radio_name(&adapter.medium)
                    || radio == adapter.medium
                    || radio == adapter.kind
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut wifi_results = Vec::new();
        for adapter in &selected {
            let message = MeshMessage::new(mesh::message::KIND_DM_PING, MeshMessageCodec::Text)
                .field(FIELD_MEDIUM, &adapter.medium)
                .field(FIELD_RADIO_ID, &adapter.id)
                .field(FIELD_STATUS, "queued");
            self.record_message("ping", "local", message);
            if adapter.medium == "wifi" || adapter.kind == "host-wifi" || radio == "nan" {
                wifi_results.push(self.rawnan_status(None));
            }
        }
        if (radio == "all" || radio == "nan" || radio == "best") && wifi_results.is_empty() {
            wifi_results.push(self.rawnan_status(None));
        }
        let unavailable = unavailable_radios(&radio);
        let result = json!({
            "ok": true,
            "radio": radio,
            "sent": selected.len(),
            "radios": selected,
            "nan": wifi_results,
            "unavailable": unavailable,
        });
        self.record("ping", result.clone());
        result
    }

    /// Send a payload over the selected radio, defaulting to current best.
    pub fn send(
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

    /// Forward one canonical tagged-CBOR record to an explicitly addressed
    /// NAN peer.  This is intentionally a byte API: callers must not turn a
    /// key-10 envelope `data` field into text just to cross the radio layer.
    /// NAN follow-up service information has a bounded 231-byte payload, so
    /// larger records are rejected here rather than silently truncated.
    pub fn send_tagged_record(&self, destination: &str, record: &[u8]) -> Value {
        let Some(target) = parse_device_id(Some(destination)) else {
            return json!({
                "ok": false,
                "error": "tagged-CBOR forwarding requires a six-byte destination MAC",
                "destination": destination,
            });
        };
        let payload = match local_device_id().and_then(|source| {
            radio_protocol::build_nan_followup("command_cbor", &source, &target, record)
        }) {
            Ok(payload) => payload,
            Err(error) => {
                return json!({
                    "ok": false,
                    "destination": destination,
                    "record_len": record.len(),
                    "error": error.to_string(),
                });
            }
        };
        let result = self.send_nan_followup(target, &payload);
        self.record("mesh.tagged.forward", result.clone());
        result
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
    pub fn link_steer(
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

    /// Start an open AP on the default channel using direct nl80211.
    pub fn wifi_ap_start_open(&self, iface: Option<String>, ssid: Option<String>) -> Value {
        self.wifi_ap_start_open_with_width(iface, ssid, None, DEFAULT_OPEN_AP_HT40, 100)
    }

    /// Start an open AP on a 2.4 GHz channel using direct nl80211.
    ///
    /// Keep the selected channel with the AP runtime: the manually generated
    /// management responses must describe the same channel as the beacon.
    pub fn wifi_ap_start_open_on_channel(
        &self,
        iface: Option<String>,
        ssid: Option<String>,
        requested_channel: Option<u8>,
        ht40: Option<bool>,
    ) -> Value {
        self.wifi_ap_start_open_on_channel_with_interval(iface, ssid, requested_channel, ht40, 100)
    }

    /// Start an open AP with a runtime beacon interval. Larger intervals are
    /// useful for raw-action throughput experiments because they reduce AP
    /// beacon contention without changing the radio channel or transport.
    pub fn wifi_ap_start_open_on_channel_with_interval(
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
        steps.push(run_command("ip", &["link", "set", &iface, "down"]));
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
                steps.push(run_command("ip", &["link", "set", &iface, "up"]));
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
                        steps.push(run_command("ip", &["link", "set", &iface, "down"]));
                        let _ = socket.set_interface_type(ifindex, NL80211_IFTYPE_STATION);
                        steps.push(run_command("ip", &["link", "set", &iface, "up"]));
                        return Err(error);
                    }
                }
                if selected_profile.is_none() {
                    steps.push(run_command("ip", &["link", "set", &iface, "down"]));
                    let _ = socket.set_interface_type(ifindex, NL80211_IFTYPE_STATION);
                    steps.push(run_command("ip", &["link", "set", &iface, "up"]));
                    bail!("nl80211 start open AP returned no selected profile");
                }
                let mgmt_iface = iface.clone();
                let history = self.history.clone();
                let discovered_devices = self.discovered_devices.clone();
                let rawnan_state = self.rawnan_state.clone();
                let active_nan_publish = self.active_nan_publish.clone();
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
                        discovered_devices,
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
                            channel,
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
    pub fn wifi_ap_stop(&self, iface: Option<String>) -> Value {
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
                steps.push(run_command("ip", &["link", "set", &iface, "down"]));
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
                steps.push(run_command("ip", &["link", "set", &iface, "up"]));
                let reset_ok = steps
                    .iter()
                    .skip(1)
                    .all(|step| step.get("ok").and_then(Value::as_bool) == Some(true));
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

    /// Return basic AP defaults and station metrics where available.
    pub fn wifi_ap_status(&self, iface: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let mac = iface_mac(&iface).ok();
        let stations = ifindex(&iface)
            .and_then(|ifindex| {
                let socket = Nl80211Socket::open()?;
                socket.station_dump(ifindex)
            })
            .ok();
        let channel = self
            .wifi_ap_handles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&iface)
            .map(|runtime| runtime.channel)
            .unwrap_or(DEFAULT_RAW_WIFI_CHANNEL);
        let result = json!({
            "ok": true,
            "backend": "linux_nl80211",
            "iface": iface,
            "ssid_default": default_open_ap_ssid(&iface),
            "channel": channel,
            "freq": channel_to_freq(channel),
            "bssid": mac.map(|mac| colon_mac(&mac)),
            "auth": "open",
            "stations": stations,
        });
        self.record("wifi.ap.status", result.clone());
        result
    }

    /// Return associated station metrics for an AP interface.
    pub fn wifi_ap_stations(&self, iface: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let result = ifindex(&iface)
            .and_then(|ifindex| {
                let socket = Nl80211Socket::open()?;
                socket
                    .station_dump(ifindex)
                    .map(|stations| (ifindex, stations))
            })
            .map(|(interface_index, stations)| {
                let link_metrics: Vec<WifiLinkMetrics> = stations
                    .iter()
                    .map(|station| station_link_metrics(station, interface_index))
                    .collect();
                for station in &stations {
                    if let Some(mac) = station.get("mac").and_then(Value::as_str) {
                        let mut message =
                            MeshMessage::new(mesh::message::KIND_EVENT, MeshMessageCodec::Text)
                                .field(FIELD_MEDIUM, "wifi")
                                .field(FIELD_RADIO_ID, "sta")
                                .field(FIELD_NODE, mac);
                        if let Some(signal) = station.get("signal_dbm").and_then(Value::as_i64) {
                            message = message.field(FIELD_RSSI, signal.to_string());
                        }
                        self.record_message("wifi.ap.station", &iface, message);
                    }
                }
                json!({
                    "ok": true,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "link_metrics_schema_version": WIFI_LINK_METRICS_SCHEMA_VERSION,
                    "link_metrics": link_metrics,
                    "stations": stations,
                })
            })
            .unwrap_or_else(|error| {
                json!({
                    "ok": false,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "error": format!("{error:#}"),
                })
            });
        self.record("wifi.ap.stations", result.clone());
        result
    }

    /// Experimentally add a station entry without observing auth/assoc.
    pub fn wifi_ap_station_add(
        &self,
        iface: Option<String>,
        mac: String,
        aid: Option<u16>,
    ) -> Value {
        let iface = wifi_iface(iface);
        let Some(mac_bytes) = parse_mac(Some(&mac)) else {
            return json!({
                "ok": false,
                "backend": "linux_nl80211",
                "iface": iface,
                "mac": mac,
                "error": "invalid station MAC",
            });
        };
        let aid = aid.unwrap_or(1).clamp(1, 2007);
        let result = ifindex(&iface)
            .and_then(|ifindex| {
                let socket = Nl80211Socket::open()?;
                socket.add_station_minimal(ifindex, mac_bytes, aid)
            })
            .map(|_| {
                json!({
                    "ok": true,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "mac": colon_mac(&mac_bytes),
                    "aid": aid,
                    "mode": "experimental_no_assoc",
                })
            })
            .unwrap_or_else(|error| {
                json!({
                    "ok": false,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "mac": colon_mac(&mac_bytes),
                    "aid": aid,
                    "mode": "experimental_no_assoc",
                    "error": format!("{error:#}"),
                })
            });
        self.record("wifi.ap.station.add", result.clone());
        result
    }

    /// Remove one associated station without stopping the AP.
    pub fn wifi_ap_station_remove(&self, iface: Option<String>, mac: String) -> Value {
        let iface = wifi_iface(iface);
        let Some(mac_bytes) = parse_mac(Some(&mac)) else {
            return json!({
                "ok": false,
                "backend": "linux_nl80211",
                "iface": iface,
                "mac": mac,
                "error": "invalid station MAC",
            });
        };
        let result = ifindex(&iface)
            .and_then(|ifindex| {
                let socket = Nl80211Socket::open()?;
                socket.remove_station(ifindex, mac_bytes)
            })
            .map(|_| {
                json!({
                    "ok": true,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "mac": colon_mac(&mac_bytes),
                })
            })
            .unwrap_or_else(|error| {
                json!({
                    "ok": false,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "mac": colon_mac(&mac_bytes),
                    "error": format!("{error:#}"),
                })
            });
        self.record("wifi.ap.station.remove", result.clone());
        result
    }

    /// Remove all associated stations without stopping the AP.
    pub fn wifi_ap_station_remove_all(&self, iface: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let result = ifindex(&iface)
            .and_then(|ifindex| {
                let socket = Nl80211Socket::open()?;
                socket.flush_stations(ifindex)
            })
            .map(|_| {
                json!({
                    "ok": true,
                    "backend": "linux_nl80211",
                    "iface": iface,
                })
            })
            .unwrap_or_else(|error| {
                json!({
                    "ok": false,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "error": format!("{error:#}"),
                })
            });
        self.record("wifi.ap.station.remove_all", result.clone());
        result
    }

    /// Run a bounded operator-requested Wi-Fi scan without changing interface
    /// lifecycle. A channel-restricted passive scan is useful for confirming
    /// that the driver reports channel-6 beacons through cfg80211; it is not
    /// a NAN discovery-window clock and must never be an E2E setup step.
    pub fn wifi_scan(
        &self,
        iface: Option<String>,
        ssid: Option<String>,
        channel: Option<u8>,
        passive: bool,
    ) -> Value {
        let iface = wifi_iface(iface);
        let channel = channel.filter(|channel| (1..=13).contains(channel));
        let frequency = channel.map(channel_to_freq);
        let frequency_text = frequency.map(|frequency| frequency.to_string());
        let link = run_command("ip", &["link", "show", &iface]);
        let mut args = vec!["dev", iface.as_str(), "scan"];
        if let Some(frequency) = frequency_text.as_deref() {
            args.extend(["freq", frequency]);
        }
        if passive {
            args.push("passive");
        } else if let Some(ssid) = ssid.as_deref().filter(|ssid| !ssid.is_empty()) {
            args.extend(["ssid", ssid]);
        }
        let result = match command_output_timeout("iw", &args, Duration::from_secs(12)) {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                let entries = parse_iw_scan(&stdout);
                // Keep the raw list for operators, and expose the DMesh AP
                // subset separately so the common host/Android/ESP probe can
                // record candidate AP identity and RSSI without guessing from
                // a human-formatted `iw` transcript.
                let direct = entries
                    .iter()
                    .filter(|entry| {
                        entry
                            .get("ssid")
                            .and_then(Value::as_str)
                            .is_some_and(|ssid| ssid.starts_with("DIRECT-"))
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                let direct_dmesh = direct
                    .iter()
                    .filter(|entry| {
                        entry.get("ssid").and_then(Value::as_str)
                            .is_some_and(|ssid| ssid.ends_with("-dmesh"))
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                let channel_ap_count = entries
                    .iter()
                    .filter(|entry| {
                        channel.is_none()
                            || entry.get("channel").and_then(Value::as_u64)
                                == channel.map(u64::from)
                    })
                    .count();
                json!({
                    "ok": output.status.success(),
                    "backend": "iw",
                    "iface": iface,
                    "ssid_filter": ssid,
                    "channel": channel,
                    "freq": frequency,
                    "passive": passive,
                    "count": entries.len(),
                    "channel_ap_count": channel_ap_count,
                    "entries": entries,
                    "direct": direct,
                    "direct_dmesh": direct_dmesh,
                    "link": link,
                    "status": output.status.code(),
                    "stderr": stderr,
                })
            }
            Err(error) => json!({
                "ok": false,
                    "backend": "iw",
                    "iface": iface,
                    "ssid_filter": ssid,
                    "channel": channel,
                    "freq": frequency,
                    "passive": passive,
                    "link": link,
                "error": error.to_string(),
            }),
        };
        self.record("wifi.scan", result.clone());
        result
    }

    /// Join an open AP as a station on channel 6.
    pub fn wifi_sta_join_open(&self, iface: Option<String>, ssid: String) -> Value {
        let iface = wifi_iface(iface);
        let channel = DEFAULT_RAW_WIFI_CHANNEL;
        let freq = channel_to_freq(channel);
        let mut steps = Vec::new();
        steps.push(run_command("ip", &["link", "set", &iface, "down"]));
        let result = ifindex(&iface)
            .and_then(|ifindex| {
                let socket = Nl80211Socket::open()?;
                socket.set_interface_type(ifindex, NL80211_IFTYPE_STATION)?;
                steps.push(run_command("ip", &["link", "set", &iface, "up"]));
                socket.connect_open(ifindex, &ssid, freq)
            })
            .map(|_| {
                json!({
                    "ok": true,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "ssid": ssid,
                    "channel": channel,
                    "freq": freq,
                    "auth": "open",
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

    /// Return station-mode association metrics for the current AP peer.
    pub fn wifi_sta_status(&self, iface: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let result = ifindex(&iface)
            .and_then(|ifindex| {
                let socket = Nl80211Socket::open()?;
                socket.station_dump(ifindex)
            })
            .map(|peers| {
                for peer in &peers {
                    if let Some(mac) = peer.get("mac").and_then(Value::as_str) {
                        let mut message =
                            MeshMessage::new(mesh::message::KIND_EVENT, MeshMessageCodec::Text)
                                .field(FIELD_MEDIUM, "wifi")
                                .field(FIELD_RADIO_ID, "sta")
                                .field(FIELD_NODE, mac);
                        if let Some(signal) = peer.get("signal_dbm").and_then(Value::as_i64) {
                            message = message.field(FIELD_RSSI, signal.to_string());
                        }
                        self.record_message("wifi.sta.peer", &iface, message);
                    }
                }
                json!({
                    "ok": true,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "associated": !peers.is_empty(),
                    "peers": peers,
                })
            })
            .unwrap_or_else(|error| {
                json!({
                    "ok": false,
                    "backend": "linux_nl80211",
                    "iface": iface,
                    "error": format!("{error:#}"),
                })
            });
        self.record("wifi.sta.status", result.clone());
        result
    }

    /// Configure a static IPv4 address through the capability-bearing service
    /// using rtnetlink. Callers own route/DHCP policy.
    pub fn wifi_sta_configure_ipv4(
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

    /// Listen for DMesh Ethernet frames on the normal AP/STA netdev path.
    pub fn wifi_data_listen(&self, iface: Option<String>, listen_sec: Option<u64>) -> Value {
        let iface = wifi_iface(iface);
        let listen_sec = listen_sec.unwrap_or(DEFAULT_RAW_WIFI_LISTEN_SECS).max(1);
        let listener_key = format!("{iface}:data");
        {
            let mut listeners = self
                .raw_wifi_listeners
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !listeners.insert(listener_key.clone()) {
                return json!({
                    "ok": true,
                    "backend": "linux_af_packet_data",
                    "iface": iface,
                    "listen_sec": listen_sec,
                    "already_running": true,
                });
            }
        }

        match DataSocket::open(&iface) {
            Ok(socket) => {
                let receive_addresses = raw_wifi_receive_addresses(&iface);
                let memberships = receive_addresses
                    .iter()
                    .map(|address| {
                        json!({
                            "mac": colon_mac(address),
                            "result": result_json(socket.add_multicast(*address)),
                        })
                    })
                    .collect::<Vec<_>>();
                let history = self.history.clone();
                let listeners = self.raw_wifi_listeners.clone();
                let iface_for_thread = iface.clone();
                let listener_key_for_thread = listener_key.clone();
                std::thread::spawn(move || {
                    data_receive_loop(
                        socket,
                        &iface_for_thread,
                        history,
                        Duration::from_secs(listen_sec),
                    );
                    listeners
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .remove(&listener_key_for_thread);
                });
                let result = json!({
                    "ok": true,
                    "backend": "linux_af_packet_data",
                    "iface": iface,
                    "listen_sec": listen_sec,
                    "ethertype": format!("0x{ETH_P_DMESH:04x}"),
                    "receive_addresses": receive_addresses
                        .iter()
                        .map(colon_mac)
                        .collect::<Vec<_>>(),
                    "memberships": memberships,
                    "note": "normal AP/STA netdev listener; delivery depends on driver data path association/state",
                });
                self.record("wifi.data.listen", result.clone());
                result
            }
            Err(error) => {
                self.raw_wifi_listeners
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(&listener_key);
                json!({
                    "ok": false,
                    "backend": "linux_af_packet_data",
                    "iface": iface,
                    "error": format!("{error:#}"),
                })
            }
        }
    }

    /// Send a DMesh Ethernet frame on the normal AP/STA netdev path.
    pub fn wifi_data_send(
        &self,
        iface: Option<String>,
        destination: Option<String>,
        payload: String,
    ) -> Value {
        let iface = wifi_iface(iface);
        let destination = raw_wifi_destination(destination.as_deref(), "multicast_data");
        let source = match iface_mac(&iface) {
            Ok(source) => source,
            Err(error) => {
                return json!({
                    "ok": false,
                    "backend": "linux_af_packet_data",
                    "iface": iface,
                    "error": format!("{error:#}"),
                });
            }
        };
        let frame = build_dmesh_ethernet_frame(destination, source, payload.as_bytes());
        let result = match DataSocket::open(&iface).and_then(|socket| socket.send(&frame)) {
            Ok(written) => json!({
                "ok": true,
                "backend": "linux_af_packet_data",
                "iface": iface,
                "destination": colon_mac(&destination),
                "source": colon_mac(&source),
                "ethertype": format!("0x{ETH_P_DMESH:04x}"),
                "payload_len": payload.len(),
                "frame_len": frame.len(),
                "written": written,
            }),
            Err(error) => json!({
                "ok": false,
                "backend": "linux_af_packet_data",
                "iface": iface,
                "destination": colon_mac(&destination),
                "source": colon_mac(&source),
                "error": format!("{error:#}"),
            }),
        };
        self.record_message(
            "wifi.data.tx",
            "host-wifi",
            MeshMessage::new(mesh::message::KIND_EVENT, MeshMessageCodec::Text)
                .field(FIELD_MEDIUM, "wifi")
                .field(FIELD_IFACE, &iface)
                .field(mesh::message::FIELD_PEER, colon_mac(&destination))
                .field(FIELD_LEN, payload.len())
                .field(FIELD_PAYLOAD, payload),
        );
        self.record("wifi.data.tx", result.clone());
        result
    }

    /// Start a direct nl80211 listener for ESP32 DMesh vendor action frames.
    ///
    /// This listener deliberately consumes an existing monitor fixture.  The
    /// managed service prepares that fixture at startup; packet tests must not
    /// change host radio state by asking for a listener.
    pub fn wifi_raw_listen(
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
                let history = self.history.clone();
                let discovered_devices = self.discovered_devices.clone();
                let listeners = self.raw_wifi_listeners.clone();
                let stop_flags = self.raw_wifi_stop_flags.clone();
                let iface_for_thread = iface.clone();
                let monitor_for_thread = monitor_iface.clone();
                let listener_key_for_thread = listener_key.clone();
                let rawnan_state = self.rawnan_state.clone();
                let active_nan_publish = self.active_nan_publish.clone();
                let pending_nan_followups = self.pending_nan_followups.clone();
                let raw_action_dispatcher = self.raw_action_dispatcher.clone();
                let stop_flag = Arc::new(AtomicBool::new(false));
                stop_flags
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert(listener_key.clone(), stop_flag.clone());
                std::thread::spawn(move || {
                    monitor_receive_loop(
                        socket,
                        &iface_for_thread,
                        &monitor_for_thread,
                        history,
                        discovered_devices,
                        rawnan_state,
                        active_nan_publish,
                        pending_nan_followups,
                        raw_action_dispatcher,
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
                    let history = self.history.clone();
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
    pub fn wifi_nan_beacon_listen(&self, iface: Option<String>) -> Value {
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
            socket.register_nan_beacon(ifindex(&iface)?)?;
            Ok(socket)
        });
        match socket {
            Ok(socket) => {
                let history = self.history.clone();
                let rawnan_state = self.rawnan_state.clone();
                let listeners = self.raw_wifi_listeners.clone();
                let iface_for_thread = iface.clone();
                std::thread::spawn(move || {
                    nl80211_nan_beacon_receive_loop(
                        socket,
                        &iface_for_thread,
                        history,
                        rawnan_state,
                    );
                    listeners
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .remove(&listener_key);
                });
                json!({"ok": true, "iface": iface, "backend": "linux_nl80211", "frame_type": "0x0080"})
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
    pub fn prepare_raw_monitor_fixture(&self, iface: Option<String>, channel: Option<u8>) -> Value {
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
    pub fn prepare_ap_raw_monitor_fixture(
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

    /// Attach a live raw-NAN subscriber to the permanent monitor fixture.
    /// The AP/monitor lifecycle is managed outside subscriptions so a client
    /// disconnect cannot perturb the RF setup used by other tests or NOW.
    pub fn rawnan_subscription_start(
        &self,
        config: &mesh::local_trace::TraceConfig,
    ) -> Option<String> {
        let target = config
            .targets
            .iter()
            .find(|target| target.starts_with("dmesh.event.wifi.rawnan"))?;
        let _ = target;
        let iface = wifi_iface(None);
        let mut subscribers = self
            .rawnan_subscribers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = subscribers.entry(iface.clone()).or_insert(0);
        *count += 1;
        let first = *count == 1;
        drop(subscribers);
        if first {
            let result = self.wifi_raw_listen(
                Some(iface.clone()),
                Some(6),
                Some(DEFAULT_RAW_WIFI_LISTEN_SECS),
                Some("monitor".to_owned()),
            );
            if !result.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                self.rawnan_subscription_stop(&iface);
                return None;
            }
        }
        Some(iface)
    }

    /// Release a live raw-NAN subscription. The permanent monitor remains up
    /// after the final subscriber disconnects.
    pub fn rawnan_subscription_stop(&self, iface: &str) {
        {
            let mut subscribers = self
                .rawnan_subscribers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(count) = subscribers.get_mut(iface) else {
                return;
            };
            *count = count.saturating_sub(1);
            if *count == 0 {
                subscribers.remove(iface);
            }
        }
    }

    /// Send an ESP32-compatible DMesh vendor action frame.
    pub fn wifi_raw_send(
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
        let source = match raw_wifi_source(source_input, &iface) {
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
                    "source_mode": raw_wifi_source_mode(source_input),
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
            let interface_up = run_command("ip", &["link", "set", &iface, "up"]);
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
                    "source_mode": raw_wifi_source_mode(source_input),
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
    pub fn wifi_raw_send_frame(
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

    /// Send a DMesh raw Wi-Fi ping and return replies observed by the nl80211 listener.
    pub fn wifi_raw_ping(
        &self,
        iface: Option<String>,
        channel: Option<u8>,
        listen_sec: Option<u64>,
        wait_ms: Option<u64>,
        nonce: Option<String>,
    ) -> Value {
        let iface = wifi_iface(iface);
        let channel = raw_wifi_channel(channel);
        let listen_sec = listen_sec.unwrap_or(DEFAULT_RAW_WIFI_LISTEN_SECS).max(1);
        let wait_ms = wait_ms.unwrap_or(900).clamp(50, 10_000);
        let nonce = nonce.unwrap_or_else(|| format!("{}-{}", std::process::id(), now_millis()));
        let payload = format!("dmesh.ping type=status source=lmesh nonce={nonce}");
        let listen = self.wifi_raw_listen(
            Some(iface.clone()),
            Some(channel),
            Some(listen_sec),
            Some("nl80211".to_string()),
        );
        let sent_at = now_millis_u64();
        let tx = self.wifi_raw_send(
            Some(iface.clone()),
            Some(channel),
            Some(listen_sec),
            None,
            None,
            Some("dont_wait_ack".to_string()),
            None,
            None,
            None,
            payload.clone(),
            None,
        );
        std::thread::sleep(Duration::from_millis(wait_ms));
        let replies = self.raw_wifi_ping_replies(sent_at, &iface);
        let result = json!({
            "ok": tx.get("ok").and_then(Value::as_bool).unwrap_or(false),
            "iface": iface,
            "channel": channel,
            "listen_sec": listen_sec,
            "wait_ms": wait_ms,
            "nonce": nonce,
            "payload": payload,
            "listen": listen,
            "tx": tx,
            "reply_count": replies.len(),
            "replies": replies,
        });
        self.record("wifi.raw.ping", result.clone());
        result
    }

    /// Host raw-NAN smoke path. This deliberately uses the existing
    /// monitor TX/RX transport but runs every received frame through the
    /// shared no_std NAN state machine, so host behavior is observable before
    /// the ESP DMOD adapter is enabled.
    pub fn rawnan_ping(
        &self,
        iface: Option<String>,
        channel: Option<u8>,
        destination: Option<String>,
        bssid: Option<String>,
        payload: String,
        wait_ms: Option<u64>,
    ) -> Value {
        let iface_value = wifi_iface(iface);
        let channel_value = raw_wifi_channel(channel);
        let wait_ms = wait_ms.unwrap_or(1_000).clamp(50, 10_000);
        let listen = self.wifi_raw_listen(
            Some(iface_value.clone()),
            Some(channel_value),
            Some((wait_ms / 1_000 + 3).max(3)),
            Some("monitor".to_string()),
        );
        let sent_at = now_millis_u64();
        let destination_bytes = raw_wifi_destination(destination.as_deref(), "monitor");
        let target = format!(
            "{:02x}{:02x}{:02x}{:02x}",
            destination_bytes[2], destination_bytes[3], destination_bytes[4], destination_bytes[5]
        );
        let payload_bytes = if payload.eq_ignore_ascii_case("ping") {
            firmware_targeted_command_cbor_with_timeout(
                "ping",
                &target,
                Some(wait_ms.min(u32::MAX as u64) as u32),
            )
            .unwrap_or_else(|_| payload.as_bytes().to_vec())
        } else if let Some(hex) = payload.strip_prefix("hex:") {
            decode_firmware_hex(hex).unwrap_or_else(|_| payload.as_bytes().to_vec())
        } else {
            payload.as_bytes().to_vec()
        };
        let bssid = bssid
            .as_deref()
            .and_then(|value| parse_mac(Some(value)))
            .or_else(|| {
                self.rawnan_state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .cluster()
                    .map(|mac| mac.0)
            })
            .unwrap_or(destination_bytes);
        let tx = match raw_wifi_source(None, &iface_value)
            .and_then(|source| {
                build_dmesh_vendor_action_frame_with_bssid(
                    destination_bytes,
                    source,
                    bssid,
                    &payload_bytes,
                )
            })
            .and_then(|frame| send_monitor_frame(&iface_value, channel_value, &frame, None))
        {
            Ok(value) => json!({
                "ok": true,
                "backend": "linux_af_packet_monitor",
                "tx_variant": "monitor",
                "iface": iface_value,
                "channel": channel_value,
                "payload_len": payload_bytes.len(),
                "frame_len": value.get("packet_len").cloned().unwrap_or_else(|| json!(0)),
                "monitor": value,
            }),
            Err(error) => json!({
                "ok": false,
                "backend": "linux_af_packet_monitor",
                "tx_variant": "monitor",
                "iface": iface_value,
                "channel": channel_value,
                "payload_len": payload_bytes.len(),
                "error": format!("{error:#}"),
            }),
        };
        std::thread::sleep(Duration::from_millis(wait_ms));
        let events = self
            .history
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter(|event| event.key == "wifi.raw.rx" && event.ts_millis >= u128::from(sent_at))
            .map(|event| event.value.clone())
            .collect::<Vec<_>>();
        let state = self
            .rawnan_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let cluster = state.cluster().map(|mac| colon_mac(&mac.0));
        let rx_count = events.len();
        let result = json!({
            "ok": tx.get("ok").and_then(Value::as_bool).unwrap_or(false),
            "backend": "rawnan_host",
            "iface": iface_value,
            "channel": channel_value,
            "payload_len": payload_bytes.len(),
            "payload_mode": if payload.eq_ignore_ascii_case("ping") { "generated_cbor" } else if payload.starts_with("hex:") { "hex" } else { "text" },
            "listen": listen,
            "tx": tx,
            "wait_ms": wait_ms,
            "rx_events": events,
            "rx_count": rx_count,
            "filter_mode": match state.mode() {
                dmesh_rawnan::FilterMode::Discovery => "discovery",
                dmesh_rawnan::FilterMode::Cluster => "cluster_a3",
            },
            "cluster_bssid": cluster,
        });
        self.record("wifi.rawnan.ping", result.clone());
        result
    }

    fn run_raw_action_client<C: RawActionClient>(
        &self,
        iface: &str,
        channel: u8,
        destination: [u8; 6],
        expected_peer: Option<[u8; 6]>,
        source: [u8; 6],
        timeout_ms: u64,
        tx_rate_mbps: u8,
        tx_variant: &str,
        client: &mut C,
    ) -> RawActionRun {
        let mut packet = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
        let mut pending = match client.start(&mut packet) {
            Ok(used) => Some(used),
            Err(error) => {
                return RawActionRun {
                    elapsed_us: 0,
                    tx_packets: 0,
                    tx_errors: 0,
                    last_tx: None,
                    rx_packets: 0,
                    retransmit_packets: 0,
                    error: Some(format!("raw action OPEN: {error:?}")),
                };
            }
        };
        let started = Instant::now();
        let start_ms = now_millis_u64();
        // The sender must not start the long-lived history listener on the
        // same monitor VIF: active monitor TX may need to recreate that VIF,
        // and the listener then races deletion/recreation while also making
        // a local AF_PACKET socket look like a successful peer path. Prepare
        // one VIF here and use the bounded direct socket below for responses.
        let _monitor_setup = if matches!(tx_variant, "monitor" | "monitor_active") {
            // A test is only a consumer of the permanent monitor fixture.
            // It cannot replace or retune that interface, even when the
            // caller spells the historical `monitor_active` variant.
            let monitor_iface = monitor_iface_name(iface);
            match require_existing_monitor_iface(&monitor_iface) {
                Ok(setup) => Some(setup),
                Err(error) => {
                    return RawActionRun {
                        elapsed_us: started.elapsed().as_micros(),
                        tx_packets: 0,
                        tx_errors: 0,
                        last_tx: None,
                        rx_packets: 0,
                        retransmit_packets: 0,
                        error: Some(format!(
                            "raw action requires a pre-provisioned monitor {monitor_iface}: {error:#}"
                        )),
                    };
                }
            }
        } else {
            None
        };
        // Keep one monitor TX socket for the lifetime of the association.
        // Opening and binding an AF_PACKET socket for every QUIC datagram
        // adds scheduler/driver latency and makes a burst look like a series
        // of independent setup operations.  The socket is opened only after
        // the monitor VIF has been prepared; opening it earlier was observed
        // to race VIF recreation and produced locally-accepted, zero-RF runs.
        let monitor_tx = if matches!(tx_variant, "monitor" | "monitor_active") {
            MonitorTxSocket::open(&monitor_iface_name(iface)).ok()
        } else {
            None
        };
        // Read the monitor socket directly in the probe loop as well as
        // consuming the shared history. The history listener is intentionally
        // long-lived for diagnostics, but a bounded request/response probe
        // must not depend on its scheduling or on a stale listener instance.
        let direct_rx = MonitorRxSocket::open(&monitor_iface_name(iface)).ok();
        let mut direct_buf = [0_u8; 4096];
        let mut direct_payload = [0_u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
        let mut seen = HashSet::new();
        let mut tx_packets = 0u64;
        let mut tx_errors = 0u64;
        let mut last_tx = None;
        let mut rx_packets = 0u64;
        let mut retransmit_packets = 0u64;
        let mut error = None;
        let local_source = colon_mac(&source);
        while started.elapsed() < Duration::from_millis(timeout_ms) {
            if let Some(used) = pending.take() {
                // This is the raw ESP-NOW-compatible QUIC bearer, not NAN
                // service discovery.  `wifi_raw_send` deliberately builds a
                // NAN public action for its generic host diagnostic API;
                // sending the QUIC bytes through that builder makes a ROC
                // receiver classify them as NAN and never feed the shared
                // NOW ingress. Build the host-tested ESP-NOW IE/action frame
                // explicitly, then use the same monitor/nl80211 injection
                // selector as every other raw action test.
                let mut action = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 64];
                let action_len = match dmesh_rawnan::espnow::encode_action_frame(
                    &mut action,
                    destination,
                    source,
                    [0xff; 6],
                    &packet[..used],
                ) {
                    Ok(length) => length,
                    Err(frame_error) => {
                        error = Some(format!("raw ESP-NOW action: {frame_error:?}"));
                        break;
                    }
                };
                let sent = if let Some(socket) = monitor_tx.as_ref() {
                    let packet = match build_radiotap_packet_at_rate_with_ack(
                        &action[..action_len],
                        Some(tx_rate_mbps),
                        // DMesh NOW carries its own QUIC acknowledgement and
                        // retransmission. Do not require a link-layer ACK:
                        // monitor/AP peers may hear a frame but be unable to
                        // acknowledge it at the 802.11 management layer.
                        false,
                    ) {
                        Ok(packet) => packet,
                        Err(radiotap_error) => {
                            error = Some(format!("raw action radiotap: {radiotap_error:#}"));
                            break;
                        }
                    };
                    match socket.send(&packet) {
                        Ok(written) if written == packet.len() => json!({
                            "ok": true,
                            "backend": "linux_af_packet_monitor_persistent",
                            "iface": iface,
                            "channel": channel,
                            "tx_variant": tx_variant,
                            "tx_rate_mbps": tx_rate_mbps,
                            "frame_len": action_len,
                            "monitor": {"iface": monitor_iface_name(iface), "packet_len": packet.len()},
                        }),
                        Ok(written) => json!({
                            "ok": false,
                            "error": format!("short monitor frame write: wrote {written}, expected {}", packet.len()),
                        }),
                        Err(error) => {
                            json!({"ok": false, "error": format!("raw action TX: {error:#}")})
                        }
                    }
                } else {
                    self.wifi_raw_send_frame(
                        Some(iface.to_owned()),
                        Some(channel),
                        Some(tx_variant.to_owned()),
                        format!("hex:{}", hex_lower(&action[..action_len])),
                        Some(tx_rate_mbps),
                    )
                };
                last_tx = Some(sent.clone());
                if !sent.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                    tx_errors = tx_errors.saturating_add(1);
                    error = Some(format!(
                        "raw action TX: {}",
                        sent.get("error")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown error")
                    ));
                    break;
                }
                tx_packets = tx_packets.saturating_add(1);
            }
            if let Some(socket) = direct_rx.as_ref() {
                if let Ok(Some(len)) = socket.recv_timeout(&mut direct_buf, Duration::from_millis(10))
                    && let Some(frame) = ieee80211_frame(&direct_buf[..len])
                    // AF_PACKET monitor sockets can reflect our own injected
                    // frame. It is never a peer response; accepting it made
                    // the old raw check falsely report bootstrap success.
                    && mac_at(frame, IEEE80211_ADDR2) != Some(source)
                    && let Some((peer, payload_len)) =
                        dmesh_rawnan::espnow::parse_action_frame_into(frame, &mut direct_payload)
                    && expected_peer.is_none_or(|expected| peer == expected)
                {
                    rx_packets = rx_packets.saturating_add(1);
                    match client.receive_at(
                        &direct_payload[..payload_len],
                        now_millis_u64(),
                        &mut packet,
                    ) {
                        Ok(next) => pending = next,
                        Err(receive_error) => {
                            // A monitor VIF can deliver a delayed response
                            // from the association that the preceding test
                            // row stopped. It is not part of this client CID;
                            // ignore it and continue waiting for the current
                            // bearer rather than converting stale RF traffic
                            // into a test failure.
                            if !raw_action_receive_error_is_ambient(receive_error) {
                                error = Some(format!("QUIC-lite direct RX: {receive_error:?}"));
                                break;
                            }
                        }
                    }
                }
            }
            // Delayed ACKs and flow-credit updates are not necessarily
            // returned from `receive`; unlike UDP, this monitor bearer has no
            // independent socket worker to poll the QUIC clock.  Queue the
            // one returned control datagram through the same raw action TX
            // path, preserving the no-owned-egress-queue invariant.
            if pending.is_none()
                && let Ok(Some(used)) = client.poll_transmit(&mut packet)
            {
                pending = Some(used);
            }
            if pending.is_none()
                // EndpointState clocks are absolute milliseconds (the same
                // unit used by receive_at). Passing a run-relative clock here
                // moves time backwards after the first response and silently
                // disables client-side PTO recovery.
                && let Ok(Some(used)) = client.poll_retransmit(
                    now_millis_u64(),
                    100,
                    &mut packet,
                )
            {
                pending = Some(used);
                retransmit_packets = retransmit_packets.saturating_add(1);
            }
            let events = self
                .history
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .iter()
                .filter(|event| {
                    event.key == "wifi.raw.rx" && event.ts_millis >= u128::from(start_ms)
                })
                .map(|event| (event.ts_millis, event.value.clone()))
                .collect::<Vec<_>>();
            for (timestamp, event) in events {
                let Some(payload_hex) = event.get("payload").and_then(Value::as_str) else {
                    continue;
                };
                if event.get("source").and_then(Value::as_str) == Some(local_source.as_str())
                    || event.get("source_mac").and_then(Value::as_str)
                        == Some(local_source.as_str())
                {
                    continue;
                }
                if let Some(expected) = expected_peer {
                    let expected = colon_mac(&expected);
                    let peer_matches = event.get("source").and_then(Value::as_str)
                        == Some(expected.as_str())
                        || event.get("source_mac").and_then(Value::as_str)
                            == Some(expected.as_str());
                    if !peer_matches {
                        continue;
                    }
                }
                if !seen.insert((timestamp, payload_hex.to_owned())) {
                    continue;
                }
                let Ok(payload) = decode_firmware_hex(payload_hex) else {
                    continue;
                };
                rx_packets = rx_packets.saturating_add(1);
                match client.receive_at(&payload, now_millis_u64(), &mut packet) {
                    Ok(next) => pending = next,
                    Err(receive_error) => {
                        if !raw_action_receive_error_is_ambient(receive_error) {
                            error = Some(format!("QUIC-lite RX: {receive_error:?}"));
                            break;
                        }
                    }
                }
                if client.is_complete() {
                    break;
                }
            }
            if client.is_complete() || error.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        RawActionRun {
            elapsed_us: started.elapsed().as_micros(),
            tx_packets,
            tx_errors,
            last_tx,
            rx_packets,
            retransmit_packets,
            error,
        }
    }

    /// Run the standard QUIC-lite IPERF service through raw ESP-NOW-compatible
    /// vendor action frames. The host owns monitor injection/capture only;
    /// bootstrap, stream request, ACKs, and IPERF validation live in the
    /// bearer-neutral `dmesh_server::raw_iperf::RawIperfClient`.
    pub fn raw_espnow_iperf(
        &self,
        iface: Option<String>,
        channel: Option<u8>,
        destination: String,
        bytes: u64,
        packet_size: Option<u64>,
        timeout_ms: Option<u64>,
        tx_rate_mbps: Option<u64>,
        tx_variant: Option<String>,
        rx_variant: Option<String>,
        expected_peer: Option<String>,
    ) -> Value {
        let iface = wifi_iface(iface);
        let channel = raw_wifi_channel(channel);
        let timeout_ms = timeout_ms.unwrap_or(20_000).clamp(1_000, 60_000);
        let packet_size = packet_size
            .unwrap_or(quic_lite::DEFAULT_MAX_DATAGRAM_SIZE as u64)
            .clamp(4, quic_lite::DEFAULT_MAX_DATAGRAM_SIZE as u64) as u16;
        let tx_rate_mbps = match tx_rate_mbps {
            None => 6,
            Some(rate @ (1 | 2 | 5 | 6 | 9 | 11 | 12 | 18 | 24 | 36 | 48 | 54)) => rate as u8,
            Some(_) => {
                return json!({
                    "ok": false,
                    "error": "tx_rate_mbps must be one of 1,2,5,6,9,11,12,18,24,36,48,54"
                });
            }
        };
        // This is deliberately a runtime selection: the host's monitor
        // injector is the historically proven on-air action path, whereas
        // NL80211_CMD_FRAME is useful to test a driver-managed route but is
        // rejected by some adapters. Neither choice changes QUIC-lite.
        let tx_variant = match tx_variant.as_deref().unwrap_or("monitor") {
            "monitor" | "monitor_active" => tx_variant.as_deref().unwrap_or("monitor"),
            "action" | "nl80211" => "action",
            other => {
                return json!({
                    "ok": false,
                    "error": format!("tx_variant must be monitor, action, or nl80211, got {other:?}"),
                });
            }
        };
        let rx_variant = match rx_variant.as_deref().unwrap_or("monitor") {
            "monitor" | "monitor_active" => rx_variant.as_deref().unwrap_or("monitor"),
            "nl80211" => "nl80211",
            other => {
                return json!({
                    "ok": false,
                    "error": format!("rx_variant must be monitor, monitor_active, or nl80211, got {other:?}"),
                });
            }
        };
        let destination_mac = match parse_mac(Some(&destination)) {
            Some(mac) => mac,
            None => return json!({"ok": false, "error": "destination must be a MAC address"}),
        };
        let expected_peer_mac = match expected_peer.as_deref() {
            Some(value) => match parse_mac(Some(value)) {
                Some(mac) => Some(mac),
                None => return json!({"ok": false, "error": "expected_peer must be a MAC address"}),
            },
            None => None,
        };
        let source = match raw_wifi_source(None, &iface) {
            Ok(mac) => mac,
            Err(error) => {
                return json!({"ok": false, "iface": iface, "error": format!("source MAC: {error:#}")});
            }
        };
        // `nl80211` frame events keep the AP's managed station association
        // intact. Monitor-VIF creation is useful for passive NAN inspection
        // but can sever an active Recovery STA on this chipset.
        // The sender uses the bounded direct monitor socket prepared by
        // `run_raw_action_client`; only the peer needs a history listener.
        // Starting another listener here used to race active monitor TX.
        let listen = json!({
            "ok": true,
            "backend": "linux_af_packet_monitor_direct",
            "iface": iface,
            "channel": channel,
            "rx_variant": rx_variant,
        });
        let cid_value = now_millis_u64().max(1);
        let client_cid = match quic_lite::ConnectionId::new(cid_value) {
            Some(cid) => cid,
            None => return json!({"ok": false, "error": "could not allocate client CID"}),
        };
        let mut client = match dmesh_server::raw_iperf::RawIperfClient::<
            16,
            { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE },
        >::new_with_packet_size(client_cid, bytes, packet_size)
        {
            Ok(client) => client,
            Err(error) => return json!({"ok": false, "error": format!("IPERF client: {error:?}")}),
        };
        let run = self.run_raw_action_client(
            &iface,
            channel,
            destination_mac,
            expected_peer_mac,
            source,
            timeout_ms,
            tx_rate_mbps,
            tx_variant,
            &mut client,
        );
        let elapsed_us = run.elapsed_us;
        let complete = client.is_complete();
        let transferred = client.bytes();
        let bps = if elapsed_us == 0 {
            0
        } else {
            transferred.saturating_mul(8).saturating_mul(1_000_000) / elapsed_us as u64
        };
        let result = json!({
            "ok": complete,
            "bearer": "espnow_raw_action",
            "iface": iface,
            "channel": channel,
            "destination": destination,
            "expected_peer": expected_peer,
            "requested_bytes": bytes,
            "packet_size": packet_size,
            "tx_rate_mbps": tx_rate_mbps,
            "tx_variant": tx_variant,
            "rx_variant": rx_variant,
            "bytes": transferred,
            "elapsed_us": elapsed_us,
            "bps": bps,
            "tx_packets": run.tx_packets,
            "tx_errors": run.tx_errors,
            "last_tx": run.last_tx,
            "rx_packets": run.rx_packets,
            "retransmit_packets": run.retransmit_packets,
            "callback_errors": client.callback_errors(),
            "server_cid": client.server_cid().map(|cid| cid.value()),
            "listen": listen,
            "error": run.error,
        });
        self.record("wifi.raw.iperf", result.clone());
        result
    }

    /// Send one normal QUIC-lite status request through the raw NOW-like
    /// bearer.  This is a production liveness/probe operation, not an IPERF
    /// shortcut: the returned status bytes and shared transport counters are
    /// useful to both host and firmware matrix runners.
    pub fn raw_espnow_check(
        &self,
        iface: Option<String>,
        channel: Option<u8>,
        destination: String,
        nonce: u64,
        timeout_ms: Option<u64>,
        tx_rate_mbps: Option<u64>,
        tx_variant: Option<String>,
        rx_variant: Option<String>,
        expected_peer: Option<String>,
    ) -> Value {
        let iface = wifi_iface(iface);
        let channel = raw_wifi_channel(channel);
        let timeout_ms = timeout_ms.unwrap_or(5_000).clamp(1_000, 60_000);
        let tx_rate_mbps = match tx_rate_mbps {
            None => 6,
            Some(rate @ (1 | 2 | 5 | 6 | 9 | 11 | 12 | 18 | 24 | 36 | 48 | 54)) => rate as u8,
            Some(_) => {
                return json!({"ok": false, "error": "tx_rate_mbps must be one of 1,2,5,6,9,11,12,18,24,36,48,54"});
            }
        };
        let tx_variant = match tx_variant.as_deref().unwrap_or("monitor") {
            "monitor" | "monitor_active" => tx_variant.as_deref().unwrap_or("monitor"),
            "action" | "nl80211" => "action",
            other => {
                return json!({"ok": false, "error": format!("tx_variant must be monitor, action, or nl80211, got {other:?}")});
            }
        };
        let rx_variant = match rx_variant.as_deref().unwrap_or("monitor") {
            "monitor" | "monitor_active" => rx_variant.as_deref().unwrap_or("monitor"),
            "nl80211" => "nl80211",
            other => {
                return json!({"ok": false, "error": format!("rx_variant must be monitor, monitor_active, or nl80211, got {other:?}")});
            }
        };
        let Some(destination_mac) = parse_mac(Some(&destination)) else {
            return json!({"ok": false, "error": "destination must be a MAC address"});
        };
        let expected_peer_mac = match expected_peer.as_deref() {
            Some(value) => match parse_mac(Some(value)) {
                Some(mac) => Some(mac),
                None => return json!({"ok": false, "error": "expected_peer must be a MAC address"}),
            },
            None => None,
        };
        let source = match raw_wifi_source(None, &iface) {
            Ok(mac) => mac,
            Err(error) => {
                return json!({"ok": false, "iface": iface, "error": format!("source MAC: {error:#}")});
            }
        };
        // As with IPERF, do not create a second history listener on the
        // sender's monitor VIF. The direct bounded socket is opened by the
        // raw action loop and shares the same prepared VIF with TX.
        let listen = json!({
            "ok": true,
            "backend": "linux_af_packet_monitor_direct",
            "iface": iface,
            "channel": channel,
            "rx_variant": rx_variant,
        });
        let Some(client_cid) = quic_lite::ConnectionId::new(now_millis_u64().max(1)) else {
            return json!({"ok": false, "error": "could not allocate client CID"});
        };
        let mut client = dmesh_server::raw_iperf::RawCheckClient::<
            16,
            { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE },
        >::new(client_cid, nonce);
        let run = self.run_raw_action_client(
            &iface,
            channel,
            destination_mac,
            expected_peer_mac,
            source,
            timeout_ms,
            tx_rate_mbps,
            tx_variant,
            &mut client,
        );
        let response_hex = client.response().map(hex_lower);
        let counters = client.counters();
        let result = json!({
            "ok": client.is_complete() && run.error.is_none(),
            "bearer": "espnow_raw_action",
            "service": "status",
            "iface": iface,
            "channel": channel,
            "destination": destination,
            "expected_peer": expected_peer,
            "nonce": nonce,
            "tx_rate_mbps": tx_rate_mbps,
            "tx_variant": tx_variant,
            "rx_variant": rx_variant,
            "elapsed_us": run.elapsed_us,
            "tx_packets": run.tx_packets,
            "tx_errors": run.tx_errors,
            "last_tx": run.last_tx,
            "rx_packets": run.rx_packets,
            "counters": {
                "bootstrap_acks": counters.bootstrap_acks,
                "stream_packets": counters.stream_packets,
                "other_packets": counters.other_packets,
            },
            "response_hex": response_hex,
            "listen": listen,
            "error": run.error,
        });
        self.record("wifi.raw.check", result.clone());
        result
    }

    /// Capture beacon and probe-response management frames through an AF_PACKET monitor socket.
    pub fn wifi_mgmt_capture(
        &self,
        iface: Option<String>,
        channel: Option<u8>,
        capture_ms: Option<u64>,
        max_frames: Option<usize>,
        active: Option<bool>,
    ) -> Result<Value> {
        let iface = wifi_iface(iface);
        let channel = raw_wifi_channel(channel);
        let capture_ms = capture_ms.unwrap_or(4_000).clamp(100, 60_000);
        let max_frames = max_frames.unwrap_or(32).clamp(1, 512);
        let monitor_iface = monitor_iface_name(&iface);
        let active = active.unwrap_or(false);
        if active {
            bail!(
                "active monitor capture is an operator radio transition; use the permanent monitor fixture"
            );
        }
        // Capture is a read-only diagnostic.  Do not let an E2E caller create
        // or reconfigure a monitor as a side effect of observing packets.
        let setup = require_existing_monitor_iface(&monitor_iface)?;
        let socket = MonitorRxSocket::open(&monitor_iface)?;
        let deadline = std::time::Instant::now() + Duration::from_millis(capture_ms);
        let mut buf = [0_u8; 4096];
        let mut frames = Vec::new();
        while frames.len() < max_frames {
            let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
                break;
            };
            if remaining.is_zero() {
                break;
            }
            match socket.recv_timeout(&mut buf, remaining.min(Duration::from_millis(250)))? {
                Some(0) | None => continue,
                Some(len) => {
                    let packet = &buf[..len];
                    let Some(frame) = ieee80211_frame(packet) else {
                        continue;
                    };
                    let subtype = frame_subtype(frame);
                    // Include action frames as well as beacons/probe
                    // responses. Host NOW/NAN validation needs an RF-level
                    // capture before any DMesh-specific parser decides
                    // whether a payload is a usable command.
                    if frame_type(frame) != 0 || !matches!(subtype, 5 | 8 | 13) {
                        continue;
                    }
                    frames.push(parse_management_frame(
                        frame,
                        &iface,
                        "linux_af_packet_monitor",
                    ));
                }
            }
        }
        // A passive scan is not available on these active AP interfaces, but
        // the permanent monitor already observes the same beacon/probe
        // traffic. Normalize that capture into one observation per BSSID for
        // the control-plane probe without discarding its underlying frames.
        let mut aps = BTreeMap::<String, Value>::new();
        for frame in &frames {
            if !matches!(frame.get("kind").and_then(Value::as_str), Some("beacon" | "probe_resp")) {
                continue;
            }
            let Some(bssid) = frame.get("bssid").and_then(Value::as_str) else {
                continue;
            };
            aps.insert(
                bssid.to_owned(),
                json!({
                    "bssid": bssid,
                    "ssid": frame.get("ssid").cloned().unwrap_or(Value::Null),
                    "channel": frame.get("channel").cloned().unwrap_or(Value::Null),
                    "beacon_interval": frame.get("fixed")
                        .and_then(|fixed| fixed.get("beacon_interval"))
                        .cloned().unwrap_or(Value::Null),
                }),
            );
        }
        let direct = aps
            .values()
            .filter(|ap| ap.get("ssid").and_then(Value::as_str)
                .is_some_and(|ssid| ssid.starts_with("DIRECT-")))
            .cloned()
            .collect::<Vec<_>>();
        let direct_dmesh = direct
            .iter()
            .filter(|ap| ap.get("ssid").and_then(Value::as_str)
                .is_some_and(|ssid| ssid.ends_with("-dmesh")))
            .cloned()
            .collect::<Vec<_>>();
        let result = json!({
            "ok": true,
            "backend": "linux_af_packet_monitor",
            "iface": iface,
            "monitor_iface": monitor_iface,
            "channel": channel,
            "capture_ms": capture_ms,
            "max_frames": max_frames,
            "frame_count": frames.len(),
            "ap_count": aps.len(),
            "aps": aps.into_values().collect::<Vec<_>>(),
            "direct": direct,
            "direct_dmesh": direct_dmesh,
            "setup": setup,
            "frames": frames,
        });
        self.record("wifi.mgmt.capture", result.clone());
        Ok(result)
    }

    fn raw_wifi_ping_replies(&self, since_ms: u64, iface: &str) -> Vec<Value> {
        self.history
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter(|event| event.ts_millis as u64 >= since_ms)
            .filter(|event| event.key == "wifi.raw.rx")
            .filter_map(|event| {
                let payload = event.value.get("payload_text")?.as_str()?;
                if !payload.starts_with("dmesh.ping ") || !payload.contains("reply=true") {
                    return None;
                }
                if event.value.get("iface").and_then(Value::as_str) != Some(iface) {
                    return None;
                }
                Some(event.value.clone())
            })
            .collect()
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

fn push_history_event(history: &Arc<Mutex<VecDeque<RadioEvent>>>, key: &str, value: Value) {
    let mut history = history
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    history.push_back(RadioEvent {
        ts_millis: now_millis(),
        key: key.to_owned(),
        source: "local".to_owned(),
        value,
        message: None,
    });
    while history.len() > MAX_HISTORY {
        history.pop_front();
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

#[derive(Debug, Serialize)]
struct NeighborInfo {
    node: String,
    last_seen_ms: u64,
    medium: Option<String>,
    network: Option<String>,
    radio_id: Option<String>,
    rssi: Option<i32>,
    snr: Option<f32>,
    source: Option<String>,
    last_event: Option<String>,
}

impl NeighborInfo {
    fn new(node: &str) -> Self {
        Self {
            node: node.to_string(),
            last_seen_ms: 0,
            medium: None,
            network: None,
            radio_id: None,
            rssi: None,
            snr: None,
            source: None,
            last_event: None,
        }
    }
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

fn mesh_radio_name(medium: &str) -> &'static str {
    match medium {
        "wifi" | "nan" => "nan",
        "ble" => "ble",
        "serial" => "serial",
        "remote" => "remote",
        "mcast" => "mcast",
        _ => "unknown",
    }
}

fn unavailable_radios(radio: &str) -> Vec<Value> {
    let mut unavailable = Vec::new();
    if radio == "all" || radio == "lora" {
        unavailable.push(json!({
            "radio": "lora",
            "ok": false,
            "error": "host LoRA send/listen is not implemented in lmesh yet",
        }));
    }
    if radio == "all" || radio == "sta" {
        unavailable.push(json!({
            "radio": "sta",
            "ok": false,
            "error": "open AP/STA attachment is not implemented in lmesh yet",
        }));
    }
    unavailable
}

fn link_quality(rssi: Option<i32>, snr: Option<f32>) -> &'static str {
    if let Some(snr) = snr {
        if snr >= 8.0 {
            return "good";
        }
        if snr >= 2.0 {
            return "fair";
        }
        return "poor";
    }
    if let Some(rssi) = rssi {
        if rssi >= -60 {
            return "good";
        }
        if rssi >= -75 {
            return "fair";
        }
        return "poor";
    }
    "unknown"
}

fn is_group_mac(mac: &str) -> bool {
    let Some(first) = mac.split(':').next() else {
        return false;
    };
    u8::from_str_radix(first, 16)
        .map(|byte| byte & 1 == 1)
        .unwrap_or(false)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
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

/// Encode a one-hop raw-NAN ping request.  This remains a host radio helper:
/// it never opens a UART and uses the documented firmware command envelope.
fn firmware_targeted_command_cbor_with_timeout(
    command: &str,
    target: &str,
    timeout_ms: Option<u32>,
) -> Result<Vec<u8>> {
    if !command.trim().eq_ignore_ascii_case("ping") {
        bail!("raw Wi-Fi helper only supports the documented ping request");
    }
    let mut bytes = Vec::with_capacity(56);
    let mut encoder = Encoder::new(&mut bytes);
    let argument_count = 2 + usize::from(timeout_ms.is_some());
    encoder.map(2)?;
    encoder.u16(0)?.u16(49)?;
    encoder.u16(6)?.map(argument_count as u64)?;
    encoder.u16(190)?.str("true")?;
    encoder.u16(331)?.str(target)?;
    if let Some(timeout_ms) = timeout_ms {
        encoder.u16(41)?.str(&timeout_ms.to_string())?;
    }
    Ok(bytes)
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

fn monitor_iface_name(iface: &str) -> String {
    if iface.ends_with("mon") {
        iface.to_string()
    } else {
        format!("{iface}mon")
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct GenlMsgHdr {
    cmd: u8,
    version: u8,
    reserved: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NlAttrHdr {
    nla_len: u16,
    nla_type: u16,
}

/// Build the nested 2.4 GHz rate attributes used by `NL80211_ATTR_TX_RATES`.
/// This is kept independent of the socket so host tests cover the exact
/// no-legacy HT diagnostic payload before it is sent to the live AP.
fn tx_rate_profile_band(
    rate_mbps: Option<u8>,
    ht_mcs: Option<u8>,
    disable_b: bool,
) -> Option<Vec<u8>> {
    if rate_mbps.is_none() && ht_mcs.is_none() && !disable_b {
        return None;
    }
    let mut band = Vec::new();
    if let Some(rate) = rate_mbps {
        append_attr(&mut band, NL80211_TXRATE_LEGACY, &[rate.saturating_mul(2)]);
    } else if disable_b && ht_mcs.is_none() {
        // OFDM-only 2.4 GHz policy: exclude 1/2/5.5/11 Mbps CCK while
        // retaining the normal OFDM fallback ladder.
        let rates: Vec<u8> = [6_u8, 9, 12, 18, 24, 36, 48, 54]
            .into_iter()
            .map(|rate| rate.saturating_mul(2))
            .collect();
        append_attr(&mut band, NL80211_TXRATE_LEGACY, &rates);
    }
    if let Some(mcs) = ht_mcs {
        // Exact HT-only diagnostic: leave legacy data rates out of this
        // rate-control profile so rate fallback cannot hide a low-MCS result.
        // AP management/control retains its BSS basic-rate policy separately.
        append_attr(&mut band, NL80211_TXRATE_HT, &[mcs]);
    }
    Some(band)
}

struct Nl80211Socket {
    fd: RawFd,
    family_id: u16,
}

struct ApRuntime {
    _owner_socket: Nl80211Socket,
    channel: u8,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

struct ApStartProfile {
    name: &'static str,
    probe_resp: bool,
    channel_type: u32,
    channel_width: u32,
    explicit_width: bool,
    freq_fixed: bool,
    hostapd_ies: bool,
    hostapd_crypto: bool,
    hostapd_tail: bool,
    capability: u16,
}

#[derive(Clone)]
struct RawWifiTxOptions {
    variant: String,
    include_freq: bool,
    duration_ms: Option<u32>,
    offchannel_tx_ok: bool,
    dont_wait_for_ack: bool,
    tx_no_cck_rate: bool,
}

impl RawWifiTxOptions {
    fn from_variant(
        variant: Option<&str>,
        listen_sec: u64,
        tx_duration_ms: Option<u32>,
    ) -> Result<Self> {
        // Host raw NOW/NAN has no association requirement.  The monitor
        // injector is therefore the default: nl80211 management-frame TX is
        // retained as an explicit driver experiment, but returns ENOTCONN on
        // an unassociated adapter and must not be the production host path.
        let variant = variant.unwrap_or("monitor").trim();
        let duration_ms = tx_duration_ms
            .unwrap_or_else(|| listen_sec.saturating_mul(1000).min(u32::MAX as u64) as u32);
        let options = match variant {
            "" | "standard" => Self {
                variant: "standard".to_string(),
                include_freq: true,
                duration_ms: Some(duration_ms),
                offchannel_tx_ok: true,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            "zero_duration" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: Some(0),
                offchannel_tx_ok: true,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            "no_duration" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: None,
                offchannel_tx_ok: true,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            "no_offchannel" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: Some(duration_ms),
                offchannel_tx_ok: false,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            "minimal" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            "dont_wait_ack" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: Some(duration_ms),
                offchannel_tx_ok: true,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "dont_wait_no_duration" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: None,
                offchannel_tx_ok: true,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "dont_wait_minimal" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "onchannel" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            "onchannel_noack" | "noack_onchannel" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "dont_wait_no_cck" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: None,
                offchannel_tx_ok: true,
                dont_wait_for_ack: true,
                tx_no_cck_rate: true,
            },
            "no_cck" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: Some(duration_ms),
                offchannel_tx_ok: true,
                dont_wait_for_ack: false,
                tx_no_cck_rate: true,
            },
            "no_freq" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: Some(duration_ms),
                offchannel_tx_ok: true,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            "monitor" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "monitor_active" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "action" | "send_action" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            "multicast_data" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "multicast_data_active" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "sta_multicast_llc" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "sta_multicast_llc_active" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "sta_direct_llc" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "sta_direct_llc_active" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "nan_data" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "nan_data_active" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "nan_data_raw"
            | "nan_data_raw_active"
            | "nan_data_multicast"
            | "nan_data_multicast_active" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "roc" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: Some(tx_duration_ms.unwrap_or(10)),
                offchannel_tx_ok: true,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "pyroute2" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: Some(duration_ms),
                offchannel_tx_ok: false,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            other => bail!(
                "unknown tx_variant {other:?}; expected standard, zero_duration, no_duration, no_offchannel, minimal, dont_wait_ack, dont_wait_no_duration, dont_wait_minimal, onchannel, onchannel_noack, action, send_action, dont_wait_no_cck, no_cck, no_freq, monitor, monitor_active, multicast_data, multicast_data_active, sta_multicast_llc, sta_multicast_llc_active, sta_direct_llc, sta_direct_llc_active, nan_data, nan_data_active, nan_data_raw, nan_data_raw_active, nan_data_multicast, nan_data_multicast_active, roc, or pyroute2"
            ),
        };
        Ok(options)
    }

    fn as_json(&self) -> Value {
        json!({
            "include_freq": self.include_freq,
            "duration_ms": self.duration_ms,
            "offchannel_tx_ok": self.offchannel_tx_ok,
            "dont_wait_for_ack": self.dont_wait_for_ack,
            "tx_no_cck_rate": self.tx_no_cck_rate,
        })
    }
}

impl Nl80211Socket {
    fn open() -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_GENERIC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to open NETLINK_GENERIC socket");
        }
        let enable: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_NETLINK,
                NETLINK_EXT_ACK,
                &enable as *const libc::c_int as *const libc::c_void,
                std::mem::size_of_val(&enable) as libc::socklen_t,
            );
        }
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_pid = 0;
        addr.nl_groups = 0;
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(error).context("failed to bind NETLINK_GENERIC socket");
        }
        let mut socket = Self { fd, family_id: 0 };
        let family_id = socket.resolve_family("nl80211")?;
        socket.family_id = family_id;
        Ok(socket)
    }

    fn resolve_family(&self, name: &str) -> Result<u16> {
        let mut payload = genl_payload(CTRL_CMD_GETFAMILY, 2);
        let mut name_bytes = name.as_bytes().to_vec();
        name_bytes.push(0);
        append_attr(&mut payload, CTRL_ATTR_FAMILY_NAME, &name_bytes);
        self.send_genl(GENL_ID_CTRL, libc::NLM_F_REQUEST as u16, 1, &payload)?;
        let response = self.recv_netlink()?;
        let attrs = genl_attrs(&response)?;
        for (kind, value) in attrs {
            if kind == CTRL_ATTR_FAMILY_ID && value.len() >= 2 {
                return Ok(u16::from_ne_bytes([value[0], value[1]]));
            }
        }
        bail!("nl80211 generic netlink family id not found")
    }

    fn register_dmesh_action(&self, ifindex: u32) -> Result<()> {
        let mut matches = vec![
            dmesh_vendor_action_header(RAW_WIFI_BROADCAST),
            dmesh_vendor_action_header(RAW_WIFI_MULTICAST),
        ];
        if let Some(iface) = ifname_from_ifindex(ifindex) {
            if let Ok(mac) = iface_mac(&iface) {
                matches.push(dmesh_vendor_action_header(mac));
                matches.push(dmesh_vendor_action_header(raw_receive_mac(mac)));
            }
        }
        let mut registered = 0;
        for frame_match in matches {
            match self.register_frame(ifindex, IEEE80211_ACTION_FRAME_TYPE, &frame_match) {
                Ok(()) => registered += 1,
                Err(error) if error.to_string().contains("Match already configured") => {}
                Err(error) if registered == 0 => return Err(error),
                Err(_) => {}
            }
        }
        Ok(())
    }

    fn register_nan_beacon(&self, ifindex: u32) -> Result<()> {
        // Beacon registration is deliberately separate from the action
        // filters. A NAN sync beacon is an ordinary management beacon, not a
        // public action frame, and must reach the shared NanState even while
        // the active monitor remains the NOW TX lane.
        self.register_frame(ifindex, 0x0080, &[])
    }

    /// Match raw-NAN USD frames while retaining the
    /// ESP-NOW/DMesh vendor-action registrations on the same nl80211 socket.
    fn register_open_ap_sme_frames(&self, ifindex: u32) -> Vec<Value> {
        // AP SME, NAN public, and DMesh/ESP-NOW vendor actions share this
        // nl80211 receive socket; the broad public/vendor matches cover all
        // of them without duplicate registrations.
        let registrations: [(&str, u16, &[u8]); 17] = [
            ("auth_open", 0x00b0, &[0x00, 0x00]),
            ("assoc_req", 0x0000, &[]),
            ("reassoc_req", 0x0020, &[]),
            ("disassoc", 0x00a0, &[]),
            ("deauth", 0x00c0, &[]),
            ("probe_req", 0x0040, &[]),
            // NAN discovery/beacon frames are ordinary management beacons;
            // receive them on the same AP-SME socket as AP management.
            ("beacon", 0x0080, &[]),
            ("action_public", IEEE80211_ACTION_FRAME_TYPE, &[0x04]),
            (
                "action_radio_measurement",
                IEEE80211_ACTION_FRAME_TYPE,
                &[0x05, 0x01],
            ),
            (
                "action_link_measurement",
                IEEE80211_ACTION_FRAME_TYPE,
                &[0x05, 0x03],
            ),
            (
                "action_neighbor_report",
                IEEE80211_ACTION_FRAME_TYPE,
                &[0x05, 0x04],
            ),
            (
                "action_fast_bss_transition",
                IEEE80211_ACTION_FRAME_TYPE,
                &[0x06],
            ),
            ("action_sa_query", IEEE80211_ACTION_FRAME_TYPE, &[0x08]),
            (
                "action_protected_dual",
                IEEE80211_ACTION_FRAME_TYPE,
                &[0x09],
            ),
            ("action_wnm", IEEE80211_ACTION_FRAME_TYPE, &[0x0a]),
            ("action_fils", IEEE80211_ACTION_FRAME_TYPE, &[0x11]),
            ("action_vendor", IEEE80211_ACTION_FRAME_TYPE, &[0x7f]),
        ];
        let mut reports = Vec::new();
        for (idx, (name, frame_type, frame_match)) in registrations.iter().enumerate() {
            match self.register_frame_with_seq(
                ifindex,
                *frame_type,
                frame_match,
                20_u32.saturating_add(idx as u32),
            ) {
                Ok(()) => reports.push(json!({
                    "name": name,
                    "ok": true,
                    "frame_type": format!("0x{frame_type:04x}"),
                    "match_hex": hex_bytes(frame_match),
                })),
                Err(error) if *name == "beacon" => reports.push(json!({
                    "name": name,
                    "ok": false,
                    "required": false,
                    "frame_type": format!("0x{frame_type:04x}"),
                    "match_hex": hex_bytes(frame_match),
                    "error": format!("{error:#}"),
                })),
                Err(error) if format!("{error:#}").contains("Operation already in progress") => {
                    reports.push(json!({
                        "name": name,
                        "ok": true,
                        "already_registered": true,
                        "frame_type": format!("0x{frame_type:04x}"),
                        "match_hex": hex_bytes(frame_match),
                    }))
                }
                Err(error) => reports.push(json!({
                    "name": name,
                    "ok": false,
                    "frame_type": format!("0x{frame_type:04x}"),
                    "match_hex": hex_bytes(frame_match),
                    "error": format!("{error:#}"),
                })),
            }
        }
        reports
    }

    fn register_frame(&self, ifindex: u32, frame_type: u16, frame_match: &[u8]) -> Result<()> {
        self.register_frame_with_seq(ifindex, frame_type, frame_match, 2)
    }

    fn register_frame_with_seq(
        &self,
        ifindex: u32,
        frame_type: u16,
        frame_match: &[u8],
        seq: u32,
    ) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_REGISTER_FRAME, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        append_attr(
            &mut payload,
            NL80211_ATTR_FRAME_TYPE,
            &frame_type.to_ne_bytes(),
        );
        append_attr(&mut payload, NL80211_ATTR_FRAME_MATCH, frame_match);
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            seq,
            &payload,
        )?;
        self.recv_ack()
    }

    fn remain_on_channel(&self, ifindex: u32, freq: u32, duration_ms: u32) -> Result<u64> {
        let mut payload = genl_payload(NL80211_CMD_REMAIN_ON_CHANNEL, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_WIPHY_FREQ, &freq.to_ne_bytes());
        append_attr(
            &mut payload,
            NL80211_ATTR_DURATION,
            &duration_ms.to_ne_bytes(),
        );
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            4,
            &payload,
        )?;
        let response = self
            .recv_reply()
            .context("nl80211 remain-on-channel failed")?;
        let cookie = genl_attrs(&response)?
            .into_iter()
            .find_map(|(kind, value)| {
                (kind & NLA_TYPE_MASK == NL80211_ATTR_COOKIE && value.len() >= 8)
                    .then(|| u64::from_ne_bytes(value[..8].try_into().unwrap()))
            })
            .ok_or_else(|| anyhow::anyhow!("nl80211 remain-on-channel returned no cookie"))?;
        let settle_ms = duration_ms.saturating_div(2).clamp(1, 20);
        std::thread::sleep(Duration::from_millis(settle_ms as u64));
        Ok(cookie)
    }

    fn set_interface_type(&self, ifindex: u32, iftype: u32) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_SET_INTERFACE, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_IFTYPE, &iftype.to_ne_bytes());
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            5,
            &payload,
        )?;
        self.recv_ack().context("nl80211 set interface type failed")
    }

    fn recv_reply(&self) -> Result<Vec<u8>> {
        loop {
            let response = self.recv_netlink_raw()?;
            if let Some(error) = netlink_error(&response) {
                bail!(
                    "netlink error: {}{}",
                    std::io::Error::from_raw_os_error(error),
                    netlink_extack_message(&response)
                );
            }
            if genl_header(&response).is_some() {
                return Ok(response);
            }
        }
    }

    fn set_channel_ht20(&self, ifindex: u32, freq: u32) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_SET_WIPHY, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_WIPHY_FREQ, &freq.to_ne_bytes());
        append_attr(
            &mut payload,
            NL80211_ATTR_WIPHY_CHANNEL_TYPE,
            &NL80211_CHAN_HT20.to_ne_bytes(),
        );
        append_attr(
            &mut payload,
            NL80211_ATTR_CHANNEL_WIDTH,
            &NL80211_CHAN_WIDTH_20.to_ne_bytes(),
        );
        append_attr(&mut payload, NL80211_ATTR_CENTER_FREQ1, &freq.to_ne_bytes());
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            16,
            &payload,
        )?;
        self.recv_ack().context("nl80211 set HT20 channel failed")
    }

    fn set_channel_ht40_plus(&self, ifindex: u32, freq: u32) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_SET_WIPHY, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_WIPHY_FREQ, &freq.to_ne_bytes());
        append_attr(
            &mut payload,
            NL80211_ATTR_WIPHY_CHANNEL_TYPE,
            &NL80211_CHAN_HT40PLUS.to_ne_bytes(),
        );
        append_attr(
            &mut payload,
            NL80211_ATTR_CHANNEL_WIDTH,
            &NL80211_CHAN_WIDTH_40.to_ne_bytes(),
        );
        append_attr(
            &mut payload,
            NL80211_ATTR_CENTER_FREQ1,
            &(freq + 10).to_ne_bytes(),
        );
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            16,
            &payload,
        )?;
        self.recv_ack().context("nl80211 set HT40+ channel failed")
    }

    /// Set the per-wiphy 2.4 GHz TX-rate allow-list. Legacy rates are encoded
    /// in 500-kbit/s units; HT rates are MCS indexes. Omitting both restores
    /// the driver's automatic rate policy.
    fn set_tx_rate_profile(
        &self,
        ifindex: u32,
        rate_mbps: Option<u8>,
        ht_mcs: Option<u8>,
        disable_b: bool,
    ) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_SET_TX_BITRATE_MASK, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        if let Some(band) = tx_rate_profile_band(rate_mbps, ht_mcs, disable_b) {
            let mut bands = Vec::new();
            append_attr(&mut bands, 1 << 15, &band); // NL80211_BAND_2GHZ | NLA_F_NESTED
            append_attr(&mut payload, NL80211_ATTR_TX_RATES | (1 << 15), &bands);
        }
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            17,
            &payload,
        )?;
        self.recv_ack()
            .context("nl80211 set TX rate profile failed")
    }

    fn set_power_save(&self, ifindex: u32, enabled: bool) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_SET_POWER_SAVE, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        let state = if enabled {
            NL80211_PS_ENABLED
        } else {
            NL80211_PS_DISABLED
        };
        append_attr(&mut payload, NL80211_ATTR_PS_STATE, &state.to_ne_bytes());
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            18,
            &payload,
        )?;
        self.recv_ack().context("nl80211 set power-save failed")
    }

    /// `NL80211_TX_POWER_LIMITED` is a ceiling in mBm.  It preserves the
    /// regulatory limit and is suitable for a near-field overload A/B;
    /// omitting the level selects `NL80211_TX_POWER_AUTOMATIC`.
    fn set_tx_power_limit(&self, ifindex: u32, dbm: Option<i16>) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_SET_WIPHY, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        let setting: u32 = if dbm.is_some() { 1 } else { 0 };
        append_attr(
            &mut payload,
            NL80211_ATTR_WIPHY_TX_POWER_SETTING,
            &setting.to_ne_bytes(),
        );
        if let Some(dbm) = dbm {
            let mbm = i32::from(dbm).saturating_mul(100);
            append_attr(
                &mut payload,
                NL80211_ATTR_WIPHY_TX_POWER_LEVEL,
                &mbm.to_ne_bytes(),
            );
        }
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            19,
            &payload,
        )?;
        self.recv_ack().context("nl80211 set TX power failed")
    }

    fn start_open_ap(
        &self,
        ifindex: u32,
        mac: [u8; 6],
        ssid: &str,
        channel: u8,
        freq: u32,
        ht40: bool,
        beacon_interval_tu: u16,
    ) -> std::result::Result<Value, (anyhow::Error, Vec<Value>)> {
        let esp_beacon_head =
            build_open_beacon_head(mac, ssid, channel).map_err(|error| (error, Vec::new()))?;
        let hostapd_beacon_head =
            build_open_beacon_head_with_capability(mac, ssid, channel, 0x0401)
                .map_err(|error| (error, Vec::new()))?;
        let esp_beacon_tail = esp_open_ap_beacon_tail(channel);
        let hostapd_beacon_tail = hostapd_open_ap_beacon_tail(channel, ht40);
        let esp_probe_resp =
            build_open_probe_resp(mac, ssid, channel).map_err(|error| (error, Vec::new()))?;
        let hostapd_probe_ies =
            hostapd_open_ap_probe_ies(ssid, channel, ht40).map_err(|error| (error, Vec::new()))?;
        let hostapd_probe_resp =
            build_open_probe_resp_with_ies(mac, ssid, channel, 0x0401, &hostapd_probe_ies)
                .map_err(|error| (error, Vec::new()))?;
        let profiles = [
            ApStartProfile {
                name: "hostapd_exact_ht",
                probe_resp: true,
                channel_type: if ht40 {
                    NL80211_CHAN_HT40PLUS
                } else {
                    NL80211_CHAN_HT20
                },
                channel_width: if ht40 {
                    NL80211_CHAN_WIDTH_40
                } else {
                    NL80211_CHAN_WIDTH_20
                },
                explicit_width: false,
                freq_fixed: false,
                hostapd_ies: true,
                hostapd_crypto: true,
                hostapd_tail: true,
                capability: 0x0401,
            },
            ApStartProfile {
                name: "hostapd_exact_noht",
                probe_resp: true,
                channel_type: NL80211_CHAN_NO_HT,
                channel_width: NL80211_CHAN_WIDTH_20_NOHT,
                explicit_width: false,
                freq_fixed: false,
                hostapd_ies: true,
                hostapd_crypto: true,
                hostapd_tail: true,
                capability: 0x0401,
            },
            ApStartProfile {
                name: "hostapd_noht",
                probe_resp: true,
                channel_type: NL80211_CHAN_NO_HT,
                channel_width: NL80211_CHAN_WIDTH_20_NOHT,
                explicit_width: false,
                freq_fixed: false,
                hostapd_ies: false,
                hostapd_crypto: false,
                hostapd_tail: false,
                capability: 0x0421,
            },
            ApStartProfile {
                name: "hostapd_noht_no_probe",
                probe_resp: false,
                channel_type: NL80211_CHAN_NO_HT,
                channel_width: NL80211_CHAN_WIDTH_20_NOHT,
                explicit_width: false,
                freq_fixed: false,
                hostapd_ies: false,
                hostapd_crypto: false,
                hostapd_tail: false,
                capability: 0x0421,
            },
            ApStartProfile {
                name: "esp_ht20",
                probe_resp: true,
                channel_type: NL80211_CHAN_HT20,
                channel_width: NL80211_CHAN_WIDTH_20,
                explicit_width: false,
                freq_fixed: false,
                hostapd_ies: false,
                hostapd_crypto: false,
                hostapd_tail: false,
                capability: 0x0421,
            },
            ApStartProfile {
                name: "esp_ht20_no_probe",
                probe_resp: false,
                channel_type: NL80211_CHAN_HT20,
                channel_width: NL80211_CHAN_WIDTH_20,
                explicit_width: false,
                freq_fixed: false,
                hostapd_ies: false,
                hostapd_crypto: false,
                hostapd_tail: false,
                capability: 0x0421,
            },
            ApStartProfile {
                name: "explicit_20_noht",
                probe_resp: true,
                channel_type: NL80211_CHAN_NO_HT,
                channel_width: NL80211_CHAN_WIDTH_20_NOHT,
                explicit_width: true,
                freq_fixed: true,
                hostapd_ies: false,
                hostapd_crypto: false,
                hostapd_tail: false,
                capability: 0x0421,
            },
            ApStartProfile {
                name: "explicit_20_ht",
                probe_resp: true,
                channel_type: NL80211_CHAN_HT20,
                channel_width: NL80211_CHAN_WIDTH_20,
                explicit_width: true,
                freq_fixed: true,
                hostapd_ies: false,
                hostapd_crypto: false,
                hostapd_tail: false,
                capability: 0x0421,
            },
        ];
        let mut attempts = Vec::new();
        let mut last_error = None;
        for (idx, profile) in profiles.iter().enumerate() {
            let mut payload = genl_payload(NL80211_CMD_START_AP, NL80211_GENL_VERSION);
            append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
            append_attr(&mut payload, NL80211_ATTR_WIPHY_FREQ, &freq.to_ne_bytes());
            append_attr(
                &mut payload,
                NL80211_ATTR_WIPHY_CHANNEL_TYPE,
                &profile.channel_type.to_ne_bytes(),
            );
            if profile.explicit_width {
                append_attr(
                    &mut payload,
                    NL80211_ATTR_CHANNEL_WIDTH,
                    &profile.channel_width.to_ne_bytes(),
                );
                append_attr(
                    &mut payload,
                    NL80211_ATTR_CENTER_FREQ1,
                    &(if ht40 { freq + 10 } else { freq }).to_ne_bytes(),
                );
            }
            if profile.freq_fixed {
                append_attr(&mut payload, NL80211_ATTR_FREQ_FIXED, &[]);
            }
            append_attr(
                &mut payload,
                NL80211_ATTR_BEACON_INTERVAL,
                &u32::from(beacon_interval_tu).to_ne_bytes(),
            );
            append_attr(&mut payload, NL80211_ATTR_DTIM_PERIOD, &1_u32.to_ne_bytes());
            let beacon_head = if profile.capability == 0x0401 {
                &hostapd_beacon_head
            } else {
                &esp_beacon_head
            };
            let beacon_tail = if profile.hostapd_tail {
                &hostapd_beacon_tail
            } else {
                &esp_beacon_tail
            };
            append_attr(&mut payload, NL80211_ATTR_BEACON_HEAD, beacon_head);
            append_attr(&mut payload, NL80211_ATTR_BEACON_TAIL, beacon_tail);
            if profile.probe_resp {
                let probe_resp = if profile.hostapd_tail {
                    &hostapd_probe_resp
                } else {
                    &esp_probe_resp
                };
                append_attr(&mut payload, NL80211_ATTR_PROBE_RESP, probe_resp);
            }
            if profile.hostapd_ies {
                let ies = hostapd_open_ap_extra_ies();
                append_attr(&mut payload, NL80211_ATTR_IE, &ies);
                append_attr(&mut payload, NL80211_ATTR_IE_PROBE_RESP, &ies);
                append_attr(&mut payload, NL80211_ATTR_IE_ASSOC_RESP, &ies);
                append_attr(
                    &mut payload,
                    NL80211_ATTR_BSS_HT_OPMODE,
                    &0_u16.to_ne_bytes(),
                );
            }
            append_attr(&mut payload, NL80211_ATTR_SSID, ssid.as_bytes());
            append_attr(
                &mut payload,
                NL80211_ATTR_HIDDEN_SSID,
                &NL80211_HIDDEN_SSID_NOT_IN_USE.to_ne_bytes(),
            );
            append_attr(
                &mut payload,
                NL80211_ATTR_AUTH_TYPE,
                &NL80211_AUTHTYPE_OPEN_SYSTEM.to_ne_bytes(),
            );
            append_attr(
                &mut payload,
                NL80211_ATTR_BSS_BASIC_RATES,
                open_ap_basic_rates(),
            );
            if profile.hostapd_crypto {
                append_attr(
                    &mut payload,
                    NL80211_ATTR_CIPHER_SUITE_GROUP,
                    &WLAN_CIPHER_SUITE_WEP40.to_ne_bytes(),
                );
            }
            append_attr(&mut payload, NL80211_ATTR_SOCKET_OWNER, &[]);
            let send = self.send_genl(
                self.family_id,
                (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
                6 + idx as u32,
                &payload,
            );
            let result = send.and_then(|_| self.recv_ack());
            match result {
                Ok(()) => {
                    attempts.push(json!({
                        "profile": profile.name,
                        "ok": true,
                        "probe_resp": profile.probe_resp,
                        "channel_type": profile.channel_type,
                        "channel_width": profile.channel_width,
                        "explicit_width": profile.explicit_width,
                        "freq_fixed": profile.freq_fixed,
                        "hostapd_ies": profile.hostapd_ies,
                        "hostapd_crypto": profile.hostapd_crypto,
                        "hostapd_tail": profile.hostapd_tail,
                        "capability": format!("0x{:04x}", profile.capability),
                        "beacon_head_len": beacon_head.len(),
                        "beacon_tail_len": beacon_tail.len(),
                    }));
                    return Ok(json!({
                        "selected": profile.name,
                        "attempts": attempts,
                    }));
                }
                Err(error) => {
                    let message = format!("{error:#}");
                    attempts.push(json!({
                        "profile": profile.name,
                        "ok": false,
                        "probe_resp": profile.probe_resp,
                        "channel_type": profile.channel_type,
                        "channel_width": profile.channel_width,
                        "explicit_width": profile.explicit_width,
                        "freq_fixed": profile.freq_fixed,
                        "hostapd_ies": profile.hostapd_ies,
                        "hostapd_crypto": profile.hostapd_crypto,
                        "hostapd_tail": profile.hostapd_tail,
                        "capability": format!("0x{:04x}", profile.capability),
                        "beacon_head_len": beacon_head.len(),
                        "beacon_tail_len": beacon_tail.len(),
                        "error": message,
                    }));
                    last_error = Some(error.context("nl80211 start open AP failed"));
                }
            }
        }
        Err((
            last_error.unwrap_or_else(|| anyhow::anyhow!("nl80211 start open AP had no profiles")),
            attempts,
        ))
    }

    fn stop_ap(&self, ifindex: u32) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_STOP_AP, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            7,
            &payload,
        )?;
        self.recv_ack().context("nl80211 stop AP failed")
    }

    fn flush_stations(&self, ifindex: u32) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_DEL_STATION, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            17,
            &payload,
        )?;
        self.recv_ack()
            .context("nl80211 flush station table failed")
    }

    fn remove_station(&self, ifindex: u32, mac: [u8; 6]) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_DEL_STATION, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_MAC, &mac);
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            18,
            &payload,
        )?;
        self.recv_ack().context("nl80211 remove station failed")
    }

    fn connect_open(&self, ifindex: u32, ssid: &str, freq: u32) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_CONNECT, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_SSID, ssid.as_bytes());
        append_attr(&mut payload, NL80211_ATTR_WIPHY_FREQ, &freq.to_ne_bytes());
        append_attr(
            &mut payload,
            NL80211_ATTR_AUTH_TYPE,
            &NL80211_AUTHTYPE_OPEN_SYSTEM.to_ne_bytes(),
        );
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            8,
            &payload,
        )?;
        self.recv_ack().context("nl80211 open STA connect failed")
    }

    fn station_dump(&self, ifindex: u32) -> Result<Vec<Value>> {
        let mut payload = genl_payload(NL80211_CMD_GET_STATION, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST as u16) | NLM_F_DUMP,
            9,
            &payload,
        )?;
        self.recv_station_dump()
            .context("nl80211 station dump failed")
    }

    fn add_station_minimal(&self, ifindex: u32, mac: [u8; 6], aid: u16) -> Result<()> {
        self.add_station(
            ifindex, mac, aid, None, None, None, None, None, false, false,
        )
    }

    fn add_station_from_assoc(
        &self,
        ifindex: u32,
        mac: [u8; 6],
        frame: &[u8],
        allow_ht: bool,
    ) -> Result<()> {
        let capability = read_u16_at(frame, IEEE80211_BODY);
        let listen_interval = read_u16_at(frame, IEEE80211_BODY + 2);
        let ies_offset = if frame_subtype(frame) == 2 {
            IEEE80211_BODY + 10
        } else {
            IEEE80211_BODY + 4
        };
        let ies = frame.get(ies_offset..).unwrap_or_default();
        let ht_capability = allow_ht.then(|| management_ie_bytes(ies, 45)).flatten();
        let extended_capability = management_ie_bytes(ies, 127);
        let mut supported_rates = Vec::with_capacity(16);
        if let Some(rates) = management_ie_bytes(ies, 1) {
            supported_rates.extend_from_slice(rates);
        }
        if let Some(rates) = management_ie_bytes(ies, 50) {
            supported_rates.extend_from_slice(rates);
        }
        let wme = management_ie_bytes(ies, 221)
            .is_some_and(|value| value.len() >= 4 && value[..4] == [0x00, 0x50, 0xf2, 0x02]);
        let short_preamble = capability.is_some_and(|value| value & (1 << 5) != 0);
        self.add_station(
            ifindex,
            mac,
            1,
            capability,
            listen_interval,
            ht_capability,
            extended_capability,
            (!supported_rates.is_empty()).then_some(supported_rates.as_slice()),
            wme,
            short_preamble,
        )
    }

    fn add_station(
        &self,
        ifindex: u32,
        mac: [u8; 6],
        aid: u16,
        capability: Option<u16>,
        listen_interval: Option<u16>,
        ht_capability: Option<&[u8]>,
        extended_capability: Option<&[u8]>,
        supported_rates: Option<&[u8]>,
        wme: bool,
        short_preamble: bool,
    ) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_NEW_STATION, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_MAC, &mac);
        append_attr(&mut payload, NL80211_ATTR_STA_AID, &aid.to_ne_bytes());
        append_attr(
            &mut payload,
            NL80211_ATTR_STA_LISTEN_INTERVAL,
            &listen_interval.unwrap_or(10).to_ne_bytes(),
        );
        append_attr(
            &mut payload,
            NL80211_ATTR_STA_SUPPORTED_RATES,
            supported_rates.unwrap_or(&OPEN_AP_OFDM_BASIC_RATES),
        );
        if let Some(capability) = capability {
            append_attr(
                &mut payload,
                NL80211_ATTR_STA_CAPABILITY,
                &capability.to_ne_bytes(),
            );
        }
        if let Some(ht_capability) = ht_capability.filter(|value| value.len() == 26) {
            append_attr(&mut payload, NL80211_ATTR_HT_CAPABILITY, ht_capability);
        }
        if let Some(extended_capability) = extended_capability {
            append_attr(
                &mut payload,
                NL80211_ATTR_STA_EXT_CAPABILITY,
                extended_capability,
            );
        }
        let mut station_flags = NL80211_STA_FLAG_AUTHORIZED
            | NL80211_STA_FLAG_AUTHENTICATED
            | NL80211_STA_FLAG_ASSOCIATED;
        if wme {
            station_flags |= NL80211_STA_FLAG_WME;
        }
        if short_preamble {
            station_flags |= NL80211_STA_FLAG_SHORT_PREAMBLE;
        }
        if wme {
            let mut wme_attributes = Vec::with_capacity(16);
            append_attr(&mut wme_attributes, 1, &[0]);
            append_attr(&mut wme_attributes, 2, &[0]);
            append_attr(
                &mut payload,
                NL80211_ATTR_STA_WME | (1 << 15),
                &wme_attributes,
            );
        }
        let mut flags_update = Vec::with_capacity(8);
        flags_update.extend_from_slice(&station_flags.to_ne_bytes());
        flags_update.extend_from_slice(&station_flags.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_STA_FLAGS2, &flags_update);
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            10,
            &payload,
        )?;
        self.recv_ack()
            .context("nl80211 add minimal station failed")
    }

    fn send_frame(
        &self,
        ifindex: u32,
        freq: u32,
        options: &RawWifiTxOptions,
        frame: &[u8],
        tx_rate_mbps: Option<u8>,
    ) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_FRAME, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        if options.include_freq {
            append_attr(&mut payload, NL80211_ATTR_WIPHY_FREQ, &freq.to_ne_bytes());
        }
        if let Some(duration_ms) = options.duration_ms {
            append_attr(
                &mut payload,
                NL80211_ATTR_DURATION,
                &duration_ms.to_ne_bytes(),
            );
        }
        append_attr(&mut payload, NL80211_ATTR_FRAME, frame);
        if options.offchannel_tx_ok {
            append_attr(&mut payload, NL80211_ATTR_OFFCHANNEL_TX_OK, &[]);
        }
        if options.dont_wait_for_ack {
            append_attr(&mut payload, NL80211_ATTR_DONT_WAIT_FOR_ACK, &[]);
        }
        if options.tx_no_cck_rate {
            append_attr(&mut payload, NL80211_ATTR_TX_NO_CCK_RATE, &[]);
        }
        if let Some(rate) = tx_rate_mbps {
            if !matches!(rate, 6 | 9 | 12 | 18 | 24 | 36 | 48 | 54) {
                bail!("unsupported per-frame legacy rate {rate} Mbps");
            }
            let mut band = Vec::new();
            append_attr(&mut band, 1, &[rate.saturating_mul(2)]); // TXRATE_LEGACY, 500 kbit/s units
            let mut bands = Vec::new();
            append_attr(&mut bands, 1 << 15, &band); // 2 GHz band, nested
            append_attr(&mut payload, NL80211_ATTR_TX_RATES | (1 << 15), &bands);
        }
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            3,
            &payload,
        )?;
        self.recv_ack().context("nl80211 frame TX failed")
    }

    fn send_mgmt_frame(&self, ifindex: u32, frame: &[u8], tx_rate_mbps: Option<u8>) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_FRAME, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        // The AP SME response is emitted while the phy is also carrying the
        // NAN monitor path.  Supplying the already-owned channel and a short
        // on-channel duration makes this an explicit managed-interface TX
        // request; mt76 otherwise intermittently returns ENOMEM for the
        // otherwise valid frame while it is draining monitor traffic.
        let freq = channel_to_freq(DEFAULT_RAW_WIFI_CHANNEL);
        append_attr(&mut payload, NL80211_ATTR_WIPHY_FREQ, &freq.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_DURATION, &100_u32.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_FRAME, frame);
        if let Some(rate) = tx_rate_mbps {
            if !matches!(rate, 6 | 9 | 12 | 18 | 24 | 36 | 48 | 54) {
                bail!("unsupported per-frame legacy rate {rate} Mbps");
            }
            let mut band = Vec::new();
            append_attr(&mut band, 1, &[rate.saturating_mul(2)]);
            let mut bands = Vec::new();
            append_attr(&mut bands, 1 << 15, &band);
            append_attr(&mut payload, NL80211_ATTR_TX_RATES | (1 << 15), &bands);
        }
        // Management TX is transiently rejected with ENOMEM when the driver
        // is draining a burst of NAN/raw frames. Auth/association responses
        // must not be lost in that window: retry the same bounded request so
        // an ESP STA can complete its open-AP handshake.
        for attempt in 0..20 {
            self.send_genl(
                self.family_id,
                (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
                18 + attempt,
                &payload,
            )?;
            match self.recv_ack() {
                Ok(()) => return Ok(()),
                Err(error)
                    if attempt < 19
                        && (error.to_string().contains("Out of memory")
                            || error.to_string().contains("os error 12")) =>
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => {
                    return Err(error).context("nl80211 management frame TX failed");
                }
            }
        }
        unreachable!()
    }

    fn recv_frame(&self) -> Result<Vec<u8>> {
        self.recv_frame_with_signal().map(|(frame, _)| frame)
    }

    fn recv_frame_with_signal(&self) -> Result<(Vec<u8>, Option<i32>)> {
        loop {
            let response = self.recv_netlink()?;
            let Some(header) = genl_header(&response) else {
                continue;
            };
            if header.cmd != NL80211_CMD_FRAME {
                continue;
            }
            let mut frame = None;
            let mut rx_signal_dbm = None;
            for (kind, value) in genl_attrs(&response)? {
                match kind {
                    NL80211_ATTR_FRAME => frame = Some(value.to_vec()),
                    NL80211_ATTR_RX_SIGNAL_DBM if value.len() >= 4 => {
                        rx_signal_dbm =
                            Some(i32::from_ne_bytes([value[0], value[1], value[2], value[3]]));
                    }
                    _ => {}
                }
            }
            if let Some(frame) = frame {
                return Ok((frame, rx_signal_dbm));
            }
        }
    }

    fn send_genl(&self, nlmsg_type: u16, flags: u16, seq: u32, payload: &[u8]) -> Result<()> {
        let header = libc::nlmsghdr {
            nlmsg_len: (std::mem::size_of::<libc::nlmsghdr>() + payload.len()) as u32,
            nlmsg_type,
            nlmsg_flags: flags,
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        };
        let mut request = Vec::with_capacity(header.nlmsg_len as usize);
        append_struct(&mut request, &header);
        request.extend_from_slice(payload);
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        kernel.nl_pid = 0;
        kernel.nl_groups = 0;
        let written = unsafe {
            libc::sendto(
                self.fd,
                request.as_ptr() as *const libc::c_void,
                request.len(),
                0,
                &kernel as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if written < 0 {
            let os_error = std::io::Error::last_os_error();
            bail!(
                "failed to send netlink request type={} len={} flags=0x{:x}: {}",
                nlmsg_type,
                request.len(),
                flags,
                os_error
            );
        }
        Ok(())
    }

    fn recv_netlink(&self) -> Result<Vec<u8>> {
        let buf = self.recv_netlink_raw()?;
        if let Some(error) = netlink_error(&buf) {
            bail!(
                "netlink error: {}{}",
                std::io::Error::from_raw_os_error(error),
                netlink_extack_message(&buf)
            );
        }
        Ok(buf)
    }

    fn recv_ack(&self) -> Result<()> {
        loop {
            let response = self.recv_netlink_raw()?;
            let mut offset = 0;
            while offset + std::mem::size_of::<libc::nlmsghdr>() <= response.len() {
                let header = unsafe {
                    std::ptr::read_unaligned(response[offset..].as_ptr() as *const libc::nlmsghdr)
                };
                let len = header.nlmsg_len as usize;
                if len < std::mem::size_of::<libc::nlmsghdr>() || offset + len > response.len() {
                    break;
                }
                let msg = &response[offset..offset + len];
                if header.nlmsg_type == NLMSG_ERROR {
                    if let Some(error) = netlink_error(msg) {
                        bail!(
                            "netlink error: {}{}",
                            std::io::Error::from_raw_os_error(error),
                            netlink_extack_message(msg)
                        );
                    }
                    if netlink_is_ack(msg) {
                        return Ok(());
                    }
                }
                offset += nlmsg_align(len);
            }
        }
    }

    fn recv_station_dump(&self) -> Result<Vec<Value>> {
        let mut stations = Vec::new();
        loop {
            let response = self.recv_netlink_raw()?;
            let mut offset = 0;
            while offset + std::mem::size_of::<libc::nlmsghdr>() <= response.len() {
                let header = unsafe {
                    std::ptr::read_unaligned(response[offset..].as_ptr() as *const libc::nlmsghdr)
                };
                let len = header.nlmsg_len as usize;
                if len < std::mem::size_of::<libc::nlmsghdr>() || offset + len > response.len() {
                    break;
                }
                let msg = &response[offset..offset + len];
                if header.nlmsg_type == libc::NLMSG_DONE as u16 {
                    return Ok(stations);
                }
                if header.nlmsg_type == NLMSG_ERROR {
                    if let Some(error) = netlink_error(msg) {
                        bail!(
                            "netlink error: {}{}",
                            std::io::Error::from_raw_os_error(error),
                            netlink_extack_message(msg)
                        );
                    }
                } else if header.nlmsg_type == self.family_id {
                    stations.push(parse_station_dump_message(msg)?);
                }
                offset += nlmsg_align(len);
            }
        }
    }

    fn recv_netlink_raw(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0_u8; 65536];
        // Requests are sent with sendto() on an unconnected generic-netlink
        // socket. Use recvfrom() symmetrically; recv() returns ENOTCONN on
        // kernels that do not implicitly connect AF_NETLINK sockets.
        let mut peer: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut peer_len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        let read = unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut peer as *mut libc::sockaddr_nl as *mut libc::sockaddr,
                &mut peer_len,
            )
        };
        if read < 0 {
            return Err(std::io::Error::last_os_error()).context("failed to receive netlink reply");
        }
        buf.truncate(read as usize);
        Ok(buf)
    }

    fn set_receive_timeout(&self, timeout: Duration) -> Result<()> {
        let micros = timeout.as_micros().min(i64::MAX as u128) as i64;
        let value = libc::timeval {
            tv_sec: micros / 1_000_000,
            tv_usec: micros % 1_000_000,
        };
        let result = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &value as *const libc::timeval as *const libc::c_void,
                std::mem::size_of_val(&value) as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to set nl80211 receive timeout");
        }
        Ok(())
    }
}

impl Drop for Nl80211Socket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

struct MonitorTxSocket {
    fd: RawFd,
}

struct MonitorRxSocket {
    fd: RawFd,
}

struct DataSocket {
    fd: RawFd,
    ifindex: u32,
}

#[repr(C)]
struct PacketMreq {
    mr_ifindex: libc::c_int,
    mr_type: libc::c_ushort,
    mr_alen: libc::c_ushort,
    mr_address: [libc::c_uchar; 8],
}

impl MonitorTxSocket {
    fn open(iface: &str) -> Result<Self> {
        let ifindex = ifindex(iface)?;
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                (ETH_P_ALL.to_be()) as i32,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to open AF_PACKET raw socket for monitor TX");
        }
        let addr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as libc::sa_family_t,
            sll_protocol: ETH_P_ALL.to_be(),
            sll_ifindex: ifindex as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(error).with_context(|| format!("failed to bind AF_PACKET to {iface}"));
        }
        Ok(Self { fd })
    }

    fn send(&self, packet: &[u8]) -> Result<usize> {
        // The monitor socket is already bound to its VIF and protocol.  Use
        // the connected-style write rather than a destination-less sendto:
        // mt7921u accepts the latter locally without placing the radiotap
        // packet on the driver TX queue.
        let written = unsafe {
            libc::send(
                self.fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
            )
        };
        if written < 0 {
            Err(std::io::Error::last_os_error()).context("failed to send monitor frame")
        } else {
            Ok(written as usize)
        }
    }
}

impl MonitorRxSocket {
    fn open(iface: &str) -> Result<Self> {
        let ifindex = ifindex(iface)?;
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                (ETH_P_ALL.to_be()) as i32,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to open AF_PACKET raw socket for monitor RX");
        }
        let addr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as libc::sa_family_t,
            sll_protocol: ETH_P_ALL.to_be(),
            sll_ifindex: ifindex as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(error).with_context(|| format!("failed to bind AF_PACKET to {iface}"));
        }
        // Bursty action responses can arrive while the callback is parsing
        // and re-encoding a QUIC datagram. Increase the kernel receive queue
        // so a short userspace scheduling delay is measured as QUIC loss only
        // when the RF frame was actually missed, not as AF_PACKET overflow.
        let receive_buffer: libc::c_int = 1 << 20;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &receive_buffer as *const libc::c_int as *const libc::c_void,
                std::mem::size_of_val(&receive_buffer) as libc::socklen_t,
            );
        }
        Ok(Self { fd })
    }

    fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read =
            unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if read < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(read as usize)
        }
    }

    fn set_receive_timeout(&self, timeout: Duration) -> Result<()> {
        let micros = timeout.as_micros().min(i64::MAX as u128) as i64;
        let value = libc::timeval {
            tv_sec: micros / 1_000_000,
            tv_usec: micros % 1_000_000,
        };
        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &value as *const libc::timeval as *const libc::c_void,
                std::mem::size_of_val(&value) as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to set monitor RX timeout");
        }
        Ok(())
    }

    fn recv_timeout(&self, buf: &mut [u8], timeout: Duration) -> Result<Option<usize>> {
        let millis = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
        let mut pollfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pollfd, 1, millis) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error()).context("poll monitor RX socket failed");
        }
        if rc == 0 {
            return Ok(None);
        }
        self.recv(buf)
            .map(Some)
            .context("recv monitor RX socket failed")
    }
}

impl DataSocket {
    fn open(iface: &str) -> Result<Self> {
        let ifindex = ifindex(iface)?;
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                (ETH_P_ALL.to_be()) as i32,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to open AF_PACKET raw socket for data path");
        }
        let addr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as libc::sa_family_t,
            sll_protocol: ETH_P_ALL.to_be(),
            sll_ifindex: ifindex as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(error).with_context(|| format!("failed to bind AF_PACKET to {iface}"));
        }
        Ok(Self { fd, ifindex })
    }

    fn add_multicast(&self, address: [u8; 6]) -> Result<()> {
        let mut mreq = PacketMreq {
            mr_ifindex: self.ifindex as libc::c_int,
            mr_type: PACKET_MR_MULTICAST,
            mr_alen: 6,
            mr_address: [0; 8],
        };
        mreq.mr_address[..6].copy_from_slice(&address);
        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                PACKET_ADD_MEMBERSHIP,
                &mreq as *const PacketMreq as *const libc::c_void,
                std::mem::size_of::<PacketMreq>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!("failed to add packet multicast {}", colon_mac(&address))
            });
        }
        Ok(())
    }

    fn send(&self, packet: &[u8]) -> Result<usize> {
        let written = unsafe {
            libc::send(
                self.fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
            )
        };
        if written < 0 {
            Err(std::io::Error::last_os_error()).context("failed to send data frame")
        } else {
            Ok(written as usize)
        }
    }

    fn recv_timeout(&self, buf: &mut [u8], timeout: Duration) -> Result<Option<usize>> {
        let millis = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
        let mut pollfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pollfd, 1, millis) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error()).context("poll data RX socket failed");
        }
        if rc == 0 {
            return Ok(None);
        }
        let read =
            unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if read < 0 {
            Err(std::io::Error::last_os_error()).context("recv data RX socket failed")
        } else {
            Ok(Some(read as usize))
        }
    }
}

impl Drop for MonitorTxSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

impl Drop for MonitorRxSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

impl Drop for DataSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

fn send_monitor_frame(
    iface: &str,
    channel: u8,
    frame: &[u8],
    tx_rate_mbps: Option<u8>,
) -> Result<Value> {
    let monitor_iface = monitor_iface_name(iface);
    // NAN receive and NOW TX use one service-owned monitor fixture. A packet
    // send must not replace it: that used to turn a working broad NAN receive
    // setup into a TX-only active monitor, and it made a test request alter
    // host radio state. Service startup owns the one-time fixture setup.
    let setup = require_existing_monitor_iface(&monitor_iface)?;
    let packet = build_radiotap_packet_at_rate(frame, tx_rate_mbps)?;
    let socket = MonitorTxSocket::open(&monitor_iface)?;
    let written = socket.send(&packet)?;
    if written != packet.len() {
        bail!(
            "short monitor frame write: wrote {written}, expected {}",
            packet.len()
        );
    }
    Ok(json!({
        "iface": monitor_iface,
        "channel": channel,
        "packet_len": packet.len(),
        "setup": setup,
    }))
}

fn ensure_monitor_iface(
    base_iface: &str,
    monitor_iface: &str,
    channel: u8,
    active: bool,
    recreate: bool,
    exclusive_phy: bool,
) -> Result<Value> {
    // Public raw-radio calls may name either the owned base (`wlan0`) or its
    // conventional monitor child (`wlan0mon`).  A monitor cannot create or
    // own another monitor VIF, so always perform VIF lifecycle operations on
    // the base in the latter case.
    let base_iface = base_iface.strip_suffix("mon").unwrap_or(base_iface);
    // `send_monitor_frame` is on the packet path. Once the listener/client
    // has prepared the VIF, repeating `ip`/`iw` setup for every response adds
    // hundreds of milliseconds and can itself perturb the radio. Reuse the
    // existing VIF for the non-recreate path; explicit active-mode startup
    // still takes the full lifecycle below when the caller requested it.
    if !recreate && ifindex(monitor_iface).is_ok() {
        return Ok(json!({
            "iface": monitor_iface,
            "reused": true,
            "channel": channel,
            "active": true,
        }));
    }
    let mut steps = Vec::new();
    // A monitor VIF can exist while its parent is administratively down. For
    // active raw-NAN operation the dedicated radio must be owned by monitor
    // mode: leaving the managed parent up makes channel selection succeed only
    // nominally and packets are looped back to AF_PACKET without reaching RF.
    // An active monitor must own the PHY.  In particular, do not bring the
    // managed parent up before replacing a passive monitor: mac80211 then
    // keeps the old VIF busy and AF_PACKET reports a successful local write
    // without an RF transmit.  Take the parent down first, replace the VIF,
    // then bring only the active monitor up.
    if active && recreate && exclusive_phy {
        steps.push(run_command("ip", &["link", "set", base_iface, "down"]));
    } else {
        steps.push(run_command("ip", &["link", "set", base_iface, "up"]));
    }
    if recreate && ifindex(monitor_iface).is_ok() {
        steps.push(run_command("ip", &["link", "set", monitor_iface, "down"]));
        steps.push(run_command("iw", &["dev", monitor_iface, "del"]));
    }
    if ifindex(monitor_iface).is_err() {
        let mut add_args = vec![
            "dev",
            base_iface,
            "interface",
            "add",
            monitor_iface,
            "type",
            "monitor",
        ];
        if active {
            // The permanent NOW VIF must remain active for real RF TX, but it
            // must also receive NAN SDFs sent to the NAN discovery address
            // and a foreign cluster BSSID. `otherbss` admits that management
            // traffic without dropping the active flag (and without changing
            // radio state during individual tests).
            // `control` is required on the host adapters that previously
            // delivered foreign NAN beacons only through the broad passive
            // monitor setup. Keep the complete receive flag set on the
            // permanent active fixture: it is also the NOW TX interface.
            add_args.extend(["flags", "active", "fcsfail", "control", "otherbss"]);
        } else {
            // A passive monitor otherwise commonly filters foreign BSS
            // traffic. Raw NAN/NOW targets other BSSIDs, so retain the broad
            // receive flags for the peer capture path.
            add_args.extend(["flags", "fcsfail", "control", "otherbss"]);
        }
        steps.push(run_command("iw", &add_args));
    }
    steps.push(run_command("ip", &["link", "set", monitor_iface, "up"]));
    if active && !recreate && exclusive_phy {
        steps.push(run_command("ip", &["link", "set", base_iface, "down"]));
    }
    let channel_step = run_command(
        "iw",
        &["dev", monitor_iface, "set", "channel", &channel.to_string()],
    );
    let channel_busy = !channel_step
        .get("ok")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && channel_step
            .get("stderr")
            .and_then(Value::as_str)
            .map(|stderr| stderr.contains("Device or resource busy"))
            .unwrap_or(false);
    steps.push(channel_step);
    if channel_busy {
        steps.push(json!({
            "program": "iw",
            "args": ["dev", monitor_iface, "set", "channel", channel.to_string()],
            "ok": true,
            "skipped": true,
            "reason": "base interface owns the channel; monitor follows it",
        }));
    }
    // The managed parent is deliberately down for an active monitor.  Pin the
    // final monitor VIF through nl80211 as well: several USB drivers accept
    // the earlier parent-VIF channel request but leave the newly-created
    // monitor with no operational channel and silently consume AF_PACKET TX.
    let monitor_channel = ifindex(monitor_iface).and_then(|ifindex| {
        let socket = Nl80211Socket::open()?;
        socket.set_channel_ht20(ifindex, channel_to_freq(channel))
    });
    steps.push(match monitor_channel {
        Ok(()) => json!({
            "program": "nl80211",
            "operation": "set_channel_ht20",
            "iface": monitor_iface,
            "channel": channel,
            "ok": true,
        }),
        Err(error) => json!({
            "program": "nl80211",
            "operation": "set_channel_ht20",
            "iface": monitor_iface,
            "channel": channel,
            "ok": false,
            "error": format!("{error:#}"),
        }),
    });
    let channel_ok = steps.iter().any(|step| {
        step.get("ok").and_then(Value::as_bool).unwrap_or(false)
            && step
                .get("args")
                .and_then(Value::as_array)
                .map(|args| args.iter().any(|arg| arg.as_str() == Some("channel")))
                .unwrap_or(false)
    });
    let failed = steps
        .iter()
        .filter(|step| {
            if step.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                return false;
            }
            let is_channel_busy = step
                .get("args")
                .and_then(Value::as_array)
                .map(|args| args.iter().any(|arg| arg.as_str() == Some("channel")))
                .unwrap_or(false)
                && step
                    .get("stderr")
                    .and_then(Value::as_str)
                    .map(|stderr| stderr.contains("Device or resource busy"))
                    .unwrap_or(false);
            if is_channel_busy && channel_ok {
                return false;
            }
            true
        })
        .cloned()
        .collect::<Vec<_>>();
    if !failed.is_empty() {
        bail!(
            "failed to prepare monitor interface {monitor_iface}: {}",
            json!(failed)
        );
    }
    Ok(json!(steps))
}

/// Test-facing monitor users may only consume the persistent fixture.  Radio
/// setup is deliberately kept out of this helper so a listener/check/iperf
/// request cannot disturb a live AP or make a passive local loopback appear
/// to be an RF result.
fn require_existing_monitor_iface(monitor_iface: &str) -> Result<Value> {
    ifindex(monitor_iface)?;
    Ok(json!({
        "iface": monitor_iface,
        "reused": true,
        "lifecycle": "externally_prepared",
    }))
}

fn run_command(program: &str, args: &[&str]) -> Value {
    match Command::new(program).args(args).output() {
        Ok(output) => json!({
            "program": program,
            "args": args,
            "ok": output.status.success(),
            "status": output.status.code(),
            "stdout": String::from_utf8_lossy(&output.stdout).trim(),
            "stderr": String::from_utf8_lossy(&output.stderr).trim(),
        }),
        Err(error) => json!({
            "program": program,
            "args": args,
            "ok": false,
            "error": error.to_string(),
        }),
    }
}

fn command_output_timeout(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> std::io::Result<std::process::Output> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let start = std::time::Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return child.wait_with_output();
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            return child.wait_with_output();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn build_radiotap_packet(frame: &[u8]) -> Vec<u8> {
    // Keep the explicit legacy rate used by the original working lmesh NAN
    // injector. Some monitor drivers accept the AF_PACKET write but do not
    // put a TX_FLAGS-only packet on the air.
    build_radiotap_packet_at_rate(frame, None).expect("default radiotap rate is valid")
}

/// Return true for NAN beacons and NAN public action frames.  NAN uses the
/// Wi-Fi Alliance OUI in address3 (the cluster BSSID); ordinary AP beacons and
/// unrelated public actions must retain the caller/driver rate policy.
fn is_nan_control_frame(frame: &[u8]) -> bool {
    frame.len() >= 24
        && frame_type(frame) == 0
        && matches!(frame_subtype(frame), 8 | 13)
        && frame[16..19] == [0x50, 0x6f, 0x9a]
}

fn build_radiotap_packet_at_rate(frame: &[u8], rate_mbps: Option<u8>) -> Result<Vec<u8>> {
    build_radiotap_packet_at_rate_with_ack(frame, rate_mbps, false)
}

fn build_radiotap_packet_at_rate_with_ack(
    frame: &[u8],
    rate_mbps: Option<u8>,
    request_ack: bool,
) -> Result<Vec<u8>> {
    let rate_mbps = rate_mbps.unwrap_or(1);
    if !matches!(
        rate_mbps,
        1 | 2 | 5 | 6 | 9 | 11 | 12 | 18 | 24 | 36 | 48 | 54
    ) {
        bail!("unsupported radiotap legacy rate {rate_mbps} Mbps");
    }
    let mut packet = Vec::with_capacity(12 + frame.len());
    packet.extend_from_slice(&[
        0x00,
        0x00, // radiotap version, pad
        0x0c,
        0x00, // radiotap length
        0x04,
        0x80,
        0x00,
        0x00,                        // present: RATE and TX_FLAGS
        rate_mbps.saturating_mul(2), // RATE in 500 kbps units
        0x00,                        // pad TX_FLAGS to u16 alignment
        if request_ack { 0x00 } else { 0x08 },
        0x00, // TX_FLAGS: request MAC ACK for unicast, no ACK for broadcast
    ]);
    packet.extend_from_slice(frame);
    Ok(packet)
}

fn genl_payload(cmd: u8, version: u8) -> Vec<u8> {
    let mut payload = Vec::new();
    append_struct(
        &mut payload,
        &GenlMsgHdr {
            cmd,
            version,
            reserved: 0,
        },
    );
    payload
}

fn append_attr(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let len = std::mem::size_of::<NlAttrHdr>() + value.len();
    append_struct(
        out,
        &NlAttrHdr {
            nla_len: len as u16,
            nla_type: kind,
        },
    );
    out.extend_from_slice(value);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

fn netlink_payload(response: &[u8]) -> Result<&[u8]> {
    if response.len() < std::mem::size_of::<libc::nlmsghdr>() {
        bail!("short netlink message");
    }
    let header = unsafe { std::ptr::read_unaligned(response.as_ptr() as *const libc::nlmsghdr) };
    let len = header.nlmsg_len as usize;
    if len < std::mem::size_of::<libc::nlmsghdr>() || len > response.len() {
        bail!("invalid netlink message length {len}");
    }
    Ok(&response[std::mem::size_of::<libc::nlmsghdr>()..len])
}

fn genl_header(response: &[u8]) -> Option<GenlMsgHdr> {
    let payload = netlink_payload(response).ok()?;
    if payload.len() < std::mem::size_of::<GenlMsgHdr>() {
        return None;
    }
    Some(unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const GenlMsgHdr) })
}

fn genl_attrs(response: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let payload = netlink_payload(response)?;
    if payload.len() < std::mem::size_of::<GenlMsgHdr>() {
        bail!("short generic netlink message");
    }
    parse_attrs(&payload[std::mem::size_of::<GenlMsgHdr>()..])
}

fn parse_station_dump_message(response: &[u8]) -> Result<Value> {
    let mut mac = None;
    let mut station_info = Vec::new();
    for (kind, value) in genl_attrs(response)? {
        match kind & NLA_TYPE_MASK {
            NL80211_ATTR_MAC if value.len() >= 6 => {
                let mut station_mac = [0_u8; 6];
                station_mac.copy_from_slice(&value[..6]);
                mac = Some(colon_mac(&station_mac));
            }
            NL80211_ATTR_STA_INFO => station_info = parse_attrs(value)?,
            _ => {}
        }
    }
    let mut out = serde_json::Map::new();
    if let Some(mac) = mac {
        out.insert("mac".to_string(), Value::String(mac));
    }
    for (kind, value) in station_info {
        match kind & NLA_TYPE_MASK {
            NL80211_STA_INFO_INACTIVE_TIME => {
                insert_u32(&mut out, "inactive_ms", value);
            }
            NL80211_STA_INFO_RX_BYTES => {
                insert_u32(&mut out, "rx_bytes", value);
            }
            NL80211_STA_INFO_TX_BYTES => {
                insert_u32(&mut out, "tx_bytes", value);
            }
            NL80211_STA_INFO_SIGNAL => {
                if let Some(signal) = value.first() {
                    out.insert("signal_dbm".to_string(), json!(*signal as i8));
                }
            }
            NL80211_STA_INFO_RX_PACKETS => {
                insert_u32(&mut out, "rx_packets", value);
            }
            NL80211_STA_INFO_TX_PACKETS => {
                insert_u32(&mut out, "tx_packets", value);
            }
            NL80211_STA_INFO_TX_RETRIES => {
                insert_u32(&mut out, "tx_retries", value);
            }
            NL80211_STA_INFO_TX_FAILED => {
                insert_u32(&mut out, "tx_failed", value);
            }
            NL80211_STA_INFO_SIGNAL_AVG => {
                if let Some(signal) = value.first() {
                    out.insert("signal_avg_dbm".to_string(), json!(*signal as i8));
                }
            }
            NL80211_STA_INFO_TX_BITRATE => {
                if let Ok(rate_attributes) = parse_attrs(value) {
                    insert_station_rate_info(&mut out, "tx", &rate_attributes);
                }
            }
            NL80211_STA_INFO_RX_BITRATE => {
                if let Ok(rate_attributes) = parse_attrs(value) {
                    insert_station_rate_info(&mut out, "rx", &rate_attributes);
                }
            }
            NL80211_STA_INFO_CONNECTED_TIME => {
                insert_u32(&mut out, "connected_sec", value);
            }
            NL80211_STA_INFO_STA_FLAGS if value.len() >= 8 => {
                let mask = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
                let set = u32::from_ne_bytes([value[4], value[5], value[6], value[7]]);
                out.insert("wmm".to_string(), json!(set & NL80211_STA_FLAG_WME != 0));
                out.insert(
                    "authorized".to_string(),
                    json!(set & NL80211_STA_FLAG_AUTHORIZED != 0),
                );
                out.insert("station_flags_mask".to_string(), json!(mask));
            }
            NL80211_STA_INFO_RX_BYTES64 => {
                insert_u64(&mut out, "rx_bytes", value);
            }
            NL80211_STA_INFO_TX_BYTES64 => {
                insert_u64(&mut out, "tx_bytes", value);
            }
            // These driver-maintained aggregates explain why application
            // goodput can be far below the last selected MCS.  They are
            // intentionally reported only by the command-rate AP status
            // endpoint, never from a packet hot path.
            NL80211_STA_INFO_EXPECTED_THROUGHPUT => {
                insert_u32(&mut out, "expected_throughput_kbit_s", value);
            }
            NL80211_STA_INFO_RX_DROP_MISC => {
                insert_u64(&mut out, "rx_drop_misc", value);
            }
            NL80211_STA_INFO_RX_DURATION => {
                insert_u64(&mut out, "rx_airtime_us", value);
            }
            NL80211_STA_INFO_ACK_SIGNAL => {
                if let Some(signal) = value.first() {
                    out.insert("ack_signal_dbm".to_string(), json!(*signal as i8));
                }
            }
            NL80211_STA_INFO_ACK_SIGNAL_AVG => {
                if let Some(signal) = value.first() {
                    out.insert("ack_signal_avg_dbm".to_string(), json!(*signal as i8));
                }
            }
            NL80211_STA_INFO_RX_MPDUS => {
                insert_u32(&mut out, "rx_mpdus", value);
            }
            NL80211_STA_INFO_FCS_ERROR_COUNT => {
                insert_u32(&mut out, "rx_fcs_errors", value);
            }
            NL80211_STA_INFO_TX_DURATION => {
                insert_u64(&mut out, "tx_airtime_us", value);
            }
            _ => {}
        }
    }
    Ok(Value::Object(out))
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

/// Preserve PHY metadata alongside the calculated rate.  A value such as
/// 26 Mbps is ambiguous on its own: it can be legacy or HT MCS 3.  Exposing
/// this in the stable AP status avoids using a legacy-rate assumption to tune
/// the Recovery data path.
fn insert_station_rate_info(
    out: &mut serde_json::Map<String, Value>,
    direction: &str,
    attributes: &[(u16, &[u8])],
) {
    let attr = |kind| {
        attributes
            .iter()
            .find(|(attribute_kind, _)| *attribute_kind & NLA_TYPE_MASK == kind)
            .map(|(_, value)| *value)
    };
    let bitrate = attr(NL80211_RATE_INFO_BITRATE32)
        .filter(|value| value.len() >= 4)
        .map(|value| u32::from_ne_bytes([value[0], value[1], value[2], value[3]]) * 100)
        .or_else(|| {
            attr(NL80211_RATE_INFO_BITRATE)
                .filter(|value| value.len() >= 2)
                .map(|value| u16::from_ne_bytes([value[0], value[1]]) as u32 * 100)
        });
    if let Some(bitrate) = bitrate {
        out.insert(format!("{direction}_bitrate_kbit_s"), json!(bitrate));
    }
    if let Some(mcs) = attr(NL80211_RATE_INFO_MCS).and_then(|value| value.first()) {
        out.insert(format!("{direction}_phy"), json!("ht"));
        out.insert(format!("{direction}_mcs"), json!(*mcs));
        out.insert(
            format!("{direction}_width_mhz"),
            json!(if attr(NL80211_RATE_INFO_40_MHZ_WIDTH).is_some() {
                40
            } else {
                20
            }),
        );
        out.insert(
            format!("{direction}_short_gi"),
            json!(attr(NL80211_RATE_INFO_SHORT_GI).is_some()),
        );
    } else if let (Some(mcs), Some(nss)) = (
        attr(NL80211_RATE_INFO_VHT_MCS).and_then(|value| value.first()),
        attr(NL80211_RATE_INFO_VHT_NSS).and_then(|value| value.first()),
    ) {
        out.insert(format!("{direction}_phy"), json!("vht"));
        out.insert(format!("{direction}_mcs"), json!(*mcs));
        out.insert(format!("{direction}_nss"), json!(*nss));
    }
}

fn insert_u32(out: &mut serde_json::Map<String, Value>, key: &str, value: &[u8]) {
    if value.len() >= 4 {
        out.insert(
            key.to_string(),
            json!(u32::from_ne_bytes([value[0], value[1], value[2], value[3]])),
        );
    }
}

fn insert_u64(out: &mut serde_json::Map<String, Value>, key: &str, value: &[u8]) {
    if value.len() >= 8 {
        out.insert(
            key.to_string(),
            json!(u64::from_ne_bytes([
                value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
            ])),
        );
    }
}

fn insert_u16_at(out: &mut serde_json::Map<String, Value>, key: &str, bytes: &[u8], offset: usize) {
    if let Some(value) = read_u16_at(bytes, offset) {
        out.insert(key.to_string(), json!(value));
    }
}

fn read_u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn parse_attrs(mut bytes: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut attrs = Vec::new();
    while bytes.len() >= std::mem::size_of::<NlAttrHdr>() {
        let header = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const NlAttrHdr) };
        let len = header.nla_len as usize;
        if len < std::mem::size_of::<NlAttrHdr>() || len > bytes.len() {
            break;
        }
        attrs.push((
            header.nla_type,
            &bytes[std::mem::size_of::<NlAttrHdr>()..len],
        ));
        let aligned = (len + 3) & !3;
        if aligned > bytes.len() {
            break;
        }
        bytes = &bytes[aligned..];
    }
    Ok(attrs)
}

fn netlink_error(response: &[u8]) -> Option<i32> {
    if response.len() < std::mem::size_of::<libc::nlmsghdr>() + 4 {
        return None;
    }
    let header = unsafe { std::ptr::read_unaligned(response.as_ptr() as *const libc::nlmsghdr) };
    if header.nlmsg_type != NLMSG_ERROR {
        return None;
    }
    let offset = std::mem::size_of::<libc::nlmsghdr>();
    let error = unsafe { std::ptr::read_unaligned(response[offset..].as_ptr() as *const i32) };
    (error < 0).then_some(-error)
}

fn netlink_extack_message(response: &[u8]) -> String {
    let Some(attrs) = netlink_extack_attrs(response) else {
        return String::new();
    };
    let mut details = Vec::new();
    for (kind, value) in attrs {
        match kind {
            NLMSGERR_ATTR_MSG => {
                let text = String::from_utf8_lossy(trim_nul(value)).trim().to_string();
                if !text.is_empty() {
                    details.push(format!("msg={text:?}"));
                }
            }
            NLMSGERR_ATTR_OFFS if value.len() >= 4 => {
                let offset = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
                details.push(format!("offset={offset}"));
            }
            NLMSGERR_ATTR_MISS_TYPE if value.len() >= 4 => {
                let attr = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
                details.push(format!("missing_attr={attr}"));
            }
            _ => {}
        }
    }
    if details.is_empty() {
        String::new()
    } else {
        format!(" ({})", details.join(", "))
    }
}

fn netlink_extack_attrs(response: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    let header_len = std::mem::size_of::<libc::nlmsghdr>();
    let error_len = std::mem::size_of::<i32>();
    if response.len() < header_len + error_len + header_len {
        return None;
    }
    let header = unsafe { std::ptr::read_unaligned(response.as_ptr() as *const libc::nlmsghdr) };
    if header.nlmsg_type != NLMSG_ERROR {
        return None;
    }
    let original_offset = header_len + error_len;
    let original = unsafe {
        std::ptr::read_unaligned(response[original_offset..].as_ptr() as *const libc::nlmsghdr)
    };
    let full_original_error_len = nlmsg_align(error_len + original.nlmsg_len as usize);
    let compact_error_len = nlmsg_align(error_len + header_len);
    for ext_offset in [
        header_len + full_original_error_len,
        header_len + compact_error_len,
    ] {
        if ext_offset < response.len()
            && let Ok(attrs) = parse_attrs(&response[ext_offset..])
            && !attrs.is_empty()
        {
            return Some(attrs);
        }
    }
    None
}

fn trim_nul(value: &[u8]) -> &[u8] {
    match value.iter().position(|byte| *byte == 0) {
        Some(pos) => &value[..pos],
        None => value,
    }
}

fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

fn netlink_is_ack(response: &[u8]) -> bool {
    if response.len() < std::mem::size_of::<libc::nlmsghdr>() + 4 {
        return false;
    }
    let header = unsafe { std::ptr::read_unaligned(response.as_ptr() as *const libc::nlmsghdr) };
    if header.nlmsg_type != NLMSG_ERROR {
        return false;
    }
    let offset = std::mem::size_of::<libc::nlmsghdr>();
    let error = unsafe { std::ptr::read_unaligned(response[offset..].as_ptr() as *const i32) };
    error == 0
}

fn nl80211_receive_loop(
    socket: Nl80211Socket,
    iface: &str,
    history: Arc<Mutex<VecDeque<RadioEvent>>>,
) {
    loop {
        match socket.recv_frame() {
            Ok(frame) => {
                if let Some(value) = parse_dmesh_vendor_action(&frame, iface) {
                    let message = mesh_message_from_raw_wifi(&value, iface);
                    push_radio_event(
                        &history,
                        RadioEvent {
                            ts_millis: now_millis(),
                            key: "wifi.raw.rx".to_string(),
                            source: iface.to_string(),
                            value,
                            message: Some(message),
                        },
                    );
                }
            }
            Err(error) => {
                push_radio_event(
                    &history,
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
fn nl80211_nan_beacon_receive_loop(
    socket: Nl80211Socket,
    iface: &str,
    history: Arc<Mutex<VecDeque<RadioEvent>>>,
    rawnan_state: Arc<Mutex<NanState>>,
) {
    let _ = socket.set_receive_timeout(Duration::from_millis(250));
    loop {
        match socket.recv_frame_with_signal() {
            Ok((frame, rx_signal_dbm)) => {
                if frame_subtype(&frame) != 8 {
                    continue;
                }
                if let Some(beacon) =
                    handle_beacon_frame(&frame, iface, rx_signal_dbm, &rawnan_state)
                {
                    push_radio_event(
                        &history,
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
            Err(error)
                if error
                    .to_string()
                    .contains("Resource temporarily unavailable") =>
            {
                continue;
            }
            Err(error) => {
                push_radio_event(
                    &history,
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

fn ap_mgmt_receive_loop(
    socket: Nl80211Socket,
    iface: &str,
    ifindex: u32,
    ap_mac: [u8; 6],
    history: Arc<Mutex<VecDeque<RadioEvent>>>,
    discovered_devices: Arc<Mutex<DiscoveredDeviceRegistry>>,
    rawnan_state: Arc<Mutex<NanState>>,
    active_nan_publish: Arc<Mutex<NanActivePublish>>,
    pending_nan_followups: Arc<Mutex<dmesh_rawnan::NanFollowupQueue>>,
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
                if frame_subtype(&frame) == 8 {
                    drain_active_nan_publish(
                        iface,
                        iface,
                        &history,
                        &rawnan_state,
                        &active_nan_publish,
                        |publish| send_monitor_frame(iface, channel, publish, Some(6)).map(|_| ()),
                    );
                    drain_pending_nan_followups(
                        iface,
                        iface,
                        &history,
                        &rawnan_state,
                        &pending_nan_followups,
                        |response| {
                            send_monitor_frame(iface, channel, response, Some(6)).map(|_| ())
                        },
                    );
                }
                if frame_subtype(&frame) == 13 {
                    if let Some(action) =
                        handle_action_frame(&frame, iface, rx_signal_dbm, &rawnan_state)
                        && let Some(object) = value.as_object_mut()
                    {
                        object.insert("action_frame".to_string(), action);
                    }
                    // The AP management socket may be the only receiver to
                    // see a host-generated SDF. Feed it through the same
                    // semantic event/follow-up path as monitor ingress;
                    // sending a response reuses the permanent monitor and
                    // never changes AP or interface state.
                    record_nan_discovery(
                        &frame,
                        iface,
                        iface,
                        &history,
                        &discovered_devices,
                        &rawnan_state,
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
                let mut message =
                    MeshMessage::new(mesh::message::KIND_EVENT, MeshMessageCodec::Text)
                        .field(FIELD_MEDIUM, "wifi")
                        .field(FIELD_RADIO_ID, "sta")
                        .field(FIELD_NODE, &source)
                        .field(FIELD_IFACE, iface)
                        .field(
                            FIELD_STATUS,
                            value.get("kind").and_then(Value::as_str).unwrap_or("mgmt"),
                        );
                if let Some(signal) = rx_signal_dbm {
                    message = message.field(FIELD_RSSI, signal.to_string());
                }
                let beacon_sync = (frame_subtype(&frame) == 8)
                    .then(|| value.get("beacon_sync").cloned())
                    .flatten();
                push_radio_event(
                    &history,
                    RadioEvent {
                        ts_millis: now_millis(),
                        key: "wifi.ap.mgmt".to_string(),
                        source: iface.to_string(),
                        value,
                        message: Some(message),
                    },
                );
                if dmesh_rawnan::is_nan_beacon(&frame) {
                    if let Some(beacon_sync) = beacon_sync {
                        push_radio_event(
                            &history,
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
                    &history,
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

/// Queue a bounded NAN payload until a beacon confirms that the selected DW
/// is open. `dmesh_rawnan` owns deduplication and replacement semantics;
/// this Wi-Fi adapter supplies the current timestamp and performs frame TX.
fn queue_nan_followup(
    pending: &Arc<Mutex<dmesh_rawnan::NanFollowupQueue>>,
    destination: [u8; 6],
    instance: u8,
    payload: Vec<u8>,
) -> bool {
    let mut queue = pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    !matches!(
        queue.enqueue(dmesh_rawnan::NanFollowupIntent {
            destination,
            instance,
            payload,
            queued_at_us: now_micros_u64(),
        }),
        dmesh_rawnan::NanFollowupEnqueue::Duplicate
    )
}

/// Send up to four queued active-subscribe responses during the current DW.
/// Both AP-SME and monitor ingress invoke this after a beacon, so a driver
/// that only exposes one of those receive paths still completes discovery.
fn drain_pending_nan_followups<F>(
    iface: &str,
    event_source: &str,
    history: &Arc<Mutex<VecDeque<RadioEvent>>>,
    rawnan_state: &Arc<Mutex<NanState>>,
    pending: &Arc<Mutex<dmesh_rawnan::NanFollowupQueue>>,
    mut send_followup: F,
) where
    F: FnMut(&[u8]) -> Result<()>,
{
    let now_us = now_micros_u64();
    let timing = rawnan_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .nan_sync_timing();
    let Some((last_beacon_us, _, _)) = timing else {
        return;
    };
    let dwell_age_us = now_us.saturating_sub(last_beacon_us);
    if !dmesh_rawnan::beacon_dwell_open(dwell_age_us) {
        return;
    }
    let bssid = rawnan_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .sync_bssid()
        .map(|mac| mac.0);
    let Ok(local) = iface_mac(iface) else {
        return;
    };
    let Some(bssid) = bssid else {
        return;
    };
    let queued = pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take_up_to(4);
    for item in queued {
        let age_us = now_us.saturating_sub(item.queued_at_us);
        let result = (|| {
            let frame = dmesh_rawnan::build_nan_followup_sdf(
                item.destination,
                local,
                bssid,
                dmesh_rawnan::DMESH_SERVICE_ID,
                item.instance,
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
                    "dwell_age_us": dwell_age_us,
                    "error": result.err().map(|error| format!("{error:#}")),
                }),
                message: None,
            },
        );
    }
}

/// Emit a configured active Publish only after a beacon has opened the
/// selected discovery window. The configuration stores Service Info rather
/// than an 802.11 frame, so every send uses the current MAC/BSSID and follows
/// an association or cluster transition safely.
fn drain_active_nan_publish<F>(
    iface: &str,
    event_source: &str,
    history: &Arc<Mutex<VecDeque<RadioEvent>>>,
    rawnan_state: &Arc<Mutex<NanState>>,
    active_publish: &Arc<Mutex<NanActivePublish>>,
    mut send_publish: F,
) where
    F: FnMut(&[u8]) -> Result<()>,
{
    let now_us = now_micros_u64();
    let timing = rawnan_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .nan_sync_timing();
    let Some((last_beacon_us, _, _)) = timing else {
        return;
    };
    let dwell_age_us = now_us.saturating_sub(last_beacon_us);
    if !dmesh_rawnan::beacon_dwell_open(dwell_age_us) {
        return;
    }
    let bssid = rawnan_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .sync_bssid()
        .map(|mac| mac.0);
    let Ok(local) = iface_mac(iface) else {
        return;
    };
    let Some(bssid) = bssid else {
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
        let frame = dmesh_rawnan::build_nan_publish_sdf(
            dmesh_rawnan::NAN_DISCOVERY_MAC,
            local,
            bssid,
            dmesh_rawnan::DMESH_SERVICE_ID,
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
                "dwell_age_us": dwell_age_us,
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
fn record_nan_discovery<F>(
    frame: &[u8],
    iface: &str,
    event_source: &str,
    history: &Arc<Mutex<VecDeque<RadioEvent>>>,
    discovered_devices: &Arc<Mutex<DiscoveredDeviceRegistry>>,
    rawnan_state: &Arc<Mutex<NanState>>,
    pending_nan_followups: &Arc<Mutex<dmesh_rawnan::NanFollowupQueue>>,
    followup_dedup: &mut FollowupDedup,
    mut send_followup: F,
) where
    F: FnMut(&[u8]) -> Result<()>,
{
    if frame_subtype(frame) != 13 {
        return;
    }
    let descriptors = dmesh_rawnan::service_descriptors(frame);
    let dmesh = descriptors
        .iter()
        .find(|item| item.service_id == dmesh_rawnan::DMESH_SERVICE_ID)
        .map(|item| item.descriptor);
    let announce = descriptors
        .iter()
        .filter_map(|item| dmesh_server::announce::decode_announce(item.descriptor.payload))
        .filter(|item| announce_identity_valid(*item))
        .find(|item| !is_placeholder_announce_id(item.device_id()));
    if let Some(announce) = announce
        && let Some(source) = mac_at(frame, IEEE80211_ADDR2)
    {
        let bssid = mac_at(frame, IEEE80211_ADDR3).map(|mac| colon_mac(&mac));
        discovered_devices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .observe_announce("nan", colon_mac(&source), bssid, announce);
    }
    let active_subscribe =
        dmesh_rawnan::active_subscribe_service_info(frame, dmesh_rawnan::DMESH_SERVICE_ID);
    if dmesh.is_none() && announce.is_none() && active_subscribe.is_none() {
        return;
    }
    let Some(descriptor) = dmesh.or_else(|| descriptors.first().map(|item| item.descriptor)) else {
        return;
    };
    let followup = dmesh.and_then(|item| dmesh_rawnan::parse_dmesh_nan_followup(item.payload));
    let duplicate = followup.as_ref().is_some_and(|item| {
        followup_dedup.is_duplicate(item.device_id, item.seq, item.msg_type, item.payload)
    });
    let now_us = now_micros_u64();
    let dw_open = rawnan_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .nan_sync_timing()
        .is_some_and(|(last_beacon_us, _tsf_us, _period_us)| {
            dmesh_rawnan::beacon_dwell_open(now_us.saturating_sub(last_beacon_us))
        });
    if let Some(subscription) = active_subscribe
        && let Some(peer) = mac_at(frame, IEEE80211_ADDR2)
        && let Some(bssid) = mac_at(frame, IEEE80211_ADDR3)
        && let Ok(local) = iface_mac(iface)
    {
        let result = dmesh_rawnan::build_dmesh_followup_payload(
            7,
            now_millis_u64() as u16,
            local,
            peer,
            subscription.service_info,
        )
        .and_then(|payload| {
            if dw_open {
                let response = dmesh_rawnan::build_nan_followup_sdf(
                    peer,
                    local,
                    bssid,
                    dmesh_rawnan::DMESH_SERVICE_ID,
                    subscription.instance,
                    &payload,
                );
                send_followup(&response)
            } else if queue_nan_followup(
                pending_nan_followups,
                peer,
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
                    "bytes": subscription.service_info.len(),
                    "error": result.err().map(|error| format!("{error:#}")),
                }),
                message: None,
            },
        );
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
                "announce": announce.map(|item| json!({
                    "kind": item.kind,
                    "device_id": hex_bytes(item.device_id()),
                    "uptime_secs": item.uptime_secs,
                    "transport_mode": item.transport_mode,
                    "counters": item.counters,
                })),
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
                "peer_availability": peer_availability_name(dmesh_rawnan::peer_availability(frame)),
                "service_id": hex_bytes(&dmesh_rawnan::DMESH_SERVICE_ID),
            }),
            message: None,
        },
    );
}

/// Classify every received 802.11 action frame in one place. AP management
/// responses remain handled by `handle_open_ap_sme_frame`; this function is
/// deliberately receive-only and covers NAN public/vendor actions and the
/// DMesh/ESP-NOW action marker without creating a second read loop.
fn handle_action_frame(
    frame: &[u8],
    iface: &str,
    rx_signal_dbm: Option<i32>,
    rawnan_state: &Arc<Mutex<NanState>>,
) -> Option<Value> {
    if frame_type(frame) != 0 || frame_subtype(frame) != 13 {
        return None;
    }
    let nan_kind = dmesh_rawnan::classify(frame);
    let nan_action = rawnan_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .observe(RawNanRxFrame {
            bytes: frame,
            rssi_dbm: rx_signal_dbm
                .unwrap_or(0)
                .clamp(i8::MIN as i32, i8::MAX as i32) as i8,
            timestamp_us: now_micros_u64(),
        });
    let source = mac_at(frame, IEEE80211_ADDR2).map(|mac| colon_mac(&mac));
    let destination = mac_at(frame, IEEE80211_ADDR1).map(|mac| colon_mac(&mac));
    let bssid = mac_at(frame, IEEE80211_ADDR3).map(|mac| colon_mac(&mac));
    let mut result = json!({
        "ok": true,
        "protocol": "80211_action",
        "iface": iface,
        "source": source,
        "destination": destination,
        "bssid": bssid,
        "frame_len": frame.len(),
        "category": frame.get(IEEE80211_BODY).copied(),
        "nan_kind": match nan_kind {
            dmesh_rawnan::FrameKind::Beacon => "beacon",
            dmesh_rawnan::FrameKind::Sdf => "service_discovery",
            dmesh_rawnan::FrameKind::Followup => "followup",
            dmesh_rawnan::FrameKind::Other => "other",
        },
        "nan_filter_action": match nan_action {
            RawNanAction::None => "none",
            RawNanAction::ArmA3(_) => "arm_a3",
            RawNanAction::DropForeign => "drop_foreign",
            RawNanAction::Rediscover => "rediscover",
        },
    });
    if let Some(signal) = rx_signal_dbm
        && let Some(object) = result.as_object_mut()
    {
        object.insert("rx_signal_dbm".to_string(), json!(signal));
    }
    if let Some(vendor) = parse_dmesh_wifi_frame(frame, iface, "linux_nl80211_ap_sme")
        && let Some(object) = result.as_object_mut()
    {
        object.insert("dmesh".to_string(), vendor);
    }
    Some(result)
}

/// A user-space AP must retire its nl80211 station entry when a peer leaves.
/// Auth/association are handled separately by `handle_open_ap_sme_frame`.
fn ap_sme_station_departed(subtype: u8) -> bool {
    matches!(subtype, 10 | 12)
}

fn handle_open_ap_sme_frame(
    socket: &Nl80211Socket,
    iface: &str,
    ifindex: u32,
    ap_mac: [u8; 6],
    frame: &[u8],
    ap_no_ht_stations: &Arc<Mutex<HashSet<[u8; 6]>>>,
    channel: u8,
    ht40: bool,
) -> Option<Value> {
    if frame_type(frame) != 0 {
        return None;
    }
    let sta_mac = mac_at(frame, IEEE80211_ADDR2)?;
    let subtype = frame_subtype(frame);
    let response = match subtype {
        11 => {
            if read_u16_at(frame, IEEE80211_BODY) != Some(NL80211_AUTHTYPE_OPEN_SYSTEM as u16) {
                return None;
            }
            let response = build_open_auth_response(ap_mac, sta_mac);
            let tx = send_open_ap_mgmt_response(socket, iface, ifindex, channel, &response);
            json!({
                "kind": "auth_resp",
                "association_attempt": true,
                "destination": colon_mac(&sta_mac),
                "frame_len": response.len(),
                "tx": tx,
            })
        }
        0 | 2 => {
            let aid = 1_u16;
            let allow_ht = !ap_no_ht_stations
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .contains(&sta_mac);
            let add_station = Nl80211Socket::open()
                .and_then(|socket| {
                    // A station entry can survive an ESP reset or a prior
                    // monitor-fallback association. Replace it before
                    // applying the new association parameters; otherwise
                    // mt76x2u accepts the response but sends reason-8
                    // disassociation about a second later.
                    let _ = socket.remove_station(ifindex, sta_mac);
                    socket.add_station_from_assoc(ifindex, sta_mac, frame, allow_ht)
                })
                .map(|_| json!({ "ok": true }))
                .unwrap_or_else(|error| json!({ "ok": false, "error": format!("{error:#}") }));
            let response = build_open_assoc_response(ap_mac, sta_mac, aid, allow_ht, channel, ht40);
            let tx = send_open_ap_mgmt_response(socket, iface, ifindex, channel, &response);
            json!({
                "kind": "assoc_resp",
                "association_attempt": true,
                "destination": colon_mac(&sta_mac),
                "aid": aid,
                "ht": allow_ht,
                "add_station": add_station,
                "frame_len": response.len(),
                "tx": tx,
            })
        }
        _ => return None,
    };
    Some(response)
}

fn send_open_ap_mgmt_response(
    socket: &Nl80211Socket,
    iface: &str,
    ifindex: u32,
    channel: u8,
    frame: &[u8],
) -> Value {
    match socket.send_mgmt_frame(ifindex, frame, None) {
        Ok(()) => json!({ "ok": true, "backend": "linux_nl80211" }),
        Err(error) => {
            // Some mac80211 drivers reject the minimal CMD_FRAME form while
            // an AP SME is active, but accept the fully-qualified on-channel
            // form used by the normal raw TX path. Try that before falling
            // back to monitor injection (which may be looped back rather than
            // emitted when the managed AP owns the parent interface).
            let options = RawWifiTxOptions {
                variant: "ap_sme".to_owned(),
                include_freq: true,
                duration_ms: Some(100),
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            };
            // mt76x2u can reject NL80211_CMD_FRAME with ENOMEM while its
            // management-TX context is busy.  The same physical radio can
            // still inject a short on-channel control frame through a
            // monitor VIF, which is also the NAN raw-frame path. Keep this a
            // narrow fallback for AP SME responses rather than changing the
            // normal NAN TX policy.
            match send_monitor_frame(iface, channel, frame, None) {
                Ok(monitor) => json!({
                    "ok": true,
                    "backend": "linux_monitor_ap_sme_fallback",
                    "nl80211_error": format!("{error:#}"),
                    "monitor": monitor,
                }),
                Err(monitor_error) => {
                    if socket
                        .send_frame(ifindex, channel_to_freq(channel), &options, frame, None)
                        .is_ok()
                    {
                        json!({
                            "ok": true,
                            "backend": "linux_nl80211_ap_sme_explicit_channel",
                            "nl80211_error": format!("{error:#}"),
                            "monitor_error": format!("{monitor_error:#}"),
                        })
                    } else {
                        json!({
                            "ok": false,
                            "backend": "linux_nl80211",
                            "error": format!("{error:#}"),
                            "monitor_fallback_error": format!("{monitor_error:#}"),
                        })
                    }
                }
            }
        }
    }
}

/// Encode and send one bearer-neutral QUIC datagram as an ESP-NOW-like
/// action. Keeping this in one helper makes immediate responses and timer
/// retransmissions use identical address/rate/framing behavior.
fn send_raw_action_datagram(
    iface: &str,
    peer: [u8; 6],
    payload: &[u8],
    tx_rate_mbps: u8,
) -> Result<()> {
    let monitor_iface = monitor_iface_name(iface);
    let socket = MonitorTxSocket::open(&monitor_iface)?;
    send_raw_action_datagram_on_socket(iface, &socket, peer, payload, tx_rate_mbps)
}

/// Send using a caller-owned AF_PACKET socket.  The receive loop sends both
/// immediate QUIC responses and PTO retransmissions; keeping one bound socket
/// for that loop avoids repeated socket/bind setup and, more importantly,
/// avoids dropping packets while the driver is switching between short-lived
/// transmit contexts.
fn send_raw_action_datagram_on_socket(
    iface: &str,
    socket: &MonitorTxSocket,
    peer: [u8; 6],
    payload: &[u8],
    tx_rate_mbps: u8,
) -> Result<()> {
    let local = iface_mac(iface).with_context(|| format!("missing local MAC for {iface}"))?;
    let mut action = [0_u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 64];
    let destination = raw_action_response_address(peer);
    let action_len = dmesh_rawnan::espnow::encode_action_frame(
        &mut action,
        destination,
        local,
        [0xff; 6],
        payload,
    )
    .map_err(|error| anyhow::anyhow!("raw NOW response frame: {error:?}"))?;
    let packet = build_radiotap_packet_at_rate_with_ack(
        &action[..action_len],
        Some(tx_rate_mbps),
        // Replies use the same DMesh NOW no-MAC-ACK policy as requests.
        false,
    )?;
    for repetition in 0..raw_action_response_repetitions() {
        if repetition != 0 {
            // A duplicate sent back-to-back can be discarded by the
            // monitor/driver queue as one write.  A short gap makes this a
            // real independent on-air attempt while retaining one shared
            // QUIC packet buffer.
            std::thread::sleep(Duration::from_millis(raw_action_burst_gap_ms()));
        }
        let written = socket.send(&packet)?;
        if written != packet.len() {
            bail!(
                "short raw NOW response write: wrote {written}, expected {}",
                packet.len()
            );
        }
    }
    Ok(())
}

/// Broadcast Address-1 is the default ESP-NOW-compatible action path.  Host
/// tests may select a peer Address-1 to compare MAC-ACK/unicast behavior
/// without changing the shared QUIC or frame parser. Firmware keeps the
/// broadcast default because its radio policy is association-specific.
fn raw_action_response_address(peer: [u8; 6]) -> [u8; 6] {
    if std::env::var("DMESH_RAW_ACTION_RESPONSE_A1").as_deref() == Ok("peer") {
        peer
    } else {
        [0xff; 6]
    }
}

fn raw_action_burst_gap_ms() -> u64 {
    std::env::var("DMESH_RAW_ACTION_BURST_GAP_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(2)
        .min(100)
}

fn raw_action_response_repetitions() -> usize {
    std::env::var("DMESH_RAW_ACTION_RESPONSE_REPETITIONS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(RAW_ACTION_RESPONSE_REPETITIONS)
        .clamp(1, 8)
}

/// Automated host comparisons may adjust the association burst without
/// rebuilding either supervised service. The shared default remains the
/// normal eight-packet profile; this is a diagnostic knob, not a retained
/// one-packet stop-and-wait policy.
fn raw_action_association_profile() -> dmesh_server::raw_iperf::RawAssociationProfile {
    let mut profile = dmesh_server::raw_iperf::RawAssociationProfile::c6_default();
    if let Ok(value) = std::env::var("DMESH_RAW_ACTION_HISTORY") {
        if let Ok(value) = value.parse::<usize>() {
            profile.history_packets = value.clamp(1, 16);
        }
    }
    if let Ok(value) = std::env::var("DMESH_RAW_ACTION_ACK_FREQUENCY") {
        if let Ok(value) = value.parse::<u8>() {
            profile.ack_frequency = value.clamp(1, quic_lite::ACK_RANGE_CAPACITY as u8);
        }
    }
    if let Ok(value) = std::env::var("DMESH_RAW_ACTION_INITIAL_WINDOW") {
        if let Ok(value) = value.parse::<usize>() {
            profile.initial_window_packets = value.clamp(1, 16);
        }
    }
    if let Ok(value) = std::env::var("DMESH_RAW_ACTION_TX_BURST") {
        if let Ok(value) = value.parse::<usize>() {
            profile.tx_burst_packets = value.clamp(1, 8);
        }
    }
    profile
}

fn radiotap_rate_mbps(packet: &[u8]) -> Option<u8> {
    if packet.len() < 9 || packet[0] != 0 || packet[1] != 0 {
        return None;
    }
    let present = u32::from_le_bytes(packet.get(4..8)?.try_into().ok()?);
    if present & (1 << 2) == 0 {
        return None;
    }
    let rate = packet[8] / 2;
    matches!(rate, 1 | 2 | 5 | 6 | 9 | 11 | 12 | 18 | 24 | 36 | 48 | 54).then_some(rate)
}

fn monitor_receive_loop(
    socket: MonitorRxSocket,
    iface: &str,
    monitor_iface: &str,
    history: Arc<Mutex<VecDeque<RadioEvent>>>,
    discovered_devices: Arc<Mutex<DiscoveredDeviceRegistry>>,
    rawnan_state: Arc<Mutex<NanState>>,
    active_nan_publish: Arc<Mutex<NanActivePublish>>,
    pending_nan_followups: Arc<Mutex<dmesh_rawnan::NanFollowupQueue>>,
    raw_action_dispatcher: Arc<
        Mutex<
            Option<
                dmesh_server::raw_iperf::RawIperfDispatcher<
                    16,
                    { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE },
                >,
            >,
        >,
    >,
    stop_flag: Arc<AtomicBool>,
) {
    let receive_addresses = raw_wifi_receive_addresses(iface);
    let mut followup_dedup = FollowupDedup::new(256);
    let mut buf = [0_u8; 4096];
    let mut last_action_rate = 1_u8;
    let tx_socket = MonitorTxSocket::open(monitor_iface).ok();
    loop {
        if stop_flag.load(Ordering::Acquire) {
            break;
        }
        // Drive server-side QUIC PTO even when the peer's last request or
        // response was lost. AF_PACKET timeouts wake this loop without a
        // second queue or transport-owned packet buffer.
        let mut timer_response = [0_u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
        let timer_path = raw_action_dispatcher
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .and_then(|dispatcher| dispatcher.reply_path());
        if let Some(path) = timer_path
            && let Ok(Some(used)) = raw_action_dispatcher
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_mut()
                .expect("reply path implies dispatcher")
                // Raw QUIC endpoint clocks are milliseconds.  Keep PTO in the
                // same unit as the dispatcher set_time call above.
                .poll_retransmit_for(path, now_millis_u64(), 100, &mut timer_response)
            && let Err(error) = match tx_socket.as_ref() {
                Some(socket) => send_raw_action_datagram_on_socket(
                    iface,
                    socket,
                    path.peer,
                    &timer_response[..used],
                    last_action_rate,
                ),
                None => send_raw_action_datagram(
                    iface,
                    path.peer,
                    &timer_response[..used],
                    last_action_rate,
                ),
            }
        {
            push_radio_event(
                &history,
                RadioEvent {
                    ts_millis: now_millis(),
                    key: "wifi.raw.dispatch".to_string(),
                    source: monitor_iface.to_string(),
                    value: json!({
                        "ok": false,
                        "timer_retransmit": true,
                        "peer": colon_mac(&path.peer),
                        "error": format!("{error:#}"),
                    }),
                    message: None,
                },
            );
        }
        match socket.recv(&mut buf) {
            Ok(0) => continue,
            Ok(len) => {
                let packet = &buf[..len];
                if let Some(rate) = radiotap_rate_mbps(packet) {
                    last_action_rate = rate;
                }
                push_radio_event(
                    &history,
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
                        &history,
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
                            &history,
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
                                &history,
                                RadioEvent {
                                    ts_millis: now_millis(),
                                    key: "wifi.rawnan.beacon".to_string(),
                                    source: monitor_iface.to_string(),
                                    value: beacon,
                                    message: None,
                                },
                            );
                        }
                        drain_active_nan_publish(
                            iface,
                            monitor_iface,
                            &history,
                            &rawnan_state,
                            &active_nan_publish,
                            |publish| {
                                let packet = build_radiotap_packet_at_rate(publish, Some(6))?;
                                let socket = tx_socket.as_ref().ok_or_else(|| {
                                    anyhow::anyhow!("monitor TX socket unavailable")
                                })?;
                                socket.send(&packet).and_then(|written| {
                                    (written == packet.len())
                                        .then_some(())
                                        .ok_or_else(|| anyhow::anyhow!("short NAN Publish write"))
                                })
                            },
                        );
                        drain_pending_nan_followups(
                            iface,
                            monitor_iface,
                            &history,
                            &rawnan_state,
                            &pending_nan_followups,
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
                            monitor_iface,
                            &history,
                            &discovered_devices,
                            &rawnan_state,
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
                    if raw_wifi_receive_address_allowed(frame, &receive_addresses) || nan_data {
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
                            let message = mesh_message_from_raw_wifi(&value, iface);
                            push_radio_event(
                                &history,
                                RadioEvent {
                                    ts_millis: now_millis(),
                                    key: "wifi.raw.rx".to_string(),
                                    source: monitor_iface.to_string(),
                                    value,
                                    message: Some(message),
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
                    let mut action_payload = [0_u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
                    if let Some((peer, payload_len)) =
                        dmesh_rawnan::espnow::parse_action_frame_into(frame, &mut action_payload)
                    {
                        let local_source = iface_mac(iface).ok();
                        push_radio_event(
                            &history,
                            RadioEvent {
                                ts_millis: now_millis(),
                                key: "wifi.raw.action".to_string(),
                                source: monitor_iface.to_string(),
                                value: json!({
                                    "peer": colon_mac(&peer),
                                    "local": local_source.map(|mac| colon_mac(&mac)),
                                    "payload_len": payload_len,
                                }),
                                message: None,
                            },
                        );
                        // The monitor VIF reflects locally injected frames.
                        // Do not turn that reflection into a local server
                        // response; only a different source MAC is a peer.
                        if iface_mac(iface).ok() == Some(peer) {
                            continue;
                        }
                        let payload = &action_payload[..payload_len];
                        // A newly booted device emits the same bounded CBOR
                        // status and identity records over NOW as UART. They
                        // are discovery records, not malformed QUIC-lite
                        // datagrams, so publish them before raw dispatch.
                        if let Some(message) = dmesh_server::services::decode_status_text(payload) {
                            push_radio_event(
                                &history,
                                RadioEvent {
                                    ts_millis: now_millis(),
                                    key: "wifi.raw.boot".to_string(),
                                    source: monitor_iface.to_string(),
                                    value: json!({
                                        "peer": colon_mac(&peer),
                                        "message": String::from_utf8_lossy(message),
                                    }),
                                    message: None,
                                },
                            );
                            continue;
                        }
                        if let Some((role, partition)) =
                            dmesh_server::direct_iperf::decode_boot_identity_payload(payload)
                        {
                            push_radio_event(
                                &history,
                                RadioEvent {
                                    ts_millis: now_millis(),
                                    key: "wifi.raw.boot".to_string(),
                                    source: monitor_iface.to_string(),
                                    value: json!({
                                        "peer": colon_mac(&peer),
                                        "role": role,
                                        "partition": partition,
                                    }),
                                    message: None,
                                },
                            );
                            continue;
                        }
                        let mut response = [0_u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
                        let path = dmesh_server::raw_iperf::RawIngressPath {
                            transport_id: 2,
                            peer,
                        };
                        let dispatch_result = {
                            let mut dispatcher = raw_action_dispatcher
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            let dispatcher = dispatcher.get_or_insert_with(|| {
                                let cid = quic_lite::ConnectionId::new(now_millis_u64().max(1))
                                    .expect("non-zero raw action server CID");
                                dmesh_server::raw_iperf::RawIperfDispatcher::new(
                                    cid,
                                    quic_lite::ConnectionLimits::default(),
                                    raw_action_association_profile(),
                                )
                            });
                            dispatcher.set_time(now_millis_u64());
                            dispatcher.receive(path, payload, &mut response)
                        };
                        match dispatch_result {
                            Ok(Some(used)) => {
                                let sent = match tx_socket.as_ref() {
                                    Some(socket) => send_raw_action_datagram_on_socket(
                                        iface,
                                        socket,
                                        peer,
                                        &response[..used],
                                        last_action_rate,
                                    ),
                                    None => send_raw_action_datagram(
                                        iface,
                                        peer,
                                        &response[..used],
                                        last_action_rate,
                                    ),
                                };
                                let transport = raw_action_dispatcher
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                                    .as_ref()
                                    .and_then(|dispatcher| dispatcher.transport_stats())
                                    .map(|stats| {
                                        json!({
                                            "received_datagrams": stats.received_datagrams,
                                            "sent_datagrams": stats.sent_datagrams,
                                            "sent_stream_datagrams": stats.sent_stream_datagrams,
                                            "sent_control_datagrams": stats.sent_control_datagrams,
                                            "duplicate_datagrams": stats.duplicate_datagrams,
                                            "out_of_order_datagrams": stats.out_of_order_datagrams,
                                            "inferred_missing_packets": stats.inferred_missing_packets,
                                            "retransmitted_datagrams": stats.retransmitted_datagrams,
                                            "loss_packet_threshold_datagrams": stats.loss_packet_threshold_datagrams,
                                            "loss_time_threshold_datagrams": stats.loss_time_threshold_datagrams,
                                            "loss_events": stats.loss_events,
                                            "loss_retransmitted_datagrams": stats.loss_retransmitted_datagrams,
                                            "pto_retransmitted_datagrams": stats.pto_retransmitted_datagrams,
                                            "ack_datagrams": stats.ack_datagrams,
                                            "ack_frequency_received": stats.ack_frequency_received,
                                            "ack_frequency_sent": stats.ack_frequency_sent,
                                        })
                                    });
                                let ack_state = raw_action_dispatcher
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                                    .as_ref()
                                    .and_then(|dispatcher| dispatcher.transport_ack_state())
                                    .map(|(largest_acked, bytes_in_flight, congestion_window)| {
                                        json!({
                                            "largest_acked_by_peer": largest_acked,
                                            "bytes_in_flight": bytes_in_flight,
                                            "congestion_window": congestion_window,
                                        })
                                    });
                                let debug_state = raw_action_dispatcher
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                                    .as_ref()
                                    .and_then(|dispatcher| dispatcher.transport_debug_state())
                                    .map(|state| {
                                        json!({
                                            "received_ranges": state.received_ranges,
                                            "peer_ack_ranges": state.peer_ack_ranges,
                                            "outstanding_packets": state.outstanding_packets,
                                            "outstanding_count": state.outstanding_count,
                                        })
                                    });
                                push_radio_event(
                                    &history,
                                    RadioEvent {
                                        ts_millis: now_millis(),
                                        key: "wifi.raw.dispatch".to_string(),
                                        source: monitor_iface.to_string(),
                                        value: json!({
                                            "ok": sent.is_ok(),
                                            "peer": colon_mac(&peer),
                                            "response_len": used,
                                            "transport": transport,
                                            "ack_state": ack_state,
                                            "debug_state": debug_state,
                                            "error": sent.err().map(|error| format!("{error:#}")),
                                        }),
                                        message: None,
                                    },
                                );
                                // The association profile permits a bounded
                                // burst. Ask the shared dispatcher for those
                                // additional packets while this callback is
                                // active; no adapter-owned egress queue is
                                // introduced and QUIC retains every packet in
                                // its normal bounded ledger.
                                let burst = raw_action_dispatcher
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                                    .as_ref()
                                    .map(|dispatcher| dispatcher.tx_burst_packets())
                                    .unwrap_or(1)
                                    .max(1);
                                for _ in 1..burst {
                                    let mut burst_response =
                                        [0_u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
                                    // Leave a short airtime gap so the
                                    // monitor driver can schedule each action
                                    // without adding an adapter-owned queue.
                                    std::thread::sleep(Duration::from_millis(
                                        raw_action_burst_gap_ms(),
                                    ));
                                    let next = {
                                        let mut dispatcher = raw_action_dispatcher
                                            .lock()
                                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                                        dispatcher.as_mut().and_then(|dispatcher| {
                                            dispatcher
                                                .poll_for(path, &mut burst_response)
                                                .ok()
                                                .flatten()
                                        })
                                    };
                                    let Some(next) = next else { break };
                                    let burst_sent = match tx_socket.as_ref() {
                                        Some(socket) => send_raw_action_datagram_on_socket(
                                            iface,
                                            socket,
                                            peer,
                                            &burst_response[..next],
                                            last_action_rate,
                                        ),
                                        None => send_raw_action_datagram(
                                            iface,
                                            peer,
                                            &burst_response[..next],
                                            last_action_rate,
                                        ),
                                    };
                                    push_radio_event(
                                        &history,
                                        RadioEvent {
                                            ts_millis: now_millis(),
                                            key: "wifi.raw.dispatch".to_string(),
                                            source: monitor_iface.to_string(),
                                            value: json!({
                                                "ok": burst_sent.is_ok(),
                                                "peer": colon_mac(&peer),
                                                "response_len": next,
                                                "burst": true,
                                                "error": burst_sent.as_ref().err().map(|error| format!("{error:#}")),
                                            }),
                                            message: None,
                                        },
                                    );
                                    if burst_sent.is_err() {
                                        break;
                                    }
                                }
                            }
                            Ok(None) => {}
                            Err(error) => push_radio_event(
                                &history,
                                RadioEvent {
                                    ts_millis: now_millis(),
                                    key: "wifi.raw.dispatch".to_string(),
                                    source: monitor_iface.to_string(),
                                    value: json!({
                                        "ok": false,
                                        "peer": colon_mac(&peer),
                                        "error": format!("QUIC-lite raw NOW receive: {error:?}"),
                                    }),
                                    message: None,
                                },
                            ),
                        }
                    }
                    if !matches!(action, RawNanAction::None) {
                        push_radio_event(
                            &history,
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
                    &history,
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

/// Consume management beacons for the shared raw-NAN synchronization state.
/// USD action frames are intentionally not treated as a timing source: sleepy
/// peers need the cluster/AP beacon TSF and interval to schedule their wake
/// window and follow-up transmission.
fn handle_beacon_frame(
    frame: &[u8],
    iface: &str,
    rx_signal_dbm: Option<i32>,
    rawnan_state: &Arc<Mutex<NanState>>,
) -> Option<Value> {
    if frame_type(frame) != 0 || frame_subtype(frame) != 8 {
        return None;
    }
    let rx = RawNanRxFrame {
        bytes: frame,
        rssi_dbm: rx_signal_dbm
            .unwrap_or(0)
            .clamp(i8::MIN as i32, i8::MAX as i32) as i8,
        timestamp_us: now_micros_u64(),
    };
    let action = if dmesh_rawnan::is_nan_beacon(frame) {
        rawnan_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .observe(rx)
    } else {
        rawnan_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .observe_ap_beacon(rx);
        RawNanAction::None
    };
    let bssid = mac_at(frame, IEEE80211_ADDR3).map(|mac| colon_mac(&mac));
    let nan = dmesh_rawnan::is_nan_beacon(frame);
    Some(json!({
        "ok": true,
        "backend": "rawnan_host",
        "iface": iface,
        "source": mac_at(frame, IEEE80211_ADDR2).map(|mac| colon_mac(&mac)),
        "bssid": bssid,
        "sync_source": if nan { "nan_cluster" } else { "ap_anchor" },
        "nan_beacon": nan,
        "tsf_us": dmesh_rawnan::beacon_tsf_us(frame),
        "beacon_interval_tu": dmesh_rawnan::beacon_interval_tu(frame),
        "rx_signal_dbm": rx_signal_dbm,
        "nan_action": match action {
            RawNanAction::None => "none",
            RawNanAction::ArmA3(_) => "arm_a3",
            RawNanAction::DropForeign => "drop_foreign",
            RawNanAction::Rediscover => "rediscover",
        },
    }))
}

fn is_nan_data_frame(frame: &[u8]) -> bool {
    if frame.len() < IEEE80211_BODY + IEEE80211_LLC_SNAP_LEN
        || frame_type(frame) != 2
        || mac_at(frame, IEEE80211_ADDR3).map(|bssid| bssid[..3] == [0x50, 0x6f, 0x9a])
            != Some(true)
    {
        return false;
    }
    true
}

fn parse_ethernet_trace(packet: &[u8], iface: &str) -> Option<Value> {
    if packet.len() < ETHERNET_HEADER_LEN {
        return None;
    }
    Some(json!({
        "ok": true,
        "backend": "linux_af_packet_data",
        "iface": iface,
        "source": colon_mac(&packet[6..12].try_into().ok()?),
        "destination": colon_mac(&packet[..6].try_into().ok()?),
        "ethertype": format!("0x{:04x}", u16::from_be_bytes([packet[12], packet[13]])),
        "frame_len": packet.len(),
        "payload_prefix": hex_bytes(&packet[ETHERNET_HEADER_LEN..packet.len().min(ETHERNET_HEADER_LEN + 128)]),
    }))
}

fn data_receive_loop(
    socket: DataSocket,
    iface: &str,
    history: Arc<Mutex<VecDeque<RadioEvent>>>,
    listen_for: Duration,
) {
    let receive_addresses = raw_wifi_receive_addresses(iface);
    let stop_at = SystemTime::now() + listen_for;
    let mut buf = [0_u8; 4096];
    loop {
        let remaining = stop_at
            .duration_since(SystemTime::now())
            .unwrap_or_else(|_| Duration::from_millis(0));
        if remaining.is_zero() {
            break;
        }
        match socket.recv_timeout(&mut buf, remaining.min(Duration::from_millis(500))) {
            Ok(Some(0)) | Ok(None) => continue,
            Ok(Some(len)) => {
                let packet = &buf[..len];
                if let Some(value) = parse_dmesh_ethernet_frame(packet, iface, &receive_addresses) {
                    let message = mesh_message_from_raw_wifi(&value, iface);
                    push_radio_event(
                        &history,
                        RadioEvent {
                            ts_millis: now_millis(),
                            key: "wifi.data.rx".to_string(),
                            source: iface.to_string(),
                            value,
                            message: Some(message),
                        },
                    );
                } else if let Some(value) = parse_ethernet_trace(packet, iface) {
                    // Keep ordinary ARP/IP traffic visible during STA/AP
                    // diagnostics without pretending it is a DMesh payload.
                    // The listener is explicitly requested and bounded, so
                    // this does not add a permanent packet-history flood.
                    push_radio_event(
                        &history,
                        RadioEvent {
                            ts_millis: now_millis(),
                            key: "wifi.data.trace".to_string(),
                            source: iface.to_string(),
                            value,
                            message: None,
                        },
                    );
                }
            }
            Err(error) => {
                push_radio_event(
                    &history,
                    RadioEvent {
                        ts_millis: now_millis(),
                        key: "wifi.data.listen.error".to_string(),
                        source: iface.to_string(),
                        value: json!({
                            "ok": false,
                            "iface": iface,
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

fn raw_wifi_receive_addresses(iface: &str) -> Vec<[u8; 6]> {
    match iface_mac(iface) {
        Ok(mac) => vec![mac, raw_receive_mac(mac), RAW_WIFI_MULTICAST],
        Err(_) => vec![RAW_WIFI_MULTICAST],
    }
}

fn raw_wifi_receive_address_allowed(frame: &[u8], addresses: &[[u8; 6]]) -> bool {
    let Some(destination) = mac_at(frame, IEEE80211_ADDR1) else {
        return false;
    };
    addresses.iter().any(|address| *address == destination)
}

fn ieee80211_frame(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < IEEE80211_BODY {
        return None;
    }
    if let Some(radiotap_len) = radiotap_len(packet) {
        let frame = packet.get(radiotap_len..)?;
        return is_plausible_80211_frame(frame).then_some(strip_valid_fcs(frame));
    }
    if is_plausible_80211_frame(packet) {
        return Some(strip_valid_fcs(packet));
    }
    None
}

/// Monitor-mode captures commonly include the four-byte 802.11 FCS while
/// nl80211 action-frame events do not.  Keep the frame boundary consistent
/// before handing a vendor payload to the CBOR dispatcher.  Verify the CRC
/// instead of blindly dropping four bytes: injected frames and drivers that
/// suppress FCS must remain usable, and arbitrary payloads may legitimately
/// end in four bytes.
fn strip_valid_fcs(frame: &[u8]) -> &[u8] {
    if frame.len() <= IEEE80211_BODY + 4 {
        return frame;
    }
    let split = frame.len() - 4;
    let expected = u32::from_le_bytes([
        frame[split],
        frame[split + 1],
        frame[split + 2],
        frame[split + 3],
    ]);
    (crc32_ieee(&frame[..split]) == expected)
        .then_some(&frame[..split])
        .unwrap_or(frame)
}

fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn radiotap_len(packet: &[u8]) -> Option<usize> {
    if packet.len() < 8 || packet[0] != 0 {
        return None;
    }
    let len = u16::from_le_bytes([packet[2], packet[3]]) as usize;
    (len >= 8 && len < packet.len()).then_some(len)
}

fn is_plausible_80211_frame(frame: &[u8]) -> bool {
    if frame.len() < IEEE80211_BODY {
        return false;
    }
    matches!(frame_type(frame), 0..=2)
}

fn parse_dmesh_vendor_action(frame: &[u8], iface: &str) -> Option<Value> {
    parse_dmesh_wifi_frame(frame, iface, "linux_nl80211")
}

fn parse_dmesh_wifi_frame(frame: &[u8], iface: &str, backend: &str) -> Option<Value> {
    // The raw NOW bearer is a standard 802.11 public/vendor action whose
    // payload is owned by `rawnan::espnow`. Parse it before the legacy DMesh
    // vendor-marker path so host monitor events expose the exact complete
    // QUIC-lite datagram that firmware receives.
    // The older DMesh marker has a deliberate fixed header.  Check it first:
    // its bytes can otherwise be interpreted as a permissive ESP-NOW IE by
    // the generic parser, losing the marker and destination metadata.
    let has_legacy_dmesh_marker = frame
        .get(IEEE80211_BODY..)
        .and_then(parse_dmesh_vendor_action_header)
        .is_some();
    if !has_legacy_dmesh_marker
        && let Some((source, payload)) = dmesh_rawnan::espnow::parse_action_frame(frame)
    {
        let destination = mac_at(frame, IEEE80211_ADDR1)?;
        let bssid = mac_at(frame, IEEE80211_ADDR3)?;
        return Some(json!({
            "protocol": "dmesh_wifi_raw",
            "layout": "espnow_action",
            "backend": backend,
            "encapsulation": "espnow_v2_vendor_ie",
            "iface": iface,
            "frame_type": frame_type(frame),
            "frame_subtype": frame_subtype(frame),
            "source": colon_mac(&source),
            "destination": colon_mac(&destination),
            "bssid": colon_mac(&bssid),
            "payload_len": payload.len(),
            "payload": hex_bytes(payload),
        }));
    }
    if frame.len() <= IEEE80211_BODY + DMESH_LEGACY_VENDOR_ACTION.len() {
        return None;
    }
    let mut body = &frame[IEEE80211_BODY..];
    let encapsulation = if body.starts_with(&IEEE80211_LLC_SNAP_IPV6) {
        return parse_nan_ipv6_udp_frame(frame, iface, backend);
    } else if body.starts_with(&IEEE80211_LLC_SNAP_DMESH) {
        body = &body[IEEE80211_LLC_SNAP_LEN..];
        "llc_snap"
    } else if body.len() >= IEEE80211_LLC_SNAP_LEN && body[..3] == [0xaa, 0xaa, 0x03] {
        // Experimental NAN data uses an LLC/SNAP prefix. Do not treat every
        // unknown action body as LLC: the ESP-NOW-compatible vendor action
        // header starts with 7f and must continue to the marker parser below.
        let llc = &body[..IEEE80211_LLC_SNAP_LEN];
        body = &body[IEEE80211_LLC_SNAP_LEN..];
        let source = mac_at(frame, IEEE80211_ADDR2)?;
        let destination = mac_at(frame, IEEE80211_ADDR1)?;
        let bssid = mac_at(frame, IEEE80211_ADDR3)?;
        return Some(json!({
            "protocol": "dmesh_wifi_raw",
            "layout": "nan_raw_data",
            "backend": backend,
            "encapsulation": "llc_experimental",
            "iface": iface,
            "frame_type": frame_type(frame),
            "frame_subtype": frame_subtype(frame),
            "source": colon_mac(&source),
            "destination": colon_mac(&destination),
            "bssid": colon_mac(&bssid),
            "llc": hex_bytes(llc),
            "payload_len": body.len(),
            "payload": hex_bytes(body),
            "payload_text": String::from_utf8_lossy(body).trim(),
        }));
    } else {
        "vendor_action"
    };
    let header = parse_dmesh_vendor_action_header(body)?;
    let payload = &body[header.header_len..];
    let source = mac_at(frame, IEEE80211_ADDR2)?;
    let destination = mac_at(frame, IEEE80211_ADDR1)?;
    let bssid = mac_at(frame, IEEE80211_ADDR3)?;
    let layout = if frame_type(frame) == 2 {
        "multicast_data"
    } else {
        "vendor_action"
    };
    Some(json!({
        "protocol": "dmesh_wifi_raw",
        "layout": layout,
        "backend": backend,
        "encapsulation": encapsulation,
        "iface": iface,
        "frame_type": frame_type(frame),
        "frame_subtype": frame_subtype(frame),
        "source": colon_mac(&source),
        "destination": colon_mac(&destination),
        "bssid": colon_mac(&bssid),
        "vendor_marker": header.marker,
        "mesh_dst4": hex_bytes(&header.mesh_dst4),
        "payload_len": payload.len(),
        "payload": hex_bytes(payload),
        "payload_text": String::from_utf8_lossy(payload).trim(),
    }))
}

fn parse_nan_ipv6_udp_frame(frame: &[u8], iface: &str, backend: &str) -> Option<Value> {
    let body = frame.get(IEEE80211_BODY + IEEE80211_LLC_SNAP_LEN..)?;
    if body.len() < 48 || body[0] >> 4 != 6 || body[6] != 17 {
        return None;
    }
    let payload_len = u16::from_be_bytes([body[4], body[5]]) as usize;
    if payload_len < 8 || body.len() < 40 + payload_len {
        return None;
    }
    let udp = &body[40..40 + payload_len];
    let source = mac_at(frame, IEEE80211_ADDR2)?;
    let destination = mac_at(frame, IEEE80211_ADDR1)?;
    let bssid = mac_at(frame, IEEE80211_ADDR3)?;
    let payload = &udp[8..];
    Some(json!({
        "protocol": "dmesh_wifi_raw",
        "layout": "nan_ipv6_udp",
        "backend": backend,
        "encapsulation": "llc_snap_ipv6",
        "iface": iface,
        "frame_type": frame_type(frame),
        "frame_subtype": frame_subtype(frame),
        "source": colon_mac(&source),
        "destination": colon_mac(&destination),
        "bssid": colon_mac(&bssid),
        "ipv6_source": format_ipv6(&body[8..24]),
        "ipv6_destination": format_ipv6(&body[24..40]),
        "udp_source": u16::from_be_bytes([udp[0], udp[1]]),
        "udp_destination": u16::from_be_bytes([udp[2], udp[3]]),
        "payload_len": payload.len(),
        "payload": hex_bytes(payload),
        "payload_text": String::from_utf8_lossy(payload).trim(),
    }))
}

fn format_ipv6(bytes: &[u8]) -> String {
    bytes
        .chunks_exact(2)
        .map(|part| format!("{:x}", u16::from_be_bytes([part[0], part[1]])))
        .collect::<Vec<_>>()
        .join(":")
}

fn parse_dmesh_ethernet_frame(
    frame: &[u8],
    iface: &str,
    receive_addresses: &[[u8; 6]],
) -> Option<Value> {
    if frame.len() <= ETHERNET_HEADER_LEN + DMESH_LEGACY_VENDOR_ACTION.len() {
        return None;
    }
    let destination = mac_at(frame, 0)?;
    if !receive_addresses
        .iter()
        .any(|address| *address == destination)
    {
        return None;
    }
    let source = mac_at(frame, 6)?;
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ETH_P_DMESH {
        return None;
    }
    let body = &frame[ETHERNET_HEADER_LEN..];
    let header = parse_dmesh_vendor_action_header(body)?;
    let payload = &body[header.header_len..];
    Some(json!({
        "protocol": "dmesh_wifi_data",
        "layout": "ethernet",
        "backend": "linux_af_packet_data",
        "encapsulation": "ethernet",
        "iface": iface,
        "source": colon_mac(&source),
        "destination": colon_mac(&destination),
        "ethertype": format!("0x{ethertype:04x}"),
        "vendor_marker": header.marker,
        "mesh_dst4": hex_bytes(&header.mesh_dst4),
        "payload_len": payload.len(),
        "payload": hex_bytes(payload),
        "payload_text": String::from_utf8_lossy(payload).trim(),
    }))
}

struct DmeshWifiHeader {
    header_len: usize,
    marker: &'static str,
    mesh_dst4: [u8; 4],
}

fn parse_dmesh_vendor_action_header(body: &[u8]) -> Option<DmeshWifiHeader> {
    if body.len() >= DMESH_VENDOR_ACTION_LEN
        && body[..DMESH_ESPNOW_PREFIX.len()] == DMESH_ESPNOW_PREFIX
    {
        // Native action frames continue with one ESP-NOW vendor IE.  The
        // Ethernet/LLC diagnostic encapsulation uses the same eight-byte
        // marker directly, so only skip the IE when it is actually present.
        let header_len = if body.len() >= DMESH_VENDOR_ACTION_LEN + DMESH_VENDOR_IE_LEN
            && body[DMESH_VENDOR_ACTION_LEN] == 0xdd
            && body[DMESH_VENDOR_ACTION_LEN + 2..DMESH_VENDOR_ACTION_LEN + 5]
                == DMESH_ESPNOW_PREFIX[1..]
            && body[DMESH_VENDOR_ACTION_LEN + 5] == 0x04
        {
            DMESH_VENDOR_ACTION_LEN + DMESH_VENDOR_IE_LEN
        } else {
            DMESH_VENDOR_ACTION_LEN
        };
        return Some(DmeshWifiHeader {
            header_len,
            marker: "espnow_dmesh",
            mesh_dst4: [body[4], body[5], body[6], body[7]],
        });
    }
    if body.starts_with(&DMESH_LEGACY_VENDOR_ACTION) {
        return Some(DmeshWifiHeader {
            header_len: DMESH_LEGACY_VENDOR_ACTION.len(),
            marker: "legacy_dmesh",
            mesh_dst4: [0xff; 4],
        });
    }
    None
}

fn parse_management_frame(frame: &[u8], iface: &str, backend: &str) -> Value {
    let subtype = frame_subtype(frame);
    let kind = match subtype {
        0 => "assoc_req",
        1 => "assoc_resp",
        2 => "reassoc_req",
        3 => "reassoc_resp",
        4 => "probe_req",
        5 => "probe_resp",
        8 => "beacon",
        10 => "disassoc",
        11 => "auth",
        12 => "deauth",
        13 => "action",
        _ => "mgmt",
    };
    let destination = mac_at(frame, IEEE80211_ADDR1).unwrap_or([0; 6]);
    let source = mac_at(frame, IEEE80211_ADDR2).unwrap_or([0; 6]);
    let bssid = mac_at(frame, IEEE80211_ADDR3).unwrap_or([0; 6]);
    let mut fixed = serde_json::Map::new();
    let ies_start = match subtype {
        0 => {
            insert_u16_at(&mut fixed, "capability", frame, IEEE80211_BODY);
            insert_u16_at(&mut fixed, "listen_interval", frame, IEEE80211_BODY + 2);
            IEEE80211_BODY + 4
        }
        1 | 3 => {
            insert_u16_at(&mut fixed, "capability", frame, IEEE80211_BODY);
            insert_u16_at(&mut fixed, "status_code", frame, IEEE80211_BODY + 2);
            insert_u16_at(&mut fixed, "aid", frame, IEEE80211_BODY + 4);
            IEEE80211_BODY + 6
        }
        2 => {
            insert_u16_at(&mut fixed, "capability", frame, IEEE80211_BODY);
            insert_u16_at(&mut fixed, "listen_interval", frame, IEEE80211_BODY + 2);
            if let Some(current_ap) = mac_at(frame, IEEE80211_BODY + 4) {
                fixed.insert("current_ap".to_string(), json!(colon_mac(&current_ap)));
            }
            IEEE80211_BODY + 10
        }
        4 => IEEE80211_BODY,
        5 | 8 => {
            if let Some(timestamp) = read_u64_at(frame, IEEE80211_BODY) {
                fixed.insert("timestamp".to_string(), json!(timestamp));
            }
            insert_u16_at(&mut fixed, "beacon_interval", frame, IEEE80211_BODY + 8);
            insert_u16_at(&mut fixed, "capability", frame, IEEE80211_BODY + 10);
            IEEE80211_BODY + 12
        }
        10 | 12 => {
            insert_u16_at(&mut fixed, "reason_code", frame, IEEE80211_BODY);
            IEEE80211_BODY + 2
        }
        11 => {
            insert_u16_at(&mut fixed, "auth_algorithm", frame, IEEE80211_BODY);
            insert_u16_at(&mut fixed, "auth_transaction", frame, IEEE80211_BODY + 2);
            insert_u16_at(&mut fixed, "status_code", frame, IEEE80211_BODY + 4);
            IEEE80211_BODY + 6
        }
        13 => {
            if let Some(category) = frame.get(IEEE80211_BODY) {
                fixed.insert("category".to_string(), json!(*category));
            }
            frame.len()
        }
        _ => frame.len(),
    };
    let ies = if ies_start <= frame.len() {
        parse_wifi_ies(&frame[ies_start..])
    } else {
        Vec::new()
    };
    let ssid = ies
        .iter()
        .find(|ie| ie.get("id").and_then(Value::as_u64) == Some(0))
        .and_then(|ie| ie.get("text"))
        .cloned()
        .unwrap_or(Value::Null);
    let channel = ies
        .iter()
        .find(|ie| ie.get("id").and_then(Value::as_u64) == Some(3))
        .and_then(|ie| ie.get("bytes").and_then(Value::as_array))
        .and_then(|bytes| bytes.first().and_then(Value::as_u64));
    json!({
        "kind": kind,
        "backend": backend,
        "iface": iface,
        "frame_type": frame_type(frame),
        "frame_subtype": subtype,
        "destination": colon_mac(&destination),
        "source": colon_mac(&source),
        "bssid": colon_mac(&bssid),
        "fixed": fixed,
        "ssid": ssid,
        "channel": channel,
        "len": frame.len(),
        "frame": hex_bytes(frame),
        "ies": ies,
    })
}

fn parse_wifi_ies(mut bytes: &[u8]) -> Vec<Value> {
    let mut ies = Vec::new();
    while bytes.len() >= 2 {
        let id = bytes[0];
        let len = bytes[1] as usize;
        bytes = &bytes[2..];
        if bytes.len() < len {
            ies.push(json!({
                "id": id,
                "name": wifi_ie_name(id),
                "truncated": true,
                "want_len": len,
                "remaining": bytes.len(),
            }));
            break;
        }
        let data = &bytes[..len];
        let mut value = json!({
            "id": id,
            "name": wifi_ie_name(id),
            "len": len,
            "hex": hex_bytes(data),
            "bytes": data.iter().map(|byte| json!(*byte)).collect::<Vec<_>>(),
        });
        if id == 0 {
            value["text"] = json!(String::from_utf8_lossy(data));
        }
        if id == 1 || id == 50 {
            value["rates_mbps"] = json!(
                data.iter()
                    .map(|rate| ((*rate & 0x7f) as f32) / 2.0)
                    .collect::<Vec<_>>()
            );
        }
        ies.push(value);
        bytes = &bytes[len..];
    }
    ies
}

fn management_ie_bytes(mut bytes: &[u8], wanted_id: u8) -> Option<&[u8]> {
    while bytes.len() >= 2 {
        let id = bytes[0];
        let length = bytes[1] as usize;
        bytes = &bytes[2..];
        if bytes.len() < length {
            return None;
        }
        let value = &bytes[..length];
        if id == wanted_id {
            return Some(value);
        }
        bytes = &bytes[length..];
    }
    None
}

fn parse_iw_scan(output: &str) -> Vec<Value> {
    let mut entries = Vec::new();
    let mut current: Option<serde_json::Map<String, Value>> = None;
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("BSS ") {
            let bssid = rest.split("(on").next().unwrap_or(rest).trim();
            if parse_mac(Some(bssid)).is_none() {
                continue;
            }
            if let Some(entry) = current.take() {
                entries.push(Value::Object(entry));
            }
            let mut entry = serde_json::Map::new();
            entry.insert("bssid".to_string(), json!(bssid));
            continue_if_bss_iface(rest, &mut entry);
            current = Some(entry);
            continue;
        }
        let Some(entry) = current.as_mut() else {
            continue;
        };
        if let Some(ssid) = trimmed.strip_prefix("SSID:") {
            entry.insert("ssid".to_string(), json!(ssid.trim()));
        } else if let Some(signal) = trimmed.strip_prefix("signal:") {
            if let Some(dbm) = signal
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<f64>().ok())
            {
                entry.insert("signal_dbm".to_string(), json!(dbm));
            }
        } else if let Some(freq) = trimmed.strip_prefix("freq:") {
            if let Ok(freq) = freq.trim().parse::<u32>() {
                entry.insert("freq".to_string(), json!(freq));
                if let Some(channel) = freq_to_channel(freq) {
                    entry.insert("channel".to_string(), json!(channel));
                }
            }
        } else if let Some(channel) = trimmed.strip_prefix("* primary channel:") {
            if let Ok(channel) = channel.trim().parse::<u8>() {
                entry.insert("channel".to_string(), json!(channel));
            }
        } else if let Some(capability) = trimmed.strip_prefix("capability:") {
            entry.insert("capability".to_string(), json!(capability.trim()));
        } else if trimmed == "RSN:" {
            entry.insert("auth".to_string(), json!("wpa2"));
        } else if trimmed == "WPA:" {
            entry.insert("auth".to_string(), json!("wpa"));
        }
    }
    if let Some(entry) = current.take() {
        entries.push(Value::Object(entry));
    }
    for entry in &mut entries {
        if entry.get("auth").is_none() {
            entry["auth"] = json!("open");
        }
    }
    entries
}

fn continue_if_bss_iface(rest: &str, entry: &mut serde_json::Map<String, Value>) {
    if let Some(iface) = rest
        .split("(on ")
        .nth(1)
        .and_then(|part| part.split(')').next())
    {
        entry.insert("iface".to_string(), json!(iface));
    }
}

fn freq_to_channel(freq: u32) -> Option<u8> {
    match freq {
        2484 => Some(14),
        2412..=2472 => Some(((freq - 2407) / 5) as u8),
        5180..=5895 => Some(((freq - 5000) / 5) as u8),
        5955..=7115 => Some(((freq - 5950) / 5) as u8),
        _ => None,
    }
}

fn wifi_ie_name(id: u8) -> &'static str {
    match id {
        0 => "ssid",
        1 => "supported_rates",
        3 => "ds_parameter_set",
        5 => "tim",
        42 => "erp",
        45 => "ht_capabilities",
        48 => "rsn",
        50 => "extended_supported_rates",
        61 => "ht_operation",
        127 => "extended_capabilities",
        221 => "vendor_specific",
        _ => "unknown",
    }
}

fn build_open_beacon_head(mac: [u8; 6], ssid: &str, channel: u8) -> Result<Vec<u8>> {
    build_open_beacon_head_with_capability(mac, ssid, channel, 0x0421)
}

fn build_open_beacon_head_with_capability(
    mac: [u8; 6],
    ssid: &str,
    channel: u8,
    capability: u16,
) -> Result<Vec<u8>> {
    if ssid.len() > 32 {
        bail!("SSID is too long for 802.11 beacon: {}", ssid.len());
    }
    let mut frame = Vec::with_capacity(48 + ssid.len());
    frame.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&RAW_WIFI_BROADCAST);
    frame.extend_from_slice(&mac);
    frame.extend_from_slice(&mac);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&[0; 8]);
    frame.extend_from_slice(&100_u16.to_le_bytes());
    frame.extend_from_slice(&capability.to_le_bytes());
    frame.extend_from_slice(&esp_open_ap_beacon_head_ies(ssid, channel)?);
    Ok(frame)
}

fn build_open_probe_resp(mac: [u8; 6], ssid: &str, channel: u8) -> Result<Vec<u8>> {
    build_open_probe_resp_with_ies(
        mac,
        ssid,
        channel,
        0x0421,
        &esp_open_ap_probe_ies(ssid, channel)?,
    )
}

fn build_open_probe_resp_with_ies(
    mac: [u8; 6],
    ssid: &str,
    _channel: u8,
    capability: u16,
    ies: &[u8],
) -> Result<Vec<u8>> {
    if ssid.len() > 32 {
        bail!("SSID is too long for 802.11 probe response: {}", ssid.len());
    }
    let mut frame = Vec::with_capacity(160 + ssid.len());
    frame.extend_from_slice(&[0x50, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&RAW_WIFI_BROADCAST);
    frame.extend_from_slice(&mac);
    frame.extend_from_slice(&mac);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&[0; 8]);
    frame.extend_from_slice(&100_u16.to_le_bytes());
    frame.extend_from_slice(&capability.to_le_bytes());
    frame.extend_from_slice(ies);
    Ok(frame)
}

fn build_open_auth_response(ap: [u8; 6], sta: [u8; 6]) -> Vec<u8> {
    let mut frame = mgmt_frame_header(0x0b, sta, ap, ap);
    frame.extend_from_slice(&(NL80211_AUTHTYPE_OPEN_SYSTEM as u16).to_le_bytes());
    frame.extend_from_slice(&2_u16.to_le_bytes());
    frame.extend_from_slice(&0_u16.to_le_bytes());
    frame
}

/// Return stations that should use legacy (non-HT) association parameters.
///
/// The AP advertises HT20 globally, but a manually managed nl80211 AP can
/// still have a particular station/driver with unreliable aggregation or
/// Block-ACK behavior. Keep the normal HT20 path as the default and allow a
/// targeted workaround without lowering the rate for every station.
/// `LMESH_WIFI_AP_NO_HT_STATIONS` is a comma-separated list of MAC addresses.
fn ap_no_ht_stations() -> HashSet<[u8; 6]> {
    std::env::var("LMESH_WIFI_AP_NO_HT_STATIONS")
        .ok()
        .into_iter()
        .flat_map(|value| value.split(',').map(str::to_string).collect::<Vec<_>>())
        .filter_map(|value| parse_mac(Some(value.trim())))
        .collect()
}

fn build_open_assoc_response(
    ap: [u8; 6],
    sta: [u8; 6],
    aid: u16,
    allow_ht: bool,
    channel: u8,
    ht40: bool,
) -> Vec<u8> {
    let mut frame = mgmt_frame_header(0x01, sta, ap, ap);
    frame.extend_from_slice(&0x0401_u16.to_le_bytes());
    frame.extend_from_slice(&0_u16.to_le_bytes());
    frame.extend_from_slice(&(0xc000 | (aid & 0x3fff)).to_le_bytes());
    frame.push(0x01);
    frame.push(OPEN_AP_OFDM_BASIC_RATES.len() as u8);
    frame.extend_from_slice(&OPEN_AP_OFDM_BASIC_RATES);
    frame.push(0x32);
    frame.push(OPEN_AP_OFDM_EXTENDED_RATES.len() as u8);
    frame.extend_from_slice(&OPEN_AP_OFDM_EXTENDED_RATES);
    // Match the HT20 capability advertised in the beacon. Without an HT
    // Capabilities element in the association response, a station can
    // associate successfully but remain on legacy rates.
    if allow_ht {
        frame.extend_from_slice(&hostapd_open_ap_ht_capability(ht40));
        frame.extend_from_slice(&hostapd_open_ap_ht_operation(channel, ht40));
    }
    frame.extend_from_slice(&hostapd_open_ap_extra_ies());
    // The beacon/probe templates advertise WMM, so the manually generated
    // association response must carry the matching WMM Parameter element too.
    // Without it, Linux reports WMM/WME=no for the station even though the AP
    // beacon contains the element; that disables the normal Wi-Fi QoS/Block
    // ACK path and is especially costly for a direct Wi-Fi transfer.
    frame.extend_from_slice(&wmm_parameter_ie());
    frame
}

fn hostapd_open_ap_ht_operation(channel: u8, ht40: bool) -> [u8; 24] {
    let mut ie = [
        0x3d, 22, channel, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    if ht40 {
        ie[3] = 0x05;
    }
    ie
}

fn hostapd_open_ap_ht_capability(ht40: bool) -> [u8; 28] {
    let mut ie = HOSTAPD_HT20_CAPABILITY;
    if ht40 {
        ie[2] |= 0x42;
    }
    ie
}

fn mgmt_frame_header(subtype: u8, addr1: [u8; 6], addr2: [u8; 6], addr3: [u8; 6]) -> Vec<u8> {
    let frame_control = ((subtype as u16) << 4).to_le_bytes();
    let mut frame = Vec::with_capacity(64);
    frame.extend_from_slice(&frame_control);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&addr1);
    frame.extend_from_slice(&addr2);
    frame.extend_from_slice(&addr3);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame
}

fn esp_open_ap_beacon_head_ies(ssid: &str, channel: u8) -> Result<Vec<u8>> {
    if ssid.len() > 32 {
        bail!("SSID is too long for 802.11 IE: {}", ssid.len());
    }
    let mut ies = Vec::with_capacity(32 + ssid.len());
    ies.push(0x00);
    ies.push(ssid.len() as u8);
    ies.extend_from_slice(ssid.as_bytes());
    ies.push(0x01);
    ies.push(OPEN_AP_OFDM_BASIC_RATES.len() as u8);
    ies.extend_from_slice(&OPEN_AP_OFDM_BASIC_RATES);
    ies.push(0x03);
    ies.push(1);
    ies.push(channel);
    Ok(ies)
}

fn esp_open_ap_beacon_tail(channel: u8) -> Vec<u8> {
    let mut ies = Vec::with_capacity(92);
    ies.push(0x2a);
    ies.push(1);
    ies.push(0x00);
    ies.push(0x32);
    ies.push(OPEN_AP_OFDM_EXTENDED_RATES.len() as u8);
    ies.extend_from_slice(&OPEN_AP_OFDM_EXTENDED_RATES);
    ies.push(0x2d);
    ies.push(26);
    ies.extend_from_slice(&[
        0x6e, 0x11, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    ies.push(0x3d);
    ies.push(22);
    ies.extend_from_slice(&[
        channel, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    ies.push(0x7f);
    ies.push(9);
    ies.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    ies.push(0xdd);
    ies.push(24);
    ies.extend_from_slice(&[
        0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x04, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4, 0x00,
        0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00,
    ]);
    ies
}

fn hostapd_open_ap_beacon_tail(channel: u8, ht40: bool) -> Vec<u8> {
    let mut ies = Vec::with_capacity(101);
    ies.push(0x2a);
    ies.push(1);
    ies.push(0x04);
    ies.push(0x32);
    ies.push(OPEN_AP_OFDM_EXTENDED_RATES.len() as u8);
    ies.extend_from_slice(&OPEN_AP_OFDM_EXTENDED_RATES);
    ies.push(0x3b);
    ies.push(2);
    ies.extend_from_slice(&[0x51, 0x00]);
    ies.extend_from_slice(&hostapd_open_ap_ht_capability(ht40));
    ies.extend_from_slice(&hostapd_open_ap_ht_operation(channel, ht40));
    ies.extend_from_slice(&hostapd_open_ap_extra_ies());
    ies.push(0xdd);
    ies.push(24);
    ies.extend_from_slice(&[
        0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x01, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4, 0x00,
        0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00,
    ]);
    ies
}

fn hostapd_open_ap_probe_ies(ssid: &str, channel: u8, ht40: bool) -> Result<Vec<u8>> {
    let mut ies = esp_open_ap_beacon_head_ies(ssid, channel)?;
    ies.extend_from_slice(&hostapd_open_ap_beacon_tail(channel, ht40));
    Ok(ies)
}

fn hostapd_open_ap_extra_ies() -> [u8; 10] {
    [0x7f, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40]
}

fn wmm_parameter_ie() -> [u8; 26] {
    [
        0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x01, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27,
        0xa4, 0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00,
    ]
}

fn esp_open_ap_probe_ies(ssid: &str, channel: u8) -> Result<Vec<u8>> {
    let mut ies = esp_open_ap_beacon_head_ies(ssid, channel)?;
    ies.extend_from_slice(&esp_open_ap_beacon_tail(channel));
    Ok(ies)
}

fn open_ap_template_lengths(ssid: &str, channel: u8) -> Result<(usize, usize)> {
    let mac = [0; 6];
    Ok((
        build_open_beacon_head(mac, ssid, channel)?.len(),
        build_open_probe_resp(mac, ssid, channel)?.len(),
    ))
}

fn default_open_ap_ssid(iface: &str) -> String {
    iface_mac(iface)
        .map(|mac| {
            format!(
                "Direct-{:02X}{:02X}{:02X}{:02X}-Dmesh-local",
                mac[2], mac[3], mac[4], mac[5]
            )
        })
        .unwrap_or_else(|_| "Direct-00000000-Dmesh-local".to_string())
}

fn build_dmesh_vendor_action_frame(
    destination: [u8; 6],
    source: [u8; 6],
    payload: &[u8],
) -> Result<Vec<u8>> {
    build_dmesh_vendor_action_frame_with_bssid(destination, source, destination, payload)
}

fn build_dmesh_vendor_action_frame_with_bssid(
    destination: [u8; 6],
    source: [u8; 6],
    bssid: [u8; 6],
    payload: &[u8],
) -> Result<Vec<u8>> {
    dmesh_rawnan::build_espnow_action_frame(destination, source, bssid, payload)
}

fn build_dmesh_multicast_data_frame(
    destination: [u8; 6],
    source: [u8; 6],
    payload: &[u8],
) -> Vec<u8> {
    let body_len = payload.len().min(1400);
    let mut frame = Vec::with_capacity(IEEE80211_BODY + DMESH_VENDOR_ACTION_LEN + body_len);
    frame.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&dmesh_vendor_action_header(destination));
    frame.extend_from_slice(&payload[..body_len]);
    frame
}

fn build_dmesh_sta_multicast_llc_frame(bssid: [u8; 6], source: [u8; 6], payload: &[u8]) -> Vec<u8> {
    let body_len = payload.len().min(1400);
    let mut frame = Vec::with_capacity(
        IEEE80211_BODY + IEEE80211_LLC_SNAP_LEN + DMESH_VENDOR_ACTION_LEN + body_len,
    );
    frame.extend_from_slice(&[0x08, 0x01, 0x00, 0x00]);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&RAW_WIFI_MULTICAST);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&IEEE80211_LLC_SNAP_DMESH);
    frame.extend_from_slice(&dmesh_vendor_action_header(RAW_WIFI_MULTICAST));
    frame.extend_from_slice(&payload[..body_len]);
    frame
}

fn build_dmesh_sta_direct_llc_frame(
    destination: [u8; 6],
    source: [u8; 6],
    payload: &[u8],
) -> Vec<u8> {
    let body_len = payload.len().min(1400);
    let mut frame = Vec::with_capacity(
        IEEE80211_BODY + IEEE80211_LLC_SNAP_LEN + DMESH_VENDOR_ACTION_LEN + body_len,
    );
    frame.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&IEEE80211_LLC_SNAP_DMESH);
    frame.extend_from_slice(&dmesh_vendor_action_header(destination));
    frame.extend_from_slice(&payload[..body_len]);
    frame
}

/// Build an unassociated NAN-cluster data frame. Address3 is the selected
/// cluster BSSID; no IP/UDP/AP association is involved. The LLC/SNAP marker is
/// intentionally the same one used by the existing raw data parser so this
/// can be compared with the action-frame path.
fn build_dmesh_nan_data_frame(
    bssid: [u8; 6],
    destination: [u8; 6],
    source: [u8; 6],
    payload: &[u8],
) -> Vec<u8> {
    dmesh_rawnan::build_nan_ipv6_udp_frame(bssid, destination, source, payload)
}

fn build_dmesh_nan_raw_data_frame(
    bssid: [u8; 6],
    destination: [u8; 6],
    source: [u8; 6],
    llc: &[u8; IEEE80211_LLC_SNAP_LEN],
    payload: &[u8],
) -> Vec<u8> {
    dmesh_rawnan::build_nan_raw_data_frame(bssid, destination, source, *llc, payload)
}

fn parse_experimental_llc(value: Option<&str>) -> Option<[u8; IEEE80211_LLC_SNAP_LEN]> {
    let value = value?;
    let value = value.strip_prefix("hex:").unwrap_or(value);
    let compact = value.replace([':', '-', ' ', '_'], "");
    if compact.len() != IEEE80211_LLC_SNAP_LEN * 2 {
        return None;
    }
    let mut out = [0u8; IEEE80211_LLC_SNAP_LEN];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn build_dmesh_ethernet_frame(destination: [u8; 6], source: [u8; 6], payload: &[u8]) -> Vec<u8> {
    let body_len = payload.len().min(1400);
    let mut frame = Vec::with_capacity(ETHERNET_HEADER_LEN + DMESH_VENDOR_ACTION_LEN + body_len);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&ETH_P_DMESH.to_be_bytes());
    frame.extend_from_slice(&dmesh_vendor_action_header(destination));
    frame.extend_from_slice(&payload[..body_len]);
    frame
}

fn dmesh_vendor_action_header(destination: [u8; 6]) -> [u8; DMESH_VENDOR_ACTION_LEN] {
    let _ = destination;
    dmesh_rawnan::espnow_action_header()
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

fn push_radio_event(history: &Arc<Mutex<VecDeque<RadioEvent>>>, event: RadioEvent) {
    // Keep radio, discovery, beacon, data, and trace records on the shared
    // mesh pub/sub stream. The trace subscriber adds the common `event_type`
    // envelope field and can filter it per connection.
    let event_type = event.key.clone();
    let source = event.source.clone();
    let data = event.value.to_string();
    // Drop only high-rate per-frame monitor diagnostics from the retained
    // history. Semantic raw receive/dispatch events remain bounded history so
    // E2E tests and operators can distinguish radio delivery from parser or
    // QUIC failures without retaining packet payload queues.
    let monitor_event = event.source.ends_with("mon")
        && matches!(
            event.key.as_str(),
            "wifi.raw.monitor" | "wifi.raw.socket" | "wifi.raw.action_candidate"
        );
    if !monitor_event {
        let mut history = history
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        history.push_back(event);
        while history.len() > MAX_HISTORY {
            history.pop_front();
        }
    }
    tracing::info!(
        target: "dmesh.event",
        event_type = %event_type,
        source = %source,
        data = %data,
        message = "event"
    );
}

fn mac_at(frame: &[u8], offset: usize) -> Option<[u8; 6]> {
    let mut out = [0_u8; 6];
    out.copy_from_slice(frame.get(offset..offset + 6)?);
    Some(out)
}

fn ifindex(iface: &str) -> Result<u32> {
    let iface_c = std::ffi::CString::new(iface.as_bytes())
        .map_err(|_| anyhow::anyhow!("interface name contains NUL byte: {iface:?}"))?;
    let ifindex = unsafe { libc::if_nametoindex(iface_c.as_ptr()) };
    if ifindex == 0 {
        bail!(
            "if_nametoindex({iface}) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(ifindex)
}

fn ifname_from_ifindex(ifindex: u32) -> Option<String> {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    let ptr = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr()) };
    if ptr.is_null() {
        return None;
    }
    let cstr = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    cstr.to_str().ok().map(ToString::to_string)
}

fn channel_to_freq(channel: u8) -> u32 {
    if channel == 14 {
        2484
    } else {
        2407 + (channel as u32 * 5)
    }
}

fn iface_mac(iface: &str) -> Result<[u8; 6]> {
    let iface_c = std::ffi::CString::new(iface.as_bytes())
        .map_err(|_| anyhow::anyhow!("interface name contains NUL byte: {iface:?}"))?;
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to open ioctl socket");
    }
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = iface_c.as_bytes_with_nul();
    if name_bytes.len() > request.ifr_name.len() {
        unsafe {
            libc::close(fd);
        }
        bail!("interface name too long: {iface}");
    }
    for (idx, byte) in name_bytes.iter().enumerate() {
        request.ifr_name[idx] = *byte as libc::c_char;
    }
    let rc = unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR as libc::Ioctl, &mut request) };
    let error = std::io::Error::last_os_error();
    unsafe {
        libc::close(fd);
    }
    if rc < 0 {
        return Err(error).with_context(|| format!("failed to read hardware address for {iface}"));
    }
    let mut out = [0_u8; 6];
    unsafe {
        let data = request.ifr_ifru.ifru_hwaddr.sa_data;
        for (idx, slot) in out.iter_mut().enumerate() {
            *slot = data[idx] as u8;
        }
    }
    Ok(out)
}

fn parse_mac(value: Option<&str>) -> Option<[u8; 6]> {
    let value = value?;
    let compact = value.replace([':', '-'], "");
    if compact.len() != 12 {
        return None;
    }
    let mut out = [0_u8; 6];
    for (idx, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&compact[idx * 2..idx * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn raw_wifi_destination(value: Option<&str>, variant: &str) -> [u8; 6] {
    if let Some(value) = value {
        if let Some(mac) = value
            .strip_prefix("rx:")
            .or_else(|| value.strip_prefix("raw:"))
            .and_then(|mac| parse_mac(Some(mac)))
        {
            // NAN data frames use ordinary 802.11 address semantics. The
            // raw-receive-MAC XOR convention is only for the ESP-NOW/action
            // probe path.
            if variant != "nan_data" && variant != "nan_data_active" {
                return raw_receive_mac(mac);
            }
            return mac;
        }
        if let Some(mac) = parse_mac(Some(value)) {
            return mac;
        }
    }
    if variant == "multicast_data" || variant == "multicast_data_active" {
        RAW_WIFI_MULTICAST
    } else {
        RAW_WIFI_BROADCAST
    }
}

fn raw_wifi_destination_mode(value: Option<&str>, variant: &str) -> &'static str {
    if let Some(value) = value {
        if (value.starts_with("rx:") || value.starts_with("raw:"))
            && variant != "nan_data"
            && variant != "nan_data_active"
        {
            return "peer_raw_receive_mac";
        }
        if parse_mac(Some(value)).is_some() {
            return "explicit_mac";
        }
    }
    if variant == "multicast_data" || variant == "multicast_data_active" {
        "ipv6_multicast_ff02_5227"
    } else {
        "broadcast"
    }
}

fn raw_wifi_source(value: Option<&str>, iface: &str) -> Result<[u8; 6]> {
    if let Some(value) = value {
        if let Some(mac) = parse_mac(Some(value)) {
            return Ok(mac);
        }
        bail!("invalid source MAC {value:?}");
    }
    iface_mac(iface)
}

fn raw_wifi_source_mode(value: Option<&str>) -> &'static str {
    if value.is_some() {
        "explicit_mac"
    } else {
        "interface_mac"
    }
}

fn raw_receive_mac(mut mac: [u8; 6]) -> [u8; 6] {
    mac[0] ^= 0x01;
    mac
}

fn frame_type(frame: &[u8]) -> u8 {
    (frame.first().copied().unwrap_or(0) & 0x0c) >> 2
}

fn frame_subtype(frame: &[u8]) -> u8 {
    frame.first().copied().unwrap_or(0) >> 4
}

fn json_scalar_string(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| value.to_string())
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NlMsgErr {
    error: i32,
    msg: NlMsgHdr,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IfInfoMsg {
    ifi_family: u8,
    ifi_pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IfAddrMsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RtAttrHdr {
    rta_len: u16,
    rta_type: u16,
}

const NLM_F_CREATE: u16 = 0x400;
const NLM_F_REPLACE: u16 = 0x100;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_BROADCAST: u16 = 4;

fn set_link_up(iface: &str) -> std::result::Result<CommandOutput, String> {
    let iface_c = std::ffi::CString::new(iface.as_bytes())
        .map_err(|_| format!("interface name contains NUL byte: {iface:?}"))?;
    let ifindex = unsafe { libc::if_nametoindex(iface_c.as_ptr()) };
    if ifindex == 0 {
        return Err(format!(
            "if_nametoindex({iface}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(format!(
            "failed to open rtnetlink socket: {}",
            std::io::Error::last_os_error()
        ));
    }

    let result = unsafe { send_setlink_up(fd, ifindex as i32) };
    unsafe {
        libc::close(fd);
    }
    result.map(|()| CommandOutput {
        status: Some(0),
        stdout: format!("set {iface} up via rtnetlink"),
        stderr: String::new(),
    })
}

fn set_ipv4_address(
    iface: &str,
    address: std::net::Ipv4Addr,
    prefix: u8,
) -> std::result::Result<CommandOutput, String> {
    let ifindex = ifindex(iface).map_err(|error| error.to_string())?;
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(format!(
            "failed to open rtnetlink socket: {}",
            std::io::Error::last_os_error()
        ));
    }

    let result = unsafe { send_setaddr(fd, ifindex, address, prefix) };
    unsafe {
        libc::close(fd);
    }
    result.map(|()| CommandOutput {
        status: Some(0),
        stdout: format!("set {iface} IPv4 address {address}/{prefix} via rtnetlink"),
        stderr: String::new(),
    })
}

unsafe fn send_setaddr(
    fd: RawFd,
    ifindex: u32,
    address: std::net::Ipv4Addr,
    prefix: u8,
) -> std::result::Result<(), String> {
    let header_len = std::mem::size_of::<NlMsgHdr>();
    let info_len = std::mem::size_of::<IfAddrMsg>();
    let mut request = Vec::with_capacity(header_len + info_len + 16);
    let header = NlMsgHdr {
        nlmsg_len: 0,
        nlmsg_type: libc::RTM_NEWADDR,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        nlmsg_seq: 2,
        nlmsg_pid: 0,
    };
    let info = IfAddrMsg {
        ifa_family: libc::AF_INET as u8,
        ifa_prefixlen: prefix,
        ifa_flags: 0,
        ifa_scope: 0,
        ifa_index: ifindex,
    };
    append_struct(&mut request, &header);
    append_struct(&mut request, &info);
    let bytes = address.octets();
    append_rt_attr(&mut request, IFA_ADDRESS, &bytes);
    append_rt_attr(&mut request, IFA_LOCAL, &bytes);
    let ip = u32::from_be_bytes(bytes);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    append_rt_attr(
        &mut request,
        IFA_BROADCAST,
        &((ip & mask) | !mask).to_be_bytes(),
    );
    let message_len = request.len() as u32;
    let header_ptr = request.as_mut_ptr() as *mut NlMsgHdr;
    unsafe {
        (*header_ptr).nlmsg_len = message_len;
    }

    let written = unsafe {
        libc::send(
            fd,
            request.as_ptr() as *const libc::c_void,
            request.len(),
            0,
        )
    };
    if written < 0 {
        return Err(format!(
            "failed to send RTM_NEWADDR: {}",
            std::io::Error::last_os_error()
        ));
    }
    if written as usize != request.len() {
        return Err(format!(
            "short RTM_NEWADDR write: wrote {written}, expected {}",
            request.len()
        ));
    }
    let mut response = [0u8; 4096];
    let read = unsafe {
        libc::recv(
            fd,
            response.as_mut_ptr() as *mut libc::c_void,
            response.len(),
            0,
        )
    };
    if read < 0 {
        return Err(format!(
            "failed to read RTM_NEWADDR ACK: {}",
            std::io::Error::last_os_error()
        ));
    }
    parse_netlink_ack(&response[..read as usize])
}

fn append_rt_attr(out: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let raw_len = std::mem::size_of::<RtAttrHdr>() + payload.len();
    let aligned_len = (raw_len + 3) & !3;
    let header = RtAttrHdr {
        rta_len: raw_len as u16,
        rta_type: attr_type,
    };
    append_struct(out, &header);
    out.extend_from_slice(payload);
    out.resize(out.len() + aligned_len - raw_len, 0);
}

unsafe fn send_setlink_up(fd: RawFd, ifindex: i32) -> std::result::Result<(), String> {
    let header_len = std::mem::size_of::<NlMsgHdr>();
    let info_len = std::mem::size_of::<IfInfoMsg>();
    let msg_len = header_len + info_len;
    let header = NlMsgHdr {
        nlmsg_len: msg_len as u32,
        nlmsg_type: libc::RTM_NEWLINK,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };
    let mut info: IfInfoMsg = unsafe { std::mem::zeroed() };
    info.ifi_family = libc::AF_UNSPEC as u8;
    info.ifi_index = ifindex;
    info.ifi_flags = IFF_UP;
    info.ifi_change = IFF_UP;
    let mut request = Vec::with_capacity(msg_len);
    append_struct(&mut request, &header);
    append_struct(&mut request, &info);

    let written = unsafe {
        libc::send(
            fd,
            request.as_ptr() as *const libc::c_void,
            request.len(),
            0,
        )
    };
    if written < 0 {
        return Err(format!(
            "failed to send RTM_NEWLINK: {}",
            std::io::Error::last_os_error()
        ));
    }
    if written as usize != request.len() {
        return Err(format!(
            "short RTM_NEWLINK write: wrote {written}, expected {}",
            request.len()
        ));
    }

    let mut response = [0u8; 4096];
    let read = unsafe {
        libc::recv(
            fd,
            response.as_mut_ptr() as *mut libc::c_void,
            response.len(),
            0,
        )
    };
    if read < 0 {
        return Err(format!(
            "failed to read RTM_NEWLINK ACK: {}",
            std::io::Error::last_os_error()
        ));
    }
    parse_netlink_ack(&response[..read as usize])
}

fn append_struct<T>(out: &mut Vec<u8>, value: &T) {
    let bytes = unsafe {
        std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>())
    };
    out.extend_from_slice(bytes);
}

fn parse_netlink_ack(response: &[u8]) -> std::result::Result<(), String> {
    if response.len() < std::mem::size_of::<NlMsgHdr>() {
        return Err("short netlink ACK".to_string());
    }
    let header = unsafe { std::ptr::read_unaligned(response.as_ptr() as *const NlMsgHdr) };
    if header.nlmsg_type != NLMSG_ERROR {
        return Ok(());
    }
    if response.len() < std::mem::size_of::<NlMsgHdr>() + std::mem::size_of::<NlMsgErr>() {
        return Err("short netlink error ACK".to_string());
    }
    let err_offset = std::mem::size_of::<NlMsgHdr>();
    let error = unsafe { std::ptr::read_unaligned(response[err_offset..].as_ptr() as *const i32) };
    if error == 0 {
        Ok(())
    } else {
        let errno = -error;
        Err(format!(
            "RTM_NEWLINK failed: {}",
            std::io::Error::from_raw_os_error(errno)
        ))
    }
}

#[derive(Debug)]
struct CommandOutput {
    status: Option<i32>,
    stdout: String,
    stderr: String,
}

fn command_result_json(output: std::result::Result<CommandOutput, String>) -> Value {
    match output {
        Ok(output) => json!({
            "ok": output.status == Some(0),
            "status": output.status,
            "stdout": output.stdout,
            "stderr": output.stderr,
        }),
        Err(error) => json!({ "ok": false, "error": error }),
    }
}

fn result_json<T>(output: Result<T>) -> Value {
    match output {
        Ok(_) => json!({ "ok": true }),
        Err(error) => json!({ "ok": false, "error": format!("{error:#}") }),
    }
}

fn wifi_iface(value: Option<String>) -> String {
    value
        .or_else(|| std::env::var("LMESH_WIFI_IFACE").ok())
        .unwrap_or_else(|| DEFAULT_WIFI_IFACE.to_string())
}

fn raw_wifi_channel(value: Option<u8>) -> u8 {
    value.unwrap_or(DEFAULT_RAW_WIFI_CHANNEL).clamp(1, 13)
}

fn process_caps() -> Value {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let caps = status
        .lines()
        .filter(|line| {
            line.starts_with("CapInh:")
                || line.starts_with("CapPrm:")
                || line.starts_with("CapEff:")
                || line.starts_with("CapBnd:")
                || line.starts_with("CapAmb:")
        })
        .map(|line| {
            let mut parts = line.split_whitespace();
            let name = parts.next().unwrap_or("").trim_end_matches(':').to_string();
            let value = parts.next().unwrap_or("").to_string();
            (name, Value::String(value))
        })
        .collect::<serde_json::Map<_, _>>();
    Value::Object(caps)
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

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Android's pre-identity NAN callback historically emitted this ASCII
/// placeholder. It is not a stable device identity and must not hide a later
/// announce carrying the framework-provided NAN MAC.
fn is_placeholder_announce_id(device_id: &[u8]) -> bool {
    device_id == b"000000" || device_id.iter().all(|byte| *byte == 0)
}

fn colon_mac(bytes: &[u8; 6]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn peer_availability_name(availability: dmesh_rawnan::PeerAvailability) -> &'static str {
    match availability {
        dmesh_rawnan::PeerAvailability::Infra => "infra",
        dmesh_rawnan::PeerAvailability::Dw0Dw8 => "dw0_dw8",
    }
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn now_millis_u64() -> u64 {
    now_millis().min(u64::MAX as u128) as u64
}

fn now_micros_u64() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announce_identity_validation_accepts_unsigned_devices_and_rejects_fake_hosts() {
        let unsigned = dmesh_server::announce::Announce::discovery([0x41; 16], 16, 1, 0, 0);
        assert!(announce_identity_valid(unsigned));

        let mut fake = unsigned;
        assert!(fake.set_public_key(b"not-a-p256-spki"));
        assert!(fake.set_signature(&[0x55; dmesh_server::announce::SIGNATURE_LEN]));
        assert!(!announce_identity_valid(fake));
    }

    #[test]
    fn discovered_device_log_records_only_new_and_dropped_nodes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("discovery.jsonl");
        let mut registry = DiscoveredDeviceRegistry::with_change_log(path.clone());
        let mut id = [0_u8; 16];
        id[..6].copy_from_slice(b"peer-a");
        let announce = dmesh_server::announce::Announce::discovery(id, 6, 1, 0, 7);
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
            },
        );
        registry.snapshot();
        let lines = std::fs::read_to_string(&path).unwrap();
        assert_eq!(lines.lines().count(), 2);
        assert!(lines.contains("\"change\":\"dropped\""));
    }

    #[test]
    fn discovered_device_log_restores_recent_nodes_across_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("discovery.jsonl");
        let mut id = [0_u8; 16];
        id[..6].copy_from_slice(b"peer-r");
        let announce = dmesh_server::announce::Announce::discovery(id, 6, 1, 0, 7);
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
        assert!(queue_nan_followup(&pending, peer, 1, vec![1, 2]));
        assert!(!queue_nan_followup(&pending, peer, 1, vec![1, 2]));
        for index in 0..MAX_PENDING_NAN_FOLLOWUPS {
            assert!(queue_nan_followup(
                &pending,
                [2, 0, 0, 0, 1, index as u8],
                1,
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
        assert_eq!(management_ie_bytes(assoc_ies, 61).map(|ie| ie[0]), Some(11));
        assert_eq!(OPEN_AP_OFDM_BASIC_RATES, [0x8c]);
        assert_eq!(OPEN_AP_OFDM_EXTENDED_RATES, [0x30, 0x48, 0x60, 0x6c]);
        assert_eq!(open_ap_basic_rates(), &[0x8c]);
    }

    #[test]
    fn hostapd_ht20_probe_response_matches_beacon_and_association_capabilities() {
        let channel = 6;
        let probe = build_open_probe_resp_with_ies(
            [1; 6],
            "Direct-test",
            channel,
            0x0401,
            &hostapd_open_ap_probe_ies("Direct-test", channel, false).unwrap(),
        )
        .unwrap();
        let probe_ies = &probe[IEEE80211_BODY + 12..];
        let beacon_ies = hostapd_open_ap_probe_ies("Direct-test", channel, false).unwrap();
        let assoc = build_open_assoc_response([1; 6], [2; 6], 1, true, channel, false);
        let assoc_ies = &assoc[IEEE80211_BODY + 6..];

        assert_eq!(read_u16_at(&probe, IEEE80211_BODY + 10), Some(0x0401));
        assert_eq!(probe_ies, beacon_ies);
        assert_eq!(management_ie_bytes(probe_ies, 1), Some(&[0x8c][..]));
        assert_eq!(
            management_ie_bytes(probe_ies, 50),
            Some(OPEN_AP_OFDM_EXTENDED_RATES.as_slice())
        );
        assert_eq!(
            management_ie_bytes(probe_ies, 45),
            management_ie_bytes(assoc_ies, 45)
        );
        assert_eq!(
            management_ie_bytes(probe_ies, 61),
            management_ie_bytes(assoc_ies, 61)
        );
        assert!(management_ie_bytes(probe_ies, 221).is_some());
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
    fn raw_wifi_vendor_action_round_trips() {
        let dst = [0xff; 6];
        let src = [0x02, 0x00, 0x00, 0xaa, 0xbb, 0xcc];
        let frame = build_dmesh_vendor_action_frame(dst, src, b"stats").unwrap();

        assert_eq!(&frame[..4], &[0xd0, 0x00, 0x00, 0x00]);
        assert_eq!(
            &frame[IEEE80211_BODY..IEEE80211_BODY + DMESH_VENDOR_ACTION_LEN],
            &dmesh_vendor_action_header(dst)
        );
        assert_eq!(
            &frame[IEEE80211_BODY..IEEE80211_BODY + 4],
            &[0x7f, 0x18, 0xfe, 0x34]
        );
        assert_eq!(&frame[IEEE80211_BODY + 4..IEEE80211_BODY + 8], &[0xff; 4]);
        assert_eq!(frame[IEEE80211_BODY + DMESH_VENDOR_ACTION_LEN], 0xdd);

        let parsed = parse_dmesh_vendor_action(&frame, "wlan-test").unwrap();
        assert_eq!(parsed["protocol"], "dmesh_wifi_raw");
        assert_eq!(parsed["vendor_marker"], "espnow_dmesh");
        assert_eq!(parsed["mesh_dst4"], "ffffffff");
        assert_eq!(parsed["source"], "02:00:00:aa:bb:cc");
        assert_eq!(parsed["destination"], "ff:ff:ff:ff:ff:ff");
        assert_eq!(parsed["payload_text"], "stats");
    }

    #[test]
    fn raw_nan_transport_action_uses_unicast_a1_a2_and_cluster_a3() {
        let dst = [0x14, 0xc1, 0x9f, 0xe5, 0x98, 0x00];
        let src = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let bssid = [0x50, 0x6f, 0x9a, 0x01, 0x54, 0x6c];
        let frame = build_dmesh_vendor_action_frame_with_bssid(dst, src, bssid, b"DMTB").unwrap();

        assert_eq!(&frame[4..10], &dst); // A1: addressed device
        assert_eq!(&frame[10..16], &src); // A2: host Wi-Fi adapter
        assert_eq!(&frame[16..22], &bssid); // A3: NAN cluster, not broadcast
        assert_ne!(&frame[4..10], &[0xff; 6]);
        assert_ne!(&frame[16..22], &[0xff; 6]);
    }

    #[test]
    fn monitor_fcs_is_removed_only_when_crc_matches() {
        let frame =
            build_dmesh_vendor_action_frame([0xff; 6], [1, 2, 3, 4, 5, 6], b"ping").unwrap();
        let crc = crc32_ieee(&frame);
        let mut captured = frame.clone();
        captured.extend_from_slice(&crc.to_le_bytes());
        assert_eq!(strip_valid_fcs(&captured), frame.as_slice());

        let mut arbitrary_tail = frame;
        arbitrary_tail.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(strip_valid_fcs(&arbitrary_tail), arbitrary_tail.as_slice());
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
    fn raw_wifi_accepts_radiotap_prefix() {
        let frame =
            build_dmesh_vendor_action_frame([0xff; 6], [1, 2, 3, 4, 5, 6], b"ping").unwrap();
        let mut packet = vec![0, 0, 8, 0, 0, 0, 0, 0];
        packet.extend_from_slice(&frame);

        assert_eq!(ieee80211_frame(&packet).unwrap(), frame.as_slice());
    }

    #[test]
    fn monitor_tx_radiotap_keeps_legacy_rate_and_no_ack() {
        let packet = build_radiotap_packet(&[0xd0, 0x00, 0x00, 0x00]);
        assert_eq!(
            &packet[..12],
            &[
                0x00, 0x00, 0x0c, 0x00, 0x04, 0x80, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00
            ]
        );
        assert_eq!(&packet[12..], &[0xd0, 0x00, 0x00, 0x00]);
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
    fn nan_control_frames_are_identified_for_six_mbps_policy() {
        let action = build_dmesh_vendor_action_frame_with_bssid(
            [0xff; 6],
            [2, 0, 0, 0xaa, 0xbb, 0xcc],
            [0x50, 0x6f, 0x9a, 1, 2, 3],
            b"probe",
        )
        .unwrap();
        assert!(is_nan_control_frame(&action));

        let ordinary =
            build_dmesh_vendor_action_frame([0xff; 6], [2, 0, 0, 0xaa, 0xbb, 0xcc], b"probe")
                .unwrap();
        assert!(!is_nan_control_frame(&ordinary));
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
        let payload = b"DMTB-test";
        let frame = build_dmesh_nan_raw_data_frame(bssid, dst, src, &RAWNAN_LLC_DEFAULT, payload);
        assert_eq!(&frame[IEEE80211_ADDR1..IEEE80211_ADDR1 + 6], &dst);
        assert_eq!(&frame[IEEE80211_ADDR3..IEEE80211_ADDR3 + 6], &bssid);
        assert_eq!(
            &frame[IEEE80211_BODY..IEEE80211_BODY + IEEE80211_LLC_SNAP_LEN],
            &RAWNAN_LLC_DEFAULT
        );
        let parsed = parse_dmesh_wifi_frame(&frame, "wlan1", "test").unwrap();
        assert_eq!(parsed["layout"], "nan_raw_data");
        assert_eq!(parsed["payload_text"], "DMTB-test");
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
    fn data_path_ethernet_frame_round_trips() {
        let src = [0x44, 0x94, 0xfc, 0xe4, 0x84, 0x15];
        let frame = build_dmesh_ethernet_frame(RAW_WIFI_MULTICAST, src, b"stats");
        let parsed =
            parse_dmesh_ethernet_frame(&frame, "wlan-test", &[RAW_WIFI_MULTICAST]).unwrap();

        assert_eq!(&frame[..6], &RAW_WIFI_MULTICAST);
        assert_eq!(&frame[6..12], &src);
        assert_eq!(&frame[12..14], &ETH_P_DMESH.to_be_bytes());
        assert_eq!(parsed["layout"], "ethernet");
        assert_eq!(parsed["payload_text"], "stats");
    }

    #[test]
    fn parses_iw_scan_bss_entries() {
        let scan = r#"
BSS a4:2b:b0:bd:00:e3(on wlan1)
	freq: 2437
	signal: -31.00 dBm
	capability: ESS ShortSlotTime (0x0401)
	SSID: Direct-E3-Dmesh-local
BSS 44:94:fc:e4:84:15(on wlan1)
	freq: 2437
	signal: -34.00 dBm
	SSID: Direct-15-Dmesh-local
	RSN:
	BSS Load:
		* station count: 1
"#;
        let entries = parse_iw_scan(scan);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["bssid"], "a4:2b:b0:bd:00:e3");
        assert_eq!(entries[0]["ssid"], "Direct-E3-Dmesh-local");
        assert_eq!(entries[0]["channel"], 6);
        assert_eq!(entries[0]["auth"], "open");
        assert_eq!(entries[1]["auth"], "wpa2");
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
}
