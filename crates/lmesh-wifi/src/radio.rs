use anyhow::{Context, Result, bail};
use mesh::message::{
    FIELD_CTRL_DIR, FIELD_IFACE, FIELD_LEN, FIELD_MEDIUM, FIELD_NETWORK, FIELD_NODE, FIELD_PAYLOAD,
    FIELD_RADIO_ID, FIELD_RSSI, FIELD_SNR, FIELD_STATUS, MeshMessage, MeshMessageCodec, TextRecord,
};
use minicbor::{Decoder, Encoder, data::Type};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::schema::FirmwareSchema;
use dmesh_rawnan::protocol as radio_protocol;
use dmesh_rawnan::{Action as RawNanAction, NanState, RxFrame as RawNanRxFrame};
use dmesh_transport::{encode_bench_stream, ConnectionId, FLAG_FIXED, Frame, ShortHeader, StreamFrame};
use uart_codec::codec::{UART_ESCAPE, UART_FLAG};

const DEFAULT_WIFI_IFACE: &str = "wlan1";
const DEFAULT_ESP_NAN_GATEWAY: &str = "lora1";
const DEFAULT_WPA_CTRL_DIR: &str = "/run/mesh/wpa-supplicant-nan";
const DEFAULT_WPA_SERVICE_NAME: &str = "dmesh";
const DEFAULT_NAN_TTL_SECS: u32 = 3600;
const DEFAULT_ESP_COMMAND_TIMEOUT_MS: u64 = 3_000;
const ESP_SLEEPY_RENDEZVOUS_TIMEOUT_MS: u64 = 8_000;
// Firmware raw-NAN peers normally wake every four seconds for a short window.
// A 700 ms probe cadence walks that phase rather than repeatedly landing on a
// fixed 250/500 ms boundary.
const STABILITY_HOST_NAN_RETRY_MS: u64 = 700;
const DEFAULT_HCI_DEV: u16 = 0;
const DEFAULT_RAW_WIFI_CHANNEL: u8 = 6;
const DEFAULT_RAW_WIFI_LISTEN_SECS: u64 = 60;
const DEFAULT_LMESH_CONFIG_FILE: &str = "/home/system/etc/lmesh/lmesh.toml";
const REMOTE_REQUEST_ID_KEY: u16 = 333;
static REMOTE_COMMAND_SEQUENCE: AtomicU64 = AtomicU64::new(1);
// Raw monitor traffic is high volume (especially with an APSTA ESP peer), so
// a short global ring could evict the semantic NAN event before a diagnostic
// client reads it. Keep enough history for one discovery/benchmark interval.
const MAX_HISTORY: usize = 4096;
const ETH_P_ALL: u16 = 0x0003;
const ETH_P_DMESH: u16 = 0x88b5;
const ETHERNET_HEADER_LEN: usize = 14;
const IEEE80211_LLC_SNAP_LEN: usize = 8;
const PACKET_ADD_MEMBERSHIP: libc::c_int = 1;
const PACKET_MR_MULTICAST: libc::c_ushort = 0;
const RFC2217_IAC: u8 = 0xff;
const RFC2217_DONT: u8 = 0xfe;
const RFC2217_DO: u8 = 0xfd;
const RFC2217_WONT: u8 = 0xfc;
const RFC2217_WILL: u8 = 0xfb;
const RFC2217_SB: u8 = 0xfa;
const RFC2217_SE: u8 = 0xf0;
const RFC2217_SE_ALT: u8 = 0xef;
const RFC2217_BINARY: u8 = 0x00;
const RFC2217_COM_PORT_OPTION: u8 = 0x2c;
const RFC2217_SET_BAUDRATE: u8 = 1;
const RFC2217_SET_DATASIZE: u8 = 2;
const RFC2217_SET_PARITY: u8 = 3;
const RFC2217_SET_STOPSIZE: u8 = 4;
const RFC2217_SET_CONTROL: u8 = 5;
const RFC2217_PURGE_DATA: u8 = 12;
const SERIAL_FORWARD_MAX_PENDING: usize = 4 * 1024 * 1024;
const SERIAL_FORWARD_IO_BUFFER_BYTES: usize = 16 * 1024;
const SERIAL_LOG_FIELD_MAX: usize = 1800;
// Local UDS control prefix; it is consumed by lmesh and never sent to the
// firmware. It is retained for compatibility with older callers, but it must
// not bypass the sleepy-device queue: a direct host UART write cannot wake a
// NAN sleeper.
const SERIAL_FORWARD_FORCE_DIRECT_PREFIX: &[u8] = b"\0DMESH-DIRECT\n";
const SERIAL_RESET_NONE: u8 = 0;
// Firmware keeps its normal console receptive during the first ten seconds
// after a recovery reset.  The forward must use that documented window to
// deliver queued framed commands even if the retained duty profile has its
// periodic UART heartbeat disabled.
// The ROM and second-stage bootloader use a different baud rate.  Do not send
// a 460800 framed command until the application has taken over UART0.
// Physical PRG wakes firmware through a short button task before UART RX is
// re-armed. Keep incoming client bytes in the kernel socket buffer until that
// transition is complete.
// UART is an HDLC/PPP-style byte stream. Its payload is compact CBOR; the
// generic mesh stream envelope remains at the lmesh UDS boundary.
const FIRMWARE_UART_FLAG: u8 = UART_FLAG;
const FIRMWARE_UART_ESCAPE: u8 = UART_ESCAPE;

/// Host-side adapter from the no-std UART codec's raw payloads to the shared
/// mesh CBOR stream-frame representation used by the Linux service.
#[derive(Default)]
struct FirmwareUartDecoder {
    codec: uart_codec::codec::Decoder,
}

impl FirmwareUartDecoder {
    fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.codec
            .push(bytes)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?
            .into_iter()
            .map(|payload| mesh::cbor::encode_stream_frame(&payload))
            .collect()
    }

    fn take_frame_activity(&mut self) -> bool {
        self.codec.take_frame_activity()
    }
}
const NAN_SLEEPY_START_TAG: u8 = 6;
const DMESH_BOOT_METHOD_SELECT: u32 = 60010;
// Host-side decoder compatibility for already deployed stage2 records. New
// selectors and all new firmware images use the CBOR event above.
const DMESH_BOOT_MAGIC: &[u8; 4] = b"DMB1";
const DMESH_BOOT_VERSION: u8 = 1;
const DMESH_BOOT_ROLE_STAGE2: u8 = 3;
const DMESH_BOOT_PARTITION_BOOTLOADER: u8 = 0;
// Reset requests are sampled between events. 100 ms keeps them responsive
// without making every idle managed forward wake one hundred times per second.
const SERIAL_FORWARD_POLL_TIMEOUT_MS: i32 = 100;
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
const NL80211_CMD_NEW_INTERFACE: u8 = 7;
const NL80211_CMD_DEL_INTERFACE: u8 = 8;
const NL80211_CMD_GET_INTERFACE: u8 = 5;
const NL80211_CMD_SET_INTERFACE: u8 = 6;
const NL80211_CMD_REMAIN_ON_CHANNEL: u8 = 55;
const NL80211_CMD_REGISTER_FRAME: u8 = 58;
const NL80211_CMD_FRAME: u8 = 59;
const NL80211_CMD_START_AP: u8 = 15;
const NL80211_CMD_STOP_AP: u8 = 16;
const NL80211_CMD_GET_STATION: u8 = 17;
const NL80211_CMD_NEW_STATION: u8 = 19;
const NL80211_CMD_DEL_STATION: u8 = 20;
const NL80211_CMD_CONNECT: u8 = 46;
const NL80211_CMD_START_NAN: u8 = 66;
const NL80211_CMD_STOP_NAN: u8 = 67;
const NL80211_CMD_ADD_NAN_FUNCTION: u8 = 68;
const NL80211_CMD_DEL_NAN_FUNCTION: u8 = 69;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFTYPE: u16 = 5;
const NL80211_ATTR_WIPHY: u16 = 1;
const NL80211_ATTR_IFNAME: u16 = 4;
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
const NL80211_ATTR_RECEIVE_MULTICAST: u16 = 289;
const NL80211_ATTR_DONT_WAIT_FOR_ACK: u16 = 142;
const NL80211_ATTR_PROBE_RESP: u16 = 145;
const NL80211_ATTR_RX_SIGNAL_DBM: u16 = 151;
const NL80211_ATTR_CHANNEL_WIDTH: u16 = 159;
const NL80211_ATTR_CENTER_FREQ1: u16 = 160;
const NL80211_ATTR_SOCKET_OWNER: u16 = 204;
const NL80211_ATTR_WDEV: u16 = 153;
const NL80211_ATTR_COOKIE: u16 = 88;
const NL80211_ATTR_NAN_MASTER_PREF: u16 = 238;
const NL80211_ATTR_BANDS: u16 = 239;
const NL80211_ATTR_NAN_FUNC: u16 = 240;
const NL80211_ATTR_NAN_MATCH: u16 = 241;
const NL80211_ATTR_NAN_FUNC_INST_ID: u16 = 242;
const NL80211_AUTHTYPE_OPEN_SYSTEM: u32 = 0;
const NL80211_HIDDEN_SSID_NOT_IN_USE: u32 = 0;
const NL80211_CHAN_NO_HT: u32 = 0;
const NL80211_CHAN_HT20: u32 = 1;
const NL80211_CHAN_WIDTH_20_NOHT: u32 = 0;
const NL80211_CHAN_WIDTH_20: u32 = 1;
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
const NL80211_RATE_INFO_BITRATE: u16 = 1;
const NL80211_RATE_INFO_BITRATE32: u16 = 5;
const NL80211_IFTYPE_STATION: u32 = 2;
const NL80211_IFTYPE_AP: u32 = 3;
const NL80211_IFTYPE_OCB: u32 = 11;
const NL80211_IFTYPE_NAN: u32 = 12;
const NL80211_STA_FLAG_AUTHORIZED: u32 = 1 << 1;
const NL80211_STA_FLAG_SHORT_PREAMBLE: u32 = 1 << 2;
const NL80211_STA_FLAG_WME: u32 = 1 << 3;
const NL80211_STA_FLAG_AUTHENTICATED: u32 = 1 << 5;
const NL80211_STA_FLAG_ASSOCIATED: u32 = 1 << 7;
const NLM_F_DUMP: u16 = 0x300;
// Netlink attributes reserve the high two type bits for NLA_F_NESTED and
// NLA_F_NET_BYTEORDER.  Match the attribute number independently of those
// flags; station/rate information is commonly nested.
const NLA_TYPE_MASK: u16 = 0x3fff;
const DMESH_ESPNOW_PREFIX: [u8; 4] = [0x7f, 0x18, 0xfe, 0x34];
const DMESH_ESPNOW_TYPE: u8 = 0x04;
const DMESH_VENDOR_ACTION_LEN: usize = 9;
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
// this eight-byte LLC value is dmesh-transport directly, not IPv6/UDP.
const RAWNAN_LLC_DEFAULT: [u8; IEEE80211_LLC_SNAP_LEN] =
    [0xaa, 0xaa, 0x03, 0xd0, 0x4d, 0x45, 0x53, 0x48];
const NAN_UDP_SOURCE_PORT: u16 = 4242;
const NAN_UDP_DEST_PORT: u16 = 4243;
const AF_BLUETOOTH: libc::c_int = 31;
const BTPROTO_HCI: libc::c_int = 1;
const HCI_CHANNEL_RAW: u16 = 0;
const HCI_COMMAND_PKT: u8 = 0x01;
const HCIDEVUP: libc::c_int = 0x400448c9_u32 as libc::c_int;
const OGF_LE_CTL: u16 = 0x08;
const OCF_LE_SET_ADV_PARAMETERS: u16 = 0x0006;
const OCF_LE_SET_ADV_DATA: u16 = 0x0008;
const OCF_LE_SET_ADV_ENABLE: u16 = 0x000a;
const OCF_LE_SET_SCAN_PARAMETERS: u16 = 0x000b;
const OCF_LE_SET_SCAN_ENABLE: u16 = 0x000c;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const IFF_UP: u32 = 0x1;

/// Linux radio backend used by the lmesh JSONL methods.
#[derive(Clone, Default)]
pub struct RadioService {
    history: Arc<Mutex<VecDeque<RadioEvent>>>,
    radios: Arc<Vec<RadioAdapter>>,
    raw_wifi_listeners: Arc<Mutex<HashSet<String>>>,
    rawnan_state: Arc<Mutex<NanState>>,
    native_nan: Arc<Mutex<BTreeMap<String, NativeNanRuntime>>>,
    wifi_ap_handles: Arc<Mutex<BTreeMap<String, ApRuntime>>>,
    serial_forwards: Arc<Mutex<BTreeMap<String, SerialForwardRuntime>>>,
    /// Persistent TCP sessions initiated by Main after it joins STA.  These
    /// deliberately reverse the usual host->board direction: AP isolation
    /// commonly prevents the host from opening a connection to a station.
    esp_reverse_sessions: Arc<BTreeMap<String, ReverseMainRuntime>>,
    /// Default infrastructure gateway for configured ESP targets. A missing
    /// explicit `gateway` on `esp.serial.command` is resolved here; all ESP
    /// UART commands still require a managed forward.
    esp_gateway: String,
    esp_targets: Arc<BTreeMap<String, String>>,
    /// Approximate target idle deadlines for NAN-created raw-action sessions.
    esp_sessions: Arc<Mutex<BTreeMap<String, Instant>>>,
    serial_log: Option<Arc<Mutex<SerialForwardLog>>>,
    stability: Arc<Mutex<Option<StabilityRuntime>>>,
    uart_enabled: bool,
}

impl RadioService {
    /// Create a radio service from environment and optional MESH_HOME/lmesh.toml config.
    pub fn from_environment() -> Self {
        Self::from_environment_with_uart(true)
    }

    /// Create a Wi-Fi-only backend without opening configured serial forwards.
    ///
    /// The full lmesh process and lmesh-uart use [`Self::from_environment`].
    /// The standalone Wi-Fi service uses this constructor so it can own AP,
    /// STA, and NAN interfaces without taking UART devices or serial sockets.
    pub fn from_environment_without_uart() -> Self {
        Self::from_environment_with_uart(false)
    }

    fn from_environment_with_uart(enable_uart: bool) -> Self {
        let serial_log = enable_uart
            .then(configured_serial_log_path)
            .flatten()
            .and_then(|path| match SerialForwardLog::open(&path) {
                Ok(log) => Some(Arc::new(Mutex::new(log))),
                Err(error) => {
                    tracing::warn!(path = %path, error = %error, "serial_forward_log_disabled");
                    None
                }
            });
        let reverse_sessions = configured_esp_reverse_sessions();
        let service = Self {
            history: Arc::new(Mutex::new(VecDeque::new())),
            radios: Arc::new(load_radio_adapters()),
            raw_wifi_listeners: Arc::new(Mutex::new(HashSet::new())),
            rawnan_state: Arc::new(Mutex::new(NanState::new(5_000_000))),
            native_nan: Arc::new(Mutex::new(BTreeMap::new())),
            wifi_ap_handles: Arc::new(Mutex::new(BTreeMap::new())),
            serial_forwards: Arc::new(Mutex::new(BTreeMap::new())),
            esp_reverse_sessions: Arc::new(reverse_sessions),
            esp_gateway: configured_esp_gateway(),
            esp_targets: Arc::new(configured_esp_targets()),
            esp_sessions: Arc::new(Mutex::new(BTreeMap::new())),
            serial_log,
            stability: Arc::new(Mutex::new(None)),
            uart_enabled: enable_uart,
        };
        if enable_uart {
            service.start_configured_serial_forwards();
            service.start_configured_esp_reverse_sessions();
        }
        service
    }

    /// Report whether this backend owns UART forwards and serial logging.
    pub fn uart_enabled(&self) -> bool {
        self.uart_enabled
    }

    pub fn default_esp_route(
        &self,
        port: Option<&str>,
        adapter: Option<&str>,
    ) -> Option<(String, String)> {
        resolve_esp_route(&self.esp_gateway, &self.esp_targets, port, adapter)
    }

    /// Start a background LoRa discovery check through an existing managed UDS
    /// forward. The managed forward remains the sole physical TTY owner.
    pub fn stability_start(
        &self,
        source: Option<String>,
        expected: Option<String>,
        interval_sec: Option<u64>,
        wait_sec: Option<u64>,
        cycles: Option<u32>,
        host_nan: Option<bool>,
    ) -> Value {
        let source = source.unwrap_or_else(|| "lora1".to_string());
        let interval_sec = interval_sec.unwrap_or(120).clamp(10, 86_400);
        let wait_sec = wait_sec.unwrap_or(12).clamp(2, 60);
        // Sleeping ESPs only listen in their own raw-NAN window. A host NAN
        // follow-up cannot be scheduled against that window through the
        // public WPA API, so direct host-to-sleepy-ESP NAN remains opt-in
        // diagnostics rather than the gateway stability default.
        let host_nan = host_nan.unwrap_or(false);
        let expected = expected
            .map(|value| split_csv(&value))
            .unwrap_or_else(|| self.stability_default_targets(&source));
        let Some(source_socket) = self.serial_forward_socket(&source) else {
            return json!({"ok": false, "source": source, "error": "source forward is not active"});
        };
        if expected.is_empty() {
            return json!({"ok": false, "source": source, "error": "no expected LoRa forwards"});
        }
        let mut guard = self
            .stability
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.as_ref().is_some_and(StabilityRuntime::running) {
            return json!({"ok": false, "error": "stability runner is already active", "status": guard.as_ref().map(StabilityRuntime::snapshot)});
        }
        let stop = Arc::new(AtomicBool::new(false));
        let state = Arc::new(Mutex::new(StabilityState::new(
            source.clone(),
            expected.clone(),
            interval_sec,
            wait_sec,
            cycles,
            host_nan,
        )));
        *guard = Some(StabilityRuntime {
            stop: stop.clone(),
            state: state.clone(),
        });
        drop(guard);

        let service = self.clone();
        std::thread::spawn(move || {
            let mut completed = 0_u32;
            while !stop.load(Ordering::Acquire)
                && cycles.map(|limit| completed < limit).unwrap_or(true)
            {
                let result = service.run_stability_cycle(
                    &source,
                    &source_socket,
                    &expected,
                    wait_sec,
                    host_nan,
                );
                completed = completed.saturating_add(1);
                {
                    let mut current = state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    current.cycles_completed = completed;
                    current.last = result.clone();
                    current.last_completed_ms = now_millis_u64();
                }
                service.record("esp.stability.cycle", result);
                append_stability_result(&state);
                let deadline = std::time::Instant::now() + Duration::from_secs(interval_sec);
                while !stop.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
            state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .running = false;
        });
        self.stability_status()
    }

    /// Return the managed stability runner state.
    pub fn stability_status(&self) -> Value {
        self.stability
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(StabilityRuntime::snapshot)
            .unwrap_or_else(|| json!({"ok": true, "running": false}))
    }

    /// Request that the stability runner stop after the current serial read.
    pub fn stability_stop(&self) -> Value {
        let guard = self
            .stability
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(runtime) = guard.as_ref() else {
            return json!({"ok": true, "running": false});
        };
        runtime.stop.store(true, Ordering::Release);
        runtime.snapshot()
    }

    fn stability_default_targets(&self, source: &str) -> Vec<String> {
        self.serial_forwards
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .keys()
            .filter(|id| id.as_str() != source && id.starts_with("lora"))
            .cloned()
            .collect()
    }

    fn serial_forward_socket(&self, id: &str) -> Option<String> {
        self.serial_forwards
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(id)
            .map(|forward| forward.socket_path.clone())
    }

    fn start_configured_esp_reverse_sessions(&self) {
        if self.esp_reverse_sessions.is_empty() {
            return;
        }
        let sessions = self.esp_reverse_sessions.clone();
        for session in sessions.values() {
            let session = session.clone();
            let uds_session = session.clone();
            let sessions = sessions.clone();
            std::thread::spawn(move || {
                if let Err(error) = reverse_main_uds_loop(uds_session.clone()) {
                    tracing::warn!(id = %uds_session.id, error = %error, "reverse_main_uds_exited");
                }
            });
            // One listener is enough for all configured boards on a port.
            // The first matching session owns it; all peers are checked
            // against the configured STA address before being accepted.
            if !sessions
                .values()
                .any(|other| other.id < session.id && other.port == session.port)
            {
                std::thread::spawn(move || {
                    if let Err(error) = reverse_main_accept_loop(session.port, sessions) {
                        tracing::warn!(port = session.port, error = %error, "reverse_main_listener_exited");
                    }
                });
            }
        }
    }

    fn run_stability_cycle(
        &self,
        source: &str,
        socket: &str,
        expected: &[String],
        wait_sec: u64,
        host_nan: bool,
    ) -> Value {
        let expected_macs = expected
            .iter()
            .map(|id| (id.clone(), self.stability_mac_suffix(id)))
            .collect::<BTreeMap<_, _>>();
        let nan_before = stability_nan_stats(socket);
        let output = match uds_console_exchange(socket, "mode ping=true", wait_sec * 1_000) {
            Ok(value) => value,
            Err(error) => return json!({"ok": false, "source": source, "error": error.to_string()}),
        };
        let nan_after = stability_nan_stats(socket);
        let nan = stability_nan_cycle(nan_before.as_ref(), nan_after.as_ref());
        let observed = parse_stability_pongs(&output);
        let host_nan =
            host_nan.then(|| self.run_host_nan_stability_cycle(&expected_macs, wait_sec));
        let missing = expected_macs
            .iter()
            .filter_map(|(id, mac)| match mac {
                Some(mac)
                    if observed
                        .iter()
                        .any(|pong| pong.get("from").and_then(Value::as_str) == Some(mac)) =>
                {
                    None
                }
                _ => Some(id.clone()),
            })
            .collect::<Vec<_>>();
        json!({
            "ok": missing.is_empty(),
            "source": source,
            "expected": expected_macs,
            "observed": observed,
            "missing": missing,
            "nan": nan,
            "host_nan": host_nan,
            "wait_sec": wait_sec,
        })
    }

    /// Probe the host-to-ESP raw-NAN command and reply path with firmware CBOR.
    fn run_host_nan_stability_cycle(
        &self,
        expected_macs: &BTreeMap<String, Option<String>>,
        wait_sec: u64,
    ) -> Value {
        let start = self.nan_start(None, None);
        let available = start
            .get("nan_capability")
            .and_then(|value| value.get("ok"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !available {
            return json!({
                "available": false,
                "ok": false,
                "start": start,
                "error": "host NAN/USD is unavailable",
            });
        }

        let payload = match firmware_mode_ping_cbor() {
            Ok(payload) => payload,
            Err(error) => {
                return json!({"available": true, "ok": false, "error": error.to_string()});
            }
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(wait_sec);
        let mut transmits = Vec::new();
        let mut all_events = Vec::new();
        while std::time::Instant::now() < deadline {
            transmits.push(self.nan_transmit(
                None,
                None,
                1,
                "ff:ff:ff:ff:ff:ff".to_string(),
                None,
                Some(hex_bytes(&payload)),
                None,
                None,
            ));
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let wait_ms = remaining
                .as_millis()
                .min(STABILITY_HOST_NAN_RETRY_MS as u128) as u64;
            if wait_ms == 0 {
                break;
            }
            let events = self.nan_events(None, None, Some(wait_ms), Some(64));
            if let Some(events) = events.get("events").and_then(Value::as_array) {
                all_events.extend(events.iter().cloned());
            }
        }
        let events = json!({"events": all_events});
        let responses = host_nan_responses(&events);
        let observed_ids = responses
            .iter()
            .filter_map(|event| event.get("device_id").and_then(Value::as_str))
            .map(str::to_ascii_lowercase)
            .collect::<HashSet<_>>();
        let missing = expected_macs
            .iter()
            .filter_map(|(id, mac)| match mac {
                Some(mac)
                    if !observed_ids
                        .iter()
                        .any(|device_id| device_id.ends_with(mac)) =>
                {
                    Some(id.clone())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let unresolved = expected_macs
            .iter()
            .filter_map(|(id, mac)| mac.is_none().then_some(id))
            .collect::<Vec<_>>();
        json!({
            "available": true,
            "ok": !responses.is_empty() && missing.is_empty(),
            "command": "mode ping=true",
            "command_cbor_bytes": payload.len(),
            "retry_interval_ms": STABILITY_HOST_NAN_RETRY_MS,
            "transmit_attempts": transmits.len(),
            "transmits": transmits,
            "responses": responses,
            "response_observed": !observed_ids.is_empty(),
            "missing": missing,
            "unresolved": unresolved,
        })
    }

    fn stability_mac_suffix(&self, id: &str) -> Option<String> {
        let socket = self.serial_forward_socket(id)?;
        let output = uds_console_exchange(&socket, "wifi status=true", 1_500).ok()?;
        output.lines().find_map(|line| {
            line.split_ascii_whitespace()
                .find_map(|field| field.strip_prefix("sta_mac="))
                .and_then(normalize_mac_suffix)
        })
    }

    fn start_configured_serial_forwards(&self) {
        let config_path = lmesh_config_path();
        let Some(config) = read_lmesh_config() else {
            self.record(
                "usb.serial.forward.config",
                json!({
                    "path": config_path,
                    "loaded": false,
                    "forwards": 0,
                }),
            );
            return;
        };
        self.record(
            "usb.serial.forward.config",
            json!({
                "path": config_path,
                "loaded": true,
                "forwards": config.serial_forwards.len(),
            }),
        );
        for forward in config.serial_forwards {
            if forward.enabled == Some(false) {
                continue;
            }
            let tcp_mode = forward
                .tcp_mode
                .clone()
                .or_else(|| forward.tcp_port.map(|_| "rfc2217".to_string()))
                .unwrap_or_else(|| "framed".to_string());
            let result = self.serial_forward_start(
                Some(forward.port.clone()),
                forward.baud,
                forward.tcp_port,
                Some(tcp_mode),
                Some(false),
                forward.multi,
                forward.direct,
            );
            self.record(
                "usb.serial.forward.autostart",
                json!({
                    "port": forward.port,
                    "result": result,
                }),
            );
        }
    }

    /// Return interface, capability, process-capability, and control status.
    pub fn status(&self) -> Value {
        let iface = wifi_iface(None);
        let ctrl_dir = wpa_ctrl_dir(None);
        let wpa_status = wpa_command(&iface, &ctrl_dir, "STATUS");
        let wpa_driver_flags2 = wpa_command(&iface, &ctrl_dir, "DRIVER_FLAGS2");

        json!({
            "wifi_iface": iface,
            "uart_enabled": self.uart_enabled,
            "wpa_ctrl_dir": ctrl_dir,
            "radios": self.radios.as_ref(),
            "capabilities": process_caps(),
            "hci": hci_probe(DEFAULT_HCI_DEV),
            "wpa": {
                "backend": "ctrl_uds",
                "status": command_result_json(wpa_status),
                "driver_flags2": command_result_json(wpa_driver_flags2),
            }
        })
    }

    /// Return the shared raw-NAN filter state used by the Linux monitor.
    /// This is deliberately independent of wpa_supplicant: the monitor
    /// observes NAN beacons and feeds them to dmesh-rawnan::NanState.
    pub fn rawnan_status(&self, iface: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let state = self
            .rawnan_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let cluster = state.cluster().map(|mac| colon_mac(&mac.0));
        let events = self
            .history
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter(|event| event.key == "wifi.rawnan.rx")
            .count();
        json!({
            "ok": true,
            "backend": "dmesh-rawnan",
            "iface": iface,
            "listener": self.raw_wifi_listeners.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).contains(&format!("{iface}:monitor")),
            "filter_mode": match state.mode() {
                dmesh_rawnan::FilterMode::Discovery => "discovery",
                dmesh_rawnan::FilterMode::Cluster => "cluster_a3",
            },
            "cluster_bssid": cluster,
            "sync_bssid": state.sync_bssid().map(|mac| colon_mac(&mac.0)),
            "last_beacon_tsf_us": state.last_beacon_tsf_us(),
            "beacon_interval_tu": state.beacon_interval_tu(),
            "nan_events": events,
        })
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
    pub fn wifi_ocb_start(&self, iface: Option<String>, freq: Option<u32>, bandwidth: Option<String>) -> Value {
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
            let args = ["dev", iface.as_str(), "ocb", "join", freq_text.as_str(), bandwidth.as_str()];
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
            && steps.iter().all(|step| step.get("ok").and_then(Value::as_bool).unwrap_or(false));
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
            "operation": "stop_nan",
            "result": self.nan_native_stop(Some(iface.clone())),
        }));
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
        let result = if steps.last().and_then(|step| step.get("ok")).and_then(Value::as_bool) != Some(true) {
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
        self.raw_wifi_listeners
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|key| !key.starts_with(&format!("{iface}:")));
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

    /// List USB serial devices that can be used as generic forward targets or radio adapters.
    pub fn usb_serial_list(&self, handshake: Option<bool>) -> Value {
        let handshake = handshake.unwrap_or(false);
        let mut devices = discover_usb_serial_devices();
        for device in &mut devices {
            if let Some(path) = device
                .get("path")
                .and_then(Value::as_str)
                .map(str::to_string)
            {
                let configured = self
                    .radios
                    .iter()
                    .filter(|radio| radio.path.as_deref() == Some(path.as_str()))
                    .map(|radio| json!(radio))
                    .collect::<Vec<_>>();
                if !configured.is_empty() {
                    device["radios"] = Value::Array(configured);
                }
                let forwards = self
                    .serial_forwards
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .values()
                    .filter(|forward| forward.port == path)
                    .map(|forward| {
                        json!({
                            "id": forward.id,
                            "socket": forward.socket_path,
                            "tcp_listen": forward.tcp_listen,
                            "baud": forward.baud,
                            "firmware": forward
                                .firmware_state
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .snapshot(),
                        })
                    })
                    .collect::<Vec<_>>();
                if !forwards.is_empty() {
                    device["forwards"] = Value::Array(forwards);
                }
                if handshake && let Some(port) = device.get("port").and_then(Value::as_str) {
                    device["handshake"] = self.usb_serial_handshake(
                        Some(port.to_string()),
                        Some("dmesh".to_string()),
                        None,
                        None,
                    );
                }
            }
        }
        json!({
            "ok": true,
            "devices": devices,
            "forwards": self.serial_forward_list().get("forwards").cloned().unwrap_or(Value::Array(Vec::new())),
        })
    }

    /// Run a generic or firmware-specific serial handshake without claiming the device permanently.
    pub fn usb_serial_handshake(
        &self,
        port: Option<String>,
        profile: Option<String>,
        timeout_sec: Option<f64>,
        baud: Option<u32>,
    ) -> Value {
        let profile = profile.unwrap_or_else(|| "generic".to_string());
        let timeout_ms = timeout_sec
            .map(|secs| (secs.max(0.05) * 1000.0).round() as u64)
            .unwrap_or(DEFAULT_ESP_COMMAND_TIMEOUT_MS)
            // Sleepy ESP nodes may expose UART only every Nth raw-NAN wake
            // (the lab default is every 16th four-second wake, about 64 s).
            // Keep the caller's bounded wait long enough to reach the next
            // authorized heartbeat instead of silently truncating it at the
            // old 30-second ceiling.
            .clamp(50, 300_000);
        let Some(target) = resolve_usb_serial_target(port.clone(), baud) else {
            return json!({
                "ok": false,
                "error": "missing USB serial target; pass port=USB0 or port=ACM0",
            });
        };
        let UsbSerialTarget {
            id,
            path,
            socket_path: _,
            baud,
        } = target;
        let commands = match profile.as_str() {
            "dmesh" | "esp" | "esp32" => vec![
                "wifi raw_stats=true".to_string(),
                "nan".to_string(),
                "ble".to_string(),
            ],
            "none" => Vec::new(),
            command if command.starts_with("cmd:") => vec![command[4..].to_string()],
            _ => vec!["help".to_string()],
        };
        // A configured managed forward is the only owner of the physical
        // UART. Opening `path` here creates a second reader and can also
        // disturb CP210x modem-line state while a boot log is in flight.
        let forward_socket = port
            .as_deref()
            .and_then(|id| self.serial_forward_socket(id))
            .or_else(|| {
                self.serial_forwards
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .values()
                    .find(|forward| forward.port == path && !forward.stop.load(Ordering::Acquire))
                    .map(|forward| forward.socket_path.clone())
            });
        let Some(forward_socket) = forward_socket else {
            return json!({
                "ok": false,
                "radio_id": id,
                "path": path,
                "baud": baud,
                "profile": profile,
                "error": "serial handshake requires an active managed serial forward",
            });
        };
        let mut exchanges = Vec::new();
        let mut ok = true;
        for command in commands {
            let wire = if command.starts_with("STA ") {
                encode_recovery_sta_packet(&command)
            } else if let Some(text) = command.strip_prefix("STA_TEXT ") {
                // Recovery control packets use the same compact method/payload
                // envelope as Main; the physical UART never receives text.
                encode_firmware_uart_payload(text.as_bytes())
            } else {
                let mut wire = command.as_bytes().to_vec();
                wire.push(b'\n');
                Ok(wire)
            };
            match wire.and_then(|wire| uds_raw_exchange(&forward_socket, &wire, timeout_ms)) {
                Ok(raw) => {
                    let messages = parse_raw_exchange_messages(&raw);
                    for message in &messages {
                        self.record_message("usb.serial.handshake.rx", &id, message.clone());
                    }
                    exchanges.push(json!({
                        "command": command,
                        "raw": raw,
                        "messages": messages,
                    }));
                }
                Err(error) => {
                    ok = false;
                    exchanges.push(json!({
                        "command": command,
                        "error": error.to_string(),
                    }));
                }
            }
        }
        let result = json!({
            "ok": ok,
            "radio_id": id,
            "path": path,
            "baud": baud,
            "profile": profile,
            "exchanges": exchanges,
        });
        self.record("usb.serial.handshake", result.clone());
        result
    }

    /// Send the fixed stage2 boot command through the already-managed UART
    /// forward.  This is intentionally separate from `esp.serial.command`:
    /// stage2 has no CBOR decoder and is still running at the boot UART rate.
    pub fn usb_serial_boot(
        &self,
        port: Option<String>,
        command: Option<String>,
        timeout_sec: Option<f64>,
        reset: Option<bool>,
    ) -> Value {
        let timeout_ms = timeout_sec
            .map(|secs| (secs.max(0.05) * 1000.0).round() as u64)
            .unwrap_or(1_000)
            .clamp(50, 30_000);
        let command = command.unwrap_or_else(|| "recovery".to_owned());
        let Some(payload) = boot_command_payload(&command).ok() else {
            return json!({
                "ok": false,
                "error": format!("unsupported boot command {command:?}; expected recovery or main"),
            });
        };
        let Some(target) = resolve_usb_serial_target(port.clone(), None) else {
            return json!({
                "ok": false,
                "error": "missing USB serial target; pass port=e5 or configure LMESH_SERIAL_DEVICES/lmesh.toml",
            });
        };
        let UsbSerialTarget {
            id,
            path,
            socket_path: _,
            baud,
        } = target;
        if reset.unwrap_or(false) {
            // Keep the managed forward as the only UART reader.  Resetting
            // the bridge is a modem-line operation; the existing forward
            // then reads, logs, and broadcasts the stage2 identity and this
            // request/response client consumes the same managed stream.
            let forward_socket = self.serial_forward_socket(&id);
            let Some(forward_socket) = forward_socket else {
                return json!({
                    "ok": false,
                    "radio_id": id,
                    "path": path,
                    "error": "stage2 reset requires an active managed serial forward",
                });
            };
            let boot_baud = 115_200;
            // Keep reset and selector on the descriptor owned by the managed
            // forward.  Opening the tty a second time is unsafe with CP210x:
            // closing that temporary descriptor can restore RTS and cancel
            // the reset before stage2 observes the selector.
            let result = connect_uds_boot(&forward_socket).and_then(|stream| {
                let forwards = self
                    .serial_forwards
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let Some(forward) = forwards.get(&id) else {
                    return Err(anyhow::anyhow!(
                        "managed serial forward {id} disappeared before stage2 reset"
                    ));
                };
                forward.stats.reset_requests.fetch_add(1, Ordering::Relaxed);
                forward
                    .reset_request
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                        Some(pending.saturating_add(1))
                    })
                    .map_err(|_| anyhow::anyhow!("failed to queue managed stage2 reset"))?;
                drop(forwards);
                uds_boot_exchange_stream(stream, &payload, timeout_ms)
            });
            return match result {
                Ok(hello) => {
                    let result = json!({
                        "ok": true,
                        "radio_id": id,
                        "path": path,
                        "baud": boot_baud,
                        "command": command,
                        "reset": true,
                        "hello": boot_identity_json(&hello),
                        "via": "managed_forward_reset",
                    });
                    self.record("usb.serial.boot", result.clone());
                    result
                }
                Err(error) => json!({
                    "ok": false,
                    "radio_id": id,
                    "path": path,
                    "baud": boot_baud,
                    "command": command,
                    "reset": true,
                    "via": "managed_forward_reset",
                    "error": error.to_string(),
                }),
            };
        }
        // Prefer the configured role key.  Matching only the resolved device
        // path is fragile when a deployment changes a symlink or when a
        // serial forward is restarted between target resolution and lookup;
        // the managed role socket remains authoritative and avoids opening
        // the physical UART as a fallback.
        let forward_socket = port
            .as_deref()
            .and_then(|id| self.serial_forward_socket(id))
            .or_else(|| {
                self.serial_forwards
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .values()
                    .find(|forward| forward.port == path && !forward.stop.load(Ordering::Acquire))
                    .map(|forward| forward.socket_path.clone())
            });
        let Some(socket_path) = forward_socket else {
            return json!({
                "ok": false,
                "radio_id": id,
                "path": path,
                "error": "stage2 boot commands require an active managed serial forward",
            });
        };
        match uds_boot_exchange(&socket_path, &payload, timeout_ms) {
            Ok(hello) => {
                let result = json!({
                    "ok": true,
                    "radio_id": id,
                    "path": path,
                    "baud": baud,
                    "command": command,
                    "hello": boot_identity_json(&hello),
                    "via": "managed_forward",
                });
                self.record("usb.serial.boot", result.clone());
                result
            }
            Err(error) => json!({
                "ok": false,
                "radio_id": id,
                "path": path,
                "baud": baud,
                "command": command,
                "via": "managed_forward",
                "error": error.to_string(),
            }),
        }
    }

    /// Start a generic byte-forwarding UDS for one USB serial device.
    pub fn serial_forward_start(
        &self,
        port: Option<String>,
        mut baud: Option<u32>,
        mut tcp_port: Option<u16>,
        mut tcp_mode: Option<String>,
        handshake: Option<bool>,
        mut multi: Option<bool>,
        direct: Option<bool>,
    ) -> Value {
        let configured = port
            .as_deref()
            .and_then(canonical_usb_port_id)
            .and_then(|id| configured_serial_forward(&id));
        let raw_output = configured
            .as_ref()
            .and_then(|configured| configured.raw)
            .unwrap_or(false);
        if let Some(configured) = configured.as_ref() {
            baud = baud.or(configured.baud);
            tcp_port = tcp_port.or(configured.tcp_port);
            tcp_mode = tcp_mode.or_else(|| configured.tcp_mode.clone());
            multi = multi.or(configured.multi);
        }
        // Probe firmware forwards immediately.  Once the device reports
        // infrastructure/active mode, client records are written directly;
        // otherwise they wait for the device's UART heartbeat/window.  Raw
        // byte forwards may still opt into immediate delivery explicitly.
        let direct_write = raw_output || direct.unwrap_or(false);
        let multi = multi.unwrap_or(false);
        let tcp_mode = match SerialForwardTcpMode::parse(tcp_mode.as_deref().unwrap_or("auto")) {
            Ok(mode) => mode,
            Err(error) => {
                return json!({
                    "ok": false,
                    "error": error.to_string(),
                });
            }
        };
        let Some(target) = resolve_usb_serial_target(port, baud) else {
            return json!({
                "ok": false,
                "error": "missing USB serial target; pass port=USB0 or port=ACM0",
            });
        };
        let UsbSerialTarget {
            id,
            path,
            socket_path,
            baud,
        } = target;
        {
            let forwards = self
                .serial_forwards
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if forwards.contains_key(&id) {
                return json!({
                    "ok": false,
                    "id": id,
                    "error": "serial forward already exists",
                });
            }
        }
        if let Some(parent) = PathBuf::from(&socket_path).parent() {
            if let Err(error) = fs::create_dir_all(parent) {
                return json!({
                    "ok": false,
                    "id": id,
                    "socket": socket_path,
                    "error": format!("failed to create socket parent: {error}"),
                });
            }
        }
        let _ = fs::remove_file(&socket_path);
        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(error) => {
                return json!({
                    "ok": false,
                    "id": id,
                    "socket": socket_path,
                    "error": format!("failed to bind serial forward socket: {error}"),
                });
            }
        };
        if let Err(error) = configure_serial_forward_socket(&socket_path) {
            let _ = fs::remove_file(&socket_path);
            return json!({
                "ok": false,
                "id": id,
                "socket": socket_path,
                "error": error.to_string(),
            });
        }
        if let Err(error) = listener.set_nonblocking(true) {
            let _ = fs::remove_file(&socket_path);
            return json!({
                "ok": false,
                "id": id,
                "socket": socket_path,
                "error": format!("failed to set serial forward listener nonblocking: {error}"),
            });
        }
        let (tcp_listener, tcp_listen) = match tcp_port {
            Some(port) => {
                let bind_addr = format!("127.0.0.1:{port}");
                match TcpListener::bind(&bind_addr) {
                    Ok(listener) => {
                        if let Err(error) = listener.set_nonblocking(true) {
                            let _ = fs::remove_file(&socket_path);
                            return json!({
                                "ok": false,
                                "id": id,
                                "tcp_listen": bind_addr,
                                "error": format!("failed to set TCP serial forward listener nonblocking: {error}"),
                            });
                        }
                        let listen = listener
                            .local_addr()
                            .map(|addr| addr.to_string())
                            .unwrap_or(bind_addr);
                        (Some(listener), Some(listen))
                    }
                    Err(error) => {
                        let _ = fs::remove_file(&socket_path);
                        return json!({
                            "ok": false,
                            "id": id,
                            "tcp_listen": bind_addr,
                            "error": format!("failed to bind TCP serial forward: {error}"),
                        });
                    }
                }
            }
            None => (None, None),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let reset_request = Arc::new(AtomicU8::new(SERIAL_RESET_NONE));
        let flush_request = Arc::new(AtomicBool::new(false));
        let log_flash_quiet_until_ms = Arc::new(AtomicU64::new(0));
        let stats = Arc::new(SerialForwardStats::default());
        let firmware_state = Arc::new(Mutex::new(FirmwareState::default()));
        let log_path = configured_serial_log_path_for_forward(&id);
        let thread_stop = stop.clone();
        let thread_reset_request = reset_request.clone();
        let thread_flush_request = flush_request.clone();
        let thread_log_flash_quiet_until_ms = log_flash_quiet_until_ms.clone();
        let thread_stats = stats.clone();
        let thread_firmware_state = firmware_state.clone();
        let thread_id = id.clone();
        let thread_path = path.clone();
        let thread_socket_path = socket_path.clone();
        let thread_tcp_listen = tcp_listen.clone();
        let thread_log_path = log_path.clone();
        let thread_log = log_path.as_ref().and_then(|_| self.serial_log.clone());
        let thread_baud = baud;
        let handle = std::thread::spawn(move || {
            if let Err(error) = serial_forward_loop(
                &thread_id,
                &thread_path,
                thread_baud,
                listener,
                tcp_listener,
                tcp_mode,
                multi,
                raw_output,
                thread_reset_request,
                thread_flush_request,
                direct_write,
                thread_log_flash_quiet_until_ms,
                thread_stop,
                thread_stats,
                thread_firmware_state,
                thread_log_path,
                thread_log,
            ) {
                tracing::warn!(
                    forward_id = %thread_id,
                    port = %thread_path,
                    socket = %thread_socket_path,
                    tcp = ?thread_tcp_listen,
                    error = %error,
                    "serial_forward_exited"
                );
            }
        });
        let runtime = SerialForwardRuntime {
            id: id.clone(),
            radio_id: id.clone(),
            port: path.clone(),
            socket_path: socket_path.clone(),
            tcp_listen: tcp_listen.clone(),
            log_path: log_path.clone(),
            baud,
            multi,
            reset_request,
            flush_request,
            stop,
            stats,
            firmware_state,
            handle: Some(handle),
            started_ms: now_millis_u64(),
        };
        self.serial_forwards
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(id.clone(), runtime);
        let handshake_result = handshake.unwrap_or(false).then(|| {
            self.usb_serial_handshake(Some(id.clone()), Some("dmesh".to_string()), Some(1.5), None)
        });
        let result = json!({
            "ok": true,
            "id": id,
            "port": path,
            "baud": baud,
            "multi": multi,
            "raw": raw_output,
            "tcp_mode": tcp_mode.name(),
            "socket": socket_path,
            "tcp_listen": tcp_listen,
            "log_path": log_path,
            "handshake": handshake_result,
        });
        self.record("usb.serial.forward.start", result.clone());
        result
    }

    /// Stop one managed serial forward.
    pub fn serial_forward_stop(&self, port: Option<String>) -> Value {
        let Some(key) = port
            .as_deref()
            .or(Some("USB0"))
            .and_then(canonical_usb_port_id)
        else {
            return json!({ "ok": false, "error": "missing USB serial target; pass port=USB0 or port=ACM0" });
        };
        let Some(mut runtime) = self
            .serial_forwards
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&key)
        else {
            return json!({ "ok": false, "id": key, "error": "serial forward not found" });
        };
        runtime.stop.store(true, Ordering::Release);
        let _ = std::os::unix::net::UnixStream::connect(&runtime.socket_path);
        if let Some(tcp_listen) = &runtime.tcp_listen {
            let _ = TcpStream::connect(tcp_listen);
        }
        if let Some(handle) = runtime.handle.take() {
            let _ = handle.join();
        }
        let _ = fs::remove_file(&runtime.socket_path);
        let result = json!({
            "ok": true,
            "id": runtime.id,
            "port": runtime.port,
            "multi": runtime.multi,
            "socket": runtime.socket_path,
            "tcp_listen": runtime.tcp_listen,
        });
        self.record("usb.serial.forward.stop", result.clone());
        result
    }

    /// List managed serial forwards.
    pub fn serial_forward_list(&self) -> Value {
        let forwards = self
            .serial_forwards
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .map(|forward| {
                json!({
                    "id": forward.id,
                    "radio_id": forward.radio_id,
                    "port": forward.port,
                    "socket": forward.socket_path,
                    "baud": forward.baud,
                    "multi": forward.multi,
                    "tcp_listen": forward.tcp_listen,
                    "log_path": forward.log_path,
                    "started_ms": forward.started_ms,
                    "running": !forward.stop.load(Ordering::Acquire),
                    "firmware": forward
                        .firmware_state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .snapshot(),
                    "stats": forward.stats.snapshot(),
                })
            })
            .collect::<Vec<_>>();
        json!({ "ok": true, "forwards": forwards })
    }

    /// Request a one-shot flush of bytes queued for a sleepy/unknown forward.
    /// This does not change mode policy or touch modem lines.
    pub fn serial_forward_flush(&self, port: Option<String>) -> Value {
        let Some(key) = port
            .as_deref()
            .or(Some("USB0"))
            .and_then(canonical_usb_port_id)
        else {
            return json!({"ok": false, "error": "missing USB serial target; pass port=e5 or configure lmesh"});
        };
        let forwards = self
            .serial_forwards
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(forward) = forwards.get(&key) else {
            return json!({"ok": false, "id": key, "error": "serial forward not found"});
        };
        forward.flush_request.store(true, Ordering::Release);
        json!({
            "ok": true,
            "id": forward.id,
            "socket": forward.socket_path,
            "queued": "flush_requested",
            "via": "managed_forward",
        })
    }

    /// Reset an explicitly requested ESP through the descriptor owned by its
    /// managed forward. This is important for CP210x devices: a second open
    /// can restore modem lines as soon as it closes, cancelling the reset.
    pub fn serial_modem_reset(&self, port: Option<String>) -> Value {
        let Some(id) = port.clone() else {
            return json!({"ok": false, "error": "missing USB serial target"});
        };
        let forwards = self
            .serial_forwards
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(forward) = forwards.get(&id) else {
            return json!({"ok": false, "id": id, "error": "RTS reset requires an active managed serial forward"});
        };
        forward.stats.reset_requests.fetch_add(1, Ordering::Relaxed);
        let _ =
            forward
                .reset_request
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                    Some(pending.saturating_add(1))
                });
        json!({
            "ok": true,
            "id": id,
            "path": forward.port,
            "line": "RTS",
            "asserted": false,
            "pulse_ms": 120,
            "via": "active_forward",
        })
    }

    /// Release DTR if an external tty opener left it asserted.
    /// Assertion and pulse operations are deliberately disabled.
    pub fn serial_modem_dtr(
        &self,
        port: Option<String>,
        asserted: Option<bool>,
        pulse_ms: Option<u64>,
    ) -> Value {
        if asserted != Some(false) {
            return json!({
                "ok": false,
                "error": "DTR assertion is disabled; only asserted=false release is permitted"
            });
        }
        self.serial_modem_line(port, libc::TIOCM_DTR, asserted, pulse_ms.unwrap_or(100))
    }

    fn serial_modem_line(
        &self,
        port: Option<String>,
        line: libc::c_int,
        asserted: Option<bool>,
        pulse_ms: u64,
    ) -> Value {
        let Some(id) = port.as_deref().and_then(canonical_usb_port_id) else {
            return json!({"ok": false, "error": "missing USB serial target"});
        };
        let Some(path) = usb_port_path(&id) else {
            return json!({"ok": false, "id": id, "error": "USB serial path not found"});
        };
        let result = (|| -> Result<Value> {
            let fd = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOCTTY)
                .open(&path)?;
            let set = |value: bool| -> Result<()> {
                let mut mask = line;
                let request = if value {
                    libc::TIOCMBIS
                } else {
                    libc::TIOCMBIC
                };
                if unsafe { libc::ioctl(fd.as_raw_fd(), request, &mut mask) } < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                Ok(())
            };
            if let Some(value) = asserted {
                set(value)?;
            } else {
                // USB-UART bridges used by ESP boards drive GPIO0 low when
                // DTR is asserted. Keep that level long enough for the
                // light-sleep GPIO wake detector to observe it.
                set(true)?;
                std::thread::sleep(std::time::Duration::from_millis(pulse_ms));
                set(false)?;
            }
            Ok(
                json!({"ok": true, "id": id, "path": path, "line": if line == libc::TIOCM_RTS {"RTS"} else {"DTR"}, "asserted": asserted.unwrap_or(true), "pulse_ms": pulse_ms}),
            )
        })();
        match result {
            Ok(value) => value,
            Err(error) => {
                json!({"ok": false, "id": id, "path": path, "error": format!("{error:#}")})
            }
        }
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
        let mut serial_results = Vec::new();
        let mut wifi_results = Vec::new();
        for adapter in &selected {
            let message = MeshMessage::new(mesh::message::KIND_DM_PING, MeshMessageCodec::Text)
                .field(FIELD_MEDIUM, &adapter.medium)
                .field(FIELD_RADIO_ID, &adapter.id)
                .field(FIELD_STATUS, "queued");
            self.record_message("ping", "local", message);
            if adapter.kind == "esp-serial" || radio == "serial" {
                serial_results.push(self.ping_serial_radio(adapter));
            }
            if adapter.medium == "wifi" || adapter.kind == "host-wifi" || radio == "nan" {
                wifi_results.push(self.nan_default(None, None, None, Some(0)));
            }
        }
        if (radio == "all" || radio == "nan" || radio == "best") && wifi_results.is_empty() {
            wifi_results.push(self.nan_default(None, None, None, Some(0)));
        }
        let unavailable = unavailable_radios(&radio);
        let result = json!({
            "ok": true,
            "radio": radio,
            "sent": selected.len(),
            "radios": selected,
            "serial": serial_results,
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
                    Ok(frame) => self.nan_transmit(
                        None,
                        None,
                        1,
                        destination,
                        None,
                        Some(hex_bytes(&frame)),
                        None,
                        None,
                    ),
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
                None,
                destination,
                None,
                Some("dont_wait_ack".to_string()),
                None,
                None,
                None,
                payload.clone(),
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

    fn esp_lora_send(&self, payload: String, destination: Option<String>) -> Value {
        if destination.is_some() {
            return json!({
                "ok": false,
                "radio": "lora",
                "error": "LoRa destination addressing is not implemented for ESP firmware send yet",
            });
        }
        let command = format!(
            "lorasend data=hex:{} format=meshtastic hop=0",
            hex_lower(payload.as_bytes())
        );
        let result = self.esp_serial_command(None, None, command, Some(8.0));
        json!({
            "ok": result.get("ok").and_then(Value::as_bool).unwrap_or(false),
            "radio": "lora",
            "adapter": "esp-serial",
            "payload_len": payload.len(),
            "result": result,
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

    /// Start an open AP on channel 6 using direct nl80211.
    pub fn wifi_ap_start_open(&self, iface: Option<String>, ssid: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let ssid = ssid.unwrap_or_else(|| default_open_ap_ssid(&iface));
        let channel = DEFAULT_RAW_WIFI_CHANNEL;
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
        let template_lengths = open_ap_template_lengths(&ssid)
            .map(|(beacon_head, probe_resp)| {
                json!({
                    "beacon_head": beacon_head,
                    "beacon_tail": esp_open_ap_beacon_tail().len(),
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
                steps.push(match socket.set_channel_ht20(ifindex, freq) {
                    Ok(()) => json!({
                        "program": "nl80211",
                        "args": ["set_wiphy", "channel_ht20"],
                        "ok": true,
                        "freq": freq,
                    }),
                    Err(error) => json!({
                        "program": "nl80211",
                        "args": ["set_wiphy", "channel_ht20"],
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
                match socket.start_open_ap(ifindex, mac, &ssid, channel, freq) {
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
                let rawnan_state = self.rawnan_state.clone();
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
                    "beacon_interval": 100,
                    "dtim_period": 1,
                    "channel_width": "20_ht",
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
                    "beacon_interval": 100,
                    "dtim_period": 1,
                    "channel_width": "20_ht",
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
        let result = json!({
            "ok": true,
            "backend": "linux_nl80211",
            "iface": iface,
            "ssid_default": default_open_ap_ssid(&iface),
            "channel": DEFAULT_RAW_WIFI_CHANNEL,
            "freq": channel_to_freq(DEFAULT_RAW_WIFI_CHANNEL),
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
                socket.station_dump(ifindex)
            })
            .map(|stations| {
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
            .map(|_| json!({
                "ok": true,
                "backend": "linux_nl80211",
                "iface": iface,
                "mac": colon_mac(&mac_bytes),
            }))
            .unwrap_or_else(|error| json!({
                "ok": false,
                "backend": "linux_nl80211",
                "iface": iface,
                "mac": colon_mac(&mac_bytes),
                "error": format!("{error:#}"),
            }));
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
            .map(|_| json!({
                "ok": true,
                "backend": "linux_nl80211",
                "iface": iface,
            }))
            .unwrap_or_else(|error| json!({
                "ok": false,
                "backend": "linux_nl80211",
                "iface": iface,
                "error": format!("{error:#}"),
            }));
        self.record("wifi.ap.station.remove_all", result.clone());
        result
    }

    /// Scan for nearby Wi-Fi BSS entries through the lmesh radio process.
    pub fn wifi_scan(&self, iface: Option<String>, ssid: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let bring_up = run_command("ip", &["link", "set", &iface, "up"]);
        let mut args = vec!["dev", iface.as_str(), "scan"];
        if let Some(ssid) = ssid.as_deref().filter(|ssid| !ssid.is_empty()) {
            args.extend(["ssid", ssid]);
        }
        let result = match command_output_timeout("iw", &args, Duration::from_secs(12)) {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                let entries = parse_iw_scan(&stdout);
                json!({
                    "ok": output.status.success(),
                    "backend": "iw",
                    "iface": iface,
                    "ssid_filter": ssid,
                    "count": entries.len(),
                    "entries": entries,
                    "bring_up": bring_up,
                    "status": output.status.code(),
                    "stderr": stderr,
                })
            }
            Err(error) => json!({
                "ok": false,
                "backend": "iw",
                "iface": iface,
                "ssid_filter": ssid,
                "bring_up": bring_up,
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
    pub fn wifi_raw_listen(
        &self,
        iface: Option<String>,
        ctrl_dir: Option<String>,
        channel: Option<u8>,
        listen_sec: Option<u64>,
        rx_variant: Option<String>,
    ) -> Value {
        let iface = wifi_iface(iface);
        let ctrl_dir = wpa_ctrl_dir(ctrl_dir);
        let channel = raw_wifi_channel(channel);
        let listen_sec = listen_sec.unwrap_or(DEFAULT_RAW_WIFI_LISTEN_SECS).max(1);
        let rx_variant = rx_variant.unwrap_or_else(|| "nl80211".to_string());
        let wpa_channel = if rx_variant == "monitor" || rx_variant == "monitor_active" {
            json!({"skipped": true, "reason": "raw-NAN monitor does not use wpa_supplicant"})
        } else {
            prepare_raw_wifi_channel(&iface, &ctrl_dir, channel, listen_sec)
        };
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
                    "ctrl_dir": ctrl_dir,
                    "channel": channel,
                    "listen_sec": listen_sec,
                    "rx_variant": rx_variant,
                    "wpa_channel": wpa_channel,
                    "already_running": true,
                });
            }
        }

        let listen_result = if rx_variant == "monitor" || rx_variant == "monitor_active" {
            let monitor_iface = monitor_iface_name(&iface);
            let active = rx_variant == "monitor_active";
            ensure_monitor_iface(&iface, &monitor_iface, channel, active, active).and_then(|setup| {
                let socket = MonitorRxSocket::open(&monitor_iface)?;
                let history = self.history.clone();
                let listeners = self.raw_wifi_listeners.clone();
                let iface_for_thread = iface.clone();
                let monitor_for_thread = monitor_iface.clone();
                let listener_key_for_thread = listener_key.clone();
                let rawnan_state = self.rawnan_state.clone();
                std::thread::spawn(move || {
                    monitor_receive_loop(
                        socket,
                        &iface_for_thread,
                        &monitor_for_thread,
                        history,
                        rawnan_state,
                    );
                    listeners
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .remove(&listener_key_for_thread);
                });
                Ok(json!({
                    "ok": true,
                    "backend": "linux_af_packet_monitor",
                    "iface": iface,
                    "monitor_iface": monitor_iface,
                    "ctrl_dir": ctrl_dir,
                    "channel": channel,
                    "listen_sec": listen_sec,
                    "rx_variant": rx_variant,
                    "monitor": setup,
                    "wpa_channel": wpa_channel,
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
                        "ctrl_dir": ctrl_dir,
                        "channel": channel,
                        "listen_sec": listen_sec,
                        "rx_variant": rx_variant,
                        "wpa_channel": wpa_channel,
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

    /// Send an ESP32-compatible DMesh vendor action frame.
    pub fn wifi_raw_send(
        &self,
        iface: Option<String>,
        ctrl_dir: Option<String>,
        channel: Option<u8>,
        listen_sec: Option<u64>,
        destination: Option<String>,
        source: Option<String>,
        tx_variant: Option<String>,
        tx_duration_ms: Option<u32>,
        bssid: Option<String>,
        llc: Option<String>,
        payload: String,
    ) -> Value {
        let iface = wifi_iface(iface);
        let ctrl_dir = wpa_ctrl_dir(ctrl_dir);
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
        let wpa_channel = if tx_options.variant == "roc"
            || tx_options.variant == "action"
            || tx_options.variant == "send_action"
            || tx_options.variant == "monitor"
            || tx_options.variant == "monitor_active"
            || tx_options.variant == "nan_data"
            || tx_options.variant == "nan_data_active"
            || tx_options.variant == "nan_data_raw"
            || tx_options.variant == "nan_data_raw_active"
            || tx_options.variant == "nan_data_multicast"
            || tx_options.variant == "nan_data_multicast_active"
        {
            json!({
                "skipped": true,
                "reason": "raw frame transport does not use wpa_supplicant",
            })
        } else {
            prepare_raw_wifi_channel(&iface, &ctrl_dir, channel, listen_sec)
        };
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
            build_dmesh_nan_raw_data_frame(nan_bssid, data_destination, source, &llc, &payload_bytes)
        } else {
            // Raw NAN action traffic must carry the discovered cluster BSSID
            // in address3. Using the peer MAC here works only before the
            // device arms its hardware cluster filter, and silently drops
            // host-originated transport packets afterwards.
            build_dmesh_vendor_action_frame_with_bssid(
                destination,
                source,
                nan_bssid,
                &payload_bytes,
            )
        };
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
            let active = tx_options.variant == "monitor_active"
                || tx_options.variant == "multicast_data_active"
                || tx_options.variant == "sta_multicast_llc_active"
                || tx_options.variant == "sta_direct_llc_active"
                || tx_options.variant == "nan_data_active"
                || tx_options.variant == "nan_data_raw_active"
                || tx_options.variant == "nan_data_multicast_active";

            match send_monitor_frame(&iface, channel, &frame, active) {
                Ok(monitor) => json!({
                    "ok": true,
                    "backend": "linux_af_packet_monitor",
                    "tx_variant": tx_options.variant,
                    "tx_options": tx_options.as_json(),
                    "monitor": monitor,
                    "iface": iface,
                    "ctrl_dir": ctrl_dir,
                    "channel": channel,
                    "listen_sec": listen_sec,
                    "tx_duration_ms": tx_duration_ms,
                    "wpa_channel": wpa_channel,
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
                    socket.send_mgmt_frame(ifindex(&iface)?, &frame)
                } else {
                    socket.send_frame(
                        ifindex(&iface)?,
                        channel_to_freq(channel),
                        &tx_options,
                        &frame,
                    )
                }
            }) {
                Ok(()) => json!({
                    "ok": true,
                    "backend": "linux_nl80211",
                    "tx_variant": tx_options.variant,
                    "tx_options": tx_options.as_json(),
                    "iface": iface,
                    "ctrl_dir": ctrl_dir,
                    "channel": channel,
                    "listen_sec": listen_sec,
                    "tx_duration_ms": tx_duration_ms,
                    "wpa_channel": wpa_channel,
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
    ) -> Value {
        let iface = wifi_iface(iface);
        let channel = raw_wifi_channel(channel);
        let variant = tx_variant.unwrap_or_else(|| "monitor".to_string());
        if variant != "monitor" && variant != "monitor_active" && variant != "af_packet" {
            return json!({
                "ok": false,
                "backend": "linux_af_packet_monitor",
                "iface": iface,
                "tx_variant": variant,
                "error": "arbitrary frame injection requires tx_variant=monitor, monitor_active, or af_packet",
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
        } else {
            let active = variant == "monitor_active";
            match send_monitor_frame(&iface, channel, &frame, active) {
                Ok(monitor) => json!({
                "ok": true,
                "backend": "linux_af_packet_monitor",
                "iface": iface,
                "channel": channel,
                "tx_variant": variant,
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

    /// Send a QUIC-shaped DMTB stream burst while preparing the monitor VIF
    /// only once. The ordinary `wifi.raw.send` method is intentionally a
    /// single-frame diagnostic and re-runs interface setup for each call;
    /// using it in a tight loop distorted the transport benchmark and could
    /// wedge some drivers while toggling the parent interface.
    pub fn wifi_raw_bench_send(
        &self,
        iface: Option<String>,
        channel: Option<u8>,
        destination: String,
        bssid: Option<String>,
        total_bytes: usize,
        chunk_bytes: Option<usize>,
        tx_variant: Option<String>,
        llc: Option<String>,
        multicast: bool,
    ) -> Value {
        let iface = wifi_iface(iface);
        let channel = raw_wifi_channel(channel);
        let destination = match parse_mac(Some(&destination)) {
            Some(mac) => mac,
            None => return json!({"ok": false, "error": "destination must be a MAC address"}),
        };
        let bssid = bssid
            .as_deref()
            .and_then(|value| parse_mac(Some(value)))
            .unwrap_or(destination);
        let tx_variant = tx_variant.unwrap_or_else(|| "monitor_active".to_string());
        let llc = parse_experimental_llc(llc.as_deref()).unwrap_or(RAWNAN_LLC_DEFAULT);
        let chunk_bytes = chunk_bytes.unwrap_or(512).clamp(64, 900);
        if total_bytes == 0 || total_bytes > 16 * 1024 * 1024 {
            return json!({"ok": false, "error": "bytes must be in 1..=16777216"});
        }
        let monitor_iface = monitor_iface_name(&iface);
        let setup = match ensure_monitor_iface(&iface, &monitor_iface, channel, true, false) {
            Ok(value) => value,
            Err(error) => return json!({"ok": false, "error": format!("{error:#}")}),
        };
        let socket = match MonitorTxSocket::open(&monitor_iface) {
            Ok(socket) => socket,
            Err(error) => return json!({"ok": false, "error": format!("{error:#}")}),
        };
        let source = match iface_mac(&iface) {
            Ok(mac) => mac,
            Err(error) => return json!({"ok": false, "error": format!("{error:#}")}),
        };
        let frame_count = total_bytes.div_ceil(chunk_bytes);
        let started = Instant::now();
        let mut stream_bytes = 0usize;
        let mut wire_bytes = 0usize;
        for sequence in 0..frame_count {
            let offset = sequence * chunk_bytes;
            let data_len = (total_bytes - offset).min(chunk_bytes);
            let mut data = vec![0u8; data_len];
            for (index, byte) in data.iter_mut().enumerate() {
                *byte = ((offset + index) & 0xff) as u8;
            }
            let mut payload = vec![0u8; 1200];
            let body_len = match encode_bench_stream(
                sequence as u32,
                offset as u64,
                sequence + 1 == frame_count,
                &data,
                &mut payload,
            ) {
                Ok(length) => length,
                Err(error) => {
                    return json!({"ok": false, "error": format!("stream encode: {error:?}")});
                }
            };
            let frame = if tx_variant == "nan_data_raw" || tx_variant == "nan_data_raw_active" {
                let data_destination = if multicast { RAW_WIFI_MULTICAST } else { destination };
                build_dmesh_nan_raw_data_frame(
                    bssid,
                    data_destination,
                    source,
                    &llc,
                    &payload[..body_len],
                )
            } else {
                build_dmesh_vendor_action_frame_with_bssid(
                    if multicast { RAW_WIFI_MULTICAST } else { destination },
                    source,
                    bssid,
                    &payload[..body_len],
                )
            };
            let packet = build_radiotap_packet(&frame);
            if let Err(error) = socket.send(&packet).and_then(|written| {
                if written == packet.len() {
                    Ok(())
                } else {
                    bail!(
                        "short monitor frame write: wrote {written}, expected {}",
                        packet.len()
                    )
                }
            }) {
                return json!({
                    "ok": false,
                    "error": format!("frame {sequence}: {error:#}"),
                    "frames_sent": sequence,
                    "stream_bytes": stream_bytes,
                    "wire_bytes": wire_bytes,
                });
            }
            stream_bytes += data_len;
            wire_bytes += packet.len();
        }
        let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
        json!({
            "ok": true,
            "backend": "linux_af_packet_monitor",
            "iface": iface,
            "monitor_iface": monitor_iface,
            "channel": channel,
            "destination": colon_mac(&destination),
            "source": colon_mac(&source),
            "bssid": colon_mac(&bssid),
            "tx_variant": tx_variant,
            "llc": hex_bytes(&llc),
            "multicast": multicast,
            "frames_sent": frame_count,
            "stream_bytes": stream_bytes,
            "wire_bytes": wire_bytes,
            "elapsed_ms": elapsed_ms,
            "stream_kbps": if elapsed_ms > 0.0 { stream_bytes as f64 * 8.0 / elapsed_ms } else { 0.0 },
            "wire_kbps": if elapsed_ms > 0.0 { wire_bytes as f64 * 8.0 / elapsed_ms } else { 0.0 },
            "setup": setup,
        })
    }

    /// Send a DMesh raw Wi-Fi ping and return replies observed by the nl80211 listener.
    pub fn wifi_raw_ping(
        &self,
        iface: Option<String>,
        ctrl_dir: Option<String>,
        channel: Option<u8>,
        listen_sec: Option<u64>,
        wait_ms: Option<u64>,
        nonce: Option<String>,
    ) -> Value {
        let iface = wifi_iface(iface);
        let ctrl_dir = wpa_ctrl_dir(ctrl_dir);
        let channel = raw_wifi_channel(channel);
        let listen_sec = listen_sec.unwrap_or(DEFAULT_RAW_WIFI_LISTEN_SECS).max(1);
        let wait_ms = wait_ms.unwrap_or(900).clamp(50, 10_000);
        let nonce = nonce.unwrap_or_else(|| format!("{}-{}", std::process::id(), now_millis()));
        let payload = format!("dmesh.ping type=status source=lmesh nonce={nonce}");
        let listen = self.wifi_raw_listen(
            Some(iface.clone()),
            Some(ctrl_dir.clone()),
            Some(channel),
            Some(listen_sec),
            Some("nl80211".to_string()),
        );
        let sent_at = now_millis_u64();
        let tx = self.wifi_raw_send(
            Some(iface.clone()),
            Some(ctrl_dir.clone()),
            Some(channel),
            Some(listen_sec),
            None,
            None,
            Some("dont_wait_ack".to_string()),
            None,
            None,
            None,
            payload.clone(),
        );
        std::thread::sleep(Duration::from_millis(wait_ms));
        let replies = self.raw_wifi_ping_replies(sent_at, &iface);
        let result = json!({
            "ok": tx.get("ok").and_then(Value::as_bool).unwrap_or(false),
            "iface": iface,
            "ctrl_dir": ctrl_dir,
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
            None,
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
            .map(|source| {
                build_dmesh_vendor_action_frame_with_bssid(
                    destination_bytes,
                    source,
                    bssid,
                    &payload_bytes,
                )
            })
            .and_then(|frame| {
                prepare_raw_wifi_channel(&iface_value, DEFAULT_WPA_CTRL_DIR, channel_value, 3);
                send_monitor_frame(&iface_value, channel_value, &frame, false)
            }) {
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
        let setup = ensure_monitor_iface(&iface, &monitor_iface, channel, active, active)?;
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
                    if frame_type(frame) != 0 || !matches!(subtype, 8 | 5) {
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
        let result = json!({
            "ok": true,
            "backend": "linux_af_packet_monitor",
            "iface": iface,
            "monitor_iface": monitor_iface,
            "channel": channel,
            "capture_ms": capture_ms,
            "max_frames": max_frames,
            "frame_count": frames.len(),
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

    fn ping_serial_radio(&self, radio: &RadioAdapter) -> Value {
        let Some(path) = radio.path.as_deref() else {
            return json!({ "radio_id": radio.id, "ok": false, "error": "missing serial path" });
        };
        let command = TextRecord::new("dm.ping")
            .field("medium", "serial")
            .field("radio_id", &radio.id)
            .field("network", radio.network.as_deref().unwrap_or("default"))
            .format();
        let socket_path = self
            .serial_forwards
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .find(|forward| forward.port == path && !forward.stop.load(Ordering::Acquire))
            .map(|forward| forward.socket_path.clone());
        let Some(socket_path) = socket_path else {
            return json!({
                "radio_id": radio.id,
                "path": path,
                "ok": false,
                "error": "serial ping requires an active managed serial forward",
            });
        };
        match uds_console_exchange(&socket_path, &command, 250) {
            Ok(output) => {
                json!({
                    "radio_id": radio.id,
                    "path": path,
                    "ok": true,
                    "via": "managed_forward",
                    "replies": [{"console": output}],
                })
            }
            Err(error) => json!({
                "radio_id": radio.id,
                "path": path,
                "ok": false,
                "error": error.to_string(),
            }),
        }
    }

    /// Run one command against an ESP firmware serial adapter.
    pub fn esp_serial_command(
        &self,
        adapter: Option<String>,
        port: Option<String>,
        command: String,
        timeout_sec: Option<f64>,
    ) -> Value {
        self.esp_serial_command_with_options(adapter, port, command, timeout_sec, false)
    }

    /// Run one command against an ESP firmware serial adapter with an
    /// optional per-client direct-delivery override. The override is only for
    /// a caller that has independently established that the board is awake;
    /// it must not change the forward's default sleepy-node policy.
    pub fn esp_serial_command_with_options(
        &self,
        adapter: Option<String>,
        port: Option<String>,
        command: String,
        timeout_sec: Option<f64>,
        force_direct: bool,
    ) -> Value {
        let timeout_ms = timeout_sec
            .map(|secs| (secs.max(0.05) * 1000.0).round() as u64)
            .unwrap_or(DEFAULT_ESP_COMMAND_TIMEOUT_MS)
            // A battery node may open UART only every sixteenth 4-second
            // raw-NAN wake (~64 s). Do not silently truncate a caller's
            // bounded wait below that rendezvous interval.
            .clamp(50, 300_000);
        let target = self.esp_serial_target(adapter, port.clone());
        let Some((radio_id, path, baud)) = target else {
            return json!({
                "ok": false,
                "error": "missing ESP serial adapter; pass port or configure LMESH_SERIAL_DEVICES/lmesh.toml",
            });
        };
        let forward_socket = port
            .as_deref()
            .and_then(|id| self.serial_forward_socket(id))
            .or_else(|| {
                self.serial_forwards
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .values()
                    .find(|forward| forward.port == path && !forward.stop.load(Ordering::Acquire))
                    .map(|forward| forward.socket_path.clone())
            });
        if let Some(socket_path) = forward_socket {
            return match uds_console_exchange_with_options(
                &socket_path,
                &command,
                timeout_ms,
                force_direct,
            ) {
                Ok(output) => {
                    let result = json!({
                        "ok": true,
                        "radio_id": radio_id,
                        "path": path,
                        "baud": baud,
                        "command": command,
                        "via": "managed_forward",
                        "messages": [{"console": output}],
                    });
                    self.record("esp.serial.command", result.clone());
                    result
                }
                Err(error) => json!({
                    "ok": false,
                    "radio_id": radio_id,
                    "path": path,
                    "baud": baud,
                    "command": command,
                    "via": "managed_forward",
                    "error": error.to_string(),
                }),
            };
        }
        json!({
            "ok": false,
            "radio_id": radio_id,
            "path": path,
            "baud": baud,
            "command": command,
            "error": "physical UART access is disabled; use an active managed serial forward",
        })
    }

    /// Send an existing compact-CBOR firmware command over Main's temporary
    /// STA maintenance listener.  This deliberately has no UART fallback:
    /// callers use NAN to activate the session, then specify the board's
    /// numeric `ip:port` endpoint for reliable command and block-image work.
    pub fn esp_tcp_command(
        &self,
        endpoint: String,
        command: String,
        timeout_sec: Option<f64>,
    ) -> Value {
        let timeout_ms = timeout_sec
            .map(|secs| (secs.max(0.05) * 1000.0).round() as u64)
            .unwrap_or(3_000)
            .clamp(50, 300_000);
        let result = match self
            .esp_reverse_sessions
            .get(&endpoint)
            .map(|session| reverse_main_exchange(session, &command, timeout_ms))
            .unwrap_or_else(|| tcp_firmware_exchange(&endpoint, &command, timeout_ms))
        {
            Ok(response) => json!({
                "ok": true,
                "endpoint": endpoint,
                "command": command,
                "via": "main_tcp_session",
                "response": response,
            }),
            Err(error) => json!({
                "ok": false,
                "endpoint": endpoint,
                "command": command,
                "via": "main_tcp_session",
                "error": error.to_string(),
            }),
        };
        self.record("esp.serial.command", result.clone());
        result
    }

    /// Route a compact-CBOR firmware command through an always-on NAN
    /// infrastructure ESP. The gateway queues the addressed command for the
    /// target's next selected DW and exposes raw responses in its bounded
    /// response history. USB/UART remains only the gateway's local fallback;
    /// the sleepy target is never opened through its own serial port.
    pub fn esp_remote_command(
        &self,
        gateway: String,
        target: Option<String>,
        command: String,
        timeout_sec: Option<f64>,
        requested_active_ms: Option<u32>,
    ) -> Value {
        let target_mac = target.as_deref().and_then(|value| parse_mac(Some(value)));
        let Some(target) = target.as_deref().and_then(normalize_mac_suffix) else {
            return json!({
                "ok": false,
                "error": "gateway delivery requires target as 8-hex suffix or MAC",
            });
        };
        let timeout_ms = timeout_sec
            .map(|secs| (secs.max(0.05) * 1000.0).round() as u64)
            .unwrap_or(DEFAULT_ESP_COMMAND_TIMEOUT_MS)
            .clamp(1_000, 300_000);
        let request_id = REMOTE_COMMAND_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let payload = match firmware_targeted_command_cbor_with_metadata(
            &command,
            &target,
            Some(timeout_ms as u32),
            Some(request_id),
        ) {
            Ok(payload) => payload,
            Err(error) => return json!({"ok": false, "error": error.to_string()}),
        };

        // NAN follow-ups are intentionally short-message transport. Larger
        // requests (for example recovery/session setup) automatically open a
        // bounded "I want to talk" window so subsequent exchange can use the
        // session-oriented bearer instead of relying on one sparse DW.
        const NAN_SHORT_PAYLOAD_MAX: usize = 96;
        if let Ok(mut sessions) = self.esp_sessions.lock() {
            sessions.retain(|_, deadline| *deadline > Instant::now());
        }
        // Every queued command starts with an explicit targeted wake packet.
        // Do not rely on a previously observed lease: the command may be
        // sitting behind a missed DW, and the target must have at least one
        // complete UART exchange window before the payload is sent.
        let requested_active_ms = Some(
            requested_active_ms
                // A rebooted sleepy target is still completing Main startup
                // while the first NAN wake is being scheduled. Keep the
                // target lease at least as long as Main's startup hold so the
                // first real command can arrive after boot, not just the
                // wake handshake.
                .unwrap_or(if payload.len() > NAN_SHORT_PAYLOAD_MAX {
                    10_000
                } else {
                    10_000
                })
                .max(4_000),
        );
        let active_payload_hex = requested_active_ms.and_then(|requested_ms| {
            firmware_targeted_active_window_cbor(&target, requested_ms.clamp(4_000, 300_000))
                .ok()
                .map(|payload| hex_lower(&payload))
        });
        let active_result = if let Some(active_payload_hex) = active_payload_hex.as_deref() {
            // Open a bounded command window before sending the request itself.
            // Both frames are queued through the same infrastructure gateway
            // so a sleepy peer can accept the wake request in one DW and
            // remain awake long enough to produce its response.
            let result = self.esp_serial_command(
                None,
                Some(gateway.clone()),
                format!("nan payload=hex:{active_payload_hex}"),
                Some(2.0),
            );
            if !result.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                return json!({
                    "ok": false,
                    "gateway": gateway,
                    "target": target,
                    "error": "failed to queue active-window handshake",
                    "active": result,
                });
            }
            Some(result)
        } else {
            None
        };
        if let Some(window_ms) = requested_active_ms {
            if let Ok(mut sessions) = self.esp_sessions.lock() {
                sessions.insert(
                    target.clone(),
                    Instant::now() + Duration::from_millis(u64::from(window_ms)),
                );
            }
        }

        // A configured target has a full Wi-Fi MAC. After the NAN wake grant,
        // use the larger ESP-NOW-style custom action bearer rather than a
        // 231-byte NAN SDF. Targets supplied only as a suffix retain the
        // legacy NAN fallback because an action frame needs a full MAC.
        // A full MAC permits the larger action bearer only when the gateway
        // actually implements it.  `esp_serial_command` reports a parsed
        // console reply as transport success, so inspect the feature probe
        // before selecting action; otherwise an older gateway would retry its
        // `unknown payload key` reply until the caller times out.
        let action_capable = if target_mac.is_some() {
            let probe = self.esp_serial_command(
                None,
                Some(gateway.clone()),
                "wifi raw_response_history=true".to_string(),
                Some(2.0),
            );
            !raw_history_unsupported(&probe)
        } else {
            false
        };
        if let Some(target_mac) = target_mac.filter(|_| action_capable) {
            let raw_history_command = "wifi raw_response_history=true".to_string();
            let mut history_command = raw_history_command.clone();
            let raw_baseline = self.esp_serial_command(
                None,
                Some(gateway.clone()),
                raw_history_command,
                Some(2.0),
            );
            // Gateways from before the raw-action response-history addition
            // still receive those action frames, but expose them through the
            // existing NAN history. Keep action transport available while a
            // gateway update rolls out.
            let use_nan_history = raw_history_unsupported(&raw_baseline);
            if use_nan_history {
                history_command = "nan response_history=true".to_string();
            }
            let baseline = if use_nan_history {
                self.esp_serial_command(
                    None,
                    Some(gateway.clone()),
                    history_command.clone(),
                    Some(2.0),
                )
            } else {
                raw_baseline
            };
            let baseline_entries = if use_nan_history {
                response_history_entries(&baseline, Some(&target))
            } else {
                raw_response_history_entries(&baseline, Some(&target))
            };
            let destination = target_mac
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(":");
            let action_command = format!(
                "wifi raw_action_hex=hex:{} dst={destination}",
                hex_lower(&payload)
            );
            let command_sent_at = Instant::now();
            let deadline = command_sent_at
                + Duration::from_millis(ESP_SLEEPY_RENDEZVOUS_TIMEOUT_MS)
                + Duration::from_millis(timeout_ms);
            let mut next_send = Instant::now();
            let mut last_history = Value::Null;
            while Instant::now() < deadline {
                if Instant::now() >= next_send {
                    let queued = self.esp_serial_command(
                        None,
                        Some(gateway.clone()),
                        action_command.clone(),
                        Some(2.0),
                    );
                    if !queued.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                        return json!({"ok": false, "gateway": gateway, "target": target,
                            "error": "failed to send raw-action session command", "active": active_result, "queued": queued});
                    }
                    next_send = Instant::now() + Duration::from_millis(700);
                }
                let history = self.esp_serial_command(
                    None,
                    Some(gateway.clone()),
                    history_command.clone(),
                    Some(2.0),
                );
                last_history = history.clone();
                let entries = if use_nan_history {
                    response_history_entries(&history, Some(&target))
                } else {
                    raw_response_history_entries(&history, Some(&target))
                };
                if entries.iter().any(|(_, payload)| is_session_end(payload)) {
                    if let Ok(mut sessions) = self.esp_sessions.lock() {
                        sessions.remove(&target);
                    }
                }
                if let Some((_, response_hex)) = entries.into_iter().find(|(entry, payload)| {
                    !baseline_entries.iter().any(|known| known.0 == *entry)
                        && response_request_id(payload) == Some(request_id)
                }) {
                    if let Ok(mut sessions) = self.esp_sessions.lock() {
                        sessions.insert(
                            target.clone(),
                            Instant::now() + Duration::from_millis(5_000),
                        );
                    }
                    return json!({"ok": true, "gateway": gateway, "target": target, "command": command,
                        "response_hex": response_hex, "response_kind": "raw_action", "active": active_result,
                        "request_id": request_id,
                        "response_latency_ms": command_sent_at.elapsed().as_millis()});
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            return json!({"ok": false, "gateway": gateway, "target": target, "command": command,
                "error": "timed out waiting for raw-action session response", "active": active_result,
                "response_history": last_history});
        }

        // Establish a response-history baseline before enqueueing. This keeps
        // a delayed response from a previous request from being mistaken for
        // the current command's result.
        let baseline = self.esp_serial_command(
            None,
            Some(gateway.clone()),
            "nan response_history=true".to_string(),
            Some(2.0),
        );
        // Keep the receipt timestamp/source in the baseline key.  Comparing
        // payloads alone is insufficient for idempotent commands such as
        // `ping`: a delayed response with the same bytes would otherwise be
        // mistaken for the current request.
        let baseline_entries = response_history_entries(&baseline, Some(&target));
        let payload_hex = hex_lower(&payload);
        let queued = self.esp_serial_command(
            None,
            Some(gateway.clone()),
            format!("nan payload=hex:{payload_hex}"),
            Some(2.0),
        );
        if !queued.get("ok").and_then(Value::as_bool).unwrap_or(false) {
            return json!({
                "ok": false,
                "gateway": gateway,
                "target": target,
                "queued": queued,
            });
        }

        let command_sent_at = Instant::now();
        let deadline = command_sent_at
            + Duration::from_millis(ESP_SLEEPY_RENDEZVOUS_TIMEOUT_MS)
            + Duration::from_millis(timeout_ms);
        let wait_for_ping_pong = command.trim().eq_ignore_ascii_case("ping")
            || command.trim().eq_ignore_ascii_case("mode ping=true");
        let pong_deadline = Instant::now() + Duration::from_millis(timeout_ms.min(5_000));
        let mut command_ack: Option<String> = None;
        // A sleepy peer can miss one selected DW because the gateway and peer
        // observe the beacon at slightly different times. Retry the addressed
        // command on a jittered cadence rather than assuming one queue drain
        // is delivery. Re-send the bounded "I want to talk" frame periodically
        // as well so a missed wake frame cannot strand the command phase.
        let mut next_command_retry = Instant::now() + Duration::from_millis(3_500);
        let mut next_active_retry = Instant::now() + Duration::from_millis(7_000);
        let mut last_history = Value::Null;
        while Instant::now() < deadline {
            let now = Instant::now();
            if now >= next_active_retry {
                if let Some(active_payload_hex) = active_payload_hex.as_deref() {
                    let _ = self.esp_serial_command(
                        None,
                        Some(gateway.clone()),
                        format!("nan payload=hex:{active_payload_hex}"),
                        Some(2.0),
                    );
                }
                next_active_retry = now + Duration::from_millis(7_000);
            }
            if now >= next_command_retry {
                let _ = self.esp_serial_command(
                    None,
                    Some(gateway.clone()),
                    format!("nan payload=hex:{payload_hex}"),
                    Some(2.0),
                );
                next_command_retry = now + Duration::from_millis(3_500);
            }
            let result = self.esp_serial_command(
                None,
                Some(gateway.clone()),
                "nan response_history=true".to_string(),
                Some(2.0),
            );
            last_history = result.clone();
            let fresh_entries = response_history_entries(&result, Some(&target))
                .into_iter()
                .filter(|(entry, _)| !baseline_entries.iter().any(|known| known.0 == *entry))
                .collect::<Vec<_>>();
            if wait_for_ping_pong {
                if let Some((_, response_hex)) = fresh_entries
                    .iter()
                    .find(|(_, response_hex)| is_firmware_pong(response_hex))
                {
                    return json!({
                        "ok": true,
                        "gateway": gateway,
                        "target": target,
                        "command": command,
                        "response_hex": response_hex,
                        "response_kind": "pong",
                        "request_id": request_id,
                        "response_latency_ms": command_sent_at.elapsed().as_millis(),
                        "active": active_result,
                        "queued": queued,
                    });
                }
            }
            // A request-id-bearing command must only consume a response with
            // the same id.  In particular, the active-window handshake is a
            // separate command and intentionally has no request id; accepting
            // any fresh id-less response here can return the handshake ACK as
            // the result of the real command.  Ping is the only exception and
            // is handled above by its semantic pong check.
            if let Some((_, response_hex)) = fresh_entries
                .into_iter()
                .find(|(_, response_hex)| response_request_id(response_hex) == Some(request_id))
            {
                if !wait_for_ping_pong || Instant::now() >= pong_deadline {
                    return json!({
                        "ok": true,
                        "gateway": gateway,
                        "target": target,
                        "command": command,
                        "response_hex": response_hex,
                        "response_kind": "ack",
                        "request_id": request_id,
                        "response_latency_ms": command_sent_at.elapsed().as_millis(),
                        "active": active_result,
                        "queued": queued,
                    });
                }
                command_ack = Some(response_hex);
            }
            if wait_for_ping_pong && Instant::now() >= pong_deadline {
                if let Some(response_hex) = command_ack {
                    return json!({
                        "ok": true,
                        "gateway": gateway,
                        "target": target,
                        "command": command,
                        "response_hex": response_hex,
                        "response_kind": "ack",
                        "active": active_result,
                        "queued": queued,
                    });
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        if let Some(response_hex) = command_ack {
            return json!({
                "ok": true,
                "gateway": gateway,
                "target": target,
                "command": command,
                "response_hex": response_hex,
                "response_kind": "ack",
                "request_id": request_id,
                "response_latency_ms": command_sent_at.elapsed().as_millis(),
                "active": active_result,
                "queued": queued,
            });
        }
        json!({
            "ok": false,
            "gateway": gateway,
            "target": target,
            "command": command,
            "error": "timed out waiting for NAN response",
            "active": active_result,
            "queued": queued,
            "response_history": last_history,
        })
    }

    /// Enter or leave an ESP runtime-only powered/transfer window.
    ///
    /// `active=true` stays enabled until explicitly released. Supplying
    /// `active_ms` makes it bounded, which is appropriate for battery-node
    /// transfer and power tests. The firmware never persists either state.
    pub fn esp_active(
        &self,
        adapter: Option<String>,
        port: Option<String>,
        active: Option<bool>,
        active_ms: Option<u32>,
        gateway: Option<String>,
        target: Option<String>,
    ) -> Value {
        let enabled = active.unwrap_or(true);
        if let Some(gateway) = gateway {
            let Some(target) = target.as_deref().and_then(normalize_mac_suffix) else {
                return json!({
                    "ok": false,
                    "error": "gateway delivery requires target as 8-hex suffix or MAC",
                });
            };
            let command = if enabled {
                active_ms
                    .map(|window_ms| format!("mode active_ms={}", window_ms.clamp(1_000, 300_000)))
                    .unwrap_or_else(|| "active".to_string())
            } else {
                "idle".to_string()
            };
            // Use the same internal gateway exchange as normal commands. It
            // sends a targeted wake first, waits for the addressed response,
            // and retries across a missed DW. A single queued wake packet is
            // not sufficient to prove that a rebooted sleepy target entered
            // its active window.
            let result = self.esp_remote_command(
                gateway.clone(),
                Some(target.clone()),
                command.clone(),
                Some(20.0),
                Some(active_ms.unwrap_or(10_000).max(10_000)),
            );
            return json!({
                "ok": result.get("ok").and_then(Value::as_bool).unwrap_or(false),
                "gateway": gateway,
                "target": target,
                "command": command,
                "gateway_result": result,
            });
        }
        let command = if !enabled {
            "idle".to_string()
        } else if let Some(active_ms) = active_ms {
            format!("mode active_ms={}", active_ms.clamp(1_000, 300_000))
        } else {
            "active".to_string()
        };
        self.esp_serial_command(adapter, port, command, Some(2.0))
    }

    /// Return LoRa status from an ESP firmware serial adapter.
    pub fn esp_lora_status(&self, adapter: Option<String>, port: Option<String>) -> Value {
        self.esp_serial_command(adapter, port, "lora status=true".to_string(), Some(2.0))
    }

    /// Return raw Wi-Fi status from an ESP firmware serial adapter.
    pub fn esp_wifi_raw_status(&self, adapter: Option<String>, port: Option<String>) -> Value {
        self.esp_serial_command(adapter, port, "wifi raw_stats=true".to_string(), Some(2.0))
    }

    /// Return sleep/power status from an ESP firmware serial adapter.
    pub fn esp_sleep_status(&self, adapter: Option<String>, port: Option<String>) -> Value {
        self.esp_serial_command(adapter, port, "sleep status=true".to_string(), Some(2.0))
    }

    /// Return telemetry counters from an ESP firmware serial adapter.
    pub fn esp_telemetry_stats(
        &self,
        adapter: Option<String>,
        port: Option<String>,
        reset: Option<bool>,
    ) -> Value {
        let command = if reset.unwrap_or(false) {
            "stats reset=true".to_string()
        } else {
            "stats".to_string()
        };
        self.esp_serial_command(adapter, port, command, Some(2.0))
    }

    /// Probe likely ESP ADC1 battery pins.
    pub fn esp_battery_adc_probe(
        &self,
        adapter: Option<String>,
        port: Option<String>,
        adc1_pins: Option<String>,
        count: Option<u32>,
    ) -> Value {
        let pins = adc1_pins.unwrap_or_else(|| "32,33,34,35,36,39".to_string());
        let count = count.unwrap_or(3).clamp(1, 100);
        let command = format!("adcprobe pins={pins} count={count}");
        self.esp_serial_command(adapter, port, command, Some(5.0))
    }

    fn esp_serial_target(
        &self,
        adapter: Option<String>,
        port: Option<String>,
    ) -> Option<(String, String, u32)> {
        self.generic_serial_target(adapter, port)
            .filter(|(radio_id, _, _)| {
                radio_id == "direct-port" || radio_id.starts_with("esp-serial")
            })
    }

    fn generic_serial_target(
        &self,
        adapter: Option<String>,
        port: Option<String>,
    ) -> Option<(String, String, u32)> {
        if let Some(port) = port.filter(|port| !port.trim().is_empty()) {
            // Product APIs use stable lmesh role names (`lora1`, `lora2`),
            // while direct diagnostics may still pass a literal tty path.
            // Resolve the role before falling back to the caller's path.
            let path = configured_serial_path(&port).unwrap_or_else(|| port.clone());
            let baud = self
                .serial_forwards
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .values()
                .find(|forward| forward.id == port || forward.port == path)
                .map(|forward| forward.baud)
                .unwrap_or(460_800);
            return Some(("direct-port".to_string(), path, baud));
        }
        if let Some(adapter) = adapter
            .as_deref()
            .filter(|adapter| !adapter.trim().is_empty())
        {
            // Managed role names (for example `e5`) are valid explicit
            // diagnostic adapters even when they are not listed in the
            // generic radio-adapter catalog.  This lets callers opt out of
            // a configured NAN gateway route without opening the physical
            // TTY: esp_serial_command will find the matching UDS forward.
            let path = configured_serial_path(adapter).unwrap_or_else(|| adapter.to_owned());
            if let Some(forward) = self
                .serial_forwards
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .values()
                .find(|forward| forward.id == adapter || forward.port == path)
            {
                return Some(("direct-port".to_string(), path, forward.baud));
            }
        }
        let requested = adapter.as_deref();
        self.radios
            .iter()
            .find(|radio| {
                radio.enabled
                    && radio.medium == "serial"
                    && requested
                        .is_none_or(|id| id == radio.id || Some(id) == radio.path.as_deref())
            })
            .and_then(|radio| {
                radio.path.as_ref().map(|path| {
                    (
                        radio.id.clone(),
                        path.clone(),
                        radio.baud.unwrap_or(460_800),
                    )
                })
            })
    }

    /// Start a raw Linux HCI BLE scan for DMesh service advertisements.
    pub fn ble_scan(
        &self,
        dev_id: Option<u16>,
        reason: Option<String>,
        scan_ms: Option<u64>,
    ) -> Result<Value> {
        let dev_id = dev_id.unwrap_or(DEFAULT_HCI_DEV);
        let scan_ms = scan_ms.unwrap_or(1_500).clamp(100, 30_000);
        let hci_up = hci_dev_up(dev_id).map_err(|error| format!("{error:#}"));
        if hci_up.as_deref() == Ok("brought_up") {
            std::thread::sleep(Duration::from_millis(300));
        }
        let socket = HciSocket::open(dev_id)?;
        socket
            .send_le_command(
                OCF_LE_SET_SCAN_PARAMETERS,
                &[0x00, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00],
            )
            .with_context(|| format!("hci_up={}", result_string_json(hci_up.clone())))?;
        socket
            .send_le_command(OCF_LE_SET_SCAN_ENABLE, &[0x01, 0x00])
            .with_context(|| format!("hci_up={}", result_string_json(hci_up.clone())))?;
        let deadline = std::time::Instant::now() + Duration::from_millis(scan_ms);
        let mut reports = Vec::new();
        let mut dmesh = Vec::new();
        while let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) {
            if remaining.is_zero() {
                break;
            }
            let Some(packet) = socket.recv_timeout(remaining.min(Duration::from_millis(250)))?
            else {
                continue;
            };
            for report in parse_hci_le_adv_reports(&packet) {
                if let Some(parsed) = parse_dmesh_ble_report(&report) {
                    if let Ok(parsed) = parsed {
                        let message =
                            MeshMessage::new(mesh::message::KIND_BLE_SCAN, MeshMessageCodec::Text)
                                .field(FIELD_MEDIUM, "ble")
                                .field(FIELD_RADIO_ID, format!("hci{dev_id}"))
                                .field(FIELD_STATUS, "rx")
                                .field(
                                    FIELD_NODE,
                                    parsed
                                        .get("address")
                                        .and_then(Value::as_str)
                                        .unwrap_or("unknown"),
                                )
                                .field(
                                    FIELD_RSSI,
                                    parsed
                                        .get("scan_rssi")
                                        .and_then(Value::as_i64)
                                        .unwrap_or(0)
                                        .to_string(),
                                );
                        self.record_message("BLE.rx", "host-ble", message);
                        dmesh.push(parsed);
                    }
                }
                reports.push(report);
            }
        }
        let disable_result = socket
            .send_le_command(OCF_LE_SET_SCAN_ENABLE, &[0x00, 0x00])
            .map(|_| true)
            .unwrap_or(false);
        let result = json!({
            "ok": true,
            "backend": "linux_hci_raw",
            "dev_id": dev_id,
            "hci_up": result_string_json(hci_up),
            "scan_ms": scan_ms,
            "service_uuid16": format!("0x{:04x}", radio_protocol::DMESH_BLE_SERVICE_UUID16),
            "operational_uuid": "5f6b6f80-4f2a-4a6f-8c42-4d6573680002",
            "reason": reason.unwrap_or_else(|| "jsonl".to_string()),
            "disable_sent": disable_result,
            "report_count": reports.len(),
            "dmesh_count": dmesh.len(),
            "reports": reports,
            "dmesh": dmesh,
        });
        self.record_message(
            "BLE.scan",
            "host-ble",
            MeshMessage::new(mesh::message::KIND_BLE_SCAN, MeshMessageCodec::Text)
                .field(FIELD_MEDIUM, "ble")
                .field(FIELD_RADIO_ID, format!("hci{dev_id}"))
                .field(FIELD_STATUS, "complete"),
        );
        self.record("BLE.scan", result.clone());
        Ok(result)
    }

    /// Enable or disable raw Linux HCI BLE advertising with DMesh service data.
    pub fn ble_adv(
        &self,
        dev_id: Option<u16>,
        on: Option<bool>,
        payload: Option<String>,
    ) -> Result<Value> {
        let dev_id = dev_id.unwrap_or(DEFAULT_HCI_DEV);
        let on = on.unwrap_or(true);
        let socket = HciSocket::open(dev_id)?;
        let payload_text = payload.unwrap_or_else(|| "lmesh".to_string());
        if on {
            let device_id = local_device_id()?;
            let service_data = radio_protocol::build_ble_service_data(
                radio_protocol::BleEvent::IdleHello,
                &device_id,
                payload_text.as_bytes(),
                0,
                0,
            )?;
            socket.send_le_command(
                OCF_LE_SET_ADV_PARAMETERS,
                &[
                    0xa0, 0x00, 0xa0, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00,
                    0x00, 0x00,
                ],
            )?;
            socket.send_le_command(OCF_LE_SET_ADV_DATA, &adv_data(&service_data)?)?;
            socket.send_le_command(OCF_LE_SET_ADV_ENABLE, &[0x01])?;
        } else {
            socket.send_le_command(OCF_LE_SET_ADV_ENABLE, &[0x00])?;
        }
        let result = json!({
            "ok": true,
            "backend": "linux_hci_raw",
            "dev_id": dev_id,
            "on": on,
        });
        self.record_message(
            "BLE.adv",
            "host-ble",
            MeshMessage::new(mesh::message::KIND_BLE_ADV, MeshMessageCodec::Text)
                .field(FIELD_MEDIUM, "ble")
                .field(FIELD_RADIO_ID, format!("hci{dev_id}"))
                .field(FIELD_STATUS, if on { "enabled" } else { "disabled" })
                .field(FIELD_PAYLOAD, payload_text),
        );
        self.record("BLE.adv", result.clone());
        Ok(result)
    }

    /// Attach to NAN through the repo-built wpa_supplicant control socket.
    pub fn default_nan_control_socket_exists(&self) -> bool {
        let iface = wifi_iface(None);
        let ctrl_dir = wpa_ctrl_dir(None);
        std::fs::metadata(std::path::Path::new(&ctrl_dir).join(iface))
            .map(|metadata| metadata.file_type().is_socket())
            .unwrap_or(false)
    }

    /// Start Linux's native cfg80211/mac80211 NAN implementation.  This is
    /// intentionally a debug service: it may replace the selected interface
    /// mode and leaves all replies/events visible through mesh.sock history.
    pub fn nan_native_start(
        &self,
        iface: Option<String>,
        service_name: Option<String>,
        subscribe: bool,
    ) -> Value {
        let iface = wifi_iface(iface);
        let service_name = service_name.unwrap_or_else(|| DEFAULT_WPA_SERVICE_NAME.to_string());
        let result = (|| -> Result<Value> {
            let wiphy = wifi_wiphy_index(&iface)?;
            let nan_name = format!("dnan{}", iface.trim_start_matches("wlan"));
            let socket = Nl80211Socket::open()?;
            // Some drivers reject creation of an NL80211_IFTYPE_NAN VIF even
            // though they still expose a normal wdev.  Probe START_NAN on the
            // existing interface as well, so the debug service distinguishes
            // a VIF-only restriction from a complete lack of NAN support.
            let (wdev, ifindex, ifname, created, already_started) = match socket.new_nan_interface(wiphy, &nan_name) {
                Ok(created) => {
                    let wdev = created
                        .get("wdev")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| anyhow::anyhow!("native NAN NEW_INTERFACE returned no wdev"))?;
                    (wdev, created.get("ifindex").and_then(Value::as_u64).map(|v| v as u32), nan_name.clone(), true, false)
                }
                Err(new_error) => {
                    let base_ifindex = ifindex(&iface)?;
                    let base_wdev = socket
                        .interface_wdev(base_ifindex)
                        .with_context(|| format!("native NAN NEW_INTERFACE failed ({new_error:#}); GET_INTERFACE on {iface} also failed"))?;
                    socket.start_nan(base_wdev, 100).with_context(|| {
                        format!("native NAN NEW_INTERFACE failed ({new_error:#}); native NAN START_NAN on existing {iface} also failed")
                    })?;
                    (base_wdev, Some(base_ifindex), iface.clone(), false, true)
                }
            };
            if !already_started {
                socket
                    .start_nan(wdev, 100)
                    .context("native NAN START_NAN")?;
            }
            let service_id = nan_service_id(&service_name);
            let service_info = radio_protocol::build_nan_service_info(
                "android",
                &local_device_id()?,
                0,
            )?;
            let function = socket.add_nan_function(
                wdev,
                if subscribe { 1 } else { 0 },
                service_id,
                &service_info,
                subscribe,
            )
            .context("native NAN ADD_NAN_FUNCTION")?;
            let stop = Arc::new(AtomicBool::new(false));
            let event_history = self.history.clone();
            let event_stop = stop.clone();
            let event_iface = iface.clone();
            std::thread::spawn(move || {
                native_nan_event_loop(socket, event_iface, event_history, event_stop);
            });
            self.native_nan.lock().unwrap().insert(
                iface.clone(),
                NativeNanRuntime {
                    wdev,
                    ifindex,
                    ifname: ifname.clone(),
                    wiphy,
                    kernel_nan: created,
                    stop,
                },
            );
            Ok(json!({
                "ok": true,
                "backend": "linux_nl80211_native_nan",
                "iface": iface,
                "nan_iface": ifname,
                "created_nan_interface": created,
                "wiphy": wiphy,
                "wdev": wdev,
                "service_name": service_name,
                "service_id": hex_bytes(&service_id),
                "function": function,
                "note": "native NAN debug service; events are available in messages.history",
            }))
        })();
        let value = result.unwrap_or_else(|error| json!({
            "ok": false,
            "backend": "linux_nl80211_native_nan",
            "iface": iface,
            "error": format!("{error:#}"),
        }));
        self.record("wifi.nan.native.start", value.clone());
        value
    }

    /// Reproduce wpa_supplicant CONFIG_NAN_USD directly: managed-interface
    /// action registration, userspace SDF construction, ROC, and NL80211
    /// FRAME injection. This intentionally does not request an NAN VIF.
    pub fn nan_usd_start(
        &self,
        iface: Option<String>,
        service_name: Option<String>,
        subscribe: bool,
        infra: bool,
    ) -> Value {
        let iface = wifi_iface(iface);
        let service_name = service_name.unwrap_or_else(|| DEFAULT_WPA_SERVICE_NAME.to_string());
        let result = (|| -> Result<Value> {
            let ifidx = ifindex(&iface)?;
            let source = iface_mac(&iface)?;
            let service_id = nan_service_id(&service_name);
            let service_info = radio_protocol::build_nan_service_info(
                "android", &local_device_id()?, 0,
            )?;
            let socket = Nl80211Socket::open()?;
            socket.register_wpa_nan_usd_and_dmesh(ifidx)?;
            let stop = Arc::new(AtomicBool::new(false));
            let event_history = self.history.clone();
            let event_stop = stop.clone();
            let event_iface = iface.clone();
            let tx_frame = dmesh_rawnan::build_nan_publish_sdf(
                dmesh_rawnan::NAN_DISCOVERY_MAC,
                source,
                [0; 6],
                service_id,
                if subscribe { 2 } else { 1 },
                &service_info,
            );
            let frame_len = tx_frame.len();
            let event_service_id = service_id;
            let event_rawnan_state = self.rawnan_state.clone();
            std::thread::spawn(move || {
                nan_usd_event_tx_loop(
                    socket, event_iface, event_history, event_stop, ifidx, tx_frame,
                    event_service_id, event_rawnan_state, infra,
                );
            });
            self.native_nan.lock().unwrap().insert(
                iface.clone(),
                NativeNanRuntime {
                    wdev: 0,
                    ifindex: Some(ifidx),
                    ifname: iface.clone(),
                    wiphy: wifi_wiphy_index(&iface)?,
                    kernel_nan: false,
                    stop,
                },
            );
            Ok(json!({
                "ok": true,
                "backend": "linux_nl80211_nan_usd",
                "iface": iface,
                "service_name": service_name,
                "service_id": hex_bytes(&service_id),
                "subscribe": subscribe,
                "infra": infra,
                "frame_len": frame_len,
                "note": "wpa_supplicant-compatible userspace USD; events are available in messages.history",
            }))
        })();
        let value = result.unwrap_or_else(|error| json!({
            "ok": false, "backend": "linux_nl80211_nan_usd", "iface": iface,
            "error": format!("{error:#}"),
        }));
        self.record("wifi.nan.usd.start", value.clone());
        value
    }

    pub fn nan_native_status(&self, iface: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let runtime = self.native_nan.lock().unwrap().get(&iface).map(|r| {
            json!({"wdev": r.wdev, "ifindex": r.ifindex, "nan_iface": r.ifname,
                   "wiphy": r.wiphy, "running": !r.stop.load(Ordering::Acquire)})
        });
        let events = self.history.lock().unwrap().iter()
            .filter(|event| event.key == "wifi.nan.native.event" && event.source == iface)
            .count();
        json!({"ok": true, "backend": "linux_nl80211_native_nan", "iface": iface,
               "runtime": runtime, "event_count": events})
    }

    pub fn nan_native_transmit(
        &self,
        iface: Option<String>,
        destination: String,
        instance_id: u8,
        requestor_id: u8,
        payload_text: String,
    ) -> Value {
        let iface = wifi_iface(iface);
        let result = (|| -> Result<Value> {
            let wdev = self.native_nan.lock().unwrap().get(&iface)
                .map(|runtime| runtime.wdev)
                .ok_or_else(|| anyhow::anyhow!("native NAN is not running on {iface}"))?;
            let destination = parse_mac(Some(&destination))
                .ok_or_else(|| anyhow::anyhow!("invalid destination MAC"))?;
            let socket = Nl80211Socket::open()?;
            let info = socket.add_nan_followup(wdev, instance_id, requestor_id, destination, payload_text.as_bytes())?;
            Ok(json!({"ok": true, "backend": "linux_nl80211_native_nan", "iface": iface,
                       "destination": colon_mac(&destination), "function": info}))
        })();
        let value = result.unwrap_or_else(|error| json!({"ok": false, "backend": "linux_nl80211_native_nan", "iface": iface, "error": format!("{error:#}")}));
        self.record("wifi.nan.native.transmit", value.clone());
        value
    }

    pub fn nan_native_stop(&self, iface: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let runtime = self.native_nan.lock().unwrap().remove(&iface);
        let Some(runtime) = runtime else {
            return json!({"ok": true, "iface": iface, "already_stopped": true});
        };
        runtime.stop.store(true, Ordering::Release);
        let result = Nl80211Socket::open()
            .and_then(|socket| {
                if runtime.kernel_nan {
                    socket.stop_nan(runtime.wdev)?;
                    if runtime.ifname != iface {
                        if let Some(ifindex) = runtime.ifindex {
                            socket.del_interface(ifindex)?;
                        }
                    }
                }
                Ok(())
            })
            .map(|_| json!({"ok": true, "backend": "linux_nl80211_native_nan", "iface": iface, "wdev": runtime.wdev}))
            .unwrap_or_else(|error| json!({"ok": false, "backend": "linux_nl80211_native_nan", "iface": iface, "wdev": runtime.wdev, "error": format!("{error:#}")}));
        self.record("wifi.nan.native.stop", result.clone());
        result
    }

    /// Attach to NAN through the repo-built wpa_supplicant control socket.
    pub fn nan_start(&self, iface: Option<String>, ctrl_dir: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let ctrl_dir = wpa_ctrl_dir(ctrl_dir);
        let link_up = set_link_up(&iface);
        let interface_add = if wpa_command(&iface, &ctrl_dir, "STATUS")
            .is_ok_and(|output| output.status == Some(0))
        {
            Ok(CommandOutput {
                status: Some(0),
                stdout: "already attached".to_string(),
                stderr: String::new(),
            })
        } else {
            let global_dir = std::env::var("LMESH_WPA_GLOBAL_CTRL_DIR")
                .unwrap_or_else(|_| "/run/mesh/wpa-supplicant".to_string());
            wpa_global_command(
                &global_dir,
                &format!("INTERFACE_ADD {iface}\t\tnl80211\tDIR={ctrl_dir} GROUP=plugdev\t\t"),
            )
        };
        let nan_capability = wpa_raw_command(&iface, &ctrl_dir, "GET_CAPABILITY nan");
        let status = wpa_command(&iface, &ctrl_dir, "STATUS");
        let driver_flags2 = wpa_command(&iface, &ctrl_dir, "DRIVER_FLAGS2");
        let result = json!({
            "link_up": command_result_json(link_up),
            "interface_add": command_result_json(interface_add),
            "nan_capability": command_result_json(nan_capability),
            "status": command_result_json(status),
            "driver_flags2": command_result_json(driver_flags2),
        });
        self.record_message(
            "N.start",
            "host-nan",
            MeshMessage::new(mesh::message::KIND_NAN_START, MeshMessageCodec::WpaText)
                .field(FIELD_MEDIUM, "nan")
                .field(FIELD_IFACE, &iface)
                .field(FIELD_CTRL_DIR, &ctrl_dir),
        );
        self.record("N.start", result.clone());
        result
    }

    /// Start the default DMesh NAN publish/subscribe service.
    pub fn nan_default(
        &self,
        iface: Option<String>,
        ctrl_dir: Option<String>,
        service_name: Option<String>,
        ttl: Option<u32>,
    ) -> Value {
        let iface_value = wifi_iface(iface);
        let ctrl_dir_value = wpa_ctrl_dir(ctrl_dir);
        let service_name = service_name.unwrap_or_else(|| DEFAULT_WPA_SERVICE_NAME.to_string());
        let ttl = ttl.unwrap_or(DEFAULT_NAN_TTL_SECS);
        let start = self.nan_start(Some(iface_value.clone()), Some(ctrl_dir_value.clone()));
        let publish = self.nan_publish(
            Some(iface_value.clone()),
            Some(ctrl_dir_value.clone()),
            Some(service_name.clone()),
            None,
            Some(ttl),
            Some(2437),
            Some(0),
        );
        let subscribe = self.nan_subscribe(
            Some(iface_value.clone()),
            Some(ctrl_dir_value.clone()),
            Some(service_name.clone()),
            None,
            Some(ttl),
            Some(2437),
            Some(true),
            Some(0),
        );
        let events = self.nan_events(
            Some(iface_value.clone()),
            Some(ctrl_dir_value.clone()),
            Some(50),
            Some(16),
        );
        let result = json!({
            "ok": true,
            "iface": iface_value,
            "ctrl_dir": ctrl_dir_value,
            "service_name": service_name,
            "ttl": ttl,
            "start": start,
            "publish": publish,
            "subscribe": subscribe,
            "events": events,
        });
        self.record("N.default", result.clone());
        result
    }

    /// Return NAN status and recent events.
    pub fn nan_status(
        &self,
        iface: Option<String>,
        ctrl_dir: Option<String>,
        events_ms: Option<u64>,
    ) -> Value {
        let iface = wifi_iface(iface);
        let ctrl_dir = wpa_ctrl_dir(ctrl_dir);
        let result = json!({
            "iface": iface,
            "ctrl_dir": ctrl_dir,
            "status": command_result_json(wpa_command(&iface, &ctrl_dir, "STATUS")),
            "driver_flags": command_result_json(wpa_command(&iface, &ctrl_dir, "DRIVER_FLAGS")),
            "driver_flags2": command_result_json(wpa_command(&iface, &ctrl_dir, "DRIVER_FLAGS2")),
            "nan_capability": command_result_json(wpa_command(&iface, &ctrl_dir, "GET_CAPABILITY nan")),
            "events": self.nan_events(Some(iface.clone()), Some(ctrl_dir.clone()), events_ms.or(Some(100)), Some(64)),
        });
        self.record("N.status", result.clone());
        result
    }

    /// Stop NAN sessions through wpa_supplicant.
    pub fn nan_stop(&self, iface: Option<String>, ctrl_dir: Option<String>) -> Value {
        let iface = wifi_iface(iface);
        let ctrl_dir = wpa_ctrl_dir(ctrl_dir);
        let publish = wpa_raw_command(&iface, &ctrl_dir, "NAN_CANCEL_PUBLISH publish_id=1");
        let subscribe = wpa_raw_command(&iface, &ctrl_dir, "NAN_CANCEL_SUBSCRIBE subscribe_id=1");
        let flush = wpa_raw_command(&iface, &ctrl_dir, "NAN_FLUSH");
        let result = json!({
            "publish": command_result_json(publish),
            "subscribe": command_result_json(subscribe),
            "flush": command_result_json(flush),
        });
        self.record("N.stop", result.clone());
        result
    }

    /// Start a NAN publish and return the assigned handle when available.
    #[allow(clippy::too_many_arguments)]
    pub fn nan_publish(
        &self,
        iface: Option<String>,
        ctrl_dir: Option<String>,
        service_name: Option<String>,
        ssi_hex: Option<String>,
        ttl: Option<u32>,
        freq: Option<u32>,
        srv_proto_type: Option<u8>,
    ) -> Value {
        let iface = wifi_iface(iface);
        let ctrl_dir = wpa_ctrl_dir(ctrl_dir);
        let _ = set_link_up(&iface);
        let ssi_hex = ssi_hex.unwrap_or_else(|| {
            radio_protocol::build_nan_service_info(
                "android",
                &local_device_id().unwrap_or([0; 6]),
                0,
            )
            .map(|bytes| hex_bytes(&bytes))
            .unwrap_or_default()
        });
        let cmd = format!(
            "NAN_PUBLISH service_name={} ttl={} freq={} srv_proto_type={} ssi={}",
            service_name.unwrap_or_else(|| DEFAULT_WPA_SERVICE_NAME.to_string()),
            ttl.unwrap_or(DEFAULT_NAN_TTL_SECS),
            freq.unwrap_or(2437),
            srv_proto_type.unwrap_or(0),
            ssi_hex
        );
        let raw = wpa_raw_command(&iface, &ctrl_dir, &cmd);
        let handle = raw
            .as_ref()
            .ok()
            .and_then(|out| out.stdout.trim().parse::<u32>().ok());
        let result = json!({
            "command": cmd,
            "handle": handle,
            "result": command_result_json(raw),
        });
        self.record("N.publish", result.clone());
        result
    }

    /// Start a NAN subscribe and return the assigned handle when available.
    #[allow(clippy::too_many_arguments)]
    pub fn nan_subscribe(
        &self,
        iface: Option<String>,
        ctrl_dir: Option<String>,
        service_name: Option<String>,
        ssi_hex: Option<String>,
        ttl: Option<u32>,
        freq: Option<u32>,
        active: Option<bool>,
        srv_proto_type: Option<u8>,
    ) -> Value {
        let iface = wifi_iface(iface);
        let ctrl_dir = wpa_ctrl_dir(ctrl_dir);
        let _ = set_link_up(&iface);
        let mut cmd = format!(
            "NAN_SUBSCRIBE service_name={} ttl={} freq={} srv_proto_type={}",
            service_name.unwrap_or_else(|| DEFAULT_WPA_SERVICE_NAME.to_string()),
            ttl.unwrap_or(DEFAULT_NAN_TTL_SECS),
            freq.unwrap_or(2437),
            srv_proto_type.unwrap_or(0)
        );
        if active.unwrap_or(true) {
            cmd.push_str(" active=1");
        }
        if let Some(ssi_hex) = ssi_hex {
            cmd.push_str(&format!(" ssi={ssi_hex}"));
        }
        let raw = wpa_raw_command(&iface, &ctrl_dir, &cmd);
        let handle = raw
            .as_ref()
            .ok()
            .and_then(|out| out.stdout.trim().parse::<u32>().ok());
        let result = json!({
            "command": cmd,
            "handle": handle,
            "result": command_result_json(raw),
        });
        self.record("N.subscribe", result.clone());
        result
    }

    /// Send a NAN follow-up.
    #[allow(clippy::too_many_arguments)]
    pub fn nan_transmit(
        &self,
        iface: Option<String>,
        ctrl_dir: Option<String>,
        handle: u32,
        address: String,
        req_instance_id: Option<u32>,
        ssi_hex: Option<String>,
        payload: Option<String>,
        cookie: Option<u32>,
    ) -> Value {
        let iface = wifi_iface(iface);
        let ctrl_dir = wpa_ctrl_dir(ctrl_dir);
        let ssi_hex = ssi_hex.or_else(|| payload.map(|payload| hex_bytes(payload.as_bytes())));
        let mut cmd = format!("NAN_TRANSMIT handle={handle} address={address}");
        if let Some(req_instance_id) = req_instance_id {
            cmd.push_str(&format!(" req_instance_id={req_instance_id}"));
        }
        if let Some(ssi_hex) = ssi_hex {
            cmd.push_str(&format!(" ssi={ssi_hex}"));
        }
        if let Some(cookie) = cookie {
            cmd.push_str(&format!(" cookie={cookie}"));
        }
        let raw = wpa_raw_command(&iface, &ctrl_dir, &cmd);
        let result = json!({
            "command": cmd,
            "result": command_result_json(raw),
        });
        self.record("N.transmit", result.clone());
        result
    }

    /// Collect NAN events by attaching to the WPA control socket.
    pub fn nan_events(
        &self,
        iface: Option<String>,
        ctrl_dir: Option<String>,
        wait_ms: Option<u64>,
        max_events: Option<usize>,
    ) -> Value {
        let iface = wifi_iface(iface);
        let ctrl_dir = wpa_ctrl_dir(ctrl_dir);
        let events = wpa_ctrl_events(
            &format!("{ctrl_dir}/{iface}"),
            wait_ms.unwrap_or(250),
            max_events.unwrap_or(64),
        );
        match events {
            Ok(events) => {
                for event in &events {
                    self.record("N.event.raw", event.clone());
                    if let Some(message) = nan_event_message(event) {
                        let event_name = event
                            .get("event")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("NAN");
                        tracing::info!(
                            event = event_name,
                            peer = message
                                .fields
                                .get(&mesh::message::FIELD_PEER)
                                .map(String::as_str)
                                .unwrap_or(""),
                            node = message
                                .fields
                                .get(&FIELD_NODE)
                                .map(String::as_str)
                                .unwrap_or(""),
                            payload = message
                                .fields
                                .get(&FIELD_PAYLOAD)
                                .map(String::as_str)
                                .unwrap_or(""),
                            "nan_event"
                        );
                        self.record_message("N.event", "host-nan", message);
                    }
                }
                json!({ "ok": true, "events": events })
            }
            Err(error) => json!({ "ok": false, "error": error }),
        }
    }

    /// Probe what service-info sizes wpa_supplicant accepts at the control/API layer.
    pub fn nan_size_probe(
        &self,
        iface: Option<String>,
        ctrl_dir: Option<String>,
        sizes: Option<String>,
        mode: Option<String>,
    ) -> Value {
        let iface = wifi_iface(iface);
        let ctrl_dir = wpa_ctrl_dir(ctrl_dir);
        let sizes = parse_size_list(sizes.as_deref())
            .unwrap_or_else(|| vec![64, 128, 192, 224, 230, 255, 384, 512, 1024]);
        let mode = mode.unwrap_or_else(|| "publish".to_string());
        let mut results = Vec::new();
        for size in sizes {
            let ssi_hex = "aa".repeat(size);
            let command = if mode == "transmit" {
                format!("NAN_TRANSMIT handle=1 address=ff:ff:ff:ff:ff:ff ssi={ssi_hex}")
            } else {
                format!(
                    "NAN_PUBLISH service_name={} ttl=0 freq=2437 srv_proto_type=0 ssi={}",
                    DEFAULT_WPA_SERVICE_NAME, ssi_hex
                )
            };
            let output = wpa_raw_command(&iface, &ctrl_dir, &command);
            let ok = output
                .as_ref()
                .map(|out| out.status == Some(0))
                .unwrap_or(false);
            results.push(json!({
                "size": size,
                "ok": ok,
                "result": command_result_json(output),
            }));
        }
        let max_ok = results
            .iter()
            .filter(|entry| entry.get("ok").and_then(Value::as_bool) == Some(true))
            .filter_map(|entry| entry.get("size").and_then(Value::as_u64))
            .max();
        let result = json!({
            "ok": true,
            "mode": mode,
            "note": "This probes wpa_supplicant/control acceptance. Over-the-air DW success still needs peer observation.",
            "max_ok": max_ok,
            "results": results,
        });
        self.record("N.size_probe", result.clone());
        result
    }

    /// Start a NAN publish using DMesh service info.
    pub fn nan_adv(&self, iface: Option<String>, ctrl_dir: Option<String>) -> Result<Value> {
        let result = self.nan_publish(iface, ctrl_dir, None, None, None, None, None);
        self.record_message(
            "N.publish",
            "host-nan",
            MeshMessage::new(mesh::message::KIND_NAN_PUBLISH, MeshMessageCodec::WpaText)
                .field(FIELD_MEDIUM, "nan")
                .field(FIELD_STATUS, "legacy_adv"),
        );
        Ok(result)
    }

    /// Start a NAN subscribe using the DMesh service name.
    pub fn nan_sub(&self, iface: Option<String>, ctrl_dir: Option<String>) -> Value {
        let result = self.nan_subscribe(iface, ctrl_dir, None, None, None, None, Some(true), None);
        self.record_message(
            "N.subscribe",
            "host-nan",
            MeshMessage::new(mesh::message::KIND_NAN_SUBSCRIBE, MeshMessageCodec::WpaText)
                .field(FIELD_MEDIUM, "nan")
                .field(FIELD_STATUS, "legacy_sub"),
        );
        result
    }

    /// Send a NAN follow-up ping/probe.
    pub fn nan_ping(
        &self,
        iface: Option<String>,
        ctrl_dir: Option<String>,
        peer: Option<String>,
        payload: Option<String>,
    ) -> Result<Value> {
        let iface = wifi_iface(iface);
        let ctrl_dir = wpa_ctrl_dir(ctrl_dir);
        let _ = set_link_up(&iface);
        let target = parse_device_id(peer.as_deref()).unwrap_or([0xff; 6]);
        let payload_text = payload.unwrap_or_else(|| "ping".to_string());
        let followup = radio_protocol::build_nan_followup(
            "hello",
            &local_device_id()?,
            &target,
            payload_text.as_bytes(),
        )?;
        let cmd = format!(
            "NAN_TRANSMIT handle=1 address={} ssi={}",
            colon_mac(&target),
            hex_bytes(&followup)
        );
        let result = command_result_json(wpa_raw_command(&iface, &ctrl_dir, &cmd));
        self.record_message(
            "N.transmit",
            "host-nan",
            MeshMessage::new(mesh::message::KIND_NAN_FOLLOWUP, MeshMessageCodec::WpaText)
                .field(FIELD_MEDIUM, "nan")
                .field(FIELD_IFACE, &iface)
                .field(FIELD_CTRL_DIR, &ctrl_dir)
                .field(FIELD_PAYLOAD, payload_text),
        );
        self.record("N.transmit", result.clone());
        Ok(result)
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

#[derive(Debug)]
struct SerialForwardRuntime {
    id: String,
    radio_id: String,
    port: String,
    socket_path: String,
    tcp_listen: Option<String>,
    log_path: Option<String>,
    baud: u32,
    multi: bool,
    reset_request: Arc<AtomicU8>,
    flush_request: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    stats: Arc<SerialForwardStats>,
    firmware_state: Arc<Mutex<FirmwareState>>,
    handle: Option<std::thread::JoinHandle<()>>,
    started_ms: u64,
}

/// Last lifecycle notification observed on a managed firmware forward.
/// This is intentionally host RAM only: it is an observation of the current
/// UART session, not device configuration or durable device identity.
#[derive(Clone, Debug, Default)]
struct FirmwareState {
    role: Option<String>,
    partition: Option<String>,
    mode: Option<String>,
    infra_active: Option<bool>,
    phase: Option<String>,
    rebooted: Option<bool>,
    reset_reason: Option<u8>,
    mac: Option<String>,
    last_event_ms: u64,
}

impl FirmwareState {
    fn snapshot(&self) -> Value {
        json!({
            "role": self.role,
            "partition": self.partition,
            "mode": self.mode,
            "infra_active": self.infra_active,
            "phase": self.phase,
            "rebooted": self.rebooted,
            "reset_reason": self.reset_reason,
            "mac": self.mac,
            "last_event_ms": self.last_event_ms,
        })
    }
}

#[derive(Clone, Debug)]
struct ReverseMainRuntime {
    id: String,
    ip: Ipv4Addr,
    port: u16,
    socket_path: String,
    stream: Arc<Mutex<Option<TcpStream>>>,
}

struct StabilityRuntime {
    stop: Arc<AtomicBool>,
    state: Arc<Mutex<StabilityState>>,
}

impl StabilityRuntime {
    fn running(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .running
    }

    fn snapshot(&self) -> Value {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .snapshot()
    }
}

#[derive(Debug)]
struct StabilityState {
    running: bool,
    source: String,
    expected: Vec<String>,
    interval_sec: u64,
    wait_sec: u64,
    cycles_requested: Option<u32>,
    host_nan: bool,
    cycles_completed: u32,
    last_completed_ms: u64,
    last: Value,
}

impl StabilityState {
    fn new(
        source: String,
        expected: Vec<String>,
        interval_sec: u64,
        wait_sec: u64,
        cycles_requested: Option<u32>,
        host_nan: bool,
    ) -> Self {
        Self {
            running: true,
            source,
            expected,
            interval_sec,
            wait_sec,
            cycles_requested,
            host_nan,
            cycles_completed: 0,
            last_completed_ms: 0,
            last: Value::Null,
        }
    }

    fn snapshot(&self) -> Value {
        json!({
            "ok": true,
            "running": self.running,
            "source": self.source,
            "expected": self.expected,
            "interval_sec": self.interval_sec,
            "wait_sec": self.wait_sec,
            "cycles_requested": self.cycles_requested,
            "host_nan": self.host_nan,
            "cycles_completed": self.cycles_completed,
            "last_completed_ms": self.last_completed_ms,
            "last": self.last,
        })
    }
}

#[derive(Default, Debug)]
struct SerialForwardStats {
    reset_requests: AtomicU64,
    reset_pulses: AtomicU64,
    reset_failures: AtomicU64,
    client_accepts: AtomicU64,
    client_drops: AtomicU64,
    client_to_serial_bytes: AtomicU64,
    serial_to_client_bytes: AtomicU64,
    serial_read_would_block: AtomicU64,
    serial_write_blocked: AtomicU64,
    client_read_would_block: AtomicU64,
    client_write_blocked: AtomicU64,
    serial_tx_queue_high_water: AtomicU64,
    serial_pending_queue_high_water: AtomicU64,
    uart_wake_frames: AtomicU64,
    uart_wake_flushes: AtomicU64,
    uart_wake_flush_bytes: AtomicU64,
    client_output_queue_high_water: AtomicU64,
    client_input_queue_high_water: AtomicU64,
    poll_calls: AtomicU64,
    poll_ready: AtomicU64,
    poll_timeouts: AtomicU64,
    log_records: AtomicU64,
    log_write_errors: AtomicU64,
    log_suppressed_records: AtomicU64,
    log_suppressed_bytes: AtomicU64,
}

impl SerialForwardStats {
    fn record_high_water(counter: &AtomicU64, value: usize) {
        counter.fetch_max(value as u64, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Value {
        json!({
            "reset_requests": self.reset_requests.load(Ordering::Relaxed),
            "reset_pulses": self.reset_pulses.load(Ordering::Relaxed),
            "reset_failures": self.reset_failures.load(Ordering::Relaxed),
            "client_accepts": self.client_accepts.load(Ordering::Relaxed),
            "client_drops": self.client_drops.load(Ordering::Relaxed),
            "client_to_serial_bytes": self.client_to_serial_bytes.load(Ordering::Relaxed),
            "serial_to_client_bytes": self.serial_to_client_bytes.load(Ordering::Relaxed),
            "serial_read_would_block": self.serial_read_would_block.load(Ordering::Relaxed),
            "serial_write_blocked": self.serial_write_blocked.load(Ordering::Relaxed),
            "client_read_would_block": self.client_read_would_block.load(Ordering::Relaxed),
            "client_write_blocked": self.client_write_blocked.load(Ordering::Relaxed),
            "serial_tx_queue_high_water": self.serial_tx_queue_high_water.load(Ordering::Relaxed),
            "serial_pending_queue_high_water": self.serial_pending_queue_high_water.load(Ordering::Relaxed),
            "uart_wake_frames": self.uart_wake_frames.load(Ordering::Relaxed),
            "uart_wake_flushes": self.uart_wake_flushes.load(Ordering::Relaxed),
            "uart_wake_flush_bytes": self.uart_wake_flush_bytes.load(Ordering::Relaxed),
            "client_output_queue_high_water": self.client_output_queue_high_water.load(Ordering::Relaxed),
            "client_input_queue_high_water": self.client_input_queue_high_water.load(Ordering::Relaxed),
            "poll_calls": self.poll_calls.load(Ordering::Relaxed),
            "poll_ready": self.poll_ready.load(Ordering::Relaxed),
            "poll_timeouts": self.poll_timeouts.load(Ordering::Relaxed),
            "log_records": self.log_records.load(Ordering::Relaxed),
            "log_write_errors": self.log_write_errors.load(Ordering::Relaxed),
            "log_suppressed_records": self.log_suppressed_records.load(Ordering::Relaxed),
            "log_suppressed_bytes": self.log_suppressed_bytes.load(Ordering::Relaxed),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SerialForwardTcpMode {
    Framed,
    Rfc2217,
    Auto,
}

impl SerialForwardTcpMode {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "framed" | "frame" | "text" | "plain" => Ok(Self::Framed),
            "rfc2217" | "telnet" | "flash" => Ok(Self::Rfc2217),
            "auto" | "" => Ok(Self::Auto),
            other => {
                bail!("unsupported serial TCP mode {other:?}; expected framed, rfc2217, or auto")
            }
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Framed => "framed",
            Self::Rfc2217 => "rfc2217",
            Self::Auto => "auto",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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

fn discover_usb_serial_devices() -> Vec<Value> {
    let mut paths = BTreeMap::<String, Value>::new();
    for prefix in ["/dev/ttyUSB", "/dev/ttyACM"] {
        for idx in 0..64 {
            let path = format!("{prefix}{idx}");
            if let Ok(metadata) = fs::metadata(&path) {
                if metadata.file_type().is_char_device() {
                    paths.insert(path.clone(), serial_device_json(&path, None));
                }
            }
        }
    }
    if let Ok(entries) = fs::read_dir("/dev/serial/by-id") {
        for entry in entries.flatten() {
            let symlink = entry.path();
            let Ok(target) = fs::canonicalize(&symlink) else {
                continue;
            };
            let Some(path) = target.to_str().map(str::to_string) else {
                continue;
            };
            let by_id = symlink.to_string_lossy().to_string();
            paths
                .entry(path.clone())
                .and_modify(|device| {
                    device["by_id"] = json!(by_id);
                })
                .or_insert_with(|| serial_device_json(&path, Some(by_id)));
        }
    }
    paths.into_values().collect()
}

fn serial_device_json(path: &str, by_id: Option<String>) -> Value {
    let metadata = fs::metadata(path).ok();
    let mode = metadata
        .as_ref()
        .map(|metadata| metadata.permissions().mode() & 0o7777);
    json!({
        "port": usb_port_id_from_path(path),
        "path": path,
        "by_id": by_id,
        "kind": if path.contains("ttyACM") { "cdc-acm" } else { "usb-serial" },
        "mode": mode.map(|mode| format!("{mode:04o}")),
    })
}

#[derive(Clone, Debug)]
struct UsbSerialTarget {
    id: String,
    path: String,
    socket_path: String,
    baud: u32,
}

fn resolve_usb_serial_target(port: Option<String>, baud: Option<u32>) -> Option<UsbSerialTarget> {
    let id = port
        .as_deref()
        .or(Some("USB0"))
        .and_then(canonical_usb_port_id)?;
    let path = usb_port_path(&id)?;
    Some(UsbSerialTarget {
        socket_path: format!("/run/mesh/lmesh/{id}.sock"),
        id,
        path,
        baud: baud.unwrap_or(460_800),
    })
}

fn canonical_usb_port_id(port: &str) -> Option<String> {
    let trimmed = port.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(name) = trimmed.strip_prefix("/dev/tty") {
        return canonical_usb_port_id(name);
    }
    let upper = trimmed.to_ascii_uppercase();
    if let Some(num) = upper.strip_prefix("USB") {
        return (!num.is_empty() && num.chars().all(|c| c.is_ascii_digit()))
            .then(|| format!("USB{num}"));
    }
    if let Some(num) = upper.strip_prefix("ACM") {
        return (!num.is_empty() && num.chars().all(|c| c.is_ascii_digit()))
            .then(|| format!("ACM{num}"));
    }
    // Configured lab/deployment roles use stable names instead of transient
    // tty numbering. Keep the accepted alphabet deliberately narrow because
    // the value is also used in the managed socket filename.
    (trimmed.len() <= 64
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')))
    .then(|| trimmed.to_string())
}

fn usb_port_path(id: &str) -> Option<String> {
    if let Some(path) = configured_serial_path(id) {
        return Some(path);
    }
    if let Some(num) = id.strip_prefix("USB") {
        return Some(format!("/dev/ttyUSB{num}"));
    }
    if let Some(num) = id.strip_prefix("ACM") {
        return Some(format!("/dev/ttyACM{num}"));
    }
    None
}

fn configured_serial_forward(id: &str) -> Option<SerialForwardConfig> {
    read_lmesh_config()?
        .serial_forwards
        .into_iter()
        .find(|forward| forward.port == id)
}

fn configured_serial_path(id: &str) -> Option<String> {
    configured_serial_forward(id)
        .and_then(|forward| forward.path)
        .filter(|path| !path.is_empty())
}

fn configured_serial_log_path() -> Option<String> {
    let config_path = lmesh_config_path();
    read_lmesh_config()?
        .serial_log_path
        .filter(|path| !path.is_empty())
        .map(|path| resolve_config_relative_path(&config_path, &path))
}

fn configured_serial_log_path_for_forward(id: &str) -> Option<String> {
    let config = read_lmesh_config()?;
    if config
        .serial_forwards
        .iter()
        .find(|forward| forward.port == id)
        .is_some_and(|forward| forward.log == Some(false))
    {
        return None;
    }
    config
        .serial_log_path
        .filter(|path| !path.is_empty())
        .map(|path| resolve_config_relative_path(&lmesh_config_path(), &path))
}

/// Resolve a relative config value beside the actual config file, following a
/// deployment symlink when present. This keeps lab captures under the checkout
/// target directory rather than under lmesh's service working directory.
fn resolve_config_relative_path(config_path: &Path, value: &str) -> String {
    let value_path = Path::new(value);
    if value_path.is_absolute() {
        return value.to_string();
    }
    let resolved_config = config_path
        .canonicalize()
        .unwrap_or_else(|_| config_path.to_path_buf());
    resolved_config
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(value_path)
        .to_string_lossy()
        .into_owned()
}

fn usb_port_id_from_path(path: &str) -> Option<String> {
    let name = path.strip_prefix("/dev/tty").unwrap_or(path);
    canonical_usb_port_id(name)
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

fn serial_forward_loop(
    id: &str,
    port: &str,
    baud: u32,
    listener: UnixListener,
    tcp_listener: Option<TcpListener>,
    tcp_mode: SerialForwardTcpMode,
    multi: bool,
    raw_output: bool,
    reset_request: Arc<AtomicU8>,
    flush_request: Arc<AtomicBool>,
    initial_direct_write: bool,
    log_flash_quiet_until_ms: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    stats: Arc<SerialForwardStats>,
    firmware_state: Arc<Mutex<FirmwareState>>,
    log_path: Option<String>,
    serial_log: Option<Arc<Mutex<SerialForwardLog>>>,
) -> Result<()> {
    let mut serial = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
        .open(port)
        .with_context(|| format!("failed to open serial port {port}"))?;
    configure_serial(serial.as_raw_fd(), baud)
        .with_context(|| format!("failed to configure serial port {port}"))?;
    // Linux's tty open path may leave DTR and/or RTS asserted even though
    // lmesh did not request them. The CP210x board circuit combines both
    // lines into EN/GPIO0, so changing only one can select reset or ROM
    // bootloader. Normalize both together to the released/normal state; this
    // is not a pulse and explicit `usb.serial.reset` remains the only reset
    // operation exposed by lmesh.
    let state = modem_state(serial.as_raw_fd())?;
    let normal_state = state & !(libc::TIOCM_DTR | libc::TIOCM_RTS);
    if state != normal_state {
        set_modem_state(serial.as_raw_fd(), normal_state)
            .with_context(|| format!("failed to normalize modem lines for {port}"))?;
        tracing::debug!(forward_id = %id, port = %port, "serial_forward_normalized_modem_lines");
    }
    if log_path.is_some() && serial_log.is_none() {
        stats.log_write_errors.fetch_add(1, Ordering::Relaxed);
    }
    let mut clients: Vec<SerialForwardClient> = Vec::new();
    let mut firmware_uart_decoder = FirmwareUartDecoder::default();
    let mut serial_tx = VecDeque::new();
    // Probe twice without waiting.  This is deliberately a transport-level
    // probe: infra boards answer and release the client queue; sleepy boards
    // leave client records pending until a UART heartbeat/window arrives.
    let mut direct_write = initial_direct_write || raw_output;
    let mut mode_known = direct_write;
    let mut mode_probe_next_ms = now_millis_u64().saturating_add(500);
    let mut mode_probe_deadline = now_millis_u64().saturating_add(10_000);
    if !raw_output {
        for _ in 0..2 {
            let probe = firmware_command_cbor("mode status=true")
                .context("failed to encode serial-forward mode probe")?;
            queue_firmware_packet(&mut serial_tx, &probe)?;
        }
    }
    let mut serial_pending = VecDeque::new();
    // UART wake is proved by the firmware's framed heartbeat or an in-band
    // command window.  The forward never creates a wake by modem control.
    let mut serial_buf = [0_u8; SERIAL_FORWARD_IO_BUFFER_BYTES];
    while !stop.load(Ordering::Acquire) {
        let mut progressed = false;
        let mut uart_wake_seen = false;
        let mut nan_sleepy_start_seen = false;
        let reset_pending = reset_request
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                (pending != SERIAL_RESET_NONE).then_some(pending - 1)
            })
            .unwrap_or(SERIAL_RESET_NONE);
        if reset_pending != SERIAL_RESET_NONE {
            if let Err(error) = serial_run_reset(serial.as_raw_fd()) {
                stats.reset_failures.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(forward_id = %id, port = %port, error = %error, "serial_reset_rejected");
            } else {
                stats.reset_pulses.fetch_add(1, Ordering::Relaxed);
                configure_serial(serial.as_raw_fd(), baud)
                    .with_context(|| format!("failed to restore serial baud for {port}"))?;
                if !raw_output {
                    // A reset is also the boot/recovery handoff boundary. The
                    // next client bytes may be a stage2 selector or Recovery
                    // command and must cross the same descriptor immediately;
                    // do not queue them behind the sleepy/Main mode probe.
                    // Main will publish its mode state after a normal boot and
                    // restore the usual sleepy/infra policy below.
                    mode_known = true;
                    direct_write = true;
                    mode_probe_next_ms = 0;
                    mode_probe_deadline = 0;
                }
            }
            progressed = true;
        }
        if flush_request.swap(false, Ordering::AcqRel) && !serial_pending.is_empty() {
            if serial_tx.len().saturating_add(serial_pending.len()) > SERIAL_FORWARD_MAX_PENDING {
                bail!(
                    "serial TX queue exceeded {} bytes while explicitly flushing UART queue",
                    SERIAL_FORWARD_MAX_PENDING
                );
            }
            serial_tx.append(&mut serial_pending);
            progressed = true;
        }
        if !raw_output
            && !mode_known
            && now_millis_u64() >= mode_probe_next_ms
            && now_millis_u64() < mode_probe_deadline
        {
            let probe = firmware_command_cbor("mode status=true")
                .context("failed to encode serial-forward mode retry")?;
            queue_firmware_packet(&mut serial_tx, &probe)?;
            mode_probe_next_ms = now_millis_u64().saturating_add(1_000);
            progressed = true;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                stats.client_accepts.fetch_add(1, Ordering::Relaxed);
                tracing::info!(
                    forward_id = %id,
                    port = %port,
                    transport = "uds",
                    "serial_forward_client"
                );
                match add_serial_forward_unix_client(&mut clients, stream) {
                    Ok(()) => {}
                    Err(error) => {
                        tracing::warn!(
                            forward_id = %id,
                            port = %port,
                            error = %error,
                            "serial_forward_client_error"
                        );
                    }
                }
                progressed = true;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error).context("failed to accept serial forward client"),
        }
        if let Some(tcp_listener) = &tcp_listener {
            loop {
                match tcp_listener.accept() {
                    Ok((stream, addr)) => {
                        stats.client_accepts.fetch_add(1, Ordering::Relaxed);
                        tracing::info!(
                            forward_id = %id,
                            port = %port,
                            transport = "tcp",
                            client = %addr,
                            "serial_forward_client"
                        );
                        match add_serial_forward_tcp_client(&mut clients, stream, tcp_mode) {
                            Ok(()) => {}
                            Err(error) => {
                                tracing::warn!(
                                    forward_id = %id,
                                    port = %port,
                                    client = %addr,
                                    error = %error,
                                    "serial_forward_client_error"
                                );
                            }
                        }
                        progressed = true;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => {
                        return Err(error).context("failed to accept TCP serial forward client");
                    }
                }
            }
        }
        let flash_log_quiet = log_flash_quiet_until_ms.load(Ordering::Acquire) > now_millis_u64();
        match serial.read(&mut serial_buf) {
            Ok(0) => {}
            Ok(n) => {
                stats
                    .serial_to_client_bytes
                    .fetch_add(n as u64, Ordering::Relaxed);
                let records = firmware_uart_decoder
                    .push(&serial_buf[..n])
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                record_serial_forward_rx_log(
                    serial_log.as_ref(),
                    &stats,
                    id,
                    &serial_buf[..n],
                    &records,
                    flash_log_quiet,
                );
                uart_wake_seen = firmware_uart_decoder.take_frame_activity();
                if uart_wake_seen {
                    stats.uart_wake_frames.fetch_add(1, Ordering::Relaxed);
                }
                broadcast_serial_output(
                    &mut clients,
                    &records,
                    &serial_buf[..n],
                    raw_output,
                    &stats,
                );
                if !raw_output {
                    for record in &records {
                        if nan_sleepy_start_event(
                            mesh::cbor::decode_stream_frame(record).unwrap_or(&[]),
                        )
                        .is_some()
                        {
                            nan_sleepy_start_seen = true;
                        }
                        if let Ok(payload) = mesh::cbor::decode_stream_frame(record) {
                            update_firmware_state_from_boot(&firmware_state, payload);
                        }
                        if let Some(text) = firmware_record_text(record) {
                            update_firmware_state_from_text(&firmware_state, &text);
                        }
                        if let Some(active) = firmware_record_direct_mode(record) {
                            direct_write = active;
                            mode_known = true;
                            mode_probe_deadline = 0;
                            tracing::debug!(
                                forward_id = %id,
                                device_direct_mode = active,
                                "serial_forward_device_mode"
                            );
                            if direct_write && !serial_pending.is_empty() {
                                serial_tx.append(&mut serial_pending);
                            }
                        }
                    }
                }
                progressed = true;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                stats
                    .serial_read_would_block
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(error) => return Err(error).with_context(|| format!("failed to read {port}")),
        }
        if !mode_known && now_millis_u64() >= mode_probe_deadline {
            direct_write = false;
            // Make the timeout terminal for this forward's startup probe.
            // Leaving the old deadline in place caused this branch to log on
            // every poll iteration, flooding the managed log and making a
            // real sleepy/UART failure difficult to correlate. A later
            // firmware mode or heartbeat record still changes the policy.
            mode_probe_deadline = 0;
            tracing::debug!(forward_id = %id, "serial_forward_mode_probe_timeout");
        }
        let mut idx = 0;
        while idx < clients.len() {
            let may_write = multi || idx == 0;
            match clients[idx].pump_to_serial(
                serial.as_raw_fd(),
                &mut serial_tx,
                &mut serial_pending,
                may_write,
                // Direct-write forwards (normally continuously awake
                // infrastructure) deliver client bytes immediately; framed
                // sleepy forwards intentionally queue until the firmware
                // emits its UART wake delimiter.
                direct_write,
                &stats,
                id,
                serial_log.as_ref(),
                flash_log_quiet,
            ) {
                Ok((true, client_progressed, _control_event)) => {
                    progressed |= client_progressed;
                    idx += 1;
                }
                Ok((false, _, _)) => {
                    tracing::debug!(
                        forward_id = %id,
                        port = %port,
                        client_id = clients[idx].id,
                        "serial_forward_client_closed_input"
                    );
                    clients.remove(idx);
                    progressed = true;
                }
                Err(error) => {
                    tracing::warn!(
                        forward_id = %id,
                        port = %port,
                        client_id = clients[idx].id,
                        error = %error,
                        "serial_forward_client_error"
                    );
                    clients.remove(idx);
                    progressed = true;
                }
            }
        }
        if uart_wake_seen && !serial_pending.is_empty() {
            if serial_tx.len().saturating_add(serial_pending.len()) > SERIAL_FORWARD_MAX_PENDING {
                bail!(
                    "serial TX queue exceeded {} bytes while flushing UART wake queue",
                    SERIAL_FORWARD_MAX_PENDING
                );
            }
            if nan_sleepy_start_seen {
                // The tagged wake event proves that Main is inside its short
                // NAN/UART window. Put the internal one-second lease request
                // ahead of queued Main CBOR records so the rest of the queue
                // is handled as one active session. DMB1 and RFC2217 traffic
                // never enters serial_pending, so stage2/Recovery are not
                // affected by this automatic Main-only control packet.
                let active = firmware_command_cbor("mode active_ms=1000")
                    .context("failed to encode automatic sleepy active request")?;
                queue_firmware_packet(&mut serial_tx, &active)?;
            }
            let flushed = serial_pending.len();
            serial_tx.append(&mut serial_pending);
            stats.uart_wake_flushes.fetch_add(1, Ordering::Relaxed);
            stats
                .uart_wake_flush_bytes
                .fetch_add(flushed as u64, Ordering::Relaxed);
            progressed = true;
        }
        SerialForwardStats::record_high_water(&stats.serial_tx_queue_high_water, serial_tx.len());
        SerialForwardStats::record_high_water(
            &stats.serial_pending_queue_high_water,
            serial_pending.len(),
        );
        let serial_tx_before = serial_tx.len();
        if flush_queue_to_writer(&mut serial, &mut serial_tx)
            .with_context(|| format!("failed to write queued client data to {port}"))?
        {
            progressed = true;
        }
        stats.client_to_serial_bytes.fetch_add(
            serial_tx_before.saturating_sub(serial_tx.len()) as u64,
            Ordering::Relaxed,
        );
        if !serial_tx.is_empty() {
            stats.serial_write_blocked.fetch_add(1, Ordering::Relaxed);
        }
        let mut idx = 0;
        while idx < clients.len() {
            let output_pending = !clients[idx].output.is_empty();
            match clients[idx].flush_output() {
                Ok(true) => {
                    progressed = true;
                    idx += 1;
                }
                Ok(false) => {
                    if output_pending {
                        stats.client_write_blocked.fetch_add(1, Ordering::Relaxed);
                    }
                    idx += 1;
                }
                Err(error) => {
                    tracing::warn!(
                        forward_id = %id,
                        port = %port,
                        client_id = clients[idx].id,
                        error = %error,
                        "serial_forward_client_output_error"
                    );
                    clients.remove(idx);
                    progressed = true;
                }
            }
        }
        if !progressed {
            wait_for_serial_forward_io(
                &serial,
                &listener,
                tcp_listener.as_ref(),
                &clients,
                !serial_tx.is_empty(),
                &stats,
            )?;
        }
    }
    Ok(())
}

/// Wait for the next serial-forward event instead of polling every few milliseconds.
///
/// The timeout keeps a queued reset request responsive even when every endpoint is idle.
fn wait_for_serial_forward_io(
    serial: &fs::File,
    listener: &UnixListener,
    tcp_listener: Option<&TcpListener>,
    clients: &[SerialForwardClient],
    serial_writable: bool,
    stats: &SerialForwardStats,
) -> Result<()> {
    let mut fds = Vec::with_capacity(3 + clients.len());
    let mut serial_events = libc::POLLIN;
    if serial_writable {
        serial_events |= libc::POLLOUT;
    }
    fds.push(libc::pollfd {
        fd: serial.as_raw_fd(),
        events: serial_events,
        revents: 0,
    });
    fds.push(libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    });
    if let Some(tcp_listener) = tcp_listener {
        fds.push(libc::pollfd {
            fd: tcp_listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
    }
    for client in clients {
        if let Some(fd) = client.stream.raw_fd() {
            let mut events = libc::POLLIN;
            if !client.output.is_empty() {
                events |= libc::POLLOUT;
            }
            fds.push(libc::pollfd {
                fd,
                events,
                revents: 0,
            });
        }
    }
    let rc = unsafe {
        libc::poll(
            fds.as_mut_ptr(),
            fds.len() as libc::nfds_t,
            SERIAL_FORWARD_POLL_TIMEOUT_MS,
        )
    };
    stats.poll_calls.fetch_add(1, Ordering::Relaxed);
    if rc > 0 {
        stats.poll_ready.fetch_add(1, Ordering::Relaxed);
    } else if rc == 0 {
        stats.poll_timeouts.fetch_add(1, Ordering::Relaxed);
    }
    if rc < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("serial forward poll failed");
        }
    }
    Ok(())
}

fn configure_serial_forward_socket(socket_path: &str) -> Result<()> {
    let gid = group_gid("dialout").context("failed to resolve dialout group")?;
    let c_path = CString::new(socket_path).context("serial forward socket path contains NUL")?;
    let rc = unsafe { libc::chown(c_path.as_ptr(), u32::MAX, gid) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to set dialout group on {socket_path}"));
    }
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o770))
        .with_context(|| format!("failed to chmod serial forward socket {socket_path} to 0770"))?;
    Ok(())
}

fn group_gid(name: &str) -> Result<libc::gid_t> {
    let c_name = CString::new(name).context("group name contains NUL")?;
    let group = unsafe { libc::getgrnam(c_name.as_ptr()) };
    if group.is_null() {
        bail!("group {name:?} not found");
    }
    Ok(unsafe { (*group).gr_gid })
}

fn add_serial_forward_unix_client(
    clients: &mut Vec<SerialForwardClient>,
    stream: UnixStream,
) -> Result<()> {
    stream
        .set_nonblocking(true)
        .context("failed to set UDS client nonblocking")?;
    add_serial_forward_client(clients, Box::new(stream), SerialForwardTcpMode::Framed);
    Ok(())
}

fn add_serial_forward_tcp_client(
    clients: &mut Vec<SerialForwardClient>,
    stream: TcpStream,
    tcp_mode: SerialForwardTcpMode,
) -> Result<()> {
    stream
        .set_nonblocking(true)
        .context("failed to set TCP client nonblocking")?;
    stream
        .set_nodelay(true)
        .context("failed to disable Nagle buffering for TCP serial forward")?;
    add_serial_forward_client(clients, Box::new(stream), tcp_mode);
    Ok(())
}

trait SerialForwardStream: Read + Write {
    fn raw_fd(&self) -> Option<RawFd> {
        None
    }
}

impl SerialForwardStream for UnixStream {
    fn raw_fd(&self) -> Option<RawFd> {
        Some(self.as_raw_fd())
    }
}

impl SerialForwardStream for TcpStream {
    fn raw_fd(&self) -> Option<RawFd> {
        Some(self.as_raw_fd())
    }
}

fn add_serial_forward_client(
    clients: &mut Vec<SerialForwardClient>,
    stream: Box<dyn SerialForwardStream>,
    tcp_mode: SerialForwardTcpMode,
) {
    let id = clients
        .last()
        .map(|client| client.id.saturating_add(1))
        .unwrap_or(1);
    clients.push(SerialForwardClient::new(id, stream, tcp_mode));
}

fn broadcast_serial_output(
    clients: &mut Vec<SerialForwardClient>,
    records: &[Vec<u8>],
    wire_bytes: &[u8],
    raw_output: bool,
    stats: &SerialForwardStats,
) {
    let mut idx = 0;
    while idx < clients.len() {
        let accepted = if raw_output || clients[idx].is_rfc2217() {
            clients[idx].queue_output(wire_bytes)
        } else if clients[idx].text_mode {
            records
                .iter()
                .all(|record| clients[idx].queue_text_record(record))
        } else {
            records
                .iter()
                .all(|record| clients[idx].queue_output(record))
        };
        if accepted {
            SerialForwardStats::record_high_water(
                &stats.client_output_queue_high_water,
                clients[idx].output.len(),
            );
            idx += 1;
        } else {
            clients.remove(idx);
            stats.client_drops.fetch_add(1, Ordering::Relaxed);
        }
    }
}

struct SerialForwardClient {
    id: u64,
    stream: Box<dyn SerialForwardStream>,
    input: Vec<u8>,
    output: VecDeque<u8>,
    tcp_mode: SerialForwardTcpMode,
    rfc2217_mode: bool,
    // UDS/TCP input is auto-detected per client. Text clients receive the
    // matching human-readable response representation; framed clients keep
    // the length-prefixed CBOR stream.
    text_mode: bool,
    force_direct: bool,
}

impl SerialForwardClient {
    fn new(id: u64, stream: Box<dyn SerialForwardStream>, tcp_mode: SerialForwardTcpMode) -> Self {
        Self {
            id,
            stream,
            input: Vec::new(),
            output: VecDeque::new(),
            tcp_mode,
            rfc2217_mode: tcp_mode == SerialForwardTcpMode::Rfc2217,
            text_mode: false,
            force_direct: false,
        }
    }

    fn queue_output(&mut self, bytes: &[u8]) -> bool {
        let escaped_len = if self.rfc2217_mode {
            bytes
                .iter()
                .filter(|byte| **byte == RFC2217_IAC)
                .count()
                .saturating_add(bytes.len())
        } else {
            bytes.len()
        };
        if self.output.len().saturating_add(escaped_len) > SERIAL_FORWARD_MAX_PENDING {
            return false;
        }
        if self.rfc2217_mode {
            for byte in bytes {
                self.output.push_back(*byte);
                if *byte == RFC2217_IAC {
                    self.output.push_back(RFC2217_IAC);
                }
            }
        } else {
            self.output.extend(bytes);
        }
        true
    }

    fn queue_text_record(&mut self, record: &[u8]) -> bool {
        let Some(text) = firmware_record_text(record) else {
            return true;
        };
        queue_client_bytes(&mut self.output, text.as_bytes()).is_ok()
    }

    fn is_rfc2217(&self) -> bool {
        self.rfc2217_mode || self.tcp_mode == SerialForwardTcpMode::Rfc2217
    }

    fn flush_output(&mut self) -> Result<bool> {
        flush_queue_to_writer(&mut *self.stream, &mut self.output)
    }

    fn pump_to_serial(
        &mut self,
        serial_fd: RawFd,
        serial_tx: &mut VecDeque<u8>,
        serial_pending: &mut VecDeque<u8>,
        may_write: bool,
        serial_direct: bool,
        stats: &SerialForwardStats,
        board: &str,
        serial_log: Option<&Arc<Mutex<SerialForwardLog>>>,
        flash_log_quiet: bool,
    ) -> Result<(bool, bool, bool)> {
        let mut buf = [0_u8; SERIAL_FORWARD_IO_BUFFER_BYTES];
        let mut progressed = false;
        let mut input_closed = false;
        loop {
            match self.stream.read(&mut buf) {
                // A short-lived client such as `printf ... | socat` can write a
                // complete newline record and close before this nonblocking
                // loop reaches EOF. Drain the buffered record before removing
                // the client, otherwise its final command is silently lost.
                Ok(0) => {
                    input_closed = true;
                    break;
                }
                Ok(n) => {
                    self.input.extend_from_slice(&buf[..n]);
                    SerialForwardStats::record_high_water(
                        &stats.client_input_queue_high_water,
                        self.input.len(),
                    );
                    progressed = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    stats
                        .client_read_would_block
                        .fetch_add(1, Ordering::Relaxed);
                    break;
                }
                Err(error) => return Err(error).context("failed to read UDS client"),
            }
        }
        if may_write {
            progressed |= self.flush_complete_records(
                serial_fd,
                serial_tx,
                serial_pending,
                serial_direct,
                serial_log,
                board,
                flash_log_quiet,
            )?;
        } else if !may_write {
            progressed |= !self.input.is_empty();
            self.input.clear();
        }
        Ok((!input_closed, progressed, false))
    }

    fn flush_complete_records(
        &mut self,
        serial_fd: RawFd,
        serial_tx: &mut VecDeque<u8>,
        serial_pending: &mut VecDeque<u8>,
        serial_direct: bool,
        serial_log: Option<&Arc<Mutex<SerialForwardLog>>>,
        board: &str,
        flash_log_quiet: bool,
    ) -> Result<bool> {
        let mut progressed = false;
        loop {
            if self.input.is_empty() {
                return Ok(progressed);
            }
            if !self.force_direct && self.input.starts_with(SERIAL_FORWARD_FORCE_DIRECT_PREFIX) {
                self.input.drain(..SERIAL_FORWARD_FORCE_DIRECT_PREFIX.len());
                self.force_direct = true;
                progressed = true;
                if self.input.is_empty() {
                    return Ok(progressed);
                }
            }
            // A request-specific direct prefix is used by stage2/Recovery
            // handoffs. It must override the forward-wide sleepy policy for
            // this client; merely recording `self.force_direct` is
            // insufficient because the packet would otherwise remain queued.
            let direct_for_client = serial_direct || self.force_direct;
            if (self.tcp_mode == SerialForwardTcpMode::Rfc2217
                || self.tcp_mode == SerialForwardTcpMode::Auto)
                && self.input[0] == RFC2217_IAC
            {
                self.rfc2217_mode = true;
                let Some(record_len) =
                    handle_rfc2217_input(&self.input, serial_fd, serial_tx, &mut self.output)?
                else {
                    return Ok(progressed);
                };
                self.input.drain(..record_len);
                progressed = true;
                continue;
            }
            if self.rfc2217_mode {
                let record_len = self
                    .input
                    .iter()
                    .position(|byte| *byte == RFC2217_IAC)
                    .unwrap_or(self.input.len());
                if record_len == 0 {
                    return Ok(progressed);
                }
                queue_serial_bytes(serial_tx, &self.input[..record_len])?;
                self.input.drain(..record_len);
                progressed = true;
                continue;
            }
            let record_len = if self.input[0] == 0 {
                if self.input.len() < 4 {
                    return Ok(progressed);
                }
                let len = u32::from_be_bytes(self.input[..4].try_into().unwrap()) as usize;
                let total = 4 + len;
                if self.input.len() < total {
                    return Ok(progressed);
                }
                total
            } else if let Some(pos) = self
                .input
                .iter()
                .position(|byte| matches!(*byte, b'\n' | b'\r'))
            {
                // readline-style clients commonly terminate with CRLF.
                // Consume the pair as one text record; otherwise the LF is
                // seen on the next pass as an empty firmware command.
                if self.input[pos] == b'\r' && self.input.get(pos + 1) == Some(&b'\n') {
                    pos + 2
                } else {
                    pos + 1
                }
            } else {
                return Ok(progressed);
            };
            if self.input[0] == 0 {
                let body = &self.input[4..record_len];
                let raw_boot =
                    (body.len() >= 6 && body[..4] == DMESH_BOOT_MAGIC[..]).then_some(body);
                if let Some(payload) = raw_boot.as_deref() {
                    // DMB1 is an explicit bootstrap command for stage2.  It
                    // must not wait for the normal active/direct policy: the
                    // bootloader has only a bounded selector window and the
                    // managed forward is the sole UART reader.
                    queue_firmware_payload(serial_tx, payload)?;
                } else if direct_for_client {
                    record_serial_forward_tx_log(
                        serial_log,
                        board,
                        &self.input[..record_len],
                        flash_log_quiet,
                    );
                    queue_firmware_packet(serial_tx, &self.input[..record_len])?;
                } else {
                    record_serial_forward_tx_log(
                        serial_log,
                        board,
                        &self.input[..record_len],
                        flash_log_quiet,
                    );
                    queue_firmware_packet(serial_pending, &self.input[..record_len])?;
                }
            } else {
                self.text_mode = true;
                let line = std::str::from_utf8(&self.input[..record_len])?.trim();
                // Empty lines are harmless interactive-console input. In
                // particular, tolerate a lone LF following a CR from a
                // client whose terminal emits mixed line endings.
                if !line.is_empty() {
                    match firmware_command_cbor(line) {
                        Ok(frame) => {
                            record_serial_forward_tx_log(
                                serial_log,
                                board,
                                &frame,
                                flash_log_quiet,
                            );
                            if direct_for_client {
                                queue_firmware_packet(serial_tx, &frame)?;
                            } else {
                                queue_firmware_packet(serial_pending, &frame)?;
                            }
                        }
                        Err(error) => {
                            queue_client_bytes(
                                &mut self.output,
                                format!("lmesh command error: {error}\n").as_bytes(),
                            )?;
                        }
                    }
                }
            }
            self.input.drain(..record_len);
            progressed = true;
        }
    }
}

/// Append a grep-friendly, lossless logfmt serial event to the shared lab log.
///
/// UART reads are arbitrary byte chunks rather than lines. `text` makes normal
/// firmware output searchable, while `hex` retains the exact bytes for boot ROM
/// or flashing traffic that is not valid UTF-8.
struct SerialForwardLog {
    file: fs::File,
    schema: FirmwareSchema,
    raw_text: BTreeMap<String, Vec<u8>>,
    ppp_active: BTreeMap<String, bool>,
    ppp_escaped: BTreeMap<String, bool>,
    ppp_payload: BTreeMap<String, bool>,
}

impl SerialForwardLog {
    fn open(path: &str) -> Result<Self> {
        let path = PathBuf::from(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create serial log directory {}", parent.display())
            })?;
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("failed to open serial log {}", path.display()))?;
        Ok(Self {
            file,
            schema: FirmwareSchema::load(),
            raw_text: BTreeMap::new(),
            ppp_active: BTreeMap::new(),
            ppp_escaped: BTreeMap::new(),
            ppp_payload: BTreeMap::new(),
        })
    }

    /// Log received UART bytes in protocol-aware form. ROM/stage2 output is
    /// not PPP and is reconstructed into complete text lines. PPP frames are
    /// represented by their decoded CBOR notification or boot identity; raw
    /// hex is retained only for an undecodable payload.
    fn append_rx(&mut self, board: &str, bytes: &[u8], records: &[Vec<u8>]) -> Result<usize> {
        let mut raw_lines = Vec::new();
        let active = self.ppp_active.entry(board.to_owned()).or_default();
        let escaped = self.ppp_escaped.entry(board.to_owned()).or_default();
        let payload_seen = self.ppp_payload.entry(board.to_owned()).or_default();
        let raw = self.raw_text.entry(board.to_owned()).or_default();
        for byte in bytes {
            if *active {
                if *escaped {
                    *escaped = false;
                    *payload_seen = true;
                } else if *byte == FIRMWARE_UART_ESCAPE {
                    *escaped = true;
                } else if *byte == FIRMWARE_UART_FLAG {
                    *active = false;
                    *payload_seen = false;
                }
                continue;
            }
            // The first byte after a completed ROM line selects the parser:
            // 0x7e starts PPP, while any other byte belongs to the ROM/text
            // stream. Do not treat a stray '~' inside an ASCII boot line as a
            // PPP delimiter.
            if *byte == FIRMWARE_UART_FLAG && raw.is_empty() {
                *active = true;
                *escaped = false;
                *payload_seen = false;
                continue;
            }
            *payload_seen = true;
            raw.push(*byte);
            if *byte == b'\n' || raw.len() >= 4096 {
                raw_lines.push(std::mem::take(raw));
            }
        }
        let raw_line_count = raw_lines.len();
        for line in raw_lines {
            self.write_text_or_binary(board, &line)?;
        }

        let mut logged = 0;
        for record in records {
            let Some(payload) = mesh::cbor::decode_stream_frame(record).ok() else {
                writeln!(
                    self.file,
                    "ts_ms={} board={} dir=rx kind=ppp undecoded=true bytes={} hex={}",
                    now_millis_u64(),
                    board,
                    record.len(),
                    compact_serial_hex(record),
                )?;
                logged += 1;
                continue;
            };
            if let Some(event) = nan_sleepy_start_event(payload) {
                writeln!(
                    self.file,
                    "ts_ms={} board={} dir=rx kind=ppp decoded=nan.sleepy_start tag=6 flags={} lora_rx_delta={} nan_beacon_delta={} cluster_changed={}",
                    now_millis_u64(),
                    board,
                    event.flags,
                    event.lora_rx_delta,
                    event.nan_beacon_delta,
                    event.cluster_changed,
                )?;
                logged += 1;
                continue;
            }
            // The shared UART decoder is deliberately permissive while it
            // resynchronizes. A stale flag can therefore make a ROM/app
            // text burst look like one PPP payload. Never call that CBOR:
            // classify printable payloads as text and keep binary lossless.
            let is_boot_identity = is_boot_identity_payload(payload);
            let is_boot_event = is_boot_event_payload(payload);
            let is_boot_selector = is_boot_selector_payload(payload);
            if !is_boot_event
                && !is_boot_selector
                && !payload.is_empty()
                && payload.first().map(|byte| byte >> 5) != Some(5)
            {
                self.write_text_or_binary(board, payload)?;
                logged += 1;
                continue;
            }
            let (kind, decoded) = if is_boot_identity {
                ("boot", format!("identity={}", boot_identity_json(payload)))
            } else if is_boot_event {
                ("boot", format!("event={}", boot_event_json(payload)))
            } else if is_boot_selector {
                (
                    "boot",
                    format!("selector_hex={}", compact_serial_hex(payload)),
                )
            } else if let Ok(decoded) =
                mesh::cbor::decode_json(payload, &mesh::cbor::Catalog::default())
            {
                let decoded = self.schema.rename_decoded(decoded);
                // decode_json represents schema/type failures as an error
                // object. Do not make malformed compact-CBOR look like a
                // valid firmware notification in the serial evidence.
                if let Some(error) = decoded.get("error").and_then(Value::as_str) {
                    (
                        "cbor_error",
                        format!(
                            "message={:?} {} payload_hex={}",
                            error,
                            cbor_first_byte_summary(payload),
                            compact_serial_hex(payload)
                        ),
                    )
                } else {
                    ("cbor", decoded.to_string())
                }
            } else {
                (
                    "cbor_error",
                    format!(
                        "{} payload_hex={}",
                        cbor_first_byte_summary(payload),
                        compact_serial_hex(payload),
                    ),
                )
            };
            let decoded = truncate_serial_log_field(&decoded);
            writeln!(
                self.file,
                "ts_ms={} board={} dir=rx kind=ppp bytes={} {} {}",
                now_millis_u64(),
                board,
                payload.len(),
                kind,
                decoded,
            )?;
            logged += 1;
        }
        self.file
            .flush()
            .context("failed to flush serial log record")?;
        Ok(logged + raw_line_count)
    }

    fn write_text_or_binary(&mut self, board: &str, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        if serial_bytes_are_text(bytes) {
            for line in bytes.split_inclusive(|byte| *byte == b'\n') {
                let text = serial_text_preview(line);
                if !text.is_empty() {
                    writeln!(
                        self.file,
                        "ts_ms={} board={} dir=rx kind=text bytes={} text={:?}",
                        now_millis_u64(),
                        board,
                        line.len(),
                        truncate_serial_log_field(&text),
                    )?;
                }
            }
        } else {
            writeln!(
                self.file,
                "ts_ms={} board={} dir=rx kind=raw_binary bytes={} hex={}",
                now_millis_u64(),
                board,
                bytes.len(),
                compact_serial_hex(bytes),
            )?;
        }
        Ok(())
    }
}

/// Stage2/Recovery boot identities are normal CBOR events.  They use an
/// indefinite map and tuple payload (`{7:60000,6:[...]}`), so they cannot be
/// passed through the regular method/payload-map JSON adapter.  Recognize the
/// registered event directly and keep it on the same packet log path as the
/// old fixed DMB1 compatibility record.
fn is_boot_identity_payload(payload: &[u8]) -> bool {
    (payload.len() >= DMESH_BOOT_HELLO_LEN && payload[..4] == DMESH_BOOT_MAGIC[..])
        || payload
            .windows(3)
            .any(|window| window == [0x19, 0xea, 0x60])
}

fn boot_event_id(payload: &[u8]) -> Option<u64> {
    payload.windows(3).find_map(|window| {
        if window[0] == 0x19 && window[1] == 0xea && (0x60..=0x63).contains(&window[2]) {
            Some(u64::from(window[2]) + 0xea00)
        } else {
            None
        }
    })
}

fn is_boot_event_payload(payload: &[u8]) -> bool {
    is_boot_identity_payload(payload) || boot_event_id(payload).is_some()
}

fn is_boot_selector_payload(payload: &[u8]) -> bool {
    payload.len() == 10
        && payload[..3] == [0xa2, 0x00, 0x1a]
        && payload[3..7] == DMESH_BOOT_METHOD_SELECT.to_be_bytes()
        && payload[7..9] == [0x06, 0x81]
        && matches!(payload[9], 0x01 | 0x02)
}

fn serial_bytes_are_text(bytes: &[u8]) -> bool {
    let printable = bytes
        .iter()
        .filter(|byte| matches!(**byte, b'\t' | b'\r' | b'\n' | 0x20..=0x7e))
        .count();
    printable * 100 >= bytes.len().saturating_mul(90)
}

fn serial_text_preview(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len());
    for byte in bytes {
        match *byte {
            b'\r' | b'\n' => {}
            b'\t' | 0x20..=0x7e => text.push(*byte as char),
            value => text.push_str(&format!("\\x{value:02x}")),
        }
    }
    text
}

fn truncate_serial_log_field(value: &str) -> String {
    if value.len() <= SERIAL_LOG_FIELD_MAX {
        return value.to_owned();
    }
    let mut result = value
        .char_indices()
        .take_while(|(index, _)| *index < SERIAL_LOG_FIELD_MAX.saturating_sub(3))
        .map(|(_, character)| character)
        .collect::<String>();
    result.push_str("...");
    result
}

fn compact_serial_hex(bytes: &[u8]) -> String {
    let ff_count = bytes.iter().filter(|byte| **byte == 0xff).count();
    if bytes.len() >= 32 && ff_count * 100 >= bytes.len().saturating_mul(90) {
        return "ff...".to_owned();
    }
    truncate_serial_log_field(&hex_lower(bytes))
}

fn cbor_uint_at(payload: &[u8], offset: &mut usize) -> Option<u64> {
    let first = *payload.get(*offset)?;
    *offset += 1;
    if first >> 5 != 0 {
        return None;
    }
    let additional = first & 0x1f;
    if additional < 24 {
        return Some(additional as u64);
    }
    let width = match additional {
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return None,
    };
    let end = offset.checked_add(width)?;
    let bytes = payload.get(*offset..end)?;
    *offset = end;
    Some(
        bytes
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)),
    )
}

fn cbor_argument_at(payload: &[u8], offset: &mut usize, first: u8) -> Option<u64> {
    let additional = first & 0x1f;
    if additional < 24 {
        return Some(additional as u64);
    }
    let width = match additional {
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return None,
    };
    let end = offset.checked_add(width)?;
    let bytes = payload.get(*offset..end)?;
    *offset = end;
    Some(
        bytes
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)),
    )
}

fn cbor_tuple_value(payload: &[u8], offset: &mut usize) -> Option<Value> {
    let first = *payload.get(*offset)?;
    *offset += 1;
    match first >> 5 {
        0 => Some(Value::from(cbor_argument_at(payload, offset, first)?)),
        1 => {
            let argument = cbor_argument_at(payload, offset, first)?;
            let value = i64::try_from(argument)
                .ok()?
                .checked_add(1)?
                .checked_neg()?;
            Some(Value::from(value))
        }
        2 => {
            let length = usize::try_from(cbor_argument_at(payload, offset, first)?).ok()?;
            let end = offset.checked_add(length)?;
            let bytes = payload.get(*offset..end)?;
            *offset = end;
            Some(Value::String(hex_lower(bytes)))
        }
        _ => None,
    }
}

fn boot_identity_tuple(payload: &[u8]) -> Option<Vec<Value>> {
    let mut offset = 0;
    if *payload.get(offset)? != 0xbf {
        return None;
    }
    offset += 1;
    let mut tuple = None;
    while *payload.get(offset)? != 0xff {
        let key = cbor_uint_at(payload, &mut offset)?;
        if key == 7 {
            let _ = cbor_uint_at(payload, &mut offset)?;
        } else if key == 6 {
            if *payload.get(offset)? != 0x9f {
                return None;
            }
            offset += 1;
            let mut values = Vec::new();
            while *payload.get(offset)? != 0xff {
                values.push(cbor_tuple_value(payload, &mut offset)?);
            }
            offset += 1;
            tuple = Some(values);
        } else {
            return None;
        }
    }
    Some(tuple?)
}

fn cbor_major_type_name(byte: u8) -> &'static str {
    match byte >> 5 {
        0 => "unsigned",
        1 => "negative",
        2 => "bytes",
        3 => "text",
        4 => "array",
        5 => "map",
        6 => "tag",
        _ => "simple/float",
    }
}

fn cbor_first_byte_summary(payload: &[u8]) -> String {
    match payload.first().copied() {
        Some(byte) => format!(
            "first_byte=0x{byte:02x} major_type={}",
            cbor_major_type_name(byte),
        ),
        None => "first_byte=none major_type=empty".to_owned(),
    }
}

fn record_serial_forward_rx_log(
    log: Option<&Arc<Mutex<SerialForwardLog>>>,
    stats: &SerialForwardStats,
    board: &str,
    bytes: &[u8],
    records: &[Vec<u8>],
    suppressed: bool,
) {
    if suppressed {
        stats.log_suppressed_records.fetch_add(1, Ordering::Relaxed);
        stats
            .log_suppressed_bytes
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        return;
    }
    let Some(log) = log else {
        return;
    };
    let mut sink = log.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    match sink.append_rx(board, bytes, records) {
        Ok(count) => {
            stats
                .log_records
                .fetch_add(count.max(1) as u64, Ordering::Relaxed);
        }
        Err(error) => {
            stats.log_write_errors.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(forward_id = %board, direction = "rx", error = %error, "serial_forward_log_write_failed");
        }
    }
}

/// Log the complete packet accepted from a managed client, after consuming
/// the UDS length/control envelope.  The old logger recorded that envelope
/// verbatim (`DMESH-DIRECT`), which made an internal lmesh marker look like a
/// physical UART protocol.  TX now uses the same CBOR classification as RX.
fn record_serial_forward_tx_log(
    log: Option<&Arc<Mutex<SerialForwardLog>>>,
    board: &str,
    stream_frame: &[u8],
    suppressed: bool,
) {
    if suppressed {
        return;
    }
    let Some(log) = log else {
        return;
    };
    let mut sink = log.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    // A boot/flash client may prepend the internal direct-delivery marker.
    // That marker is consumed by the forward and is not part of the UDS
    // stream envelope.  Strip it before decoding so TX logs describe the
    // actual CBOR packet instead of falling back to an unhelpful hex dump.
    let stream_frame = stream_frame
        .strip_prefix(SERIAL_FORWARD_FORCE_DIRECT_PREFIX)
        .unwrap_or(stream_frame);
    let payload = mesh::cbor::decode_stream_frame(stream_frame).unwrap_or(stream_frame);
    let (kind, body) = if is_boot_identity_payload(payload) {
        ("boot", format!("identity={}", boot_identity_json(payload)))
    } else if is_boot_event_payload(payload) {
        ("boot", format!("event={}", boot_event_json(payload)))
    } else if is_boot_selector_payload(payload) {
        (
            "boot",
            format!("selector_hex={}", compact_serial_hex(payload)),
        )
    } else if payload.first().map(|byte| byte >> 5) == Some(5)
        || payload.first().map(|byte| byte >> 5) == Some(4)
    {
        match mesh::cbor::decode_json(payload, &mesh::cbor::Catalog::default()) {
            Ok(decoded) => ("cbor", decoded.to_string()),
            Err(error) => (
                "cbor_error",
                format!("message={:?} {}", error, cbor_first_byte_summary(payload)),
            ),
        }
    } else {
        ("raw", format!("hex={}", compact_serial_hex(payload)))
    };
    let _ = writeln!(
        sink.file,
        "ts_ms={} board={} dir=tx kind=ppp bytes={} {} {}",
        now_millis_u64(),
        board,
        payload.len(),
        kind,
        truncate_serial_log_field(&body),
    );
    let _ = sink.file.flush();
}

fn queue_serial_bytes(queue: &mut VecDeque<u8>, bytes: &[u8]) -> Result<()> {
    if queue.len().saturating_add(bytes.len()) > SERIAL_FORWARD_MAX_PENDING {
        bail!(
            "serial TX queue exceeded {} bytes",
            SERIAL_FORWARD_MAX_PENDING
        );
    }
    queue.extend(bytes);
    Ok(())
}

/// Encode Recovery's STA handoff as the compact CBOR payload expected by the
/// managed UDS exchange. `uds_raw_exchange` adds the UDS length envelope and
/// the serial forward adds the physical PPP envelope; returning PPP here
/// would double-wrap the packet and make Recovery see 0x7e as CBOR.
fn encode_recovery_sta_packet(command: &str) -> Result<Vec<u8>> {
    let fields = command.split_ascii_whitespace().collect::<Vec<_>>();
    if (fields.len() < 4 || fields.len() > 6) || fields.first() != Some(&"STA") {
        bail!("Recovery STA packet requires: STA endpoint local_ip ssid [password] [dryrun]");
    }
    let endpoint = fields[1].as_bytes();
    let local_ip = fields[2].as_bytes();
    let ssid = fields[3].as_bytes();
    let dry_run = fields.get(4).is_some_and(|value| *value == "dryrun")
        || fields.get(5).is_some_and(|value| *value == "dryrun");
    let password = if fields.get(4).is_some_and(|value| *value == "dryrun") {
        &[]
    } else {
        fields.get(4).map(|value| value.as_bytes()).unwrap_or(&[])
    };
    if endpoint.is_empty()
        || endpoint.len() >= 128
        || local_ip.is_empty()
        || local_ip.len() >= 32
        || ssid.is_empty()
        || ssid.len() >= 33
        || password.len() >= 32
        || endpoint.len() > u8::MAX as usize
        || local_ip.len() > u8::MAX as usize
        || ssid.len() > u8::MAX as usize
        || password.len() > u8::MAX as usize
    {
        bail!("Recovery STA packet field is too long or empty");
    }
    let mut packet =
        Vec::with_capacity(64 + endpoint.len() + local_ip.len() + ssid.len() + password.len());
    packet.extend_from_slice(&[
        0xa2,
        0x00,
        0x18,
        68,
        0x06,
        if dry_run { 0xa5 } else { 0xa4 },
    ]);
    for (key, value) in [
        ("server", endpoint),
        ("ip", local_ip),
        ("ssid", ssid),
        ("password", password),
    ] {
        packet.push(0x60 + key.len() as u8);
        packet.extend_from_slice(key.as_bytes());
        if value.len() < 24 {
            packet.push(0x60 + value.len() as u8);
        } else {
            packet.extend_from_slice(&[0x78, value.len() as u8]);
        }
        packet.extend_from_slice(value);
    }
    if dry_run {
        packet.extend_from_slice(&[0x67]);
        packet.extend_from_slice(b"dry_run");
        packet.push(0xf5);
    }
    Ok(packet)
}

#[cfg(test)]
fn encode_firmware_uart_frame(stream_frame: &[u8]) -> Result<Vec<u8>> {
    let payload = mesh::cbor::decode_stream_frame(stream_frame)?;
    encode_firmware_uart_payload(payload)
}

fn encode_firmware_uart_payload(cbor: &[u8]) -> Result<Vec<u8>> {
    uart_codec::codec::encode_payload(cbor, mesh::cbor::ESP_RECORD_MAX)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

#[derive(Default)]
struct NanSleepyStartEvent {
    flags: u16,
    lora_rx_delta: u32,
    nan_beacon_delta: u32,
    cluster_changed: bool,
}

fn nan_sleepy_start_event(payload: &[u8]) -> Option<NanSleepyStartEvent> {
    let mut decoder = Decoder::new(payload);
    if decoder.tag().ok()?.as_u64() != u64::from(NAN_SLEEPY_START_TAG) {
        return None;
    }
    let map_len = decoder.map().ok()?;
    let mut event = NanSleepyStartEvent::default();
    let mut remaining = map_len;
    loop {
        if remaining == Some(0) {
            break;
        }
        if remaining.is_none() && decoder.datatype().ok()? == Type::Break {
            decoder.skip().ok()?;
            break;
        }
        let key = decoder.u8().ok()?;
        match key {
            0 => event.flags = decoder.u16().ok()?,
            1 => event.lora_rx_delta = decoder.u32().ok()?,
            2 => event.nan_beacon_delta = decoder.u32().ok()?,
            _ => {
                decoder.skip().ok()?;
            }
        }
        if let Some(value) = remaining.as_mut() {
            *value = value.saturating_sub(1);
        }
    }
    event.cluster_changed = event.flags & (1 << 2) != 0;
    Some(event)
}

fn queue_firmware_packet(queue: &mut VecDeque<u8>, stream_frame: &[u8]) -> Result<()> {
    let payload = mesh::cbor::decode_stream_frame(stream_frame)?;
    queue_firmware_payload(queue, payload)
}

/// Queue one already-decoded physical UART payload.  Normal firmware records
/// are compact CBOR, but stage2 uses a fixed DMB1 payload so it can run without
/// a CBOR implementation.  Both payload kinds use the same PPP envelope.
fn queue_firmware_payload(queue: &mut VecDeque<u8>, payload: &[u8]) -> Result<()> {
    let wire = uart_codec::codec::encode_payload(payload, mesh::cbor::ESP_RECORD_MAX)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    queue_serial_bytes(queue, &wire)
}

/// Decode one firmware response for a client that selected text input.
/// Framed clients receive the original stream record unchanged. The firmware
/// response text is carried in its private CBOR payload tag 32; retain the
/// generic message/error/status fallbacks for control-plane records.
fn firmware_record_text(record: &[u8]) -> Option<String> {
    let payload = mesh::cbor::decode_stream_frame(record).ok()?;
    if let Some(event) = nan_sleepy_start_event(payload) {
        return Some(format!(
            "event type=nan.sleepy_start flags={} lora_rx_delta={} nan_beacon_delta={} cluster_changed={}",
            event.flags, event.lora_rx_delta, event.nan_beacon_delta, event.cluster_changed,
        ));
    }
    let decoded = mesh::cbor::decode_json(payload, &mesh::cbor::Catalog::default()).ok()?;
    let message = decoded
        .get("payload")
        .and_then(Value::as_object)
        .and_then(|payload| payload.get("32"))
        .and_then(Value::as_str)
        .or_else(|| decoded.get("message").and_then(Value::as_str))
        .or_else(|| decoded.get("error").and_then(Value::as_str))
        .or_else(|| decoded.get("status").and_then(Value::as_str))?;
    let mut text = message.to_owned();
    if !text.ends_with('\n') {
        text.push('\n');
    }
    Some(text)
}

/// Return the current write policy advertised by a firmware status/event.
/// Infrastructure mode is continuously reachable; a sleepy device is only
/// directly writable while its bounded active session is reported true.
fn firmware_record_direct_mode(record: &[u8]) -> Option<bool> {
    let payload = mesh::cbor::decode_stream_frame(record).ok()?;
    if nan_sleepy_start_event(payload).is_some() {
        // NAN_SLEEPY_START proves that the device has just opened a short
        // UART receive window; it does not prove that a queued command may be
        // written immediately.  Keep the command in serial_pending so the
        // caller below can put `mode active_ms=1000` first and only then
        // release the command.  Returning Some(true) here used to promote
        // the forward to direct-write mode and bypass that ordering, which
        // lost status/flash commands on sleepy devices.
        return None;
    }
    let text = firmware_record_text(record)?;
    let active = text
        .split_whitespace()
        .find_map(|field| field.strip_prefix("active="))?;
    // `active=infra` is the continuously reachable gateway role. The
    // infra_active field describes only a bounded target/session lease and
    // must not make lora1's own UART queue sleepy.
    if active == "infra" {
        return Some(true);
    }
    if active != "companion" && active != "sleepy" {
        return None;
    }
    // A sleepy device can expose a bounded active window. In that case the
    // role remains `active=sleepy`, while `infra_active=true` is the actual
    // write-reachability signal.
    text.split_whitespace()
        .find_map(|field| field.strip_prefix("infra_active="))
        .and_then(|value| match value {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        })
}

fn update_firmware_state_from_text(state: &Arc<Mutex<FirmwareState>>, text: &str) {
    let text = text.trim();
    let is_boot = text.starts_with("event type=boot.state");
    let is_mode = text.starts_with("event type=mode.state") || text.starts_with("mode active=");
    if !is_boot && !is_mode {
        return;
    }
    let mut state = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for field in text.split_whitespace() {
        if let Some(value) = field.strip_prefix("mode=") {
            state.mode = Some(value.to_string());
        } else if let Some(value) = field.strip_prefix("active=") {
            state.mode = Some(value.to_string());
        } else if let Some(value) = field.strip_prefix("infra_active=") {
            state.infra_active = match value {
                "true" => Some(true),
                "false" => Some(false),
                _ => state.infra_active,
            };
        } else if let Some(value) = field.strip_prefix("phase=") {
            state.phase = Some(value.to_string());
        } else if let Some(value) = field.strip_prefix("rebooted=") {
            state.rebooted = match value {
                "true" => Some(true),
                "false" => Some(false),
                _ => state.rebooted,
            };
        }
    }
    state.last_event_ms = now_millis_u64();
}

fn update_firmware_state_from_boot(state: &Arc<Mutex<FirmwareState>>, payload: &[u8]) {
    if payload.len() < DMESH_BOOT_HELLO_LEN
        || payload[..4] != DMESH_BOOT_MAGIC[..]
        || payload[4] != DMESH_BOOT_VERSION
        || payload[5] != 1
    {
        return;
    }
    let role = match payload[6] {
        1 => "main",
        2 => "recovery",
        3 => "stage2",
        _ => "unknown",
    };
    let partition = match payload[7] {
        0 => "bootloader",
        1 => "main",
        2 => "recovery",
        _ => "unknown",
    };
    let mut state = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    state.role = Some(role.to_string());
    state.partition = Some(partition.to_string());
    state.reset_reason = Some(payload[8]);
    state.mac = Some(
        payload[12..18]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    );
    state.phase = Some("started".to_string());
    state.last_event_ms = now_millis_u64();
}

fn queue_client_bytes(queue: &mut VecDeque<u8>, bytes: &[u8]) -> Result<()> {
    if queue.len().saturating_add(bytes.len()) > SERIAL_FORWARD_MAX_PENDING {
        bail!(
            "serial forward client output queue exceeded {} bytes",
            SERIAL_FORWARD_MAX_PENDING
        );
    }
    queue.extend(bytes);
    Ok(())
}

fn flush_queue_to_writer(writer: &mut dyn Write, queue: &mut VecDeque<u8>) -> Result<bool> {
    let mut progressed = false;
    while !queue.is_empty() {
        let (front, _) = queue.as_slices();
        if front.is_empty() {
            break;
        }
        match writer.write(front) {
            Ok(0) => break,
            Ok(n) => {
                queue.drain(..n);
                progressed = true;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).context("failed to flush queued serial forward bytes"),
        }
    }
    Ok(progressed)
}

fn handle_rfc2217_input(
    input: &[u8],
    serial_fd: RawFd,
    serial_tx: &mut VecDeque<u8>,
    output: &mut VecDeque<u8>,
) -> Result<Option<usize>> {
    if input.len() < 2 {
        return Ok(None);
    }
    if input[1] == RFC2217_IAC {
        queue_serial_bytes(serial_tx, &[RFC2217_IAC])?;
        return Ok(Some(2));
    }
    if matches!(
        input[1],
        RFC2217_WILL | RFC2217_WONT | RFC2217_DO | RFC2217_DONT
    ) {
        if input.len() < 3 {
            return Ok(None);
        }
        respond_rfc2217_option(output, input[1], input[2])?;
        return Ok(Some(3));
    }
    if input[1] != RFC2217_SB {
        return Ok(Some(2));
    }
    let Some((end_idx, terminator_len)) = rfc2217_subnegotiation_end(input) else {
        return Ok(None);
    };
    if input.len() < 3 || input[2] != RFC2217_COM_PORT_OPTION {
        return Ok(Some(end_idx + terminator_len));
    }
    apply_rfc2217_com_port_option(serial_fd, output, &input[2..end_idx])?;
    Ok(Some(end_idx + terminator_len))
}

fn respond_rfc2217_option(output: &mut VecDeque<u8>, verb: u8, option: u8) -> Result<()> {
    let supported = matches!(option, RFC2217_BINARY | RFC2217_COM_PORT_OPTION);
    let response = match (verb, supported) {
        (RFC2217_DO, true) => [RFC2217_IAC, RFC2217_WILL, option],
        (RFC2217_WILL, true) => [RFC2217_IAC, RFC2217_DO, option],
        (RFC2217_DO, false) => [RFC2217_IAC, RFC2217_WONT, option],
        (RFC2217_WILL, false) => [RFC2217_IAC, RFC2217_DONT, option],
        (RFC2217_DONT, _) => [RFC2217_IAC, RFC2217_WONT, option],
        (RFC2217_WONT, _) => [RFC2217_IAC, RFC2217_DONT, option],
        _ => return Ok(()),
    };
    queue_client_bytes(output, &response)
}

fn rfc2217_subnegotiation_end(input: &[u8]) -> Option<(usize, usize)> {
    input
        .windows(2)
        .enumerate()
        .skip(2)
        .find_map(|(idx, window)| {
            (window[0] == RFC2217_IAC && (window[1] == RFC2217_SE || window[1] == RFC2217_SE_ALT))
                .then_some((idx, 2))
        })
}

fn apply_rfc2217_com_port_option(
    fd: RawFd,
    output: &mut VecDeque<u8>,
    payload: &[u8],
) -> Result<()> {
    if payload.len() < 2 || payload[0] != RFC2217_COM_PORT_OPTION {
        return Ok(());
    }
    let command = payload[1];
    let args = &payload[2..];
    match command {
        RFC2217_SET_BAUDRATE => {
            if args.len() < 4 {
                bail!("short RFC2217 SET-BAUDRATE command");
            }
            let baud = u32::from_be_bytes([args[0], args[1], args[2], args[3]]);
            tracing::debug!(baud, "rfc2217_set_baudrate");
            if baud != 0 {
                let _ = set_serial_baud(fd, baud);
            }
            ack_rfc2217_com_port_option(output, command, args)?;
        }
        RFC2217_SET_DATASIZE => {
            if let Some(bits) = args.first().copied()
                && bits != 0
            {
                tracing::debug!(bits, "rfc2217_set_datasize");
                let _ = set_serial_data_size(fd, bits);
            }
            ack_rfc2217_com_port_option(output, command, args)?;
        }
        RFC2217_SET_PARITY => {
            if let Some(parity) = args.first().copied()
                && parity != 0
            {
                tracing::debug!(parity, "rfc2217_set_parity");
                let _ = set_serial_parity(fd, parity);
            }
            ack_rfc2217_com_port_option(output, command, args)?;
        }
        RFC2217_SET_STOPSIZE => {
            if let Some(stop_bits) = args.first().copied()
                && stop_bits != 0
            {
                tracing::debug!(stop_bits, "rfc2217_set_stopsize");
                let _ = set_serial_stop_size(fd, stop_bits);
            }
            ack_rfc2217_com_port_option(output, command, args)?;
        }
        RFC2217_SET_CONTROL => {
            if let Some(control) = args.first().copied() {
                tracing::debug!(control, "rfc2217_set_control");
                let _ = set_serial_control(fd, control);
            }
            ack_rfc2217_com_port_option(output, command, args)?;
        }
        RFC2217_PURGE_DATA => {
            if let Some(purge) = args.first().copied() {
                let _ = purge_serial_data(fd, purge);
            }
            ack_rfc2217_com_port_option(output, command, args)?;
        }
        _ => {}
    }
    Ok(())
}

fn ack_rfc2217_com_port_option(output: &mut VecDeque<u8>, command: u8, args: &[u8]) -> Result<()> {
    let mut response = Vec::with_capacity(args.len() + 6);
    response.extend_from_slice(&[
        RFC2217_IAC,
        RFC2217_SB,
        RFC2217_COM_PORT_OPTION,
        command.saturating_add(100),
    ]);
    for byte in args {
        response.push(*byte);
        if *byte == RFC2217_IAC {
            response.push(RFC2217_IAC);
        }
    }
    response.extend_from_slice(&[RFC2217_IAC, RFC2217_SE]);
    queue_client_bytes(output, &response)
}

fn update_termios(fd: RawFd, update: impl FnOnce(&mut libc::termios) -> Result<()>) -> Result<()> {
    let mut termios = unsafe {
        let mut termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut termios) != 0 {
            return Err(std::io::Error::last_os_error()).context("tcgetattr failed");
        }
        termios
    };
    update(&mut termios)?;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) } != 0 {
        return Err(std::io::Error::last_os_error()).context("tcsetattr failed");
    }
    Ok(())
}

fn set_serial_baud(fd: RawFd, baud: u32) -> Result<()> {
    let speed = baud_to_speed(baud)?;
    update_termios(fd, |termios| {
        if unsafe { libc::cfsetspeed(termios, speed) } != 0 {
            return Err(std::io::Error::last_os_error()).context("cfsetspeed failed");
        }
        Ok(())
    })
}

fn set_serial_data_size(fd: RawFd, bits: u8) -> Result<()> {
    update_termios(fd, |termios| {
        termios.c_cflag &= !libc::CSIZE;
        termios.c_cflag |= match bits {
            5 => libc::CS5,
            6 => libc::CS6,
            7 => libc::CS7,
            8 => libc::CS8,
            _ => bail!("unsupported RFC2217 data size {bits}"),
        };
        Ok(())
    })
}

fn set_serial_parity(fd: RawFd, parity: u8) -> Result<()> {
    update_termios(fd, |termios| {
        termios.c_cflag &= !(libc::PARENB | libc::PARODD);
        match parity {
            1 => {}
            2 => {
                termios.c_cflag |= libc::PARENB | libc::PARODD;
            }
            3 => {
                termios.c_cflag |= libc::PARENB;
            }
            _ => bail!("unsupported RFC2217 parity {parity}"),
        }
        Ok(())
    })
}

fn set_serial_stop_size(fd: RawFd, stop_bits: u8) -> Result<()> {
    update_termios(fd, |termios| {
        match stop_bits {
            1 => termios.c_cflag &= !libc::CSTOPB,
            2 => termios.c_cflag |= libc::CSTOPB,
            _ => bail!("unsupported RFC2217 stop size {stop_bits}"),
        }
        Ok(())
    })
}

fn set_serial_control(fd: RawFd, control: u8) -> Result<()> {
    match control {
        5 => {
            if unsafe { libc::ioctl(fd, libc::TIOCSBRK) } < 0 {
                return Err(std::io::Error::last_os_error()).context("TIOCSBRK failed");
            }
        }
        6 => {
            if unsafe { libc::ioctl(fd, libc::TIOCCBRK) } < 0 {
                return Err(std::io::Error::last_os_error()).context("TIOCCBRK failed");
            }
        }
        7 | 10 => {}
        // DTR/RTS are deliberately ignored.  CP210x modem transitions are
        // wired to ESP EN/GPIO0 and can reset or strap a board.  Bootloader
        // and recovery flashing owns modem control through direct esptool;
        // lmesh is a passive diagnostics forward only.
        8 | 9 | 11 | 12 => {}
        _ => {}
    }
    Ok(())
}

fn purge_serial_data(fd: RawFd, purge: u8) -> Result<()> {
    let queue = match purge {
        1 => libc::TCIFLUSH,
        2 => libc::TCOFLUSH,
        3 => libc::TCIOFLUSH,
        _ => return Ok(()),
    };
    if unsafe { libc::tcflush(fd, queue) } != 0 {
        return Err(std::io::Error::last_os_error()).context("tcflush failed");
    }
    Ok(())
}

/// Convert the lmesh debug command boundary to the firmware's compact-CBOR
/// wire format. Text never reaches the ESP UART: it is only accepted here so
/// existing JSONL/MCP tooling can keep a convenient command parameter.
fn firmware_command_cbor(command: &str) -> Result<Vec<u8>> {
    let mut words = command.split_ascii_whitespace();
    let method = words.next().context("empty firmware command")?;
    let mut fields: Vec<(String, Option<Vec<u8>>, String)> = Vec::new();
    for word in words {
        let (key, value) = word.split_once('=').unwrap_or((word, "true"));
        if key == "payload" {
            let hex = value.strip_prefix("hex:").unwrap_or(value);
            let payload = decode_firmware_hex(hex)?;
            fields.push(("data".to_owned(), Some(payload), String::new()));
        } else {
            fields.push((key.to_owned(), None, value.to_owned()));
        }
    }
    let mut cbor = Vec::with_capacity(64);
    let mut encoder = Encoder::new(&mut cbor);
    encoder.map(if fields.is_empty() { 1 } else { 2 })?;
    encoder.u16(0)?.str(method)?;
    if !fields.is_empty() {
        encoder.u16(6)?.map(fields.len() as u64)?;
        for (key, bytes, value) in fields {
            if let Some(tag) = firmware_arg_tag(&key) {
                encoder.u16(tag)?;
            } else {
                encoder.str(&key)?;
            }
            if let Some(bytes) = bytes {
                encoder.bytes(&bytes)?;
            } else {
                encoder.str(&value)?;
            }
        }
    }
    mesh::cbor::encode_stream_frame(&cbor)
}

/// Numeric firmware argument IDs for the compact command fields used by the
/// managed ESP path. Keep unknown/debug fields as text for compatibility, but
/// make module-flash requests match Main's native schema exactly.
fn firmware_arg_tag(name: &str) -> Option<u16> {
    Some(match name {
        "op" => 87,
        "name" => 409,
        "server" => 246,
        "port" => 191,
        "target" => 346,
        "dry_run" => 257,
        "object_action_stats" => 272,
        _ => return None,
    })
}

/// Accept one persistent reverse Main connection for every configured STA
/// address. Unknown peers are discarded rather than becoming an implicit
/// maintenance endpoint.
fn reverse_main_accept_loop(
    port: u16,
    sessions: Arc<BTreeMap<String, ReverseMainRuntime>>,
) -> Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
        .with_context(|| format!("failed to bind reverse Main listener on 0.0.0.0:{port}"))?;
    tracing::info!(port, "reverse_main_listener_started");
    for accepted in listener.incoming() {
        let stream = accepted.context("failed to accept reverse Main connection")?;
        let peer = stream
            .peer_addr()
            .context("failed to identify reverse Main peer")?;
        let Some((id, session)) = sessions
            .iter()
            .find(|(_, session)| peer.ip() == std::net::IpAddr::V4(session.ip))
        else {
            tracing::warn!(peer = %peer, port, "reverse_main_unknown_peer");
            continue;
        };
        stream.set_nodelay(true).ok();
        let mut current = session
            .stream
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *current = Some(stream);
        tracing::info!(id = %id, peer = %peer, socket = %session.socket_path, "reverse_main_connected");
    }
    Ok(())
}

/// Expose the accepted connection as the familiar per-device managed socket.
/// Each UDS client sends one `u32 length + CBOR` request and receives the
/// matching framed response. The shared reverse stream is serialized so one
/// device cannot have replies assigned to the wrong local caller.
fn reverse_main_uds_loop(session: ReverseMainRuntime) -> Result<()> {
    if let Some(parent) = PathBuf::from(&session.socket_path).parent() {
        fs::create_dir_all(parent)?;
    }
    let _ = fs::remove_file(&session.socket_path);
    let listener = UnixListener::bind(&session.socket_path)
        .with_context(|| format!("failed to bind reverse Main socket {}", session.socket_path))?;
    configure_serial_forward_socket(&session.socket_path)?;
    for accepted in listener.incoming() {
        let mut client = accepted.context("failed to accept reverse Main socket client")?;
        let session = session.clone();
        std::thread::spawn(move || {
            let result = (|| -> Result<()> {
                let mut length = [0_u8; 4];
                client.read_exact(&mut length)?;
                let length = u32::from_be_bytes(length) as usize;
                if length == 0 || length > 4096 {
                    bail!("invalid reverse Main request length {length}");
                }
                let mut payload = vec![0_u8; length];
                client.read_exact(&mut payload)?;
                let response = reverse_main_exchange_payload(&session, &payload, 30_000)?;
                client.write_all(&(response.len() as u32).to_be_bytes())?;
                client.write_all(&response)?;
                client.flush()?;
                Ok(())
            })();
            if let Err(error) = result {
                tracing::debug!(id = %session.id, error = %error, "reverse_main_socket_exchange_failed");
            }
        });
    }
    Ok(())
}

fn reverse_main_exchange(
    session: &ReverseMainRuntime,
    command: &str,
    timeout_ms: u64,
) -> Result<Value> {
    let stream_frame = firmware_command_cbor(command)?;
    let payload = mesh::cbor::decode_stream_frame(&stream_frame)?;
    let response = reverse_main_exchange_payload(session, &payload, timeout_ms)?;
    mesh::cbor::decode_json(&response, &mesh::cbor::Catalog::default())
        .context("Main reverse TCP response is not compact CBOR")
}

fn reverse_main_exchange_payload(
    session: &ReverseMainRuntime,
    payload: &[u8],
    timeout_ms: u64,
) -> Result<Vec<u8>> {
    let timeout = Duration::from_millis(timeout_ms);
    let mut guard = session
        .stream
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let stream = guard
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("Main reverse session {} is not connected", session.id))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let length = u32::try_from(payload.len()).context("firmware command is too large for TCP")?;
    if let Err(error) = stream
        .write_all(&length.to_be_bytes())
        .and_then(|_| stream.write_all(payload))
        .and_then(|_| stream.flush())
    {
        *guard = None;
        return Err(error).context("failed to write Main reverse command");
    }
    let mut length = [0_u8; 4];
    if let Err(error) = stream.read_exact(&mut length) {
        *guard = None;
        return Err(error).context("failed to read Main reverse response length");
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > 4096 {
        bail!("invalid Main reverse response length {length}");
    }
    let mut response = vec![0_u8; length];
    if let Err(error) = stream.read_exact(&mut response) {
        *guard = None;
        return Err(error).context("failed to read Main reverse response");
    }
    Ok(response)
}

/// One request/response exchange with Main's STA maintenance command port.
/// The outer u32 is TCP framing only; its payload is the same compact CBOR
/// accepted by radio and UART command dispatch.
fn tcp_firmware_exchange(endpoint: &str, command: &str, timeout_ms: u64) -> Result<Value> {
    let address: SocketAddr = endpoint
        .parse()
        .with_context(|| format!("TCP endpoint must be numeric ip:port, got {endpoint:?}"))?;
    let timeout = Duration::from_millis(timeout_ms);
    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .with_context(|| format!("failed to connect Main maintenance endpoint {endpoint}"))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let stream_frame = firmware_command_cbor(command)?;
    let payload = mesh::cbor::decode_stream_frame(&stream_frame)?;
    let length = u32::try_from(payload.len()).context("firmware command is too large for TCP")?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;

    let mut length = [0_u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > 4096 {
        bail!("invalid Main TCP response length {length}");
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    mesh::cbor::decode_json(&payload, &mesh::cbor::Catalog::default())
        .context("Main TCP response is not compact CBOR")
}

fn decode_firmware_hex(value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        bail!("firmware payload hex must have an even length");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex input is ASCII bytes");
            u8::from_str_radix(text, 16).context("firmware payload must be hex")
        })
        .collect()
}

fn boot_command_payload(command: &str) -> Result<Vec<u8>> {
    let partition = if command.eq_ignore_ascii_case("recovery") {
        2_u8
    } else if command.eq_ignore_ascii_case("main") {
        1_u8
    } else {
        bail!("unsupported boot command {command:?}");
    };
    // {0:60010,6:[partition]}: the same compact method/payload envelope
    // used by Main, with no bootloader-specific legacy format.
    Ok(vec![
        0xa2,
        0x00,
        0x1a,
        (DMESH_BOOT_METHOD_SELECT >> 24) as u8,
        (DMESH_BOOT_METHOD_SELECT >> 16) as u8,
        (DMESH_BOOT_METHOD_SELECT >> 8) as u8,
        DMESH_BOOT_METHOD_SELECT as u8,
        0x06,
        0x81,
        partition,
    ])
}

fn boot_identity_json(payload: &[u8]) -> Value {
    let hex = payload
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if payload
        .windows(3)
        .any(|window| window == [0x19, 0xea, 0x60])
    {
        let tuple = boot_identity_tuple(payload);
        let mut result = json!({
            "valid": true,
            "kind": "event",
            "event_id": 60000,
            "event_name": "boot.identity",
            "tuple": tuple,
        });
        if let Some(values) = result["tuple"].as_array() {
            if values.len() >= 10 {
                result["stage2_version"] = values[8].clone();
            }
        }
        return result;
    }
    if payload.len() < 18 || payload[..4] != DMESH_BOOT_MAGIC[..] {
        return json!({"raw_hex": hex, "valid": false});
    }
    json!({
        "valid": payload[4] == DMESH_BOOT_VERSION && payload[5] == 1,
        "version": payload[4],
        "kind": payload[5],
        "role": payload[6],
        "partition": payload[7],
        "role_name": match payload[6] {
            1 => "main",
            2 => "recovery",
            3 => "stage2",
            _ => "unknown",
        },
        "partition_name": match payload[7] {
            0 => "bootloader",
            1 => "main",
            2 => "recovery",
            _ => "unknown",
        },
        "reset_reason": payload[8],
        "boot_count": payload[9],
        "timestamp": u16::from_be_bytes([payload[10], payload[11]]),
        "mac": payload[12..18].iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(":"),
        "raw_hex": hex,
    })
}

fn boot_event_json(payload: &[u8]) -> Value {
    let event_id = boot_event_id(payload).unwrap_or(0);
    let event_name = match event_id {
        60000 => "boot.identity",
        60001 => "flash.complete",
        60002 => "flash.error",
        60003 => "recovery.network_up",
        _ => "boot.event",
    };
    json!({
        "valid": event_id != 0,
        "kind": "event",
        "event_id": event_id,
        "event_name": event_name,
        "tuple": boot_identity_tuple(payload),
    })
}

const DMESH_BOOT_HELLO_LEN: usize = 18;

/// The managed UART forward preserves byte order but not physical UART read
/// boundaries. A DMB1 hello may therefore be split across several stream
/// records; reassemble it before validating the fixed fields.
fn find_stage2_identity(bytes: &[u8]) -> Option<Vec<u8>> {
    bytes
        .windows(DMESH_BOOT_HELLO_LEN)
        .find(|payload| {
            payload[..4] == DMESH_BOOT_MAGIC[..]
                && payload[4] == DMESH_BOOT_VERSION
                && payload[5] == 1
                && payload[6] == DMESH_BOOT_ROLE_STAGE2
                && payload[7] == DMESH_BOOT_PARTITION_BOOTLOADER
        })
        .map(|payload| payload.to_vec())
}

/// Reset an ESP bridge and send the fixed stage2 command on the same open
/// descriptor. Keeping reset, transmit, and receive in one operation avoids
/// losing stage2's short UART selector window. The managed serial forward is
/// deliberately left active so it continues to retain evidence.
fn set_modem_line(fd: RawFd, line: libc::c_int, enabled: bool) -> Result<()> {
    // Preserve the other modem line and submit the complete mask. Some
    // CP210x bridges do not reliably propagate a standalone TIOCMBIS/BIC
    // transition while the tty is shared with a long-lived forward; TIOCMSET
    // matches the control-line transaction used by the ESP reset tooling.
    let mut state = modem_state(fd)?;
    if enabled {
        state |= line;
    } else {
        state &= !line;
    }
    set_modem_state(fd, state)
}

fn set_modem_state(fd: RawFd, mut state: libc::c_int) -> Result<()> {
    if unsafe { libc::ioctl(fd, libc::TIOCMSET, &mut state) } < 0 {
        return Err(std::io::Error::last_os_error()).context("TIOCMSET failed");
    }
    Ok(())
}

fn modem_state(fd: RawFd) -> Result<libc::c_int> {
    let mut state: libc::c_int = 0;
    if unsafe { libc::ioctl(fd, libc::TIOCMGET, &mut state) } < 0 {
        return Err(std::io::Error::last_os_error()).context("TIOCMGET failed");
    }
    Ok(state)
}

/// Reset a running ESP through the descriptor owned by lmesh.
///
/// Some CP210x bridges leave DTR asserted after a previous client or open.
/// Refusing the reset in that state makes the recovery path unusable: the
/// request is accepted but no RTS pulse is performed. Release DTR on this same
/// descriptor first, then pulse RTS. Using the managed descriptor avoids the
/// second-open/close race that can restore modem lines and cancel the reset.
fn serial_run_reset(fd: RawFd) -> Result<()> {
    let state = modem_state(fd)?;
    if state & libc::TIOCM_DTR != 0 {
        set_modem_line(fd, libc::TIOCM_DTR, false)?;
        std::thread::sleep(Duration::from_millis(20));
    }
    // Establish the released level first.  A USB-UART bridge may already
    // report RTS asserted when it is opened; asserting an already-asserted
    // line produces no edge and therefore no ESP reset.
    set_modem_line(fd, libc::TIOCM_RTS, false)?;
    std::thread::sleep(Duration::from_millis(20));
    set_modem_line(fd, libc::TIOCM_RTS, true)?;
    std::thread::sleep(Duration::from_millis(120));
    set_modem_line(fd, libc::TIOCM_RTS, false)?;
    // Stage2's selector is sent by the same managed forward immediately
    // after this reset operation. Do not hold the descriptor for half a
    // second: that would consume a short boot-selector window before the
    // queued PPP packet reaches the UART.
    std::thread::sleep(Duration::from_millis(20));
    Ok(())
}

/// Send a PPP-CBOR boot selector through a managed UDS forward and wait for
/// the next structured boot identity record.
fn connect_uds_boot(socket_path: &str) -> Result<UnixStream> {
    UnixStream::connect(socket_path)
        .with_context(|| format!("failed to connect managed serial socket {socket_path}"))
}

fn uds_boot_exchange(socket_path: &str, command: &[u8], timeout_ms: u64) -> Result<Vec<u8>> {
    let stream = connect_uds_boot(socket_path)?;
    uds_boot_exchange_stream(stream, command, timeout_ms)
}

fn uds_boot_exchange_stream(
    mut stream: UnixStream,
    command: &[u8],
    timeout_ms: u64,
) -> Result<Vec<u8>> {
    let command_frame = mesh::cbor::encode_stream_frame(command)?;
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .context("failed to set managed serial read timeout")?;
    // ROM output precedes the custom bootloader. The selector must wait until
    // the PPP boot identity proves that stage2 has started polling UART.
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut output = Vec::new();
    let mut boot_bytes = Vec::new();
    let mut buf = [0_u8; 512];
    while std::time::Instant::now() < deadline {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(count) => output.extend_from_slice(&buf[..count]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error).context("failed to read stage2 identity"),
        }
        while output.len() >= 4 {
            let body_len = u32::from_be_bytes(output[..4].try_into().unwrap()) as usize;
            if !(4..=mesh::cbor::ESP_RECORD_MAX + 4).contains(&body_len) {
                output.remove(0);
                continue;
            }
            let frame_len = 4 + body_len;
            if output.len() < frame_len {
                break;
            }
            let frame = output.drain(..frame_len).collect::<Vec<_>>();
            let payload = mesh::cbor::decode_stream_frame(&frame)
                .context("invalid managed stage2 stream envelope")?;
            boot_bytes.extend_from_slice(&payload);
            if boot_bytes.len() > DMESH_BOOT_HELLO_LEN * 4 {
                let keep = DMESH_BOOT_HELLO_LEN * 4;
                boot_bytes.drain(..boot_bytes.len() - keep);
            }
            if let Some(identity) = find_stage2_identity(&boot_bytes) {
                stream
                    .write_all(SERIAL_FORWARD_FORCE_DIRECT_PREFIX)
                    .context("failed to select direct delivery for stage2 command")?;
                stream
                    .write_all(&command_frame)
                    .context("failed to write fixed stage2 command")?;
                stream
                    .flush()
                    .context("failed to flush fixed stage2 command")?;
                return Ok(identity);
            }
            if boot_bytes
                .windows(3)
                .any(|window| window == [0x19, 0xea, 0x60])
            {
                stream
                    .write_all(SERIAL_FORWARD_FORCE_DIRECT_PREFIX)
                    .context("failed to select direct delivery for stage2 command")?;
                stream
                    .write_all(&command_frame)
                    .context("failed to write fixed stage2 command")?;
                stream
                    .flush()
                    .context("failed to flush fixed stage2 command")?;
                return Ok(boot_bytes.clone());
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    bail!("timed out waiting for fixed stage2 identity")
}

/// Exchange arbitrary UART bytes through the managed framed forward.  This is
/// used by Recovery's small ASCII parser, which is not a normal Main CBOR
/// command and therefore cannot use `uds_console_exchange`.
fn uds_raw_exchange(socket_path: &str, payload: &[u8], timeout_ms: u64) -> Result<String> {
    static UDS_RAW_SERIALIZE: OnceLock<Mutex<()>> = OnceLock::new();
    let _exchange_guard = UDS_RAW_SERIALIZE
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| anyhow::anyhow!("managed raw exchange lock poisoned"))?;
    let mut stream = UnixStream::connect(socket_path)
        .with_context(|| format!("failed to connect managed serial socket {socket_path}"))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(5)))
        .context("failed to set stale-record timeout")?;
    let mut stale = [0_u8; 2048];
    loop {
        match stream.read(&mut stale) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(error) => return Err(error).context("failed to drain managed serial socket"),
        }
    }
    let command_frame = mesh::cbor::encode_stream_frame(payload)?;
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .context("failed to set managed raw read timeout")?;
    stream
        .write_all(SERIAL_FORWARD_FORCE_DIRECT_PREFIX)
        .context("failed to select direct delivery for Recovery command")?;
    stream
        .write_all(&command_frame)
        .context("failed to write managed raw serial command")?;
    stream
        .flush()
        .context("failed to flush managed raw serial command")?;

    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut output = Vec::new();
    let mut raw = Vec::new();
    let mut buf = [0_u8; 512];
    while std::time::Instant::now() < deadline {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(count) => output.extend_from_slice(&buf[..count]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error).context("failed to read managed raw response"),
        }
        while output.len() >= 4 {
            let body_len = u32::from_be_bytes(output[..4].try_into().unwrap()) as usize;
            if !(4..=mesh::cbor::ESP_RECORD_MAX + 4).contains(&body_len) {
                output.remove(0);
                continue;
            }
            let frame_len = 4 + body_len;
            if output.len() < frame_len {
                break;
            }
            let frame = output.drain(..frame_len).collect::<Vec<_>>();
            let body = mesh::cbor::decode_stream_frame(&frame)
                .context("invalid managed raw stream envelope")?;
            raw.extend_from_slice(&body);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(String::from_utf8_lossy(&raw).to_string())
}

fn parse_raw_exchange_messages(raw: &str) -> Vec<MeshMessage> {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| mesh::message::parse_firmware_message_line(line).ok())
        .collect()
}

/// Send one console command through a managed forward.
///
/// The forward broadcasts UART records to its connected clients.  A command
/// request must therefore disconnect as soon as it has its first complete
/// firmware response: keeping it alive for the entire timeout lets a later
/// command's response be attributed to this one.  Long-running observations
/// belong on the trace/event API, not this request/response path.
fn uds_console_exchange(socket_path: &str, command: &str, timeout_ms: u64) -> Result<String> {
    uds_console_exchange_with_options(socket_path, command, timeout_ms, false)
}

fn uds_console_exchange_with_options(
    socket_path: &str,
    command: &str,
    timeout_ms: u64,
    force_direct: bool,
) -> Result<String> {
    uds_console_exchange_inner(socket_path, command, timeout_ms, force_direct)
}

fn uds_console_exchange_inner(
    socket_path: &str,
    command: &str,
    timeout_ms: u64,
    force_direct: bool,
) -> Result<String> {
    // A managed forward broadcasts every UART record to every connected UDS
    // client. Serialize request/reply exchanges and discard records already
    // queued when this client connects; otherwise a delayed response to a
    // previous `nan queued` request can be returned as the current command's
    // response (especially visible during DW retries).
    static UDS_CONSOLE_SERIALIZE: OnceLock<Mutex<()>> = OnceLock::new();
    let _exchange_guard = UDS_CONSOLE_SERIALIZE
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| anyhow::anyhow!("managed console exchange lock poisoned"))?;
    let command_frame = firmware_command_cbor(command)?;
    let mut stream = UnixStream::connect(socket_path)
        .with_context(|| format!("failed to connect managed serial socket {socket_path}"))?;
    // Drain only data that was present before this command was written. The
    // short timeout keeps this bounded for a sleeping target.
    stream
        .set_read_timeout(Some(Duration::from_millis(5)))
        .with_context(|| format!("failed to set stale-record timeout on {socket_path}"))?;
    let mut stale = [0_u8; 2048];
    loop {
        match stream.read(&mut stale) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(error) => {
                return Err(error).with_context(|| format!("failed to drain {socket_path}"));
            }
        }
    }
    stream
        .set_read_timeout(Some(Duration::from_millis(250)))
        .with_context(|| format!("failed to set read timeout on {socket_path}"))?;
    // Battery nodes advertise a tagged UART wake event during their configured
    // raw-NAN window. The managed forward keeps this command pending until
    // that authoritative event arrives, then flushes it while
    // firmware UART RX is open. GPIO0/PRG is a recovery control and is not a
    // reliable product wake mechanism: using it here can consume the first
    // command on a board waking from light sleep.
    if force_direct {
        stream
            .write_all(SERIAL_FORWARD_FORCE_DIRECT_PREFIX)
            .with_context(|| format!("failed to select direct delivery on {socket_path}"))?;
    }
    stream
        .write_all(&command_frame)
        .with_context(|| format!("failed to write managed serial command to {socket_path}"))?;
    stream
        .flush()
        .with_context(|| format!("failed to flush {socket_path}"))?;
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut output = Vec::new();
    let mut records = String::new();
    let mut buf = [0_u8; 1024];
    while std::time::Instant::now() < deadline {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(count) => {
                output.extend_from_slice(&buf[..count]);
                while output.len() >= 4 {
                    let body_len = u32::from_be_bytes(output[..4].try_into().unwrap()) as usize;
                    let frame_len = body_len.saturating_add(4);
                    if !(4..=mesh::cbor::ESP_RECORD_MAX + 4).contains(&body_len) {
                        // Firmware logs can precede a valid record. Do not
                        // write a synthetic marker into UART: the previous
                        // 0xff recovery sequence was observable by the
                        // firmware and could monopolize a sleeping board's
                        // console. Discard one byte and keep scanning for the
                        // next authoritative stream-frame boundary.
                        let byte = output.remove(0);
                        records.push_str(&String::from_utf8_lossy(&[byte]));
                        continue;
                    }
                    if output.len() < frame_len {
                        break;
                    }
                    let frame = output.drain(..frame_len).collect::<Vec<_>>();
                    // The managed forward can contain a stale partial record
                    // after a board reset or wake.  It is not a command error:
                    // discard this candidate and continue looking for the next
                    // length-prefixed CBOR response on the same connection.
                    // In particular, do not let one bad record prevent a
                    // sleepy board's valid response from being observed.
                    let payload = match mesh::cbor::decode_stream_frame(&frame) {
                        Ok(payload) => payload,
                        Err(error) => {
                            tracing::debug!(%socket_path, %error, "ignored malformed UART stream frame");
                            continue;
                        }
                    };
                    let decoded = match mesh::cbor::decode_json(
                        payload,
                        &mesh::cbor::Catalog::default(),
                    ) {
                        Ok(decoded) => decoded,
                        Err(error) => {
                            tracing::debug!(%socket_path, %error, "ignored malformed UART CBOR payload");
                            continue;
                        }
                    };
                    // Firmware response text is compact-CBOR payload tag 32.
                    // The generic catalog intentionally does not assign this
                    // firmware-private tag a global field name.
                    let record_start = records.len();
                    if let Some(message) = decoded
                        .get("payload")
                        .and_then(Value::as_object)
                        .and_then(|payload| payload.get("32"))
                        .and_then(Value::as_str)
                    {
                        records.push_str(message);
                        records.push('\n');
                    } else if let Some(message) = decoded.get("message").and_then(Value::as_str) {
                        records.push_str(message);
                        records.push('\n');
                    } else if let Some(error) = decoded.get("error").and_then(Value::as_str) {
                        records.push_str("error message=");
                        records.push_str(error);
                        records.push('\n');
                    } else if let Some(status) = decoded.get("status").and_then(Value::as_str) {
                        records.push_str("status=");
                        records.push_str(status);
                        records.push('\n');
                    } else {
                        records.push_str(&decoded.to_string());
                        records.push('\n');
                    }
                    // Forward startup and wake classification records are
                    // broadcast to every UDS client. They are useful for
                    // lmesh's mode tracker but are not replies to an
                    // unrelated command (a `status` request must not be
                    // satisfied by `mode status=true`). Keep waiting for the
                    // command's own record on this same serialized client.
                    if is_unsolicited_console_record(command, &records[record_start..]) {
                        records.truncate(record_start);
                        continue;
                    }
                    // Firmware commands produce one authoritative CBOR
                    // response. Return immediately so this connection cannot
                    // receive and steal the response for a later command.
                    return Ok(records);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => {
                return Err(error).with_context(|| format!("failed to read {socket_path}"));
            }
        }
    }
    if !output.is_empty() {
        records.push_str(&String::from_utf8_lossy(&output));
    }
    bail!("timed out waiting for framed firmware response from {socket_path}")
}

fn is_unsolicited_console_record(command: &str, record: &str) -> bool {
    let command = command.trim_start();
    let record = record.trim_start();
    // State notifications are broadcast to all clients, including the client
    // that issued a mode command. They are never the command's authoritative
    // response, even for the compact `active`/`idle` aliases.
    if record.starts_with("event type=boot") || record.starts_with("event type=mode") {
        return true;
    }
    // `active` and `idle` are compact aliases for the mode control command.
    // Their authoritative response is rendered as `mode active=...`, so it
    // must not be mistaken for the broadcast mode-state event.
    if command.starts_with("mode") || command.starts_with("active") || command.starts_with("idle") {
        return false;
    }
    record.starts_with("mode active=")
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn normalize_mac_suffix(value: &str) -> Option<String> {
    let hex = value
        .bytes()
        .filter(u8::is_ascii_hexdigit)
        .map(char::from)
        .collect::<String>();
    match hex.len() {
        8 => Some(hex.to_ascii_lowercase()),
        12 => Some(hex[4..].to_ascii_lowercase()),
        _ => None,
    }
}

fn response_history_entries(value: &Value, target: Option<&str>) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let Some(messages) = value.get("messages").and_then(Value::as_array) else {
        return entries;
    };
    for message in messages {
        let Some(console) = message.get("console").and_then(Value::as_str) else {
            continue;
        };
        for line in console.lines() {
            let Some(raw_entries) = line.split_once("entries=").map(|(_, entries)| entries) else {
                continue;
            };
            for entry in raw_entries.split(",local_us:").map(|entry| {
                if entry.starts_with("local_us:") {
                    entry.to_owned()
                } else {
                    format!("local_us:{entry}")
                }
            }) {
                let Some((_, payload)) = entry.split_once("payload_hex:") else {
                    continue;
                };
                if let Some(target) = target {
                    let Some((_, source)) = entry.split_once("source:") else {
                        continue;
                    };
                    let source = source.split(':').take(6).collect::<String>();
                    let Some(source) = normalize_mac_suffix(&source) else {
                        continue;
                    };
                    if !mac_suffix_variants(target)
                        .iter()
                        .any(|suffix| suffix == &source)
                    {
                        continue;
                    }
                }
                entries.push((entry.trim().to_owned(), payload.trim().to_ascii_lowercase()));
            }
        }
    }
    entries
}

/// Parse lora1's bounded custom-action response history. The source spelling
/// may be the ESP SoftAP MAC (station + 1), just like NAN response history.
fn raw_response_history_entries(value: &Value, target: Option<&str>) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let Some(messages) = value.get("messages").and_then(Value::as_array) else {
        return entries;
    };
    for message in messages {
        let Some(console) = message.get("console").and_then(Value::as_str) else {
            continue;
        };
        let Some(raw_entries) = console.split_once("entries=").map(|(_, value)| value) else {
            continue;
        };
        for entry in raw_entries.split(",local_us:").map(|entry| {
            if entry.starts_with("local_us:") {
                entry.to_owned()
            } else {
                format!("local_us:{entry}")
            }
        }) {
            let Some((head, payload)) = entry.split_once(":payload_hex:") else {
                continue;
            };
            if let Some(target) = target {
                let Some(source) = head.split_once("source=").map(|(_, value)| value) else {
                    continue;
                };
                let Some(source) = normalize_mac_suffix(source) else {
                    continue;
                };
                if !mac_suffix_variants(target)
                    .iter()
                    .any(|candidate| candidate == &source)
                {
                    continue;
                }
            }
            entries.push((entry.trim().to_owned(), payload.trim().to_ascii_lowercase()));
        }
    }
    entries
}

/// Returns true when an older gateway has no dedicated action-frame history
/// command. Such gateways expose the same received replies through the NAN
/// response history during the compatibility rollout.
fn raw_history_unsupported(value: &Value) -> bool {
    value
        .get("messages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|message| message.get("console").and_then(Value::as_str))
        .any(|console| console.contains("unknown payload key string: raw_response_history"))
}

fn is_session_end(payload_hex: &str) -> bool {
    decode_firmware_hex(payload_hex)
        .map(|payload| {
            payload
                .windows(b"session_end".len())
                .any(|part| part == b"session_end")
        })
        .unwrap_or(false)
}

fn response_request_id(payload_hex: &str) -> Option<u64> {
    let payload = decode_firmware_hex(payload_hex).ok()?;
    let decoded = mesh::cbor::decode_json(&payload, &mesh::cbor::Catalog::default()).ok()?;
    let request_id_key = REMOTE_REQUEST_ID_KEY.to_string();
    decoded
        .get("payload")
        .and_then(Value::as_object)
        .and_then(|payload| payload.get(&request_id_key))
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<u64>().ok())
}

/// Return true for the compact firmware-level NAN ping response.  Ping
/// replies are transport observations and intentionally do not carry the
/// command request-id used by the command acknowledgement.
fn is_firmware_pong(payload_hex: &str) -> bool {
    decode_firmware_hex(payload_hex).is_ok_and(|payload| {
        payload.as_slice() == [0xa2, 0x00, 0x18, 0x21, 0x04, 0x64, b'p', b'o', b'n', b'g']
    })
}

/// ESP32 exposes the station MAC in some command paths and the AP MAC in raw
/// NAN frames. They differ only in the final byte (AP = STA + 1), so response
/// history matching must accept both forms for one addressed node.
fn mac_suffix_variants(value: &str) -> Vec<String> {
    let Some(normalized) = normalize_mac_suffix(value) else {
        return Vec::new();
    };
    let mut variants = vec![normalized.clone()];
    let Ok(last) = u8::from_str_radix(&normalized[6..], 16) else {
        return variants;
    };
    for adjacent in [last.wrapping_sub(1), last.wrapping_add(1)] {
        let candidate = format!("{}{:02x}", &normalized[..6], adjacent);
        if !variants.contains(&candidate) {
            variants.push(candidate);
        }
    }
    variants
}

/// Encode a raw-NAN command for one ESP target. The receiver applies the
/// normal `to=` filter before dispatching the method, so a broadcast follow-up
/// from the gateway cannot activate unrelated battery nodes.
fn firmware_targeted_command_cbor(command: &str, target: &str) -> Result<Vec<u8>> {
    firmware_targeted_command_cbor_with_metadata(command, target, None, None)
}

fn firmware_targeted_command_cbor_with_timeout(
    command: &str,
    target: &str,
    timeout_ms: Option<u32>,
) -> Result<Vec<u8>> {
    firmware_targeted_command_cbor_with_metadata(command, target, timeout_ms, None)
}

fn firmware_targeted_command_cbor_with_metadata(
    command: &str,
    target: &str,
    timeout_ms: Option<u32>,
    request_id: Option<u64>,
) -> Result<Vec<u8>> {
    // Keep the public remote-command shortcut aligned with the firmware ABI.
    // `ping` is a host convenience alias for `mode ping=true`; encoding the
    // literal method name would otherwise produce an unknown-command response
    // on the ESP and can be mistaken for a lost DW delivery.
    if command.trim().eq_ignore_ascii_case("ping") {
        let mut bytes = Vec::with_capacity(56);
        let mut encoder = Encoder::new(&mut bytes);
        let arg_count = 2 + usize::from(timeout_ms.is_some()) + usize::from(request_id.is_some());
        encoder.map(2)?;
        encoder.u16(0)?.u16(49)?;
        encoder.u16(6)?.map(arg_count as u64)?;
        encoder.u16(190)?.str("true")?;
        encoder.u16(331)?.str(target)?;
        if let Some(timeout_ms) = timeout_ms {
            encoder.u16(41)?.str(&timeout_ms.to_string())?;
        }
        if let Some(request_id) = request_id {
            encoder
                .u16(REMOTE_REQUEST_ID_KEY)?
                .str(&request_id.to_string())?;
        }
        return Ok(bytes);
    }
    let mut words = command.split_whitespace();
    let method = words
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("remote firmware command is empty"))?;
    let mut command_args = Vec::new();
    for word in words {
        let (key, value) = word.split_once('=').unwrap_or((word, "true"));
        command_args.push((key.to_owned(), value.to_owned()));
    }
    let mut bytes = Vec::with_capacity(32);
    let mut encoder = Encoder::new(&mut bytes);
    let arg_count = command_args.len()
        + 1
        + usize::from(timeout_ms.is_some())
        + usize::from(request_id.is_some());
    encoder
        .map(2)
        .and_then(|encoder| encoder.u16(0))
        .and_then(|encoder| encoder.str(method))
        .and_then(|encoder| encoder.u16(6))
        .and_then(|encoder| encoder.map(arg_count as u64))
        .map_err(|error| anyhow::Error::msg(error.to_string()))?;
    for (key, value) in command_args {
        encoder
            .str(&key)
            .and_then(|encoder| encoder.str(&value))
            .map_err(|error| anyhow::Error::msg(error.to_string()))?;
    }
    encoder
        .u16(331)
        .and_then(|encoder| encoder.str(target))
        .and_then(|encoder| {
            if let Some(timeout_ms) = timeout_ms {
                encoder
                    .u16(41)
                    .and_then(|encoder| encoder.str(&timeout_ms.to_string()))
            } else {
                Ok(encoder)
            }
        })
        .and_then(|encoder| {
            if let Some(request_id) = request_id {
                encoder
                    .u16(REMOTE_REQUEST_ID_KEY)
                    .and_then(|encoder| encoder.str(&request_id.to_string()))
            } else {
                Ok(encoder)
            }
        })
        .map_err(|error| anyhow::Error::msg(error.to_string()))?;
    Ok(bytes)
}

/// Encode a bounded target wake. The target receives the regular `mode`
/// command with `active_ms`, entering command/transfer mode without requiring
/// a second UART or USB intervention.
fn firmware_targeted_active_window_cbor(target: &str, active_ms: u32) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(48);
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .map(2)
        .and_then(|encoder| encoder.u16(0))
        .and_then(|encoder| encoder.str("mode"))
        .and_then(|encoder| encoder.u16(6))
        .and_then(|encoder| encoder.map(2))
        .and_then(|encoder| encoder.u16(80))
        .and_then(|encoder| encoder.str(&active_ms.clamp(1_000, 300_000).to_string()))
        .and_then(|encoder| encoder.u16(331))
        .and_then(|encoder| encoder.str(target))
        .map_err(|error| anyhow::Error::msg(error.to_string()))?;
    Ok(bytes)
}

/// Encode the firmware's `mode ping=true` command. The numeric tags are part
/// of the documented ESP firmware ABI: method 49 (`mode`) and argument 190
/// (`ping`). Keep host NAN command traffic binary even while UART debug text
/// remains supported.
fn firmware_mode_ping_cbor() -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(16);
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .map(2)
        .and_then(|encoder| encoder.u16(0))
        .and_then(|encoder| encoder.u16(49))
        .and_then(|encoder| encoder.u16(6))
        .and_then(|encoder| encoder.map(1))
        .and_then(|encoder| encoder.u16(190))
        .and_then(|encoder| encoder.str("true"))
        .map_err(|error| anyhow::Error::msg(error.to_string()))?;
    Ok(bytes)
}

/// Extract DMesh follow-up replies delivered by wpa_supplicant as
/// `NAN-RECEIVE` events. The DMesh header's device ID is the stable firmware
/// identity; the WPA peer address may be randomized by platform NAN stacks.
fn host_nan_responses(events: &Value) -> Vec<Value> {
    events
        .get("events")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|event| event.get("event").and_then(Value::as_str) == Some("NAN-RECEIVE"))
        .filter_map(|event| {
            let fields = event.get("fields")?;
            let dmesh = fields.get("ssi_dmesh")?;
            (dmesh.get("protocol").and_then(Value::as_str) == Some("dmesh_nan_followup")).then(
                || {
                    json!({
                        "device_id": dmesh.get("device_id"),
                        "target_id": dmesh.get("target_id"),
                        "msg_type": dmesh.get("msg_type"),
                        "payload": dmesh.get("payload_text"),
                        "peer": fields.get("address"),
                    })
                },
            )
        })
        .collect()
}

fn parse_stability_pongs(output: &str) -> Vec<Value> {
    output
        .lines()
        .filter(|line| line.contains("type=lora.dmesh_control") && line.contains("kind=pong"))
        .filter_map(|line| {
            let mut fields = BTreeMap::new();
            for field in line.split_ascii_whitespace() {
                let Some((key, value)) = field.split_once('=') else {
                    continue;
                };
                fields.insert(key, value);
            }
            let from = fields.get("from")?;
            Some(json!({
                "from": from,
                "uptime_ms": fields.get("uptime_ms").copied().unwrap_or("-"),
                "link_rssi_dbm": fields.get("link_rssi_dbm").copied().unwrap_or("-"),
                "snr": fields.get("snr").copied().unwrap_or("-"),
                "nan": {
                    "running": fields.get("nrun").copied().unwrap_or("-"),
                    "mgmt_rx": fields.get("nmg").copied().unwrap_or("-"),
                    "sdf_rx": fields.get("nsdf").copied().unwrap_or("-"),
                    "response_rx": fields.get("nrx").copied().unwrap_or("-"),
                    "response_tx": fields.get("ntx").copied().unwrap_or("-"),
                    "prefilter_drop": fields.get("ndrop").copied().unwrap_or("-"),
                    "beacon_age_ms": fields.get("nage").copied().unwrap_or("-"),
                },
            }))
        })
        .collect()
}

/// Read the compact raw-NAN counters exposed by the firmware debug command.
/// The stability cycle takes a snapshot before and after its ping observation
/// window, making raw-NAN response delivery observable independently of the
/// LoRa console packet that carries the human-readable pong.
fn stability_nan_stats(socket: &str) -> Option<BTreeMap<String, u64>> {
    // A sleepy console may miss the first heartbeat at a duty-window boundary.
    // Retry once so the stability monitor does not turn that normal boundary
    // race into a missing raw-NAN health sample.
    for _ in 0..2 {
        let Ok(output) = uds_console_exchange(socket, "nan stats=true", 1_500) else {
            continue;
        };
        let Some(line) = output
            .lines()
            .find_map(|line| line.find("nan support=raw").map(|offset| &line[offset..]))
        else {
            continue;
        };
        let mut fields = BTreeMap::new();
        for field in line.split_ascii_whitespace() {
            let Some((key, value)) = field.split_once('=') else {
                continue;
            };
            if matches!(
                key,
                "raw_sdf" | "raw_resp_rx" | "raw_resp_tx" | "raw_beacon" | "rx_queue_drop"
            ) && let Ok(value) = value.parse::<u64>()
            {
                fields.insert(key.to_string(), value);
            }
        }
        return Some(fields);
    }
    None
}

fn stability_nan_cycle(
    before: Option<&BTreeMap<String, u64>>,
    after: Option<&BTreeMap<String, u64>>,
) -> Value {
    let delta = |key: &str| match (
        before.and_then(|values| values.get(key)),
        after.and_then(|values| values.get(key)),
    ) {
        (Some(before), Some(after)) => Some(after.saturating_sub(*before)),
        _ => None,
    };
    let response_rx_delta = delta("raw_resp_rx");
    json!({
        "before": before,
        "after": after,
        "sdf_rx_delta": delta("raw_sdf"),
        "response_rx_delta": response_rx_delta,
        "response_tx_delta": delta("raw_resp_tx"),
        "beacon_delta": delta("raw_beacon"),
        "queue_drop_delta": delta("rx_queue_drop"),
        "response_observed": response_rx_delta.is_some_and(|value| value > 0),
    })
}

fn append_stability_result(state: &Arc<Mutex<StabilityState>>) {
    let snapshot = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .snapshot();
    let directory = std::env::var("MESH_LOG_DIR").unwrap_or_else(|_| "/run/mesh/lmesh".to_string());
    let path = PathBuf::from(directory).join("lora-stability.jsonl");
    let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(&path) else {
        tracing::warn!(path = %path.display(), "stability_log_open_failed");
        return;
    };
    if let Err(error) = writeln!(file, "{}", snapshot) {
        tracing::warn!(path = %path.display(), error = %error, "stability_log_write_failed");
    }
}

fn configure_serial(fd: RawFd, baud: u32) -> Result<()> {
    let mut termios = unsafe {
        let mut termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut termios) != 0 {
            return Err(std::io::Error::last_os_error()).context("tcgetattr failed");
        }
        termios
    };
    unsafe {
        libc::cfmakeraw(&mut termios);
    }
    let speed = baud_to_speed(baud)?;
    let rc = unsafe { libc::cfsetspeed(&mut termios, speed) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("cfsetspeed failed");
    }
    termios.c_cflag |= libc::CLOCAL | libc::CREAD;
    let rc = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("tcsetattr failed");
    }
    Ok(())
}

fn baud_to_speed(baud: u32) -> Result<libc::speed_t> {
    match baud {
        9_600 => Ok(libc::B9600),
        19_200 => Ok(libc::B19200),
        38_400 => Ok(libc::B38400),
        57_600 => Ok(libc::B57600),
        115_200 => Ok(libc::B115200),
        230_400 => Ok(libc::B230400),
        460_800 => Ok(libc::B460800),
        921_600 => Ok(libc::B921600),
        _ => bail!("unsupported serial baud {baud}"),
    }
}

#[derive(Debug, Deserialize)]
struct LmeshToml {
    #[serde(default)]
    radios: Vec<RadioConfig>,
    #[serde(default)]
    serial_forwards: Vec<SerialForwardConfig>,
    #[serde(default)]
    esp_gateway: Option<String>,
    #[serde(default)]
    esp_targets: BTreeMap<String, String>,
    /// Main STA sessions originate at the ESP and are accepted by lmesh.
    #[serde(default)]
    esp_reverse_sessions: Vec<EspReverseSessionConfig>,
    /// One append-only, host-timestamped capture for all managed serial forwards.
    serial_log_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EspReverseSessionConfig {
    id: String,
    ip: Ipv4Addr,
    #[serde(default = "default_reverse_main_port")]
    port: u16,
    socket: Option<String>,
}

fn default_reverse_main_port() -> u16 {
    3343
}

fn configured_esp_gateway() -> String {
    if let Ok(value) = std::env::var("LMESH_ESP_GATEWAY") {
        if !value.trim().is_empty() {
            return value;
        }
    }
    read_lmesh_config()
        .and_then(|config| config.esp_gateway)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_ESP_NAN_GATEWAY.to_string())
}

fn configured_esp_targets() -> BTreeMap<String, String> {
    let mut targets = read_lmesh_config()
        .map(|config| config.esp_targets)
        .unwrap_or_default();
    if let Ok(value) = std::env::var("LMESH_ESP_TARGETS") {
        for entry in value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            if let Some((role, target)) = entry.split_once('=') {
                if !role.trim().is_empty() && !target.trim().is_empty() {
                    targets.insert(role.trim().to_owned(), target.trim().to_owned());
                }
            }
        }
    }
    targets
}

fn configured_esp_reverse_sessions() -> BTreeMap<String, ReverseMainRuntime> {
    read_lmesh_config()
        .map(|config| config.esp_reverse_sessions)
        .unwrap_or_default()
        .into_iter()
        .map(|config| {
            let socket_path = config
                .socket
                .unwrap_or_else(|| format!("/run/mesh/lmesh/{}-ip.sock", config.id));
            let runtime = ReverseMainRuntime {
                id: config.id.clone(),
                ip: config.ip,
                port: config.port,
                socket_path,
                stream: Arc::new(Mutex::new(None)),
            };
            (config.id, runtime)
        })
        .collect()
}

fn resolve_esp_route(
    gateway: &str,
    targets: &BTreeMap<String, String>,
    port: Option<&str>,
    adapter: Option<&str>,
) -> Option<(String, String)> {
    // An explicitly named adapter is the escape hatch for UART diagnostics.
    if adapter.is_some() {
        return None;
    }
    if gateway.trim().is_empty() {
        return None;
    }
    let target = targets.get(port?)?.clone();
    Some((gateway.to_owned(), target))
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

#[derive(Clone, Debug, Deserialize)]
struct SerialForwardConfig {
    port: String,
    path: Option<String>,
    baud: Option<u32>,
    tcp_port: Option<u16>,
    tcp_mode: Option<String>,
    multi: Option<bool>,
    log: Option<bool>,
    /// Forward unframed serial output verbatim. This is for external sources
    /// such as power meters, never ESP firmware UARTs.
    raw: Option<bool>,
    /// Write complete client command records immediately while retaining
    /// decoded framed output. Use for continuously awake infrastructure ESPs.
    direct: Option<bool>,
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
            path: Some(format!("{}/{}", wpa_ctrl_dir(None), wifi_iface(None))),
            network: None,
            baud: None,
            enabled: true,
        },
    ];

    if let Ok(devices) = std::env::var("LMESH_SERIAL_DEVICES") {
        for (idx, path) in devices
            .split(',')
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .enumerate()
        {
            radios.push(RadioAdapter {
                id: format!("esp-serial-{idx}"),
                kind: "esp-serial".to_string(),
                medium: "serial".to_string(),
                path: Some(path.to_string()),
                network: None,
                baud: Some(460_800),
                enabled: true,
            });
        }
    }

    if let Some(config) = read_lmesh_config() {
        for radio in config.radios {
            let default_baud = (radio.kind == "esp-serial").then_some(460_800);
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
                baud: radio.baud.or(default_baud),
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
        "esp-serial" => "serial",
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

fn parse_hci_le_adv_reports(packet: &[u8]) -> Vec<Value> {
    if packet.len() < 4 || packet[0] != 0x04 || packet[1] != 0x3e || packet[3] != 0x02 {
        return Vec::new();
    }
    let mut offset = 5;
    let mut reports = Vec::new();
    let count = packet.get(4).copied().unwrap_or(0) as usize;
    for _ in 0..count {
        if offset + 9 > packet.len() {
            break;
        }
        let event_type = packet[offset];
        let addr_type = packet[offset + 1];
        let address = mac_string_reversed(&packet[offset + 2..offset + 8]);
        let data_len = packet[offset + 8] as usize;
        offset += 9;
        if offset + data_len + 1 > packet.len() {
            break;
        }
        let data = packet[offset..offset + data_len].to_vec();
        offset += data_len;
        let rssi = packet[offset] as i8;
        offset += 1;
        reports.push(json!({
            "event_type": event_type,
            "addr_type": addr_type,
            "address": address,
            "scan_rssi": rssi,
            "data": hex_bytes(&data),
            "fields": ble_ad_fields_json(&data),
        }));
    }
    reports
}

fn parse_dmesh_ble_report(report: &Value) -> Option<Result<Value>> {
    let address = report.get("address")?.as_str()?;
    let scan_rssi = report.get("scan_rssi")?.as_i64()? as i32;
    let data_hex = report.get("data")?.as_str()?;
    let data = parse_hex_bytes(data_hex).ok()?;
    let mut offset = 0;
    while offset < data.len() {
        let field_len = data[offset] as usize;
        offset += 1;
        if field_len == 0 {
            break;
        }
        if offset + field_len > data.len() {
            break;
        }
        let field_type = data[offset];
        let field_data = &data[offset + 1..offset + field_len];
        if field_type == 0x16 || field_type == 0x21 {
            let parsed = radio_protocol::parse_ble_service_data(field_data, scan_rssi, address);
            if parsed.is_ok() {
                return Some(parsed);
            }
        }
        offset += field_len;
    }
    None
}

fn ble_ad_fields_json(data: &[u8]) -> Vec<Value> {
    let mut offset = 0;
    let mut fields = Vec::new();
    while offset < data.len() {
        let field_len = data[offset] as usize;
        offset += 1;
        if field_len == 0 {
            break;
        }
        if offset + field_len > data.len() {
            break;
        }
        let field_type = data[offset];
        let field_data = &data[offset + 1..offset + field_len];
        fields.push(json!({
            "type": format!("0x{field_type:02x}"),
            "data": hex_bytes(field_data),
        }));
        offset += field_len;
    }
    fields
}

#[repr(C)]
struct SockaddrHci {
    hci_family: libc::sa_family_t,
    hci_dev: u16,
    hci_channel: u16,
}

struct HciSocket {
    fd: RawFd,
}

impl HciSocket {
    fn open(dev_id: u16) -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                AF_BLUETOOTH,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                BTPROTO_HCI,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context(
                "failed to open AF_BLUETOOTH raw HCI socket; CAP_NET_RAW is usually required",
            );
        }
        let addr = SockaddrHci {
            hci_family: AF_BLUETOOTH as libc::sa_family_t,
            hci_dev: dev_id,
            hci_channel: HCI_CHANNEL_RAW,
        };
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const SockaddrHci as *const libc::sockaddr,
                std::mem::size_of::<SockaddrHci>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(error).with_context(|| format!("failed to bind HCI device {dev_id}"));
        }
        Ok(Self { fd })
    }

    fn send_le_command(&self, ocf: u16, params: &[u8]) -> Result<()> {
        if params.len() > u8::MAX as usize {
            bail!("HCI command parameters too large: {}", params.len());
        }
        let opcode = (OGF_LE_CTL << 10) | ocf;
        let mut packet = Vec::with_capacity(4 + params.len());
        packet.push(HCI_COMMAND_PKT);
        packet.extend_from_slice(&opcode.to_le_bytes());
        packet.push(params.len() as u8);
        packet.extend_from_slice(params);
        let written = unsafe {
            libc::send(
                self.fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
            )
        };
        if written < 0 {
            let error = std::io::Error::last_os_error();
            bail!("failed to send HCI command: {error}");
        }
        Ok(())
    }

    fn recv_timeout(&self, timeout: Duration) -> Result<Option<Vec<u8>>> {
        let timeout_ms = timeout
            .as_millis()
            .min(libc::c_int::MAX as u128)
            .try_into()
            .unwrap_or(libc::c_int::MAX);
        let mut poll_fd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
        if ready < 0 {
            return Err(std::io::Error::last_os_error()).context("failed to poll HCI socket");
        }
        if ready == 0 || (poll_fd.revents & libc::POLLIN) == 0 {
            return Ok(None);
        }
        let mut packet = vec![0_u8; 260];
        let read = unsafe {
            libc::recv(
                self.fd,
                packet.as_mut_ptr() as *mut libc::c_void,
                packet.len(),
                0,
            )
        };
        if read < 0 {
            return Err(std::io::Error::last_os_error()).context("failed to receive HCI event");
        }
        packet.truncate(read as usize);
        Ok(Some(packet))
    }
}

impl Drop for HciSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
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

struct Nl80211Socket {
    fd: RawFd,
    family_id: u16,
}

struct ApRuntime {
    _owner_socket: Nl80211Socket,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

struct NativeNanRuntime {
    wdev: u64,
    ifindex: Option<u32>,
    ifname: String,
    wiphy: u32,
    kernel_nan: bool,
    stop: Arc<AtomicBool>,
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
        let variant = variant.unwrap_or("standard").trim();
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
            "nan_data_raw" | "nan_data_raw_active" | "nan_data_multicast" | "nan_data_multicast_active" => Self {
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
                Err(error)
                    if error.to_string().contains("Match already configured") => {}
                Err(error) if registered == 0 => return Err(error),
                Err(_) => {}
            }
        }
        Ok(())
    }

    /// Match wpa_supplicant's CONFIG_NAN_USD registration while retaining the
    /// ESP-NOW/DMesh vendor-action registrations on the same nl80211 socket.
    fn register_wpa_nan_usd_and_dmesh(&self, ifindex: u32) -> Result<()> {
        let nan_match = [0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13];
        let mut multicast_error = None;
        let mut registered = false;
        for multicast in [true, false] {
            let mut payload = genl_payload(NL80211_CMD_REGISTER_FRAME, NL80211_GENL_VERSION);
            append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
            if multicast {
                append_attr(&mut payload, NL80211_ATTR_RECEIVE_MULTICAST, &[]);
            }
            append_attr(
                &mut payload,
                NL80211_ATTR_FRAME_TYPE,
                &IEEE80211_ACTION_FRAME_TYPE.to_ne_bytes(),
            );
            append_attr(&mut payload, NL80211_ATTR_FRAME_MATCH, &nan_match);
            self.send_genl(
                self.family_id,
                (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
                77 + u32::from(!multicast),
                &payload,
            )?;
            match self.recv_ack() {
                Ok(()) => { registered = true; break; }
                // A long-lived AP/monitor owner may already hold this exact
                // nl80211 match.  That is sufficient for receive delivery;
                // do not prevent the beacon-gated sender from starting.
                Err(error) if error.to_string().contains("Match already configured") => {
                    registered = true;
                    break;
                }
                Err(error) if multicast => multicast_error = Some(error),
                Err(error) => return Err(error).context("nl80211 NAN USD frame registration failed"),
            }
        }
        if !registered {
            return Err(multicast_error.unwrap_or_else(|| anyhow::anyhow!("NAN USD frame registration failed")));
        }
        self.register_dmesh_action(ifindex)
    }

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
                Err(error) if format!("{error:#}").contains("Operation already in progress") => reports.push(json!({
                    "name": name,
                    "ok": true,
                    "already_registered": true,
                    "frame_type": format!("0x{frame_type:04x}"),
                    "match_hex": hex_bytes(frame_match),
                })),
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
        let response = self.recv_reply().context("nl80211 remain-on-channel failed")?;
        let cookie = genl_attrs(&response)?.into_iter()
            .find_map(|(kind, value)| (kind & NLA_TYPE_MASK == NL80211_ATTR_COOKIE && value.len() >= 8)
                .then(|| u64::from_ne_bytes(value[..8].try_into().unwrap())))
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

    fn new_nan_interface(&self, wiphy: u32, ifname: &str) -> Result<Value> {
        let mut payload = genl_payload(NL80211_CMD_NEW_INTERFACE, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_WIPHY, &wiphy.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_IFNAME, format!("{ifname}\0").as_bytes());
        append_attr(&mut payload, NL80211_ATTR_IFTYPE, &NL80211_IFTYPE_NAN.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_SOCKET_OWNER, &[]);
        self.send_genl(self.family_id, (NLM_F_REQUEST | NLM_F_ACK) as u16, 70, &payload)?;
        let response = self.recv_reply()?;
        let mut out = serde_json::Map::new();
        for (kind, value) in genl_attrs(&response)? {
            match kind & NLA_TYPE_MASK {
                NL80211_ATTR_IFINDEX if value.len() >= 4 => {
                    out.insert("ifindex".to_string(), json!(u32::from_ne_bytes(value[..4].try_into()?)));
                }
                NL80211_ATTR_WDEV if value.len() >= 8 => {
                    out.insert("wdev".to_string(), json!(u64::from_ne_bytes(value[..8].try_into()?)));
                }
                _ => {}
            }
        }
        Ok(Value::Object(out))
    }

    fn interface_wdev(&self, ifindex: u32) -> Result<u64> {
        let mut payload = genl_payload(NL80211_CMD_GET_INTERFACE, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        self.send_genl(self.family_id, (NLM_F_REQUEST | NLM_F_ACK) as u16, 76, &payload)?;
        let response = self.recv_reply()?;
        for (attr, value) in genl_attrs(&response)? {
            if attr & NLA_TYPE_MASK == NL80211_ATTR_WDEV && value.len() >= 8 {
                return Ok(u64::from_ne_bytes(value[..8].try_into()?));
            }
        }
        bail!("nl80211 GET_INTERFACE returned no wdev for ifindex {ifindex}")
    }

    fn start_nan(&self, wdev: u64, master_pref: u8) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_START_NAN, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_WDEV, &wdev.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_NAN_MASTER_PREF, &[master_pref]);
        append_attr(&mut payload, NL80211_ATTR_BANDS, &1_u32.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_SOCKET_OWNER, &[]);
        self.send_genl(self.family_id, (NLM_F_REQUEST | NLM_F_ACK) as u16, 71, &payload)?;
        self.recv_ack().context("nl80211 native NAN start failed")
    }

    fn add_nan_function(
        &self,
        wdev: u64,
        kind: u8,
        service_id: [u8; 6],
        service_info: &[u8],
        active_subscribe: bool,
    ) -> Result<Value> {
        let mut function = Vec::new();
        append_attr(&mut function, 1, &[kind]);
        append_attr(&mut function, 2, &service_id);
        if kind == 0 {
            append_attr(&mut function, 3, &[2]); // unsolicited publish
        } else if active_subscribe {
            append_attr(&mut function, 6, &[]);
        }
        append_attr(&mut function, 11, &3600_u32.to_ne_bytes());
        append_attr(&mut function, 12, service_info);
        let mut payload = genl_payload(NL80211_CMD_ADD_NAN_FUNCTION, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_WDEV, &wdev.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_NAN_FUNC | (1 << 15), &function);
        append_attr(&mut payload, NL80211_ATTR_SOCKET_OWNER, &[]);
        self.send_genl(self.family_id, (NLM_F_REQUEST | NLM_F_ACK) as u16, 72, &payload)?;
        let response = self.recv_reply()?;
        let mut out = serde_json::Map::new();
        for (attr, value) in genl_attrs(&response)? {
            match attr & NLA_TYPE_MASK {
                NL80211_ATTR_NAN_FUNC_INST_ID if !value.is_empty() => {
                    out.insert("instance_id".to_string(), json!(value[0]));
                }
                NL80211_ATTR_COOKIE if value.len() >= 8 => {
                    out.insert("cookie".to_string(), json!(u64::from_ne_bytes(value[..8].try_into()?)));
                }
                _ => {}
            }
        }
        Ok(Value::Object(out))
    }

    fn add_nan_followup(&self, wdev: u64, instance_id: u8, requestor_id: u8, destination: [u8; 6], payload_bytes: &[u8]) -> Result<Value> {
        let mut function = Vec::new();
        append_attr(&mut function, 1, &[2]);
        append_attr(&mut function, 7, &[instance_id]);
        append_attr(&mut function, 8, &[requestor_id]);
        append_attr(&mut function, 9, &destination);
        append_attr(&mut function, 12, payload_bytes);
        let mut payload = genl_payload(NL80211_CMD_ADD_NAN_FUNCTION, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_WDEV, &wdev.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_NAN_FUNC | (1 << 15), &function);
        append_attr(&mut payload, NL80211_ATTR_SOCKET_OWNER, &[]);
        self.send_genl(self.family_id, (NLM_F_REQUEST | NLM_F_ACK) as u16, 75, &payload)?;
        let response = self.recv_reply()?;
        let mut out = serde_json::Map::new();
        for (attr, value) in genl_attrs(&response)? {
            if attr & NLA_TYPE_MASK == NL80211_ATTR_COOKIE && value.len() >= 8 {
                out.insert("cookie".to_string(), json!(u64::from_ne_bytes(value[..8].try_into()?)));
            }
        }
        Ok(Value::Object(out))
    }

    fn stop_nan(&self, wdev: u64) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_STOP_NAN, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_WDEV, &wdev.to_ne_bytes());
        self.send_genl(self.family_id, (NLM_F_REQUEST | NLM_F_ACK) as u16, 73, &payload)?;
        self.recv_ack().context("nl80211 native NAN stop failed")
    }

    fn del_interface(&self, ifindex: u32) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_DEL_INTERFACE, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        self.send_genl(self.family_id, (NLM_F_REQUEST | NLM_F_ACK) as u16, 74, &payload)?;
        self.recv_ack().context("nl80211 native NAN interface delete failed")
    }

    fn recv_reply(&self) -> Result<Vec<u8>> {
        loop {
            let response = self.recv_netlink_raw()?;
            if let Some(error) = netlink_error(&response) {
                bail!("netlink error: {}{}", std::io::Error::from_raw_os_error(error), netlink_extack_message(&response));
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

    fn start_open_ap(
        &self,
        ifindex: u32,
        mac: [u8; 6],
        ssid: &str,
        channel: u8,
        freq: u32,
    ) -> std::result::Result<Value, (anyhow::Error, Vec<Value>)> {
        let esp_beacon_head =
            build_open_beacon_head(mac, ssid, channel).map_err(|error| (error, Vec::new()))?;
        let hostapd_beacon_head =
            build_open_beacon_head_with_capability(mac, ssid, channel, 0x0401)
                .map_err(|error| (error, Vec::new()))?;
        let esp_beacon_tail = esp_open_ap_beacon_tail();
        let hostapd_beacon_tail = hostapd_open_ap_beacon_tail(channel);
        let probe_resp =
            build_open_probe_resp(mac, ssid, channel).map_err(|error| (error, Vec::new()))?;
        let profiles = [
            ApStartProfile {
                name: "hostapd_exact_ht20",
                probe_resp: true,
                channel_type: NL80211_CHAN_HT20,
                channel_width: NL80211_CHAN_WIDTH_20,
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
                append_attr(&mut payload, NL80211_ATTR_CENTER_FREQ1, &freq.to_ne_bytes());
            }
            if profile.freq_fixed {
                append_attr(&mut payload, NL80211_ATTR_FREQ_FIXED, &[]);
            }
            append_attr(
                &mut payload,
                NL80211_ATTR_BEACON_INTERVAL,
                &100_u32.to_ne_bytes(),
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
                append_attr(&mut payload, NL80211_ATTR_PROBE_RESP, &probe_resp);
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
                &[0x02, 0x04, 0x0b, 0x16],
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
            supported_rates.unwrap_or(&[0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]),
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
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            3,
            &payload,
        )?;
        self.recv_ack().context("nl80211 frame TX failed")
    }

    fn send_mgmt_frame(&self, ifindex: u32, frame: &[u8]) -> Result<()> {
        let mut payload = genl_payload(NL80211_CMD_FRAME, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_FRAME, frame);
        self.send_genl(
            self.family_id,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            18,
            &payload,
        )?;
        self.recv_ack()
            .context("nl80211 management frame TX failed")
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
    ifindex: u32,
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
                (ETH_P_ALL as i32).to_be(),
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
        Ok(Self { fd, ifindex })
    }

    fn send(&self, packet: &[u8]) -> Result<usize> {
        let addr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as libc::sa_family_t,
            sll_protocol: ETH_P_ALL.to_be(),
            sll_ifindex: self.ifindex as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let written = unsafe {
            libc::sendto(
                self.fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
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
                (ETH_P_ALL as i32).to_be(),
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
                (ETH_P_ALL as i32).to_be(),
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

fn send_monitor_frame(iface: &str, channel: u8, frame: &[u8], active: bool) -> Result<Value> {
    let monitor_iface = monitor_iface_name(iface);
    let setup = ensure_monitor_iface(iface, &monitor_iface, channel, active, false)?;
    let packet = build_radiotap_packet(frame);
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
) -> Result<Value> {
    let mut steps = Vec::new();
    // A monitor VIF can exist while its parent is administratively down. For
    // active raw-NAN operation the dedicated radio must be owned by monitor
    // mode: leaving the managed parent up makes channel selection succeed only
    // nominally and packets are looped back to AF_PACKET without reaching RF.
    steps.push(run_command("ip", &["link", "set", base_iface, "up"]));
    if active && recreate && ifindex(monitor_iface).is_ok() {
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
            add_args.extend(["flags", "active"]);
        }
        steps.push(run_command("iw", &add_args));
    }
    steps.push(run_command("ip", &["link", "set", monitor_iface, "up"]));
    if active {
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

fn wifi_wiphy_index(iface: &str) -> Result<u32> {
    let path = format!("/sys/class/net/{iface}/phy80211/name");
    let name = fs::read_to_string(&path)
        .with_context(|| format!("failed to resolve PHY for {iface} via {path}"))?;
    name.trim()
        .strip_prefix("phy")
        .ok_or_else(|| anyhow::anyhow!("unexpected PHY name {:?}", name.trim()))?
        .parse()
        .with_context(|| format!("invalid PHY name {:?}", name.trim()))
}

fn nan_service_id(service_name: &str) -> [u8; 6] {
    // wpa_supplicant's NAN Discovery Engine lowercases the service name
    // before hashing it (nan_de_derive_service_id()).  Match that ABI so a
    // native/raw publisher and the working CONFIG_NAN_USD path share IDs.
    let normalized = service_name.to_ascii_lowercase();
    let digest = Sha256::digest(normalized.as_bytes());
    let mut id = [0_u8; 6];
    id.copy_from_slice(&digest[..6]);
    id
}

fn native_nan_event_loop(
    socket: Nl80211Socket,
    iface: String,
    history: Arc<Mutex<VecDeque<RadioEvent>>>,
    stop: Arc<AtomicBool>,
) {
    let _ = socket.set_receive_timeout(Duration::from_millis(250));
    while !stop.load(Ordering::Acquire) {
        let response = match socket.recv_netlink_raw() {
            Ok(response) => response,
            Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|e| matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock)) => continue,
            Err(error) => {
                push_radio_event(&history, RadioEvent {
                    ts_millis: now_millis(), key: "wifi.nan.native.error".to_string(), source: iface.clone(),
                    value: json!({"ok": false, "error": format!("{error:#}")}), message: None,
                });
                break;
            }
        };
        let Some(header) = genl_header(&response) else { continue };
        if header.cmd != 69 && header.cmd != 71 { continue; }
        let mut attrs = serde_json::Map::new();
        if let Ok(values) = genl_attrs(&response) {
            for (kind, value) in values {
                let key = format!("attr_{}", kind & NLA_TYPE_MASK);
                attrs.insert(key, json!(hex_bytes(value)));
            }
        }
        push_radio_event(&history, RadioEvent {
            ts_millis: now_millis(), key: "wifi.nan.native.event".to_string(), source: iface.clone(),
            value: json!({"ok": true, "backend": "linux_nl80211_native_nan", "command": header.cmd, "attrs": attrs}),
            message: None,
        });
    }
}

fn nan_usd_event_tx_loop(
    rx_socket: Nl80211Socket,
    iface: String,
    history: Arc<Mutex<VecDeque<RadioEvent>>>,
    stop: Arc<AtomicBool>,
    ifindex: u32,
    frame: Vec<u8>,
    service_id: [u8; 6],
    rawnan_state: Arc<Mutex<NanState>>,
    infra: bool,
) {
    // Poll frequently enough to catch the short post-beacon rendezvous.
    let _ = rx_socket.set_receive_timeout(Duration::from_millis(5));
    let tx_socket = match Nl80211Socket::open() {
        Ok(socket) => socket,
        Err(error) => {
            push_radio_event(&history, RadioEvent {
                ts_millis: now_millis(), key: "wifi.nan.usd.error".to_string(), source: iface,
                value: json!({"ok": false, "stage": "tx_socket", "error": format!("{error:#}")}), message: None,
            });
            return;
        }
    };
    let options = RawWifiTxOptions {
        variant: "nan_usd".to_string(),
        include_freq: true,
        duration_ms: Some(100),
        offchannel_tx_ok: true,
        dont_wait_for_ack: false,
        tx_no_cck_rate: true,
    };
    let mut last_slot_tsf = 0_u64;
    let mut next_infra_tx = Instant::now();
    while !stop.load(Ordering::Acquire) {
        let timing = rawnan_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .nan_sync_timing();
        if let Some((beacon_local_us, beacon_tsf_us, period_us)) = timing {
            let now_us = now_micros_u64();
            let age_us = now_us.saturating_sub(beacon_local_us);
            // NAN beacons define the rendezvous.  Permit a bounded post-beacon
            // dwell, and never emit a second frame for the same TSF slot.
            let slot = beacon_tsf_us / period_us.max(1);
            if (age_us <= 32_000 && slot != last_slot_tsf)
                || (infra && Instant::now() >= next_infra_tx)
            {
                let mut tx_frame = frame.clone();
                if let Some(cluster) = rawnan_state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .cluster()
                {
                    tx_frame[16..22].copy_from_slice(&cluster.0);
                }
                let result = tx_socket
                    .remain_on_channel(ifindex, 2437, 40)
                    .and_then(|_| tx_socket.send_frame(ifindex, 2437, &options, &tx_frame));
                push_radio_event(&history, RadioEvent {
                    ts_millis: now_millis(), key: "wifi.nan.usd.tx".to_string(), source: iface.clone(),
                    value: json!({"ok": result.is_ok(), "frame_len": frame.len(), "slot_tsf": beacon_tsf_us, "beacon_age_us": age_us, "sync": "nan", "error": result.err().map(|e| format!("{e:#}"))}), message: None,
                });
                last_slot_tsf = slot;
                if infra {
                    next_infra_tx = Instant::now() + Duration::from_millis(500);
                }
            }
        } else if infra && Instant::now() >= next_infra_tx {
            let result = tx_socket
                .remain_on_channel(ifindex, 2437, 40)
                .and_then(|_| tx_socket.send_frame(ifindex, 2437, &options, &frame));
            push_radio_event(&history, RadioEvent {
                ts_millis: now_millis(), key: "wifi.nan.usd.tx".to_string(), source: iface.clone(),
                value: json!({"ok": result.is_ok(), "frame_len": frame.len(), "sync": "infra", "error": result.err().map(|e| format!("{e:#}"))}), message: None,
            });
            next_infra_tx = Instant::now() + Duration::from_millis(500);
        }
        let response = match rx_socket.recv_netlink_raw() {
            Ok(response) => response,
            Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|e| matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock)) => continue,
            Err(error) => {
                push_radio_event(&history, RadioEvent {
                    ts_millis: now_millis(), key: "wifi.nan.usd.error".to_string(), source: iface.clone(),
                    value: json!({"ok": false, "stage": "rx", "error": format!("{error:#}")}), message: None,
                });
                break;
            }
        };
        let Some(header) = genl_header(&response) else { continue };
        if header.cmd != NL80211_CMD_FRAME { continue; }
        let frame_value = genl_attrs(&response).ok().and_then(|attrs| attrs.into_iter()
            .find(|(kind, _)| kind & NLA_TYPE_MASK == NL80211_ATTR_FRAME)
            .map(|(_, value)| value));
        if let Some(frame_value) = frame_value {
            let service_match = dmesh_rawnan::service_descriptor(&frame_value, service_id);
            push_radio_event(&history, RadioEvent {
                ts_millis: now_millis(), key: "wifi.nan.usd.rx".to_string(), source: iface.clone(),
                value: json!({"ok": true, "frame_len": frame_value.len(), "frame_hex": hex_bytes(&frame_value[..frame_value.len().min(256)]), "kind": format!("{:?}", dmesh_rawnan::classify(&frame_value))}), message: None,
            });
            if let Some(descriptor) = service_match {
                let peer = frame_value.get(dmesh_rawnan::FRAME_SRC..dmesh_rawnan::FRAME_SRC + 6)
                    .map(|bytes| hex_bytes(bytes));
                push_radio_event(&history, RadioEvent {
                    ts_millis: now_millis(), key: "wifi.nan.usd.discovery".to_string(), source: iface.clone(),
                    value: json!({"ok": true, "peer": peer, "instance_id": descriptor.instance, "requestor_instance_id": descriptor.requestor_instance, "control": descriptor.control, "peer_availability": peer_availability_name(dmesh_rawnan::peer_availability(&frame_value)), "service_id": hex_bytes(&service_id)}), message: None,
                });
            }
        }
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
    let mut packet = Vec::with_capacity(12 + frame.len());
    packet.extend_from_slice(&[
        0x00, 0x00, // radiotap version, pad
        0x0c, 0x00, // radiotap length
        0x04, 0x80, 0x00, 0x00, // present: RATE and TX_FLAGS
        0x02, // RATE: 1 Mbps, in 500 kbps units
        0x00, // pad TX_FLAGS to u16 alignment
        0x08, 0x00, // TX_FLAGS: no ACK
    ]);
    packet.extend_from_slice(frame);
    packet
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
                    if let Some((_, rate)) = rate_attributes.iter().find(|(kind, value)| {
                        *kind & NLA_TYPE_MASK == NL80211_RATE_INFO_BITRATE32 && value.len() >= 4
                    }) {
                        out.insert(
                            "tx_bitrate_kbit_s".to_string(),
                            json!(u32::from_ne_bytes([rate[0], rate[1], rate[2], rate[3]]) * 100),
                        );
                    } else if let Some((_, rate)) = rate_attributes.iter().find(|(kind, value)| {
                        *kind & NLA_TYPE_MASK == NL80211_RATE_INFO_BITRATE && value.len() >= 2
                    }) {
                        out.insert(
                            "tx_bitrate_kbit_s".to_string(),
                            json!(u16::from_ne_bytes([rate[0], rate[1]]) as u32 * 100),
                        );
                    }
                }
            }
            NL80211_STA_INFO_RX_BITRATE => {
                if let Ok(rate_attributes) = parse_attrs(value) {
                    if let Some((_, rate)) = rate_attributes.iter().find(|(kind, value)| {
                        *kind & NLA_TYPE_MASK == NL80211_RATE_INFO_BITRATE32 && value.len() >= 4
                    }) {
                        out.insert(
                            "rx_bitrate_kbit_s".to_string(),
                            json!(u32::from_ne_bytes([rate[0], rate[1], rate[2], rate[3]]) * 100),
                        );
                    } else if let Some((_, rate)) = rate_attributes.iter().find(|(kind, value)| {
                        *kind & NLA_TYPE_MASK == NL80211_RATE_INFO_BITRATE && value.len() >= 2
                    }) {
                        out.insert(
                            "rx_bitrate_kbit_s".to_string(),
                            json!(u16::from_ne_bytes([rate[0], rate[1]]) as u32 * 100),
                        );
                    }
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
            _ => {}
        }
    }
    Ok(Value::Object(out))
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

fn ap_mgmt_receive_loop(
    socket: Nl80211Socket,
    iface: &str,
    ifindex: u32,
    ap_mac: [u8; 6],
    history: Arc<Mutex<VecDeque<RadioEvent>>>,
    rawnan_state: Arc<Mutex<NanState>>,
    stop: Arc<AtomicBool>,
) {
    let _ = socket.set_receive_timeout(Duration::from_millis(100));
    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }
        match socket.recv_frame_with_signal() {
            Ok((frame, rx_signal_dbm)) => {
                let mut value = parse_management_frame(&frame, iface, "linux_nl80211_ap_sme");
                if frame_subtype(&frame) == 8
                    && let Some(beacon) = handle_beacon_frame(&frame, iface, rx_signal_dbm, &rawnan_state)
                    && let Some(object) = value.as_object_mut()
                {
                    object.insert("beacon_sync".to_string(), beacon);
                }
                if frame_subtype(&frame) == 13
                    && let Some(action) = handle_action_frame(&frame, iface, rx_signal_dbm, &rawnan_state)
                    && let Some(object) = value.as_object_mut()
                {
                    object.insert("action_frame".to_string(), action);
                }
                if let Some(response) = handle_open_ap_sme_frame(ifindex, ap_mac, &frame)
                    && let Some(object) = value.as_object_mut()
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
                            key: "wifi.nan.beacon".to_string(),
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
            rssi_dbm: rx_signal_dbm.unwrap_or(0).clamp(i8::MIN as i32, i8::MAX as i32) as i8,
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

fn handle_open_ap_sme_frame(ifindex: u32, ap_mac: [u8; 6], frame: &[u8]) -> Option<Value> {
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
            let tx = send_open_ap_mgmt_response(ifindex, &response);
            json!({
                "kind": "auth_resp",
                "destination": colon_mac(&sta_mac),
                "frame_len": response.len(),
                "tx": tx,
            })
        }
        0 | 2 => {
            let aid = 1_u16;
            let allow_ht = !ap_no_ht_stations().contains(&sta_mac);
            let add_station = Nl80211Socket::open()
                .and_then(|socket| socket.add_station_from_assoc(ifindex, sta_mac, frame, allow_ht))
                .map(|_| json!({ "ok": true }))
                .unwrap_or_else(|error| json!({ "ok": false, "error": format!("{error:#}") }));
            let response = build_open_assoc_response(ap_mac, sta_mac, aid, allow_ht);
            let tx = send_open_ap_mgmt_response(ifindex, &response);
            json!({
                "kind": "assoc_resp",
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

fn send_open_ap_mgmt_response(ifindex: u32, frame: &[u8]) -> Value {
    Nl80211Socket::open()
        .and_then(|socket| socket.send_mgmt_frame(ifindex, frame))
        .map(|_| json!({ "ok": true, "backend": "linux_nl80211" }))
        .unwrap_or_else(|error| {
            json!({
                "ok": false,
                "backend": "linux_nl80211",
                "error": format!("{error:#}"),
            })
        })
}

fn monitor_receive_loop(
    socket: MonitorRxSocket,
    iface: &str,
    monitor_iface: &str,
    history: Arc<Mutex<VecDeque<RadioEvent>>>,
    rawnan_state: Arc<Mutex<NanState>>,
) {
    let receive_addresses = raw_wifi_receive_addresses(iface);
    let mut buf = [0_u8; 4096];
    loop {
        match socket.recv(&mut buf) {
            Ok(0) => continue,
            Ok(len) => {
                let packet = &buf[..len];
                if let Some(frame) = ieee80211_frame(packet) {
                    if frame_subtype(frame) == 8 && dmesh_rawnan::is_nan_beacon(frame) {
                        if let Some(beacon) = handle_beacon_frame(
                            frame,
                            iface,
                            None,
                            &rawnan_state,
                        ) {
                            push_radio_event(
                                &history,
                                RadioEvent {
                                    ts_millis: now_millis(),
                                    key: "wifi.nan.beacon".to_string(),
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
                    // Same-cluster synchronized SDFs are valid even when the
                    // filter action is None. Preserve a semantic discovery
                    // event so host-only tests can attribute wlan1 replies.
                    if frame_subtype(frame) == 13
                        && let Some(descriptor) = dmesh_rawnan::service_descriptor(
                            frame,
                            dmesh_rawnan::DMESH_SERVICE_ID,
                        )
                    {
                        push_radio_event(
                            &history,
                            RadioEvent {
                                ts_millis: now_millis(),
                                key: "wifi.nan.usd.discovery".to_string(),
                                source: monitor_iface.to_string(),
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
                                    "peer_availability": peer_availability_name(dmesh_rawnan::peer_availability(frame)),
                                    "service_id": hex_bytes(&dmesh_rawnan::DMESH_SERVICE_ID),
                                }),
                                message: None,
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
            rssi_dbm: rx_signal_dbm.unwrap_or(0).clamp(i8::MIN as i32, i8::MAX as i32) as i8,
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
    if frame.len() <= IEEE80211_BODY + DMESH_LEGACY_VENDOR_ACTION.len() {
        return None;
    }
    let mut body = &frame[IEEE80211_BODY..];
    let encapsulation = if body.starts_with(&IEEE80211_LLC_SNAP_IPV6) {
        return parse_nan_ipv6_udp_frame(frame, iface, backend);
    } else if body.starts_with(&IEEE80211_LLC_SNAP_DMESH) {
        body = &body[IEEE80211_LLC_SNAP_LEN..];
        "llc_snap"
    } else {
        if body.len() < IEEE80211_LLC_SNAP_LEN {
            return None;
        }
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
        && body[8] == DMESH_ESPNOW_TYPE
    {
        return Some(DmeshWifiHeader {
            header_len: DMESH_VENDOR_ACTION_LEN,
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
    frame.extend_from_slice(&0x0421_u16.to_le_bytes());
    frame.extend_from_slice(&esp_open_ap_probe_ies(ssid, channel)?);
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

fn build_open_assoc_response(ap: [u8; 6], sta: [u8; 6], aid: u16, allow_ht: bool) -> Vec<u8> {
    let mut frame = mgmt_frame_header(0x01, sta, ap, ap);
    frame.extend_from_slice(&0x0401_u16.to_le_bytes());
    frame.extend_from_slice(&0_u16.to_le_bytes());
    frame.extend_from_slice(&(0xc000 | (aid & 0x3fff)).to_le_bytes());
    frame.push(0x01);
    frame.push(4);
    frame.extend_from_slice(&[0x82, 0x84, 0x8b, 0x96]);
    frame.push(0x32);
    frame.push(4);
    frame.extend_from_slice(&[0x0c, 0x12, 0x18, 0x24]);
    // Match the HT20 capability advertised in the beacon. Without an HT
    // Capabilities element in the association response, a station can
    // associate successfully but remain on legacy rates.
    if allow_ht {
        frame.extend_from_slice(&hostapd_open_ap_ht_capability());
        frame.extend_from_slice(&hostapd_open_ap_ht_operation(DEFAULT_RAW_WIFI_CHANNEL));
    }
    frame.extend_from_slice(&hostapd_open_ap_extra_ies());
    // The beacon/probe templates advertise WMM, so the manually generated
    // association response must carry the matching WMM Parameter element too.
    // Without it, Linux reports WMM/WME=no for the station even though the AP
    // beacon contains the element; that disables the normal Wi-Fi QoS/Block
    // ACK path and is especially costly for the direct TCP flash link.
    frame.extend_from_slice(&wmm_parameter_ie());
    frame
}

fn hostapd_open_ap_ht_operation(channel: u8) -> [u8; 24] {
    [
        0x3d, 22, channel, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
}

fn hostapd_open_ap_ht_capability() -> [u8; 28] {
    [
        0x2d, 26, 0x0c, 0x00, 0x1b, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
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
    ies.push(8);
    ies.extend_from_slice(&[0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]);
    ies.push(0x03);
    ies.push(1);
    ies.push(channel);
    Ok(ies)
}

fn esp_open_ap_beacon_tail() -> Vec<u8> {
    let mut ies = Vec::with_capacity(92);
    ies.push(0x2a);
    ies.push(1);
    ies.push(0x00);
    ies.push(0x32);
    ies.push(4);
    ies.extend_from_slice(&[0x6c, 0x12, 0x24, 0x48]);
    ies.push(0x2d);
    ies.push(26);
    ies.extend_from_slice(&[
        0x6e, 0x11, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    ies.push(0x3d);
    ies.push(22);
    ies.extend_from_slice(&[
        DEFAULT_RAW_WIFI_CHANNEL,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
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

fn hostapd_open_ap_beacon_tail(channel: u8) -> Vec<u8> {
    let mut ies = Vec::with_capacity(101);
    ies.push(0x2a);
    ies.push(1);
    ies.push(0x04);
    ies.push(0x32);
    ies.push(4);
    ies.extend_from_slice(&[0x30, 0x48, 0x60, 0x6c]);
    ies.push(0x3b);
    ies.push(2);
    ies.extend_from_slice(&[0x51, 0x00]);
    ies.push(0x2d);
    ies.push(26);
    ies.extend_from_slice(&[
        0x0c, 0x00, 0x1b, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    ies.push(0x3d);
    ies.push(22);
    ies.extend_from_slice(&[
        channel, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    ies.extend_from_slice(&hostapd_open_ap_extra_ies());
    ies.push(0xdd);
    ies.push(24);
    ies.extend_from_slice(&[
        0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x01, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4, 0x00,
        0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00,
    ]);
    ies
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
    ies.extend_from_slice(&esp_open_ap_beacon_tail());
    Ok(ies)
}

fn open_ap_template_lengths(ssid: &str) -> Result<(usize, usize)> {
    let channel = DEFAULT_RAW_WIFI_CHANNEL;
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
) -> Vec<u8> {
    build_dmesh_vendor_action_frame_with_bssid(destination, source, destination, payload)
}

fn build_dmesh_vendor_action_frame_with_bssid(
    destination: [u8; 6],
    source: [u8; 6],
    bssid: [u8; 6],
    payload: &[u8],
) -> Vec<u8> {
    let body_len = payload.len().min(1400);
    let mut frame = Vec::with_capacity(IEEE80211_BODY + DMESH_VENDOR_ACTION_LEN + body_len);
    frame.extend_from_slice(&[0xd0, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&dmesh_vendor_action_header(destination));
    frame.extend_from_slice(&payload[..body_len]);
    frame
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
    let ip_payload = build_nan_ipv6_udp(source, destination, payload);
    let mut frame = Vec::with_capacity(IEEE80211_BODY + IEEE80211_LLC_SNAP_LEN + ip_payload.len());
    frame.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&IEEE80211_LLC_SNAP_IPV6);
    frame.extend_from_slice(&ip_payload);
    frame
}

fn build_dmesh_nan_raw_data_frame(
    bssid: [u8; 6],
    destination: [u8; 6],
    source: [u8; 6],
    llc: &[u8; IEEE80211_LLC_SNAP_LEN],
    payload: &[u8],
) -> Vec<u8> {
    let body_len = payload.len().min(1400);
    let mut frame = Vec::with_capacity(IEEE80211_BODY + llc.len() + body_len);
    frame.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(llc);
    frame.extend_from_slice(&payload[..body_len]);
    frame
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
    let mut i = 0;
    while i + 1 < bytes.len() {
        *sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
        i += 2;
    }
    if i < bytes.len() {
        *sum += (bytes[i] as u32) << 8;
    }
}

fn checksum_finalize(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_nan_ipv6_udp(source: [u8; 6], destination: [u8; 6], payload: &[u8]) -> Vec<u8> {
    let body_len = payload.len().min(1200);
    let udp_len = 8 + body_len;
    let mut out = vec![0u8; 40 + udp_len];
    out[0] = 0x60;
    out[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    out[6] = 17; // UDP
    out[7] = 1; // hop limit
    let src = nan_link_local(source);
    let dst = nan_link_local(destination);
    out[8..24].copy_from_slice(&src);
    out[24..40].copy_from_slice(&dst);
    out[40..42].copy_from_slice(&NAN_UDP_SOURCE_PORT.to_be_bytes());
    out[42..44].copy_from_slice(&NAN_UDP_DEST_PORT.to_be_bytes());
    out[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
    out[48..48 + body_len].copy_from_slice(&payload[..body_len]);
    let mut sum = 0u32;
    checksum_add(&mut sum, &src);
    checksum_add(&mut sum, &dst);
    checksum_add(&mut sum, &(udp_len as u32).to_be_bytes());
    checksum_add(&mut sum, &[0, 0, 0, 17]);
    checksum_add(&mut sum, &out[40..48 + body_len]);
    out[46..48].copy_from_slice(&checksum_finalize(sum).to_be_bytes());
    out
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
    let mut header = [0_u8; DMESH_VENDOR_ACTION_LEN];
    header[..DMESH_ESPNOW_PREFIX.len()].copy_from_slice(&DMESH_ESPNOW_PREFIX);
    let _ = destination;
    header[4..8].copy_from_slice(&DMESH_MESH_DST4_BROADCAST);
    header[8] = DMESH_ESPNOW_TYPE;
    header
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
    let mut history = history
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    history.push_back(event);
    while history.len() > MAX_HISTORY {
        history.pop_front();
    }
    drop(history);
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

fn adv_data(service_data: &[u8]) -> Result<Vec<u8>> {
    let field_len = 1 + service_data.len();
    if field_len > 0x1f {
        bail!("BLE advertisement service data too large: {}", field_len);
    }
    let mut adv = Vec::with_capacity(32);
    adv.push(field_len as u8);
    adv.push(0x16);
    adv.extend_from_slice(service_data);
    let mut out = Vec::with_capacity(32);
    out.push(adv.len() as u8);
    out.extend_from_slice(&adv);
    out.resize(32, 0);
    Ok(out)
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
        return Err(format!("failed to open rtnetlink socket: {}", std::io::Error::last_os_error()));
    }

    let result = unsafe { send_setaddr(fd, ifindex, address, prefix) };
    unsafe { libc::close(fd); }
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
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix)) };
    append_rt_attr(&mut request, IFA_BROADCAST, &((ip & mask) | !mask).to_be_bytes());
    let message_len = request.len() as u32;
    let header_ptr = request.as_mut_ptr() as *mut NlMsgHdr;
    unsafe { (*header_ptr).nlmsg_len = message_len; }

    let written = unsafe {
        libc::send(fd, request.as_ptr() as *const libc::c_void, request.len(), 0)
    };
    if written < 0 {
        return Err(format!("failed to send RTM_NEWADDR: {}", std::io::Error::last_os_error()));
    }
    if written as usize != request.len() {
        return Err(format!("short RTM_NEWADDR write: wrote {written}, expected {}", request.len()));
    }
    let mut response = [0u8; 4096];
    let read = unsafe {
        libc::recv(fd, response.as_mut_ptr() as *mut libc::c_void, response.len(), 0)
    };
    if read < 0 {
        return Err(format!("failed to read RTM_NEWADDR ACK: {}", std::io::Error::last_os_error()));
    }
    parse_netlink_ack(&response[..read as usize])
}

fn append_rt_attr(out: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let raw_len = std::mem::size_of::<RtAttrHdr>() + payload.len();
    let aligned_len = (raw_len + 3) & !3;
    let header = RtAttrHdr { rta_len: raw_len as u16, rta_type: attr_type };
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

fn wpa_command(
    iface: &str,
    ctrl_dir: &str,
    command: &str,
) -> std::result::Result<CommandOutput, String> {
    wpa_ctrl_command(iface, ctrl_dir, command)
}

fn wpa_raw_command(
    iface: &str,
    ctrl_dir: &str,
    command: &str,
) -> std::result::Result<CommandOutput, String> {
    wpa_ctrl_command(iface, ctrl_dir, command)
}

fn wpa_ctrl_command(
    iface: &str,
    ctrl_dir: &str,
    command: &str,
) -> std::result::Result<CommandOutput, String> {
    let server_path = format!("{ctrl_dir}/{iface}");
    wpa_ctrl_command_path(&server_path, command)
}

fn wpa_global_command(
    global_dir: &str,
    command: &str,
) -> std::result::Result<CommandOutput, String> {
    let server_path = format!("{global_dir}/global");
    wpa_ctrl_command_path(&server_path, command)
}

fn wpa_ctrl_command_path(
    server_path: &str,
    command: &str,
) -> std::result::Result<CommandOutput, String> {
    let client_path = format!(
        "/tmp/lmesh-wpa-{}-{}-{}.sock",
        unsafe { libc::getuid() },
        std::process::id(),
        now_millis()
    );
    let socket = UnixDatagram::bind(&client_path)
        .map_err(|error| format!("failed to bind WPA client socket {client_path}: {error}"))?;
    let _unlink_client = UnlinkOnDrop(client_path.clone());
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("failed to set WPA read timeout: {error}"))?;
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("failed to set WPA write timeout: {error}"))?;
    socket
        .connect(&server_path)
        .map_err(|error| format!("failed to connect WPA control socket {server_path}: {error}"))?;
    socket
        .send(command.as_bytes())
        .map_err(|error| format!("failed to send WPA command {command:?}: {error}"))?;
    let mut response = vec![0_u8; 8192];
    let len = socket
        .recv(&mut response)
        .map_err(|error| format!("failed to receive WPA response for {command:?}: {error}"))?;
    response.truncate(len);
    let stdout = String::from_utf8_lossy(&response).trim().to_string();
    let ok = !(stdout.starts_with("FAIL") || stdout.starts_with("UNKNOWN COMMAND"));
    Ok(CommandOutput {
        status: Some(if ok { 0 } else { 1 }),
        stdout,
        stderr: String::new(),
    })
}

fn wpa_ctrl_events(
    server_path: &str,
    wait_ms: u64,
    max_events: usize,
) -> std::result::Result<Vec<Value>, String> {
    let client_path = format!(
        "/tmp/lmesh-wpa-events-{}-{}-{}.sock",
        unsafe { libc::getuid() },
        std::process::id(),
        now_millis()
    );
    let socket = UnixDatagram::bind(&client_path)
        .map_err(|error| format!("failed to bind WPA event socket {client_path}: {error}"))?;
    let _unlink_client = UnlinkOnDrop(client_path.clone());
    socket
        .set_read_timeout(Some(Duration::from_millis(wait_ms.max(1))))
        .map_err(|error| format!("failed to set WPA event read timeout: {error}"))?;
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("failed to set WPA event write timeout: {error}"))?;
    socket
        .connect(server_path)
        .map_err(|error| format!("failed to connect WPA control socket {server_path}: {error}"))?;
    socket
        .send(b"ATTACH")
        .map_err(|error| format!("failed to ATTACH WPA event socket: {error}"))?;
    let mut buf = vec![0_u8; 8192];
    let _ = socket.recv(&mut buf);
    let deadline = std::time::Instant::now() + Duration::from_millis(wait_ms.max(1));
    let mut events = Vec::new();
    while events.len() < max_events && std::time::Instant::now() < deadline {
        match socket.recv(&mut buf) {
            Ok(len) => {
                let line = String::from_utf8_lossy(&buf[..len]).trim().to_string();
                if let Some(event) = parse_wpa_event_line(&line) {
                    events.push(event);
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(error) => return Err(format!("failed to read WPA event: {error}")),
        }
    }
    let _ = socket.send(b"DETACH");
    Ok(events)
}

fn parse_wpa_event_line(line: &str) -> Option<Value> {
    let line = line.strip_prefix("<3>").unwrap_or(line);
    let line = line.strip_prefix("<2>").unwrap_or(line);
    let line = line.strip_prefix("<1>").unwrap_or(line);
    if !line.starts_with("NAN-") {
        return None;
    }
    let mut parts = line.split_whitespace();
    let event = parts.next()?.trim_end_matches(':').to_string();
    let mut fields = serde_json::Map::new();
    for part in parts {
        if let Some((key, value)) = part.split_once('=') {
            fields.insert(key.to_string(), text_json_value(value));
            if key == "ssi"
                && let Ok(bytes) = parse_hex_bytes(value)
            {
                fields.insert("ssi_len".to_string(), json!(bytes.len()));
                if let Ok(parsed) = radio_protocol::parse_nan_service_info(&bytes) {
                    fields.insert("ssi_dmesh".to_string(), parsed);
                } else if let Ok(parsed) = radio_protocol::parse_nan_followup(&bytes) {
                    fields.insert("ssi_dmesh".to_string(), parsed);
                }
            }
        }
    }
    Some(json!({
        "event": event,
        "raw": line,
        "fields": fields,
    }))
}

fn nan_event_message(event: &Value) -> Option<MeshMessage> {
    let name = event.get("event").and_then(Value::as_str)?;
    let fields = event.get("fields").and_then(Value::as_object);
    let mut message = MeshMessage::new(mesh::message::KIND_NAN_FOLLOWUP, MeshMessageCodec::WpaText)
        .field(FIELD_MEDIUM, "nan")
        .field(FIELD_STATUS, name);
    if let Some(fields) = fields {
        if let Some(address) = fields.get("address").and_then(Value::as_str) {
            message = message.field(mesh::message::FIELD_PEER, address);
        }
        if let Some(ssi) = fields.get("ssi_dmesh") {
            if let Some(device_id) = ssi.get("device_id").and_then(Value::as_str) {
                message = message.field(FIELD_NODE, device_id);
            }
            if let Some(payload) = ssi.get("payload_text").and_then(Value::as_str) {
                message = message.field(FIELD_PAYLOAD, payload);
            }
        }
    }
    Some(message)
}

fn text_json_value(value: &str) -> Value {
    if value.eq_ignore_ascii_case("true") {
        return Value::Bool(true);
    }
    if value.eq_ignore_ascii_case("false") {
        return Value::Bool(false);
    }
    if let Ok(number) = value.parse::<i64>() {
        return json!(number);
    }
    if let Ok(number) = value.parse::<f64>() {
        return json!(number);
    }
    Value::String(value.to_string())
}

struct UnlinkOnDrop(String);

impl Drop for UnlinkOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
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

fn wpa_ctrl_dir(value: Option<String>) -> String {
    value
        .or_else(|| std::env::var("LMESH_WPA_CTRL_DIR").ok())
        .unwrap_or_else(|| DEFAULT_WPA_CTRL_DIR.to_string())
}

fn raw_wifi_channel(value: Option<u8>) -> u8 {
    value.unwrap_or(DEFAULT_RAW_WIFI_CHANNEL).clamp(1, 13)
}

fn prepare_raw_wifi_channel(iface: &str, ctrl_dir: &str, channel: u8, listen_sec: u64) -> Value {
    let set_channel = wpa_raw_command(
        iface,
        ctrl_dir,
        &format!("P2P_SET listen_channel {channel}"),
    );
    let disallow_freq = wpa_raw_command(iface, ctrl_dir, "P2P_SET disallow_freq ");
    let listen = wpa_raw_command(iface, ctrl_dir, &format!("P2P_LISTEN {listen_sec}"));
    json!({
        "set_channel": command_result_json(set_channel),
        "disallow_freq": command_result_json(disallow_freq),
        "listen": command_result_json(listen),
    })
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

fn hci_probe(dev_id: u16) -> Value {
    match HciSocket::open(dev_id) {
        Ok(_) => json!({ "ok": true, "dev_id": dev_id, "backend": "linux_hci_raw" }),
        Err(error) => json!({ "ok": false, "dev_id": dev_id, "error": error.to_string() }),
    }
}

fn result_string_json(output: std::result::Result<String, String>) -> Value {
    match output {
        Ok(value) => json!({ "ok": true, "value": value }),
        Err(error) => json!({ "ok": false, "error": error }),
    }
}

fn hci_dev_up(dev_id: u16) -> Result<String> {
    let fd = unsafe {
        libc::socket(
            AF_BLUETOOTH,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            BTPROTO_HCI,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to open HCI control socket");
    }
    let rc = unsafe { libc::ioctl(fd, HCIDEVUP as libc::Ioctl, dev_id as libc::c_int) };
    let result = if rc < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EALREADY) {
            Ok("already_up".to_string())
        } else {
            Err(error).with_context(|| format!("failed to bring hci{dev_id} up"))
        }
    } else {
        Ok("brought_up".to_string())
    };
    unsafe {
        libc::close(fd);
    }
    result
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

fn peer_availability_name(availability: dmesh_rawnan::PeerAvailability) -> &'static str {
    match availability {
        dmesh_rawnan::PeerAvailability::Infra => "infra",
        dmesh_rawnan::PeerAvailability::Dw0Dw8 => "dw0_dw8",
    }
}

fn parse_hex_bytes(value: &str) -> Result<Vec<u8>> {
    let value = value.trim();
    if value.len() % 2 != 0 {
        bail!("hex byte string must have even length");
    }
    (0..value.len())
        .step_by(2)
        .map(|idx| {
            u8::from_str_radix(&value[idx..idx + 2], 16)
                .with_context(|| format!("invalid hex byte at offset {idx}"))
        })
        .collect()
}

fn parse_size_list(value: Option<&str>) -> Option<Vec<usize>> {
    let value = value?;
    let sizes = value
        .split(',')
        .filter_map(|part| part.trim().parse::<usize>().ok())
        .collect::<Vec<_>>();
    (!sizes.is_empty()).then_some(sizes)
}

fn colon_mac(bytes: &[u8; 6]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn mac_string_reversed(bytes: &[u8]) -> String {
    bytes
        .iter()
        .rev()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
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
    fn wifi_only_backend_does_not_enable_uart_ownership() {
        assert!(!RadioService::from_environment_without_uart().uart_enabled());
    }
    use std::io::{Error, ErrorKind};

    #[test]
    fn host_nan_ping_uses_firmware_cbor_envelope() {
        assert_eq!(
            firmware_mode_ping_cbor().unwrap(),
            vec![
                0xa2, 0x00, 0x18, 49, 0x06, 0xa1, 0x18, 190, 0x64, b't', b'r', b'u', b'e'
            ]
        );
    }

    #[test]
    fn firmware_pong_is_distinguished_from_command_ack() {
        assert!(is_firmware_pong("a20018210464706f6e67"));
        assert!(!is_firmware_pong("a300183104677061727469616c"));
    }

    #[test]
    fn unsolicited_mode_records_do_not_satisfy_other_commands() {
        assert!(is_unsolicited_console_record(
            "status",
            "mode active=sleepy infra_active=true\n"
        ));
        assert!(is_unsolicited_console_record(
            "status",
            "event type=boot.state rebooted=true\n"
        ));
        assert!(!is_unsolicited_console_record(
            "mode status=true",
            "mode active=sleepy infra_active=true\n"
        ));
        assert!(!is_unsolicited_console_record(
            "active ms=60000",
            "mode active=infra infra_active=true\n"
        ));
        assert!(!is_unsolicited_console_record(
            "idle",
            "mode active=infra infra_active=false\n"
        ));
        assert!(is_unsolicited_console_record(
            "active ms=60000",
            "event type=mode.state active=infra infra_active=true\n"
        ));
        assert!(!is_unsolicited_console_record(
            "status",
            "status uptime_ms=42\n"
        ));
    }

    #[test]
    fn serial_debug_command_is_framed_cbor_before_uart() {
        let frame = firmware_command_cbor("mode active=true").unwrap();
        let payload = mesh::cbor::decode_stream_frame(&frame).unwrap();
        assert_eq!(
            payload,
            [
                0xa2, 0x00, 0x64, b'm', b'o', b'd', b'e', 0x06, 0xa1, 0x66, b'a', b'c', b't', b'i',
                b'v', b'e', 0x64, b't', b'r', b'u', b'e'
            ]
        );
        assert_eq!(
            u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize,
            frame.len() - 4
        );
    }

    #[test]
    fn stage2_boot_command_is_cbor_payload_inside_ppp() {
        let command = boot_command_payload("recovery").unwrap();
        assert_eq!(
            command,
            vec![0xa2, 0x00, 0x1a, 0x00, 0x00, 0xea, 0x6a, 0x06, 0x81, 0x02]
        );

        let stream = WouldBlockOnceWriter {
            writes: 0,
            bytes: Vec::new(),
        };
        let mut client =
            SerialForwardClient::new(1, Box::new(stream), SerialForwardTcpMode::Framed);
        let mut serial_tx = VecDeque::new();
        let mut serial_pending = VecDeque::new();
        client
            .input
            .extend_from_slice(&mesh::cbor::encode_stream_frame(&command).unwrap());
        client
            .flush_complete_records(
                -1,
                &mut serial_tx,
                &mut serial_pending,
                true,
                None,
                "test",
                false,
            )
            .unwrap();
        let wire = serial_tx.into_iter().collect::<Vec<_>>();
        let mut decoder = FirmwareUartDecoder::default();
        let records = decoder.push(&wire).unwrap();
        assert_eq!(
            records,
            vec![mesh::cbor::encode_stream_frame(&command).unwrap()]
        );
        assert_eq!(
            boot_identity_json(&[
                b'D', b'M', b'B', b'1', 1, 1, 3, 0, 7, 4, 0, 9, 0, 1, 2, 3, 4, 5
            ])["partition"],
            0
        );
        assert_eq!(
            boot_identity_json(&[
                b'D', b'M', b'B', b'1', 1, 1, 3, 0, 7, 4, 0, 9, 0, 1, 2, 3, 4, 5
            ])["role_name"],
            "stage2"
        );
        assert_eq!(
            boot_identity_json(&[
                b'D', b'M', b'B', b'1', 1, 1, 3, 0, 7, 4, 0, 9, 0, 1, 2, 3, 4, 5
            ])["partition_name"],
            "bootloader"
        );
    }

    #[test]
    fn recovery_sta_command_is_typed_and_ppp_framed() {
        let wire = encode_recovery_sta_packet(
            "STA 10.78.0.1:3336 10.78.84.60 Direct-FCE48415-Dmesh-local",
        )
        .unwrap();
        let packet = wire;
        assert_eq!(&packet[..6], &[0xa2, 0x00, 0x18, 68, 0x06, 0xa4]);
        assert!(packet.windows(6).any(|window| window == b"server"));
        assert!(packet.windows(2).any(|window| window == [0x6e, b'1']));
    }

    #[test]
    fn recovery_sta_dry_run_is_a_typed_boolean_field() {
        let wire = encode_recovery_sta_packet(
            "STA 10.78.0.1:3336 10.78.84.60 Direct-FCE48415-Dmesh-local dryrun",
        )
        .unwrap();
        let packet = wire;
        assert!(packet.windows(8).any(|window| window == b"dry_run\xF5"));
    }

    #[test]
    fn stage2_identity_reassembles_across_forward_records() {
        let identity = [
            b'D', b'M', b'B', b'1', 1, 1, 3, 0, 7, 4, 0, 9, 0, 1, 2, 3, 4, 5,
        ];
        let mut bytes = Vec::new();
        for part in identity.chunks(5) {
            bytes.extend_from_slice(part);
            if bytes.len() < identity.len() {
                assert_eq!(find_stage2_identity(&bytes), None);
            }
        }
        assert_eq!(find_stage2_identity(&bytes), Some(identity.to_vec()));
    }

    #[test]
    fn indefinite_cbor_boot_identity_is_not_logged_as_cbor_error() {
        let payload = [
            0xbf, 0x07, 0x19, 0xea, 0x60, 0x06, 0x9f, 0x03, 0x00, 0x01, 0x18, 0xf2, 0x00, 0x00,
            0x00, 0x00, 0x46, 0x84, 0x0d, 0x8e, 0x07, 0x42, 0xc4, 0xff, 0xff,
        ];
        assert_eq!(payload[0] >> 5, 5);
        assert!(is_boot_identity_payload(&payload));
        assert_eq!(boot_identity_json(&payload)["event_id"], 60000);
    }

    #[test]
    fn recovery_network_event_decodes_negative_rssi_tuple() {
        let payload = [
            0xbf, 0x07, 0x19, 0xea, 0x63, 0x06, 0x9f, 0x02, 0x4c, b'1', b'0', b'.', b'7', b'8',
            b'.', b'6', b'6', b'.', b'1', b'9', b'6', 0x46, 0x44, 0x94, 0xfc, 0xe4, 0x84, 0x15,
            0x38, 0x2d, 0xff, 0xff,
        ];
        assert!(is_boot_event_payload(&payload));
        let event = boot_event_json(&payload);
        assert_eq!(event["event_id"], 60003);
        assert_eq!(event["tuple"][0], 2);
        assert_eq!(event["tuple"][3], -46);
    }

    #[test]
    fn sleepy_active_window_uses_explicit_reachability() {
        fn event(text: &str) -> Vec<u8> {
            let mut payload = Vec::new();
            let mut encoder = Encoder::new(&mut payload);
            encoder
                .map(3)
                .unwrap()
                .u16(0)
                .unwrap()
                .u16(33)
                .unwrap()
                .u16(4)
                .unwrap()
                .str("event")
                .unwrap()
                .u16(6)
                .unwrap()
                .map(1)
                .unwrap()
                .u16(32)
                .unwrap()
                .str(text)
                .unwrap();
            mesh::cbor::encode_stream_frame(&payload).unwrap()
        }
        let active =
            event("event type=mode.state active=sleepy infra_active=true phase=active_window");
        let sleeping =
            event("event type=mode.state active=sleepy infra_active=false phase=enter_sleep");
        assert_eq!(firmware_record_direct_mode(&active), Some(true));
        assert_eq!(firmware_record_direct_mode(&sleeping), Some(false));
    }

    #[test]
    fn sleepy_start_does_not_bypass_active_window_queue() {
        let mut payload = Vec::new();
        let mut encoder = Encoder::new(&mut payload);
        encoder
            .tag(minicbor::data::Tag::new(6))
            .unwrap()
            .map(0)
            .unwrap();
        let record = mesh::cbor::encode_stream_frame(&payload).unwrap();
        assert_eq!(firmware_record_direct_mode(&record), None);
    }

    #[test]
    fn lifecycle_state_tracks_recovery_hello_and_sleep_transition() {
        let state = Arc::new(Mutex::new(FirmwareState::default()));
        update_firmware_state_from_boot(
            &state,
            &[
                b'D', b'M', b'B', b'1', 1, 1, 2, 2, 7, 0, 0, 1, 0, 1, 2, 3, 4, 5,
            ],
        );
        update_firmware_state_from_text(
            &state,
            "event type=mode.state active=sleepy infra_active=false phase=enter_sleep",
        );
        let snapshot = state.lock().unwrap().snapshot();
        assert_eq!(snapshot["role"], "recovery");
        assert_eq!(snapshot["partition"], "recovery");
        assert_eq!(snapshot["phase"], "enter_sleep");
        assert_eq!(snapshot["infra_active"], false);
    }

    #[test]
    fn firmware_uart_codec_round_trips_escaped_cbor() {
        let frame = firmware_command_cbor("mode active=true").unwrap();
        let wire = encode_firmware_uart_frame(&frame).unwrap();
        assert_eq!(wire.first(), Some(&FIRMWARE_UART_FLAG));
        assert_eq!(wire.last(), Some(&FIRMWARE_UART_FLAG));

        let mut decoder = FirmwareUartDecoder::default();
        let split = wire.len() / 2;
        assert!(decoder.push(&wire[..split]).unwrap().is_empty());
        assert_eq!(decoder.push(&wire[split..]).unwrap(), vec![frame]);

        let escaped =
            mesh::cbor::encode_stream_frame(&[FIRMWARE_UART_FLAG, FIRMWARE_UART_ESCAPE]).unwrap();
        let escaped_wire = encode_firmware_uart_frame(&escaped).unwrap();
        let mut decoder = FirmwareUartDecoder::default();
        assert_eq!(decoder.push(&escaped_wire).unwrap(), vec![escaped]);
    }

    #[test]
    fn firmware_uart_decoder_resynchronizes_after_oversize_record() {
        let frame = firmware_command_cbor("status").unwrap();
        let valid = encode_firmware_uart_frame(&frame).unwrap();
        let mut noisy = vec![FIRMWARE_UART_FLAG];
        noisy.extend(std::iter::repeat_n(0_u8, mesh::cbor::ESP_RECORD_MAX + 1));
        noisy.push(FIRMWARE_UART_FLAG);
        noisy.extend(valid);

        let mut decoder = FirmwareUartDecoder::default();
        assert_eq!(decoder.push(&noisy).unwrap(), vec![frame]);
    }

    #[test]
    fn empty_uart_frame_is_ignored_not_a_wake_event() {
        let mut decoder = FirmwareUartDecoder::default();
        assert!(
            decoder
                .push(&[FIRMWARE_UART_FLAG, FIRMWARE_UART_FLAG])
                .unwrap()
                .is_empty()
        );
        assert!(!decoder.take_frame_activity());
        assert!(!decoder.take_frame_activity());
    }

    #[test]
    fn tagged_nan_sleepy_start_is_a_wake_event() {
        let payload = [0xc6, 0xa0];
        let record = mesh::cbor::encode_stream_frame(&payload).unwrap();
        let event = nan_sleepy_start_event(&payload).expect("tagged wake event");
        assert_eq!(event.flags, 0);
        assert_eq!(event.lora_rx_delta, 0);
        assert_eq!(event.nan_beacon_delta, 0);
        assert!(!event.cluster_changed);
        assert_eq!(
            firmware_record_text(&record).as_deref(),
            Some(
                "event type=nan.sleepy_start flags=0 lora_rx_delta=0 nan_beacon_delta=0 cluster_changed=false",
            )
        );
    }

    #[test]
    fn serial_log_path_resolves_from_symlink_target_directory() {
        // `radio.rs` is also compiled into the service crates while the
        // extraction is in progress.  Resolve the example from either the
        // owning lmesh crate or a service crate's sibling path so the test is
        // independent of the build working directory.
        let config = [
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/lab-forwards.toml"),
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../lmesh/examples/lab-forwards.toml"),
        ]
        .into_iter()
        .find_map(|path| path.canonicalize().ok())
        .expect("lab forward example exists");
        let path = resolve_config_relative_path(
            &config,
            "../../../target/lmesh-wifi-build/log/serial.log",
        );
        let expected = config
            .parent()
            .expect("lab forward parent")
            .join("../../../target/lmesh-wifi-build/log/serial.log");
        assert_eq!(path, expected.to_string_lossy());
    }

    #[test]
    fn framed_uds_command_waits_for_tagged_uart_wake() {
        let stream = WouldBlockOnceWriter {
            writes: 0,
            bytes: Vec::new(),
        };
        let mut client =
            SerialForwardClient::new(1, Box::new(stream), SerialForwardTcpMode::Framed);
        let mut serial_tx = VecDeque::new();
        let mut serial_pending = VecDeque::new();
        let frame = firmware_command_cbor("status").unwrap();
        client.input.extend_from_slice(&frame);

        assert!(
            client
                .flush_complete_records(
                    -1,
                    &mut serial_tx,
                    &mut serial_pending,
                    false,
                    None,
                    "test",
                    false
                )
                .unwrap()
        );
        assert!(serial_tx.is_empty());
        assert!(!serial_pending.is_empty());

        let mut decoder = FirmwareUartDecoder::default();
        let wake =
            encode_firmware_uart_frame(&mesh::cbor::encode_stream_frame(&[0xc6, 0xa0]).unwrap())
                .unwrap();
        assert_eq!(decoder.push(&wake).unwrap().len(), 1);
        assert!(decoder.take_frame_activity());
        serial_tx.append(&mut serial_pending);
        assert!(!serial_tx.is_empty());
    }

    #[test]
    fn framed_uds_command_flushes_during_explicit_uart_wake_window() {
        let stream = WouldBlockOnceWriter {
            writes: 0,
            bytes: Vec::new(),
        };
        let mut client =
            SerialForwardClient::new(1, Box::new(stream), SerialForwardTcpMode::Framed);
        let mut serial_tx = VecDeque::new();
        let mut serial_pending = VecDeque::new();
        let frame = firmware_command_cbor("status").unwrap();
        client.input.extend_from_slice(&frame);

        assert!(
            client
                .flush_complete_records(
                    -1,
                    &mut serial_tx,
                    &mut serial_pending,
                    true,
                    None,
                    "test",
                    false
                )
                .unwrap()
        );
        assert!(!serial_tx.is_empty());
        assert!(serial_pending.is_empty());
    }

    #[test]
    fn framed_uds_force_direct_prefix_does_not_bypass_sleepy_queue() {
        let stream = WouldBlockOnceWriter {
            writes: 0,
            bytes: Vec::new(),
        };
        let mut client =
            SerialForwardClient::new(1, Box::new(stream), SerialForwardTcpMode::Framed);
        let mut serial_tx = VecDeque::new();
        let mut serial_pending = VecDeque::new();
        let frame = firmware_command_cbor("status").unwrap();
        client
            .input
            .extend_from_slice(SERIAL_FORWARD_FORCE_DIRECT_PREFIX);
        client.input.extend_from_slice(&frame);

        assert!(
            client
                .flush_complete_records(
                    -1,
                    &mut serial_tx,
                    &mut serial_pending,
                    false,
                    None,
                    "test",
                    false
                )
                .unwrap()
        );
        assert!(client.force_direct);
        assert!(!serial_tx.is_empty());
        assert!(serial_pending.is_empty());
    }

    #[test]
    fn text_forward_accepts_readline_crlf_without_empty_command_error() {
        let stream = WouldBlockOnceWriter {
            writes: 0,
            bytes: Vec::new(),
        };
        let mut client =
            SerialForwardClient::new(1, Box::new(stream), SerialForwardTcpMode::Framed);
        let mut serial_tx = VecDeque::new();
        let mut serial_pending = VecDeque::new();
        client.input.extend_from_slice(b"status\r\n");

        client
            .flush_complete_records(
                -1,
                &mut serial_tx,
                &mut serial_pending,
                true,
                None,
                "test",
                false,
            )
            .unwrap();

        assert_eq!(
            serial_tx.into_iter().collect::<Vec<_>>(),
            encode_firmware_uart_frame(&firmware_command_cbor("status").unwrap()).unwrap()
        );
        assert!(client.output.is_empty());
    }

    #[test]
    fn text_forward_decodes_firmware_response_back_to_text() {
        let stream = WouldBlockOnceWriter {
            writes: 0,
            bytes: Vec::new(),
        };
        let mut client =
            SerialForwardClient::new(1, Box::new(stream), SerialForwardTcpMode::Framed);
        client.text_mode = true;
        let mut clients = vec![client];
        let stats = SerialForwardStats::default();
        let mut payload = Vec::new();
        let mut encoder = Encoder::new(&mut payload);
        encoder
            .map(3)
            .unwrap()
            .u16(0)
            .unwrap()
            .u16(33)
            .unwrap()
            .u16(4)
            .unwrap()
            .str("ok")
            .unwrap()
            .u16(6)
            .unwrap()
            .map(1)
            .unwrap()
            .u16(32)
            .unwrap()
            .str("status ok=true")
            .unwrap();
        let record = mesh::cbor::encode_stream_frame(&payload).unwrap();

        broadcast_serial_output(&mut clients, &[record], &[], false, &stats);

        let output = clients[0].output.iter().copied().collect::<Vec<_>>();
        assert_eq!(output, b"status ok=true\n");
    }

    #[test]
    fn gateway_active_command_is_addressed_compact_cbor() {
        let payload = firmware_targeted_command_cbor("active", "8e074170").unwrap();
        assert_eq!(
            payload,
            vec![
                0xa2, 0x00, 0x66, b'a', b'c', b't', b'i', b'v', b'e', 0x06, 0xa1, 0x19, 0x01, 0x4b,
                0x68, b'8', b'e', b'0', b'7', b'4', b'1', b'7', b'0'
            ]
        );
        assert_eq!(
            normalize_mac_suffix("84:0d:8e:07:41:70"),
            Some("8e074170".to_owned())
        );
        assert_eq!(
            normalize_mac_suffix("8E074170"),
            Some("8e074170".to_owned())
        );
    }

    #[test]
    fn gateway_active_window_is_addressed_and_bounded() {
        let payload = firmware_targeted_active_window_cbor("1d4c5e1d", 12_000).unwrap();
        let decoded = mesh::cbor::decode_json(&payload, &mesh::cbor::Catalog::default()).unwrap();
        assert_eq!(decoded["method"], "mode");
        assert_eq!(decoded["payload"]["80"], "12000");
        assert_eq!(decoded["payload"]["331"], "1d4c5e1d");

        let clamped = firmware_targeted_active_window_cbor("1d4c5e1d", 100).unwrap();
        let decoded = mesh::cbor::decode_json(&clamped, &mesh::cbor::Catalog::default()).unwrap();
        assert_eq!(decoded["payload"]["80"], "1000");
    }

    #[test]
    fn gateway_command_carries_response_timeout() {
        let payload =
            firmware_targeted_command_cbor_with_timeout("ping", "1d4c5e1d", Some(8_000)).unwrap();
        let decoded = mesh::cbor::decode_json(&payload, &mesh::cbor::Catalog::default()).unwrap();
        assert_eq!(decoded["payload"]["41"], "8000");
        assert_eq!(decoded["payload"]["331"], "1d4c5e1d");
    }

    #[test]
    fn gateway_ping_alias_uses_mode_ping_abi() {
        let payload =
            firmware_targeted_command_cbor_with_timeout("ping", "1d4c5e1d", Some(8_000)).unwrap();
        let decoded = mesh::cbor::decode_json(&payload, &mesh::cbor::Catalog::default()).unwrap();
        assert_eq!(decoded["method"], 49);
        assert_eq!(decoded["payload"]["190"], "true");
        assert_eq!(decoded["payload"]["41"], "8000");
    }

    #[test]
    fn gateway_command_parses_text_arguments() {
        let payload = firmware_targeted_command_cbor_with_timeout(
            "recovery ssid=Direct-Dmesh server=10.78.0.1 reboot=true",
            "1d4c5e1d",
            Some(45_000),
        )
        .unwrap();
        let decoded = mesh::cbor::decode_json(&payload, &mesh::cbor::Catalog::default()).unwrap();
        assert_eq!(decoded["method"], "recovery");
        assert_eq!(decoded["payload"]["ssid"], "Direct-Dmesh");
        assert_eq!(decoded["payload"]["server"], "10.78.0.1");
        assert_eq!(decoded["payload"]["reboot"], "true");
        assert_eq!(decoded["payload"]["41"], "45000");
    }

    #[test]
    fn configured_esp_roles_default_to_lora1_and_adapter_is_diagnostic_escape() {
        let targets = BTreeMap::from([
            ("lora2".to_owned(), "1d4c5e1d".to_owned()),
            ("lora4".to_owned(), "f6fc543d".to_owned()),
        ]);
        assert_eq!(
            resolve_esp_route("lora1", &targets, Some("lora2"), None),
            Some(("lora1".to_owned(), "1d4c5e1d".to_owned()))
        );
        assert_eq!(
            resolve_esp_route("lora1", &targets, Some("lora2"), Some("direct-port")),
            None
        );
        assert_eq!(
            resolve_esp_route("lora1", &targets, Some("unknown"), None),
            None
        );
    }

    #[test]
    fn host_nan_response_parser_keeps_dmesh_device_id() {
        let events = json!({"events": [{
            "event": "NAN-RECEIVE",
            "fields": {
                "address": "84:0d:8e:07:41:70",
                "ssi_dmesh": {
                    "protocol": "dmesh_nan_followup",
                    "device_id": "840d8e074170",
                    "target_id": "001122334455",
                    "msg_type": "response",
                    "payload_text": "ok"
                }
            }
        }]});
        let responses = host_nan_responses(&events);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0]["device_id"], "840d8e074170");
        assert_eq!(responses[0]["peer"], "84:0d:8e:07:41:70");
    }

    #[test]
    fn response_history_keys_include_timestamp_and_filter_target() {
        let history = json!({"messages": [{"console":
            "nan response_history count=2 entries=local_us:10:source:d8:a0:1d:4c:5e:1d:payload_hex:a20018210464706f6e67,local_us:11:source:44:1b:f6:fc:54:3d:payload_hex:a20018210464706f6e67\n"
        }]});
        let entries = response_history_entries(&history, Some("1d4c5e1d"));
        assert_eq!(entries.len(), 1);
        assert!(entries[0].0.contains("local_us:10"));
        assert_eq!(entries[0].1, "a20018210464706f6e67");
        let sta_entries = response_history_entries(&history, Some("1d4c5e1c"));
        assert_eq!(sta_entries.len(), 1);
        assert!(sta_entries[0].0.contains("local_us:10"));
    }

    struct WouldBlockOnceWriter {
        writes: usize,
        bytes: Vec<u8>,
    }

    impl Read for WouldBlockOnceWriter {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(Error::from(ErrorKind::WouldBlock))
        }
    }

    impl Write for WouldBlockOnceWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.writes == 0 {
                self.writes += 1;
                return Err(Error::from(ErrorKind::WouldBlock));
            }
            let n = buf.len().min(3);
            self.bytes.extend_from_slice(&buf[..n]);
            self.writes += 1;
            Ok(n)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl SerialForwardStream for WouldBlockOnceWriter {}

    #[test]
    fn parses_device_ids() {
        assert_eq!(
            parse_device_id(Some("001122334455")).unwrap(),
            [0, 17, 34, 51, 68, 85]
        );
        assert_eq!(
            parse_device_id(Some("00:11:22:33:44:55")).unwrap(),
            [0, 17, 34, 51, 68, 85]
        );
        assert!(parse_device_id(Some("0011")).is_none());
    }

    #[test]
    fn serial_queue_preserves_bytes_across_would_block() {
        let mut queue = VecDeque::from(Vec::from(&b"abcdef"[..]));
        let mut writer = WouldBlockOnceWriter {
            writes: 0,
            bytes: Vec::new(),
        };

        assert!(!flush_queue_to_writer(&mut writer, &mut queue).unwrap());
        assert_eq!(queue.iter().copied().collect::<Vec<_>>(), b"abcdef");

        assert!(flush_queue_to_writer(&mut writer, &mut queue).unwrap());
        assert_eq!(writer.bytes, b"abcdef");
        assert!(queue.is_empty());
    }

    #[test]
    fn rfc2217_parser_queues_escaped_iac_and_option_response() {
        let mut serial_tx = VecDeque::new();
        let mut output = VecDeque::new();

        assert_eq!(
            handle_rfc2217_input(&[RFC2217_IAC, RFC2217_IAC], -1, &mut serial_tx, &mut output)
                .unwrap(),
            Some(2)
        );
        assert_eq!(
            serial_tx.iter().copied().collect::<Vec<_>>(),
            vec![RFC2217_IAC]
        );

        assert_eq!(
            handle_rfc2217_input(
                &[RFC2217_IAC, RFC2217_DO, RFC2217_COM_PORT_OPTION],
                -1,
                &mut serial_tx,
                &mut output
            )
            .unwrap(),
            Some(3)
        );
        assert_eq!(
            output.iter().copied().collect::<Vec<_>>(),
            vec![RFC2217_IAC, RFC2217_WILL, RFC2217_COM_PORT_OPTION]
        );
    }

    #[test]
    fn rfc2217_mode_forwards_plain_binary_until_iac() {
        let stream = WouldBlockOnceWriter {
            writes: 0,
            bytes: Vec::new(),
        };
        let mut client =
            SerialForwardClient::new(1, Box::new(stream), SerialForwardTcpMode::Rfc2217);
        let mut serial_tx = VecDeque::new();
        let mut serial_pending = VecDeque::new();

        client
            .input
            .extend_from_slice(&[0x01, 0x02, RFC2217_IAC, RFC2217_IAC, 0x03]);
        assert!(
            client
                .flush_complete_records(
                    -1,
                    &mut serial_tx,
                    &mut serial_pending,
                    false,
                    None,
                    "test",
                    false
                )
                .unwrap()
        );
        assert_eq!(
            serial_tx.iter().copied().collect::<Vec<_>>(),
            vec![0x01, 0x02, RFC2217_IAC, 0x03]
        );
        assert!(client.input.is_empty());
    }

    #[test]
    fn rfc2217_serial_output_escapes_iac_for_client() {
        let stream = WouldBlockOnceWriter {
            writes: 0,
            bytes: Vec::new(),
        };
        let mut client =
            SerialForwardClient::new(1, Box::new(stream), SerialForwardTcpMode::Rfc2217);

        assert!(client.queue_output(&[0x41, RFC2217_IAC, 0x42]));
        assert_eq!(
            client.output.iter().copied().collect::<Vec<_>>(),
            vec![0x41, RFC2217_IAC, RFC2217_IAC, 0x42]
        );
    }

    #[test]
    fn raw_wifi_vendor_action_round_trips() {
        let dst = [0xff; 6];
        let src = [0x02, 0x00, 0x00, 0xaa, 0xbb, 0xcc];
        let frame = build_dmesh_vendor_action_frame(dst, src, b"stats");

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
        assert_eq!(frame[IEEE80211_BODY + 8], 0x04);

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
        let frame = build_dmesh_vendor_action_frame_with_bssid(dst, src, bssid, b"DMTB");

        assert_eq!(&frame[4..10], &dst); // A1: addressed device
        assert_eq!(&frame[10..16], &src); // A2: host Wi-Fi adapter
        assert_eq!(&frame[16..22], &bssid); // A3: NAN cluster, not broadcast
        assert_ne!(&frame[4..10], &[0xff; 6]);
        assert_ne!(&frame[16..22], &[0xff; 6]);
    }

    #[test]
    fn monitor_fcs_is_removed_only_when_crc_matches() {
        let frame = build_dmesh_vendor_action_frame([0xff; 6], [1, 2, 3, 4, 5, 6], b"ping");
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
        let frame = build_dmesh_vendor_action_frame([0xff; 6], [1, 2, 3, 4, 5, 6], b"ping");
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
        assert_eq!(parse_experimental_llc(Some("hex:aAaA03d04d455348")), Some(RAWNAN_LLC_DEFAULT));
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

    #[test]
    fn native_nan_service_id_is_six_byte_sha256_prefix() {
        let first = nan_service_id("dmesh");
        assert_eq!(first.len(), 6);
        assert_eq!(first, nan_service_id("dmesh"));
        assert_eq!(first, nan_service_id("DMESH"));
        assert_ne!(first, nan_service_id("other"));
    }
}
