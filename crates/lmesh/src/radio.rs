use anyhow::{Context, Result, bail};
use mesh::message::{
    FIELD_CTRL_DIR, FIELD_IFACE, FIELD_LEN, FIELD_MEDIUM, FIELD_NETWORK, FIELD_NODE, FIELD_PAYLOAD,
    FIELD_RADIO_ID, FIELD_RSSI, FIELD_SNR, FIELD_STATUS, MeshMessage, MeshMessageCodec, TextRecord,
};
use minicbor::Encoder;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::radio_protocol;

const DEFAULT_WIFI_IFACE: &str = "wlan1";
const DEFAULT_WPA_CTRL_DIR: &str = "/run/mesh/wpa-supplicant-nan";
const DEFAULT_WPA_SERVICE_NAME: &str = "dmesh";
const DEFAULT_NAN_TTL_SECS: u32 = 3600;
// Firmware raw-NAN peers normally wake every four seconds for a short window.
// A 700 ms probe cadence walks that phase rather than repeatedly landing on a
// fixed 250/500 ms boundary.
const STABILITY_HOST_NAN_RETRY_MS: u64 = 700;
const DEFAULT_HCI_DEV: u16 = 0;
const DEFAULT_RAW_WIFI_CHANNEL: u8 = 6;
const DEFAULT_RAW_WIFI_LISTEN_SECS: u64 = 60;
const DEFAULT_LMESH_CONFIG_FILE: &str = "/home/system/etc/lmesh/lmesh.toml";
const MAX_HISTORY: usize = 128;
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
const SERIAL_DTR_DEFAULT_MS: u64 = 120;
const SERIAL_DTR_MAX_MS: u64 = 10_000;
const SERIAL_DTR_FLUSH_WINDOW_MS: u64 = 2_000;
// GPIO0/DTR wakes firmware through a short button task before UART RX is
// re-armed. Keep incoming client bytes in the kernel socket buffer until that
// transition is complete.
// GPIO0 wake reaches the firmware button task before UART RX is re-armed.
// Some boards need a full scheduler/light-sleep transition after DTR rises;
// 600 ms still lost the first compact-CBOR record after a cold idle period.
const SERIAL_FLASH_LOG_QUIET_MS: u64 = 60_000;
// UART is an HDLC/PPP-style byte stream. Its payload is compact CBOR; the
// generic mesh stream envelope remains at the lmesh UDS boundary.
const FIRMWARE_UART_FLAG: u8 = 0x7e;
const FIRMWARE_UART_ESCAPE: u8 = 0x7d;
const FIRMWARE_UART_ESCAPE_XOR: u8 = 0x20;
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
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFTYPE: u16 = 5;
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
const NL80211_ATTR_TX_NO_CCK_RATE: u16 = 135;
const NL80211_ATTR_DONT_WAIT_FOR_ACK: u16 = 142;
const NL80211_ATTR_PROBE_RESP: u16 = 145;
const NL80211_ATTR_RX_SIGNAL_DBM: u16 = 151;
const NL80211_ATTR_CHANNEL_WIDTH: u16 = 159;
const NL80211_ATTR_CENTER_FREQ1: u16 = 160;
const NL80211_ATTR_SOCKET_OWNER: u16 = 204;
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
const NL80211_STA_INFO_RX_PACKETS: u16 = 9;
const NL80211_STA_INFO_TX_PACKETS: u16 = 10;
const NL80211_STA_INFO_TX_RETRIES: u16 = 11;
const NL80211_STA_INFO_TX_FAILED: u16 = 12;
const NL80211_STA_INFO_SIGNAL_AVG: u16 = 13;
const NL80211_STA_INFO_CONNECTED_TIME: u16 = 16;
const NL80211_STA_INFO_RX_BYTES64: u16 = 23;
const NL80211_STA_INFO_TX_BYTES64: u16 = 24;
const NL80211_IFTYPE_STATION: u32 = 2;
const NL80211_IFTYPE_AP: u32 = 3;
const NL80211_STA_FLAG_AUTHORIZED: u32 = 1 << 1;
const NL80211_STA_FLAG_AUTHENTICATED: u32 = 1 << 5;
const NL80211_STA_FLAG_ASSOCIATED: u32 = 1 << 7;
const NLM_F_DUMP: u16 = 0x300;
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
    wifi_ap_handles: Arc<Mutex<BTreeMap<String, ApRuntime>>>,
    serial_forwards: Arc<Mutex<BTreeMap<String, SerialForwardRuntime>>>,
    serial_log: Option<Arc<Mutex<SerialForwardLog>>>,
    stability: Arc<Mutex<Option<StabilityRuntime>>>,
}

impl RadioService {
    /// Create a radio service from environment and optional MESH_HOME/lmesh.toml config.
    pub fn from_environment() -> Self {
        let serial_log =
            configured_serial_log_path().and_then(|path| match SerialForwardLog::open(&path) {
                Ok(log) => Some(Arc::new(Mutex::new(log))),
                Err(error) => {
                    tracing::warn!(path = %path, error = %error, "serial_forward_log_disabled");
                    None
                }
            });
        let service = Self {
            history: Arc::new(Mutex::new(VecDeque::new())),
            radios: Arc::new(load_radio_adapters()),
            raw_wifi_listeners: Arc::new(Mutex::new(HashSet::new())),
            wifi_ap_handles: Arc::new(Mutex::new(BTreeMap::new())),
            serial_forwards: Arc::new(Mutex::new(BTreeMap::new())),
            serial_log,
            stability: Arc::new(Mutex::new(None)),
        };
        service.start_configured_serial_forwards();
        service
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
                forward.dtr,
                forward.multi,
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
    ) -> Value {
        let profile = profile.unwrap_or_else(|| "generic".to_string());
        let timeout_ms = timeout_sec
            .map(|secs| (secs.max(0.05) * 1000.0).round() as u64)
            .unwrap_or(1_500)
            .clamp(50, 30_000);
        let Some(target) = resolve_usb_serial_target(port, None) else {
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
        let mut exchanges = Vec::new();
        let mut ok = true;
        for command in commands {
            match serial_exchange_raw(&path, baud, &command, timeout_ms) {
                Ok(exchange) => {
                    for message in &exchange.messages {
                        self.record_message("usb.serial.handshake.rx", &id, message.clone());
                    }
                    exchanges.push(json!({
                        "command": command,
                        "raw": exchange.raw_text,
                        "messages": exchange.messages,
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

    /// Pulse ESP USB serial modem lines into bootloader or running-app mode.
    pub fn usb_serial_reset(&self, port: Option<String>, mode: Option<String>) -> Value {
        let mode = mode.unwrap_or_else(|| "run".to_string());
        let Some(target) = resolve_usb_serial_target(port, None) else {
            return json!({
                "ok": false,
                "error": "missing USB serial target; pass port=USB0 or port=ACM0",
            });
        };
        let UsbSerialTarget { id, path, .. } = target;
        let reset_kind = match mode.as_str() {
            "boot" | "bootloader" | "download" => SERIAL_RESET_BOOTLOADER,
            "run" | "app" | "firmware" => SERIAL_RESET_RUN,
            other => {
                return json!({
                    "ok": false,
                    "id": id,
                    "port": path,
                    "mode": mode,
                    "error": format!("unsupported serial reset mode {other}; use bootloader or run"),
                });
            }
        };
        {
            let forwards = self
                .serial_forwards
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(forward) = forwards.get(&id) {
                if reset_kind == SERIAL_RESET_BOOTLOADER {
                    forward.log_flash_quiet_until_ms.store(
                        now_millis_u64().saturating_add(SERIAL_FLASH_LOG_QUIET_MS),
                        Ordering::Release,
                    );
                }
                forward.reset_request.store(reset_kind, Ordering::Release);
                let result = json!({
                    "ok": true,
                    "id": id,
                    "port": path,
                    "mode": mode,
                    "via": "active_forward",
                });
                self.record("usb.serial.reset", result.clone());
                return result;
            }
        }
        let serial = match fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(serial) => serial,
            Err(error) => {
                return json!({
                    "ok": false,
                    "id": id,
                    "port": path,
                    "mode": mode,
                    "error": format!("failed to open serial target: {error}"),
                });
            }
        };
        let reset = match reset_kind {
            SERIAL_RESET_BOOTLOADER => esp32_bootloader_reset(serial.as_raw_fd()),
            SERIAL_RESET_RUN => esp32_run_reset(serial.as_raw_fd()),
            _ => Ok(()),
        };
        let result = match reset {
            Ok(()) => json!({
                "ok": true,
                "id": id,
                "port": path,
                "mode": mode,
            }),
            Err(error) => json!({
                "ok": false,
                "id": id,
                "port": path,
                "mode": mode,
                "error": error.to_string(),
            }),
        };
        self.record("usb.serial.reset", result.clone());
        result
    }

    /// Start a generic byte-forwarding UDS for one USB serial device.
    pub fn serial_forward_start(
        &self,
        port: Option<String>,
        mut baud: Option<u32>,
        mut tcp_port: Option<u16>,
        mut tcp_mode: Option<String>,
        handshake: Option<bool>,
        _dtr: Option<bool>,
        mut multi: Option<bool>,
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
        let log_flash_quiet_until_ms = Arc::new(AtomicU64::new(0));
        let stats = Arc::new(SerialForwardStats::default());
        let log_path = configured_serial_log_path_for_forward(&id);
        let thread_stop = stop.clone();
        let thread_reset_request = reset_request.clone();
        let thread_log_flash_quiet_until_ms = log_flash_quiet_until_ms.clone();
        let thread_stats = stats.clone();
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
                thread_log_flash_quiet_until_ms,
                thread_stop,
                thread_stats,
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
            log_flash_quiet_until_ms,
            stop,
            stats,
            handle: Some(handle),
            started_ms: now_millis_u64(),
        };
        self.serial_forwards
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(id.clone(), runtime);
        let handshake_result = handshake.unwrap_or(false).then(|| {
            self.usb_serial_handshake(Some(id.clone()), Some("dmesh".to_string()), Some(1.5))
        });
        let result = json!({
            "ok": true,
            "id": id,
            "port": path,
            "baud": baud,
            "dtr": false,
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
            "dtr": false,
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
                    "dtr": false,
                    "multi": forward.multi,
                    "tcp_listen": forward.tcp_listen,
                    "log_path": forward.log_path,
                    "started_ms": forward.started_ms,
                    "running": !forward.stop.load(Ordering::Acquire),
                    "stats": forward.stats.snapshot(),
                })
            })
            .collect::<Vec<_>>();
        json!({ "ok": true, "forwards": forwards })
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
                std::thread::spawn(move || {
                    ap_mgmt_receive_loop(mgmt_socket, &mgmt_iface, ifindex, mac, history);
                });
                self.wifi_ap_handles
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert(
                        iface.clone(),
                        ApRuntime {
                            _owner_socket: socket,
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
        self.wifi_ap_handles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&iface);
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
        let wpa_channel = prepare_raw_wifi_channel(&iface, &ctrl_dir, channel, listen_sec);
        let rx_variant = rx_variant.unwrap_or_else(|| "nl80211".to_string());
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
                std::thread::spawn(move || {
                    monitor_receive_loop(socket, &iface_for_thread, &monitor_for_thread, history);
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
        let wpa_channel = if tx_options.variant == "roc" {
            json!({
                "skipped": true,
                "reason": "tx_variant=roc owns nl80211 remain-on-channel directly",
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
        let frame = if tx_options.variant == "multicast_data"
            || tx_options.variant == "multicast_data_active"
        {
            build_dmesh_multicast_data_frame(destination, source, payload.as_bytes())
        } else if tx_options.variant == "sta_multicast_llc"
            || tx_options.variant == "sta_multicast_llc_active"
        {
            build_dmesh_sta_multicast_llc_frame(destination, source, payload.as_bytes())
        } else if tx_options.variant == "sta_direct_llc"
            || tx_options.variant == "sta_direct_llc_active"
        {
            build_dmesh_sta_direct_llc_frame(destination, source, payload.as_bytes())
        } else {
            build_dmesh_vendor_action_frame(destination, source, payload.as_bytes())
        };
        let result = if tx_options.variant == "monitor"
            || tx_options.variant == "monitor_active"
            || tx_options.variant == "multicast_data"
            || tx_options.variant == "multicast_data_active"
            || tx_options.variant == "sta_multicast_llc"
            || tx_options.variant == "sta_multicast_llc_active"
            || tx_options.variant == "sta_direct_llc"
            || tx_options.variant == "sta_direct_llc_active"
        {
            let active = tx_options.variant == "monitor_active"
                || tx_options.variant == "multicast_data_active"
                || tx_options.variant == "sta_multicast_llc_active"
                || tx_options.variant == "sta_direct_llc_active";
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
                    "source": colon_mac(&source),
                    "source_mode": raw_wifi_source_mode(source_input),
                    "payload_len": payload.len(),
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
            match Nl80211Socket::open().and_then(|socket| {
                if tx_options.variant == "roc" {
                    socket.remain_on_channel(
                        ifindex(&iface)?,
                        channel_to_freq(channel),
                        tx_options.duration_ms.unwrap_or(10),
                    )?;
                }
                socket.send_frame(
                    ifindex(&iface)?,
                    channel_to_freq(channel),
                    &tx_options,
                    &frame,
                )
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
                    "destination": colon_mac(&destination),
                    "destination_mode": destination_mode,
                    "source": colon_mac(&source),
                    "source_mode": raw_wifi_source_mode(source_input),
                    "payload_len": payload.len(),
                    "frame_len": frame.len(),
                }),
                Err(error) => json!({
                    "ok": false,
                    "backend": "linux_nl80211",
                    "tx_variant": tx_options.variant,
                    "tx_options": tx_options.as_json(),
                    "iface": iface,
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
                .field(FIELD_LEN, payload.len())
                .field(FIELD_PAYLOAD, payload),
        );
        self.record("wifi.raw.tx", result.clone());
        result
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
        match serial_exchange(path, radio.baud.unwrap_or(460_800), &command, 250) {
            Ok(messages) => {
                for message in &messages {
                    self.record_message("esp-serial.rx", &radio.id, message.clone());
                }
                json!({
                    "radio_id": radio.id,
                    "path": path,
                    "ok": true,
                    "replies": messages,
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
        let timeout_ms = timeout_sec
            .map(|secs| (secs.max(0.05) * 1000.0).round() as u64)
            .unwrap_or(1_500)
            .clamp(50, 30_000);
        let target = self.esp_serial_target(adapter, port);
        let Some((radio_id, path, baud)) = target else {
            return json!({
                "ok": false,
                "error": "missing ESP serial adapter; pass port or configure LMESH_SERIAL_DEVICES/lmesh.toml",
            });
        };
        let forward_socket = self
            .serial_forwards
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .find(|forward| forward.port == path && !forward.stop.load(Ordering::Acquire))
            .map(|forward| forward.socket_path.clone());
        if let Some(socket_path) = forward_socket {
            return match uds_console_exchange(&socket_path, &command, timeout_ms) {
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
        match serial_exchange(&path, baud, &command, timeout_ms) {
            Ok(messages) => {
                for message in &messages {
                    self.record_message("esp.serial.rx", &radio_id, message.clone());
                }
                let result = json!({
                    "ok": true,
                    "radio_id": radio_id,
                    "path": path,
                    "baud": baud,
                    "command": command,
                    "messages": messages,
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
                "error": error.to_string(),
            }),
        }
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
            if active_ms.is_some() {
                return json!({
                    "ok": false,
                    "error": "gateway active supports persistent active=true or active=false; use a later bounded protocol command for active_ms",
                });
            }
            let command = if enabled { "active" } else { "idle" };
            let payload = match firmware_targeted_command_cbor(command, &target) {
                Ok(payload) => payload,
                Err(error) => return json!({"ok": false, "error": error.to_string()}),
            };
            let payload_hex = hex_lower(&payload);
            let result = self.esp_serial_command(
                None,
                Some(gateway.clone()),
                format!("nan payload=hex:{payload_hex}"),
                Some(2.0),
            );
            return json!({
                "ok": result.get("ok").and_then(Value::as_bool).unwrap_or(false),
                "gateway": gateway,
                "target": target,
                "command": command,
                "queued_over": "raw_nan",
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
            let path = configured_serial_path(&port).unwrap_or(port);
            return Some(("direct-port".to_string(), path, 460_800));
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
    log_flash_quiet_until_ms: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    stats: Arc<SerialForwardStats>,
    handle: Option<std::thread::JoinHandle<()>>,
    started_ms: u64,
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

const SERIAL_RESET_NONE: u8 = 0;
const SERIAL_RESET_BOOTLOADER: u8 = 1;
const SERIAL_RESET_RUN: u8 = 2;

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
        "readable": fs::OpenOptions::new().read(true).open(path).is_ok(),
        "writable": fs::OpenOptions::new().write(true).open(path).is_ok(),
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
    read_lmesh_config()?
        .serial_log_path
        .filter(|path| !path.is_empty())
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
    config.serial_log_path.filter(|path| !path.is_empty())
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
    log_flash_quiet_until_ms: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    stats: Arc<SerialForwardStats>,
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
    // USB-UART drivers may assert modem-control lines on open. On ESP boards
    // these are wired to GPIO0/EN, so leave both deasserted until an explicit
    // reset, console DTR pulse, or RFC2217 control request changes them.
    set_modem_lines(serial.as_raw_fd(), false, false)
        .with_context(|| format!("failed to deassert modem lines for {port}"))?;
    if log_path.is_some() && serial_log.is_none() {
        stats.log_write_errors.fetch_add(1, Ordering::Relaxed);
    }
    let mut clients: Vec<SerialForwardClient> = Vec::new();
    let mut had_rfc2217_client = false;
    let mut firmware_uart_decoder = FirmwareUartDecoder::default();
    let mut serial_tx = VecDeque::new();
    // Firmware drops physical UART output while idle. Keep normal UDS command
    // records here until any framed UART activity proves its bounded console
    // window is open. RFC2217 bytes remain immediate for flashing/control.
    let mut serial_pending = VecDeque::new();
    // A DTR pulse is an explicit UART wake request. Firmware keeps UART awake
    // for a bounded window, but may not emit a heartbeat first.
    let mut serial_flush_until_ms = 0_u64;
    let mut serial_buf = [0_u8; SERIAL_FORWARD_IO_BUFFER_BYTES];
    while !stop.load(Ordering::Acquire) {
        let mut progressed = false;
        let mut uart_wake_seen = false;
        match reset_request.swap(SERIAL_RESET_NONE, Ordering::AcqRel) {
            SERIAL_RESET_BOOTLOADER => {
                esp32_bootloader_reset(serial.as_raw_fd())
                    .with_context(|| format!("failed to reset {port} to bootloader"))?;
                configure_serial(serial.as_raw_fd(), baud)
                    .with_context(|| format!("failed to restore serial baud for {port}"))?;
                progressed = true;
            }
            SERIAL_RESET_RUN => {
                esp32_run_reset(serial.as_raw_fd())
                    .with_context(|| format!("failed to reset {port} to running firmware"))?;
                configure_serial(serial.as_raw_fd(), baud)
                    .with_context(|| format!("failed to restore serial baud for {port}"))?;
                progressed = true;
            }
            _ => {}
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
        let flash_log_quiet = log_flash_quiet_until_ms.load(Ordering::Acquire) > now_millis_u64()
            || clients.iter().any(SerialForwardClient::is_rfc2217);
        match serial.read(&mut serial_buf) {
            Ok(0) => {}
            Ok(n) => {
                stats
                    .serial_to_client_bytes
                    .fetch_add(n as u64, Ordering::Relaxed);
                record_serial_forward_log(
                    serial_log.as_ref(),
                    &stats,
                    id,
                    "rx",
                    &serial_buf[..n],
                    flash_log_quiet,
                );
                let records = firmware_uart_decoder.push(&serial_buf[..n])?;
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
                progressed = true;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                stats
                    .serial_read_would_block
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(error) => return Err(error).with_context(|| format!("failed to read {port}")),
        }
        let mut idx = 0;
        while idx < clients.len() {
            let may_write = multi || idx == 0;
            match clients[idx].pump_to_serial(
                serial.as_raw_fd(),
                &mut serial_tx,
                &mut serial_pending,
                may_write,
                now_millis_u64() < serial_flush_until_ms,
                &stats,
                id,
                serial_log.as_ref(),
                flash_log_quiet,
            ) {
                Ok((true, client_progressed, dtr_wake)) => {
                    progressed |= client_progressed;
                    if dtr_wake {
                        serial_flush_until_ms =
                            now_millis_u64().saturating_add(SERIAL_DTR_FLUSH_WINDOW_MS);
                        uart_wake_seen = true;
                    }
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
        if (uart_wake_seen || now_millis_u64() < serial_flush_until_ms)
            && !serial_pending.is_empty()
        {
            if serial_tx.len().saturating_add(serial_pending.len()) > SERIAL_FORWARD_MAX_PENDING {
                bail!(
                    "serial TX queue exceeded {} bytes while flushing UART wake queue",
                    SERIAL_FORWARD_MAX_PENDING
                );
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
        let has_rfc2217_client = clients.iter().any(SerialForwardClient::is_rfc2217);
        if had_rfc2217_client && !has_rfc2217_client {
            set_modem_lines(serial.as_raw_fd(), false, false)
                .with_context(|| format!("failed to restore modem lines for {port}"))?;
        }
        had_rfc2217_client = has_rfc2217_client;
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

fn pulse_console_dtr_for(
    fd: RawFd,
    hold_ms: u64,
) -> Result<(libc::c_int, libc::c_int, libc::c_int)> {
    // A console wake must touch only DTR. TIOCMSET rewrites RTS as well, and
    // the RTS/EN side of CP210x auto-program circuits can reset an ESP even
    // when the caller only requested PRG/DTR. TIOCMBIS/TIOCMBIC preserve RTS.
    let before = modem_line_state(fd)?;
    set_modem_line(fd, libc::TIOCM_DTR, true).context("TIOCMBIS DTR on failed")?;
    let asserted = modem_line_state(fd)?;
    std::thread::sleep(Duration::from_millis(hold_ms));
    set_modem_line(fd, libc::TIOCM_DTR, false).context("TIOCMBIC DTR off failed")?;
    let released = modem_line_state(fd)?;
    Ok((before, asserted, released))
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
    uart_flush_requested: bool,
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
            uart_flush_requested: false,
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
                    record_serial_forward_log(
                        serial_log,
                        stats,
                        board,
                        "tx",
                        &buf[..n],
                        flash_log_quiet,
                    );
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
            progressed |=
                self.flush_complete_records(serial_fd, serial_tx, serial_pending, serial_direct)?;
        } else if !may_write {
            progressed |= !self.input.is_empty();
            self.input.clear();
        }
        Ok((
            !input_closed,
            progressed,
            std::mem::take(&mut self.uart_flush_requested),
        ))
    }

    fn flush_complete_records(
        &mut self,
        serial_fd: RawFd,
        serial_tx: &mut VecDeque<u8>,
        serial_pending: &mut VecDeque<u8>,
        serial_direct: bool,
    ) -> Result<bool> {
        let mut progressed = false;
        loop {
            if self.input.is_empty() {
                return Ok(progressed);
            }
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
                pos + 1
            } else {
                return Ok(progressed);
            };
            if self.input[0] != 0
                && handle_serial_forward_command(
                    &self.input[..record_len],
                    serial_fd,
                    &mut self.output,
                )?
            {
                if matches!(
                    parse_serial_forward_command(&self.input[..record_len]),
                    Some(Ok(SerialForwardCommand::Dtr(_)))
                ) {
                    self.uart_flush_requested = true;
                }
                self.input.drain(..record_len);
                progressed = true;
                continue;
            }
            if self.input[0] == 0 {
                if serial_direct || self.uart_flush_requested {
                    queue_firmware_packet(serial_tx, &self.input[..record_len])?;
                } else {
                    queue_firmware_packet(serial_pending, &self.input[..record_len])?;
                }
            } else {
                let line = std::str::from_utf8(&self.input[..record_len])?.trim();
                match firmware_command_cbor(line) {
                    Ok(frame) => {
                        if serial_direct || self.uart_flush_requested {
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
        Ok(Self { file })
    }

    fn append(&mut self, board: &str, direction: &str, bytes: &[u8]) -> Result<()> {
        let text = String::from_utf8_lossy(bytes);
        writeln!(
            self.file,
            "ts_ms={} board={} dir={} bytes={} hex={} text={:?}",
            now_millis_u64(),
            board,
            direction,
            bytes.len(),
            hex_lower(bytes),
            text,
        )
        .context("failed to write serial log record")?;
        self.file
            .flush()
            .context("failed to flush serial log record")
    }
}

fn record_serial_forward_log(
    log: Option<&Arc<Mutex<SerialForwardLog>>>,
    stats: &SerialForwardStats,
    board: &str,
    direction: &str,
    bytes: &[u8],
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
    match sink.append(board, direction, bytes) {
        Ok(()) => {
            stats.log_records.fetch_add(1, Ordering::Relaxed);
        }
        Err(error) => {
            stats.log_write_errors.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(forward_id = %board, direction, error = %error, "serial_forward_log_write_failed");
        }
    }
}

enum SerialForwardCommand {
    Dtr(u64),
    Reset,
}

fn parse_serial_forward_command(record: &[u8]) -> Option<Result<SerialForwardCommand>> {
    let line = std::str::from_utf8(record).ok()?;
    let mut words = line.split_ascii_whitespace();
    match words.next()? {
        "dtr" => {
            let hold_ms = match words.next() {
                Some(value) => match value.parse::<u64>() {
                    Ok(value) => value,
                    Err(_) => return Some(Err(anyhow::anyhow!("duration must be milliseconds"))),
                },
                None => SERIAL_DTR_DEFAULT_MS,
            };
            if words.next().is_some() {
                return Some(Err(anyhow::anyhow!("usage: dtr [milliseconds]")));
            }
            if !(1..=SERIAL_DTR_MAX_MS).contains(&hold_ms) {
                return Some(Err(anyhow::anyhow!(
                    "duration must be between 1 and {SERIAL_DTR_MAX_MS} ms"
                )));
            }
            Some(Ok(SerialForwardCommand::Dtr(hold_ms)))
        }
        "rst" => {
            if words.next().is_some() {
                Some(Err(anyhow::anyhow!("usage: rst")))
            } else {
                Some(Ok(SerialForwardCommand::Reset))
            }
        }
        _ => None,
    }
}

fn handle_serial_forward_command(
    record: &[u8],
    serial_fd: RawFd,
    output: &mut VecDeque<u8>,
) -> Result<bool> {
    let Some(command) = parse_serial_forward_command(record) else {
        return Ok(false);
    };
    match command {
        Ok(SerialForwardCommand::Dtr(hold_ms)) => {
            let (before, asserted, released) = pulse_console_dtr_for(serial_fd, hold_ms)?;
            queue_client_bytes(
                output,
                format!(
                    "event type=lmesh.dtr ok=true hold_ms={hold_ms} before=0x{before:x} asserted=0x{asserted:x} released=0x{released:x}\n"
                )
                .as_bytes(),
            )?;
        }
        Ok(SerialForwardCommand::Reset) => {
            esp32_run_reset(serial_fd)?;
            queue_client_bytes(output, b"event type=lmesh.rst ok=true\n")?;
        }
        Err(error) => {
            queue_client_bytes(
                output,
                format!("event type=lmesh.command ok=false error={error:?}\n").as_bytes(),
            )?;
        }
    }
    Ok(true)
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

/// Convert a generic mesh UDS record into the compact-CBOR UART wire form.
fn encode_firmware_uart_frame(stream_frame: &[u8]) -> Result<Vec<u8>> {
    let cbor = mesh::cbor::decode_stream_frame(stream_frame)?;
    if cbor.is_empty() || cbor.len() > mesh::cbor::ESP_RECORD_MAX {
        bail!(
            "firmware UART CBOR record must be 1..={} bytes",
            mesh::cbor::ESP_RECORD_MAX
        );
    }
    let mut wire = Vec::with_capacity(cbor.len() * 2 + 2);
    wire.push(FIRMWARE_UART_FLAG);
    for byte in cbor {
        if matches!(*byte, FIRMWARE_UART_FLAG | FIRMWARE_UART_ESCAPE) {
            wire.push(FIRMWARE_UART_ESCAPE);
            wire.push(*byte ^ FIRMWARE_UART_ESCAPE_XOR);
        } else {
            wire.push(*byte);
        }
    }
    wire.push(FIRMWARE_UART_FLAG);
    Ok(wire)
}

#[derive(Default)]
struct FirmwareUartDecoder {
    in_frame: bool,
    escaped: bool,
    discard_until_flag: bool,
    payload: Vec<u8>,
    frame_activity: bool,
}

impl FirmwareUartDecoder {
    fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut records = Vec::new();
        for byte in bytes {
            if *byte == FIRMWARE_UART_FLAG {
                if !self.in_frame {
                    self.in_frame = true;
                    self.escaped = false;
                    self.discard_until_flag = false;
                    self.payload.clear();
                    continue;
                }
                if self.escaped {
                    self.payload.clear();
                    self.escaped = false;
                    self.discard_until_flag = false;
                    continue;
                }
                self.escaped = false;
                if self.discard_until_flag || self.payload.is_empty() {
                    self.discard_until_flag = false;
                    self.payload.clear();
                    self.frame_activity = true;
                    continue;
                }
                records.push(mesh::cbor::encode_stream_frame(&self.payload)?);
                self.payload.clear();
                self.frame_activity = true;
                continue;
            }
            if !self.in_frame || self.discard_until_flag {
                continue;
            }
            if self.escaped {
                self.payload.push(*byte ^ FIRMWARE_UART_ESCAPE_XOR);
                self.escaped = false;
            } else if *byte == FIRMWARE_UART_ESCAPE {
                self.escaped = true;
                continue;
            } else {
                self.payload.push(*byte);
            }
            if self.payload.len() > mesh::cbor::ESP_RECORD_MAX {
                self.payload.clear();
                self.escaped = false;
                self.discard_until_flag = true;
            }
        }
        Ok(records)
    }

    /// Return whether a complete physical UART frame ended since the prior
    /// call. Empty delimiter frames are intentional firmware heartbeats.
    fn take_frame_activity(&mut self) -> bool {
        std::mem::take(&mut self.frame_activity)
    }
}

fn queue_firmware_packet(queue: &mut VecDeque<u8>, stream_frame: &[u8]) -> Result<()> {
    let wire = encode_firmware_uart_frame(stream_frame)?;
    queue_serial_bytes(queue, &wire)
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
        9 => set_modem_line(fd, libc::TIOCM_DTR, false)?,
        8 => set_modem_line(fd, libc::TIOCM_DTR, true)?,
        11 => set_modem_line(fd, libc::TIOCM_RTS, true)?,
        12 => set_modem_line(fd, libc::TIOCM_RTS, false)?,
        _ => {}
    }
    Ok(())
}

fn set_modem_line(fd: RawFd, line: libc::c_int, enabled: bool) -> Result<()> {
    let mut bits = line;
    let request = if enabled {
        libc::TIOCMBIS
    } else {
        libc::TIOCMBIC
    };
    if unsafe { libc::ioctl(fd, request, &mut bits) } < 0 {
        return Err(std::io::Error::last_os_error()).context("modem line ioctl failed");
    }
    Ok(())
}

fn modem_line_state(fd: RawFd) -> Result<libc::c_int> {
    let mut bits: libc::c_int = 0;
    if unsafe { libc::ioctl(fd, libc::TIOCMGET, &mut bits) } < 0 {
        return Err(std::io::Error::last_os_error()).context("TIOCMGET failed");
    }
    Ok(bits)
}

fn set_modem_lines(fd: RawFd, dtr: bool, rts: bool) -> Result<()> {
    let mut bits: libc::c_int = 0;
    if dtr {
        bits |= libc::TIOCM_DTR;
    }
    if rts {
        bits |= libc::TIOCM_RTS;
    }
    if unsafe { libc::ioctl(fd, libc::TIOCMSET, &bits) } < 0 {
        return Err(std::io::Error::last_os_error()).context("TIOCMSET failed");
    }
    Ok(())
}

fn esp32_bootloader_reset(fd: RawFd) -> Result<()> {
    set_modem_lines(fd, false, false)?;
    set_modem_lines(fd, true, true)?;
    set_modem_lines(fd, false, true)?;
    std::thread::sleep(Duration::from_millis(100));
    set_modem_lines(fd, true, false)?;
    std::thread::sleep(Duration::from_millis(50));
    set_modem_lines(fd, false, false)?;
    set_modem_line(fd, libc::TIOCM_DTR, false)?;
    Ok(())
}

fn esp32_run_reset(fd: RawFd) -> Result<()> {
    set_modem_line(fd, libc::TIOCM_DTR, false)?;
    set_modem_line(fd, libc::TIOCM_RTS, true)?;
    std::thread::sleep(Duration::from_millis(120));
    set_modem_line(fd, libc::TIOCM_RTS, false)?;
    std::thread::sleep(Duration::from_millis(500));
    set_modem_line(fd, libc::TIOCM_DTR, false)?;
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

fn serial_exchange(
    path: &str,
    baud: u32,
    command: &str,
    timeout_ms: u64,
) -> Result<Vec<MeshMessage>> {
    serial_exchange_cbor(path, baud, command, timeout_ms)
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
            encoder.str(&key)?;
            if let Some(bytes) = bytes {
                encoder.bytes(&bytes)?;
            } else {
                encoder.str(&value)?;
            }
        }
    }
    mesh::cbor::encode_stream_frame(&cbor)
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

/// Send one framed CBOR command directly to a serial adapter and decode each
/// complete response as a binary mesh message. The firmware never emits a
/// console prompt, so frame boundaries are authoritative.
fn serial_exchange_cbor(
    path: &str,
    baud: u32,
    command: &str,
    timeout_ms: u64,
) -> Result<Vec<MeshMessage>> {
    let frame = firmware_command_cbor(command)?;
    let frame = encode_firmware_uart_frame(&frame)?;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("failed to open serial radio {path}"))?;
    configure_serial(file.as_raw_fd(), baud)
        .with_context(|| format!("failed to configure serial radio {path}"))?;
    file.write_all(&frame)
        .with_context(|| format!("failed to write binary firmware command to {path}"))?;
    file.flush()
        .with_context(|| format!("failed to flush binary firmware command to {path}"))?;

    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut decoder = FirmwareUartDecoder::default();
    let mut messages = Vec::new();
    let mut buf = [0_u8; 512];
    while std::time::Instant::now() < deadline {
        match file.read(&mut buf) {
            Ok(0) => std::thread::sleep(Duration::from_millis(10)),
            Ok(count) => {
                for frame in decoder.push(&buf[..count])? {
                    let payload = mesh::cbor::decode_stream_frame(&frame)?;
                    let decoded =
                        mesh::cbor::decode_json(payload, &mesh::cbor::Catalog::default())?;
                    let mut message = MeshMessage::new(0, MeshMessageCodec::Cbor);
                    if let Some(status) = decoded.get("status") {
                        message.fields.insert(FIELD_STATUS, status.to_string());
                    }
                    if let Some(error) = decoded.get("error") {
                        message.fields.insert(FIELD_CTRL_DIR, error.to_string());
                    }
                    message.payload = Some(serde_json::to_vec(&decoded)?);
                    messages.push(message);
                }
                if !messages.is_empty() {
                    return Ok(messages);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error).with_context(|| format!("failed to read from {path}")),
        }
    }
    if messages.is_empty() {
        bail!("timed out waiting for binary firmware response");
    }
    Ok(messages)
}

/// Send one console command through a managed forward and retain asynchronous
/// radio output until the requested observation window ends.
fn uds_console_exchange(socket_path: &str, command: &str, timeout_ms: u64) -> Result<String> {
    uds_console_exchange_inner(socket_path, command, timeout_ms)
}

fn uds_console_exchange_inner(socket_path: &str, command: &str, timeout_ms: u64) -> Result<String> {
    let command_frame = firmware_command_cbor(command)?;
    let mut stream = UnixStream::connect(socket_path)
        .with_context(|| format!("failed to connect managed serial socket {socket_path}"))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(250)))
        .with_context(|| format!("failed to set read timeout on {socket_path}"))?;
    stream
        .write_all(&command_frame)
        .with_context(|| format!("failed to write managed serial command to {socket_path}"))?;
    stream
        .flush()
        .with_context(|| format!("failed to flush {socket_path}"))?;
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut output = Vec::new();
    let mut records = String::new();
    let mut response_records = 0_usize;
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
                    let payload = mesh::cbor::decode_stream_frame(&frame)?;
                    let decoded =
                        mesh::cbor::decode_json(payload, &mesh::cbor::Catalog::default())?;
                    // Firmware response text is compact-CBOR payload tag 32.
                    // The generic catalog intentionally does not assign this
                    // firmware-private tag a global field name.
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
                    response_records += 1;
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
    if response_records == 0 {
        bail!("timed out waiting for framed firmware response from {socket_path}");
    }
    Ok(records)
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

/// Encode a raw-NAN command for one ESP target. The receiver applies the
/// normal `to=` filter before dispatching the method, so a broadcast follow-up
/// from the gateway cannot activate unrelated battery nodes.
fn firmware_targeted_command_cbor(command: &str, target: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(32);
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .map(2)
        .and_then(|encoder| encoder.u16(0))
        .and_then(|encoder| encoder.str(command))
        .and_then(|encoder| encoder.u16(6))
        .and_then(|encoder| encoder.map(1))
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
    // The first bytes after a DTR console wake can be consumed by UART wake
    // recovery. Retry once so the stability monitor does not turn a normal
    // dormant console into a missing raw-NAN health sample.
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

#[derive(Debug)]
struct SerialExchange {
    raw_text: String,
    messages: Vec<MeshMessage>,
}

fn serial_exchange_raw(
    path: &str,
    baud: u32,
    command: &str,
    timeout_ms: u64,
) -> Result<SerialExchange> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("failed to open serial radio {path}"))?;
    configure_serial(file.as_raw_fd(), baud)
        .with_context(|| format!("failed to configure serial radio {path}"))?;
    file.write_all(command.as_bytes())
        .with_context(|| format!("failed to write serial command to {path}"))?;
    file.write_all(b"\n")
        .with_context(|| format!("failed to write serial newline to {path}"))?;
    file.flush()
        .with_context(|| format!("failed to flush serial command to {path}"))?;

    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut bytes = Vec::new();
    let mut buf = [0_u8; 512];
    while std::time::Instant::now() < deadline {
        match file.read(&mut buf) {
            Ok(0) => std::thread::sleep(Duration::from_millis(10)),
            Ok(n) => {
                bytes.extend_from_slice(&buf[..n]);
                if bytes.ends_with(b"dm-rs> ") || bytes.ends_with(b"dm-rs>") {
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error).with_context(|| format!("failed to read from {path}")),
        }
    }

    let raw_text = String::from_utf8_lossy(&bytes).to_string();
    let messages = raw_text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| mesh::message::parse_firmware_message_line(line).ok())
        .collect();
    Ok(SerialExchange { raw_text, messages })
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
    /// One append-only, host-timestamped capture for all managed serial forwards.
    serial_log_path: Option<String>,
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
    dtr: Option<bool>,
    multi: Option<bool>,
    log: Option<bool>,
    /// Forward unframed serial output verbatim. This is for external sources
    /// such as power meters, never ESP firmware UARTs.
    raw: Option<bool>,
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
                "unknown tx_variant {other:?}; expected standard, zero_duration, no_duration, no_offchannel, minimal, dont_wait_ack, dont_wait_no_duration, dont_wait_minimal, onchannel, onchannel_noack, dont_wait_no_cck, no_cck, no_freq, monitor, monitor_active, multicast_data, multicast_data_active, sta_multicast_llc, sta_multicast_llc_active, sta_direct_llc, sta_direct_llc_active, roc, or pyroute2"
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
                Err(error) if registered == 0 => return Err(error),
                Err(_) => {}
            }
        }
        Ok(())
    }

    fn register_open_ap_sme_frames(&self, ifindex: u32) -> Vec<Value> {
        let registrations: [(&str, u16, &[u8]); 16] = [
            ("auth_open", 0x00b0, &[0x00, 0x00]),
            ("assoc_req", 0x0000, &[]),
            ("reassoc_req", 0x0020, &[]),
            ("disassoc", 0x00a0, &[]),
            ("deauth", 0x00c0, &[]),
            ("probe_req", 0x0040, &[]),
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

    fn remain_on_channel(&self, ifindex: u32, freq: u32, duration_ms: u32) -> Result<()> {
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
        self.recv_ack()
            .context("nl80211 remain-on-channel failed")?;
        let settle_ms = duration_ms.saturating_div(2).clamp(1, 20);
        std::thread::sleep(Duration::from_millis(settle_ms as u64));
        Ok(())
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
                probe_resp: false,
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
                probe_resp: false,
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
        let mut payload = genl_payload(NL80211_CMD_NEW_STATION, NL80211_GENL_VERSION);
        append_attr(&mut payload, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        append_attr(&mut payload, NL80211_ATTR_MAC, &mac);
        append_attr(&mut payload, NL80211_ATTR_STA_AID, &aid.to_ne_bytes());
        append_attr(
            &mut payload,
            NL80211_ATTR_STA_LISTEN_INTERVAL,
            &10_u16.to_ne_bytes(),
        );
        append_attr(
            &mut payload,
            NL80211_ATTR_STA_SUPPORTED_RATES,
            &[0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24],
        );
        let station_flags = NL80211_STA_FLAG_AUTHORIZED
            | NL80211_STA_FLAG_AUTHENTICATED
            | NL80211_STA_FLAG_ASSOCIATED;
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
        let mut buf = vec![0_u8; 65536];
        let read =
            unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if read < 0 {
            return Err(std::io::Error::last_os_error()).context("failed to receive netlink reply");
        }
        buf.truncate(read as usize);
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
        let read =
            unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if read < 0 {
            return Err(std::io::Error::last_os_error()).context("failed to receive netlink reply");
        }
        buf.truncate(read as usize);
        Ok(buf)
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
        Ok(Self { fd })
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
        match kind {
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
        match kind {
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
            NL80211_STA_INFO_CONNECTED_TIME => {
                insert_u32(&mut out, "connected_sec", value);
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
) {
    loop {
        match socket.recv_frame_with_signal() {
            Ok((frame, rx_signal_dbm)) => {
                let mut value = parse_management_frame(&frame, iface, "linux_nl80211_ap_sme");
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
            }
            Err(error) => {
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
            let add_station = Nl80211Socket::open()
                .and_then(|socket| socket.add_station_minimal(ifindex, sta_mac, aid))
                .map(|_| json!({ "ok": true }))
                .unwrap_or_else(|error| json!({ "ok": false, "error": format!("{error:#}") }));
            let response = build_open_assoc_response(ap_mac, sta_mac, aid);
            let tx = send_open_ap_mgmt_response(ifindex, &response);
            json!({
                "kind": "assoc_resp",
                "destination": colon_mac(&sta_mac),
                "aid": aid,
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
) {
    let receive_addresses = raw_wifi_receive_addresses(iface);
    let mut buf = [0_u8; 4096];
    loop {
        match socket.recv(&mut buf) {
            Ok(0) => continue,
            Ok(len) => {
                let packet = &buf[..len];
                if let Some(frame) = ieee80211_frame(packet)
                    && raw_wifi_receive_address_allowed(frame, &receive_addresses)
                    && let Some(value) =
                        parse_dmesh_wifi_frame(frame, iface, "linux_af_packet_monitor")
                {
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
        return is_plausible_80211_frame(frame).then_some(frame);
    }
    if is_plausible_80211_frame(packet) {
        return Some(packet);
    }
    None
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
    let encapsulation = if body.starts_with(&IEEE80211_LLC_SNAP_DMESH) {
        body = &body[IEEE80211_LLC_SNAP_LEN..];
        "llc_snap"
    } else {
        "raw_body"
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

fn build_open_assoc_response(ap: [u8; 6], sta: [u8; 6], aid: u16) -> Vec<u8> {
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
    frame.extend_from_slice(&hostapd_open_ap_extra_ies());
    frame
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
    let body_len = payload.len().min(1400);
    let mut frame = Vec::with_capacity(IEEE80211_BODY + DMESH_VENDOR_ACTION_LEN + body_len);
    frame.extend_from_slice(&[0xd0, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&destination);
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
    let mut history = history
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    history.push_back(event);
    while history.len() > MAX_HISTORY {
        history.pop_front();
    }
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
    let rc = unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR as libc::c_int, &mut request) };
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
            return raw_receive_mac(mac);
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
        if value.starts_with("rx:") || value.starts_with("raw:") {
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
    let rc = unsafe { libc::ioctl(fd, HCIDEVUP, dev_id as libc::c_int) };
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

#[cfg(test)]
mod tests {
    use super::*;
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
    fn empty_uart_frame_is_wake_activity_not_a_mesh_record() {
        let mut decoder = FirmwareUartDecoder::default();
        assert!(
            decoder
                .push(&[FIRMWARE_UART_FLAG, FIRMWARE_UART_FLAG])
                .unwrap()
                .is_empty()
        );
        assert!(decoder.take_frame_activity());
        assert!(!decoder.take_frame_activity());
    }

    #[test]
    fn framed_uds_command_waits_for_uart_heartbeat() {
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
                .flush_complete_records(-1, &mut serial_tx, &mut serial_pending, false)
                .unwrap()
        );
        assert!(serial_tx.is_empty());
        assert!(!serial_pending.is_empty());

        let mut decoder = FirmwareUartDecoder::default();
        assert!(
            decoder
                .push(&[FIRMWARE_UART_FLAG, FIRMWARE_UART_FLAG])
                .unwrap()
                .is_empty()
        );
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
                .flush_complete_records(-1, &mut serial_tx, &mut serial_pending, true)
                .unwrap()
        );
        assert!(!serial_tx.is_empty());
        assert!(serial_pending.is_empty());
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
                .flush_complete_records(-1, &mut serial_tx, &mut serial_pending, false)
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
    fn serial_forward_local_commands_are_bounded() {
        assert!(matches!(
            parse_serial_forward_command(b"dtr\n"),
            Some(Ok(SerialForwardCommand::Dtr(SERIAL_DTR_DEFAULT_MS)))
        ));
        assert!(matches!(
            parse_serial_forward_command(b"dtr 2500\r\n"),
            Some(Ok(SerialForwardCommand::Dtr(2500)))
        ));
        assert!(matches!(
            parse_serial_forward_command(b"rst\n"),
            Some(Ok(SerialForwardCommand::Reset))
        ));
        assert!(matches!(
            parse_serial_forward_command(b"dtr 0\n"),
            Some(Err(_))
        ));
        assert!(matches!(
            parse_serial_forward_command(b"dtr 10001\n"),
            Some(Err(_))
        ));
        assert!(parse_serial_forward_command(b"status\n").is_none());
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
