//! Hardware matrix for the shared raw UDP6/NOW transport.
//!
//! This is intentionally one ignored test: it holds one UART owner for e6
//! and one for e7 for the entire matrix rather than reopening USB serial for
//! each case. Run only on the lab host after both images are flashed and have
//! remained booted for at least 20 seconds; the suite never flashes, resets,
//! or starts/stops host Wi-Fi interfaces.
//!
//! ```sh
//! DMESH_E2E_E6=/dev/serial/by-id/...98:00-if00 \
//! DMESH_E2E_E7=/dev/serial/by-id/...5D:48-if00 \
//! cargo test -p dmesh-cli --test firmware_e2e -- --ignored --nocapture
//! ```

use dmesh_cli::{DeviceSession, DeviceSessionEvent};
use dmesh_server::cbor::Encoder;
use dmesh_server::probe::{ProbeEndpoint, ProbeEndpointKind, ProbeMode, ProbeRequest};
use dmesh_server::raw_wifi::{
    RAW_WIFI_METHOD_RESET_COUNTERS, RAW_WIFI_METHOD_SNAPSHOT, RawWifiApMode, RawWifiCheckRequest,
    RawWifiControlRequest, RawWifiDwPolicy, RawWifiInterface, RawWifiIperfRequest, RawWifiStaMode,
    RawWifiStaState, decode_raw_wifi_snapshot, encode_raw_wifi_check_request,
    encode_raw_wifi_control_request, encode_raw_wifi_iperf_request,
    encode_raw_wifi_snapshot_request,
};
use dmesh_server::{
    control::{self, Request as ControlRequest, TransportKind},
    iperf::{IperfServiceRequest, encode_iperf_service_request},
    tagged::decode as decode_tagged_record,
    udp::{ReceivedStream, UdpClient},
};
use mesh::{
    cbor::{decode_record, decode_stream_frame, encode_record, encode_stream_frame},
    tagged::{NameOrTag, TaggedCatalog, TaggedRecord},
};
use quic_lite::{ConnectionId, FIRST_CLIENT_BIDI_STREAM_ID, SERVICE_ECHO};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    os::unix::net::{UnixListener, UnixStream},
    process::Command,
    sync::LazyLock,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::time::timeout;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const E6_MAC: [u8; 6] = [0x14, 0xc1, 0x9f, 0xe5, 0x98, 0x00];
const E7_MAC: [u8; 6] = [0x14, 0xc1, 0x9f, 0xe4, 0x5d, 0x48];
const RAW_UDP6_PORT: u16 = 3339;
const STABLE_WIFI_UDP_PORT: u16 = 3336;
/// Default keeps the full hardware matrix quick enough for every shared
/// transport change. Set `DMESH_E2E_UDP6_BYTES=1048576` for the reproducible
/// sustained-goodput row without changing or reflashing firmware.
const E2E_UDP6_DEFAULT_BYTES: u64 = 64 * 1024;
const E2E_UDP6_PACKET_SIZE: u16 = quic_lite::DEFAULT_MAX_DATAGRAM_SIZE as u16;
const E2E_UDP6_TRANSFER_DEADLINE: Duration = Duration::from_secs(45);
const E2E_ACTION_IPERF_BYTES: u64 = 64 * 1024;

/// Stable, human-selected identity for a lab node. Android keeps its USB
/// serial because Wi-Fi MAC randomization means a MAC is only an observation.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct NodeIdentity {
    name: String,
    kind: String,
    mac: Option<String>,
    android_serial: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct PairProbeStatus {
    peer: String,
    test: String,
    last_result: String,
    last_seen_unix_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    nan_service_info: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sta_associated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    association_ms: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rssi_dbm: Option<i8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    throughput_bps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_us: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct NodeStatus {
    schema_version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity: Option<NodeIdentity>,
    #[serde(default)]
    pairs: BTreeMap<String, PairProbeStatus>,
}

fn node_store_root() -> std::path::PathBuf {
    std::env::var_os("DMESH_E2E_NODES_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("nodes"))
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_millis()
}

fn android_node_identity(serial: &str) -> NodeIdentity {
    let name = match serial {
        "94AAY0LALC" => "ap3a1",
        "RFCNB05AJ7E" => "agal1",
        _ => "andrunk",
    };
    NodeIdentity {
        name: name.to_owned(),
        kind: "android".to_owned(),
        mac: None,
        android_serial: Some(serial.to_owned()),
    }
}

fn e6_node_identity() -> NodeIdentity {
    NodeIdentity {
        name: "e6".to_owned(),
        kind: "esp32c6-recovery".to_owned(),
        mac: Some(hex(&E6_MAC)),
        android_serial: None,
    }
}

/// Persist the latest pair row in both node directories and append every run
/// to history.jsonl. TOML stays readable while JSONL remains analysis-ready.
fn record_pair_probe(left: &NodeIdentity, right: &NodeIdentity, mut observation: PairProbeStatus) {
    let root = node_store_root();
    let now = unix_millis();
    observation.last_seen_unix_ms = now;
    for (node, peer) in [(left, right), (right, left)] {
        let directory = root.join(&node.name);
        fs::create_dir_all(&directory)
            .unwrap_or_else(|error| panic!("create node directory {}: {error}", directory.display()));
        let status_path = directory.join("status.toml");
        let mut status = fs::read_to_string(&status_path)
            .ok()
            .and_then(|text| toml::from_str::<NodeStatus>(&text).ok())
            .unwrap_or_else(|| NodeStatus {
                schema_version: 1,
                identity: None,
                pairs: BTreeMap::new(),
            });
        status.schema_version = 1;
        status.identity = Some(node.clone());
        let mut pair = observation.clone();
        pair.peer = peer.name.clone();
        status.pairs.insert(peer.name.clone(), pair.clone());
        let encoded = toml::to_string_pretty(&status)
            .unwrap_or_else(|error| panic!("encode node status {}: {error}", node.name));
        fs::write(&status_path, encoded)
            .unwrap_or_else(|error| panic!("write node status {}: {error}", status_path.display()));
        let event = serde_json::json!({
            "schema_version": 1,
            "at_unix_ms": now,
            "node": node,
            "peer": peer,
            "result": pair,
        });
        let mut history = OpenOptions::new().create(true).append(true)
            .open(directory.join("history.jsonl"))
            .unwrap_or_else(|error| panic!("open node history {}: {error}", node.name));
        writeln!(history, "{event}")
            .unwrap_or_else(|error| panic!("append node history {}: {error}", node.name));
    }
}

/// Apply one endpoint mode as a complete replacement, never as a setting
/// overlay. The device side remains a low-level radio/control endpoint; the
/// privileged host controller owns this A-to-B orchestration and its signed
/// production counterpart records the same snapshots.
fn configure_probe_endpoint(
    session: &mut DeviceSession,
    mode: ProbeMode,
    ssid: &str,
    request_id: u64,
) {
    match mode.transport_kind {
        6 => configure_nan_for_channel(session, 6, request_id),
        1 => configure_sta_for_wlan0(session, ssid, request_id),
        unsupported => panic!("unsupported control-plane probe mode {unsupported}"),
    }
}

/// Establish the requested endpoint personalities and capture the common
/// NAN/DW/RSSI baseline. Bearer rows remain explicit below: this prevents a
/// successful NOW echo from being mistaken for UDP6 or NAN SD completion.
fn probe(
    source: &mut DeviceSession,
    target: &mut DeviceSession,
    request: ProbeRequest,
    ssid: &str,
    source_id: u64,
    target_id: u64,
) -> (
    dmesh_server::raw_wifi::RawWifiSnapshot,
    dmesh_server::raw_wifi::RawWifiSnapshot,
) {
    configure_probe_endpoint(source, request.source.mode, ssid, source_id);
    configure_probe_endpoint(target, request.target.mode, ssid, target_id);
    let source_snapshot = match request.source.mode.transport_kind {
        6 => wait_for_unassociated_channel_6(source),
        1 => wait_for_associated_channel_6(source),
        unsupported => panic!("unsupported control-plane probe mode {unsupported}"),
    };
    let target_snapshot = match request.target.mode.transport_kind {
        6 => wait_for_unassociated_channel_6(target),
        1 => wait_for_associated_channel_6(target),
        unsupported => panic!("unsupported control-plane probe mode {unsupported}"),
    };
    eprintln!(
        "firmware-e2e row=probe setup source_mode={:?} target_mode={:?} nan={} now={} udp6={} source=({}) target=({})",
        request.source.mode,
        request.target.mode,
        request.test_nan,
        request.test_now,
        request.test_udp6,
        snapshot_summary(&source_snapshot),
        snapshot_summary(&target_snapshot),
    );
    (source_snapshot, target_snapshot)
}

static LMESH_CATALOG: LazyLock<TaggedCatalog> = LazyLock::new(|| {
    let mut tools =
        serde_json::from_str::<serde_json::Value>(include_str!("../../lmesh/resources/tools.json"))
            .expect("lmesh tools catalog must be valid JSON");
    let wifi_tools = serde_json::from_str::<serde_json::Value>(include_str!(
        "../../lmesh-wifi/resources/tools.json"
    ))
    .expect("lmesh-wifi tools catalog must be valid JSON");
    tools
        .as_array_mut()
        .expect("lmesh tools catalog must be an array")
        .extend(
            wifi_tools
                .as_array()
                .expect("lmesh-wifi tools catalog must be an array")
                .iter()
                .cloned(),
        );
    TaggedCatalog::from_tools_json(&tools).expect("lmesh tools catalog must be valid")
});

static LMESH_WIFI_CATALOG: LazyLock<TaggedCatalog> = LazyLock::new(|| {
    TaggedCatalog::from_tools_json(
        &serde_json::from_str(include_str!("../../lmesh-wifi/resources/tools.json"))
            .expect("lmesh-wifi tools catalog must be valid JSON"),
    )
    .expect("lmesh-wifi tools catalog must be valid")
});

fn action_iperf_enabled() -> bool {
    matches!(
        std::env::var("DMESH_E2E_ACTION_IPERF").as_deref(),
        Ok("1" | "true")
    )
}

/// Number of fresh, one-shot action associations in each direction before an
/// IPERF row.  The normal regression stays quick; a lab run raises this (for
/// example `DMESH_E2E_ACTION_CHECK_REPEATS=12`) without reflashing.
fn action_check_repeats() -> u64 {
    match std::env::var("DMESH_E2E_ACTION_CHECK_REPEATS") {
        Ok(value) => value.parse::<u64>().unwrap_or_else(|error| {
            panic!("DMESH_E2E_ACTION_CHECK_REPEATS must be an integer, got {value:?}: {error}")
        }),
        Err(std::env::VarError::NotPresent) => 1,
        Err(error) => panic!("read DMESH_E2E_ACTION_CHECK_REPEATS: {error}"),
    }
    .clamp(1, 32)
}

/// MAC ACK remains an association-scoped radio choice, not a build feature.
/// The test records its exact value so off/on comparisons differ in only that
/// driver request field.
fn action_mac_ack() -> bool {
    match std::env::var("DMESH_E2E_ACTION_MAC_ACK") {
        Ok(value) if matches!(value.as_str(), "1" | "true" | "on") => true,
        Ok(value) if matches!(value.as_str(), "0" | "false" | "off") => false,
        Ok(value) => panic!("DMESH_E2E_ACTION_MAC_ACK must be on or off, got {value:?}"),
        Err(std::env::VarError::NotPresent) => false,
        Err(error) => panic!("read DMESH_E2E_ACTION_MAC_ACK: {error}"),
    }
}

/// Use the mandatory 6 Mbps OFDM rate for the automated bulk-performance row.
/// Legacy 1 Mbps remains selectable with `DMESH_E2E_NOW_RATE=1` when testing
/// the lowest-rate delivery path; it is not a useful host throughput baseline.
fn e2e_now_rate() -> u64 {
    match std::env::var("DMESH_E2E_NOW_RATE") {
        Ok(value) => value.parse::<u64>().unwrap_or_else(|error| {
            panic!("DMESH_E2E_NOW_RATE must be an integer Mbps rate, got {value:?}: {error}")
        }),
        Err(std::env::VarError::NotPresent) => 6,
        Err(error) => panic!("read DMESH_E2E_NOW_RATE: {error}"),
    }
}

fn e2e_now_timeout_ms() -> u64 {
    match std::env::var("DMESH_E2E_NOW_TIMEOUT_MS") {
        Ok(value) => value.parse::<u64>().unwrap_or_else(|error| {
            panic!("DMESH_E2E_NOW_TIMEOUT_MS must be an integer, got {value:?}: {error}")
        }),
        Err(std::env::VarError::NotPresent) => 10_000,
        Err(error) => panic!("read DMESH_E2E_NOW_TIMEOUT_MS: {error}"),
    }
}

fn e2e_now_packet_size() -> u64 {
    match std::env::var("DMESH_E2E_NOW_PACKET_SIZE") {
        Ok(value) => value.parse::<u64>().unwrap_or_else(|error| {
            panic!("DMESH_E2E_NOW_PACKET_SIZE must be an integer, got {value:?}: {error}")
        }),
        // Bulk IPERF uses the largest raw QUIC datagram that fits the action
        // bearer. Small control packets remain testable with an explicit
        // `DMESH_E2E_NOW_PACKET_SIZE=256` diagnostic run, but using them as
        // the throughput default amplifies one RF loss into a long PTO stall.
        Err(std::env::VarError::NotPresent) => quic_lite::DEFAULT_MAX_DATAGRAM_SIZE as u64,
        Err(error) => panic!("read DMESH_E2E_NOW_PACKET_SIZE: {error}"),
    }
}

fn e2e_now_bytes() -> u64 {
    std::env::var("DMESH_E2E_NOW_BYTES")
        .ok()
        .and_then(|value| value.parse().ok())
        // The separate `wifi.raw.check` row is the short bootstrap gate.
        // Once it succeeds, measure a meaningful sustained transfer by
        // default; callers can still choose a bounded diagnostic size.
        .unwrap_or(64 * 1024)
        .clamp(256, 1_048_576)
}

fn e2e_now_destination() -> String {
    if matches!(
        std::env::var("DMESH_E2E_NOW_A1").as_deref(),
        Ok("peer" | "unicast")
    ) {
        interface_mac("wlan1")
    } else {
        "ff:ff:ff:ff:ff:ff".to_owned()
    }
}

fn e2e_now_tx_variant() -> String {
    // The permanent active monitor is the connectionless NOW transmitter.
    // Managed nl80211 vendor-action TX remains an explicit driver diagnostic.
    std::env::var("DMESH_E2E_NOW_TX_VARIANT").unwrap_or_else(|_| "monitor".to_owned())
}

fn e2e_now_rx_variant() -> String {
    std::env::var("DMESH_E2E_NOW_RX_VARIANT").unwrap_or_else(|_| "monitor".to_owned())
}

fn e2e_now_min_bps() -> u64 {
    std::env::var("DMESH_E2E_NOW_MIN_BPS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000)
}

fn serial_from_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name} to the device serial path"))
}

fn interface_index(name: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
        .unwrap_or_else(|error| panic!("read {name} interface index: {error}"))
        .trim()
        .parse()
        .unwrap_or_else(|error| panic!("parse {name} interface index: {error}"))
}

fn interface_mac(name: &str) -> String {
    std::fs::read_to_string(format!("/sys/class/net/{name}/address"))
        .unwrap_or_else(|error| panic!("read {name} MAC: {error}"))
        .trim()
        .to_owned()
}

fn mem_available_kib() -> Option<u64> {
    std::fs::read_to_string("/proc/meminfo")
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("MemAvailable:")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
}

/// Invoke a supervised host service through its existing Unix socket with a
/// typed request. The request is serialized directly into catalog-tagged
/// fields; it never makes a `key=value` text round trip.
fn mesh_rpc_typed<T: Serialize>(service: &str, method: &str, request: &T) -> serde_json::Value {
    mesh_rpc_typed_at(
        service,
        method,
        request,
        &format!("/run/mesh/{service}/mesh.sock"),
    )
}

fn mesh_rpc_typed_at<T: Serialize>(
    service: &str,
    method: &str,
    request: &T,
    socket_path: &str,
) -> serde_json::Value {
    mesh_rpc_value_at(
        service,
        method,
        serde_json::to_value(request)
            .unwrap_or_else(|error| panic!("serialize {service} {method} request: {error}")),
        socket_path,
    )
}

/// The production AP fixture is externally provisioned. Tests may select the
/// development AP without changing it: `lmesh-wifi`/`wlan0` remains the
/// default, while `DMESH_E2E_AP_SERVICE=lmesh DMESH_E2E_AP_IFACE=wlan1`
/// selects the independent test service.
fn e2e_ap_service() -> String {
    std::env::var("DMESH_E2E_AP_SERVICE").unwrap_or_else(|_| "lmesh-wifi".to_owned())
}

fn e2e_ap_iface() -> String {
    std::env::var("DMESH_E2E_AP_IFACE").unwrap_or_else(|_| "wlan0".to_owned())
}

/// Read the AP identity from its owner.  Device association is deliberately
/// an explicit test action: no UDP row may depend on whichever SSID happened
/// to be left in a board's NVS by a prior flash or lab experiment.
fn wlan0_ssid() -> String {
    let service = e2e_ap_service();
    let iface = e2e_ap_iface();
    let response = mesh_rpc_typed(
        &service,
        "wifi.ap.status",
        &lmesh_wifi::api::ApStatusRequest {
            iface: Some(iface.clone()),
        },
    );
    response["data"]["ssid_default"]
        .as_str()
        .filter(|ssid| !ssid.is_empty())
        .unwrap_or_else(|| panic!("{service} did not report {iface} SSID: {response}"))
        .to_owned()
}

/// The supervised AP is the source of the complete ephemeral STA target.
/// Future NAN Service Info carries this same identity in one CBOR command.
fn wlan0_bssid_channel() -> ([u8; 6], u8) {
    let service = e2e_ap_service();
    let iface = e2e_ap_iface();
    let response = mesh_rpc_typed(
        &service,
        "wifi.ap.status",
        &lmesh_wifi::api::ApStatusRequest {
            iface: Some(iface.clone()),
        },
    );
    let bssid_text = response["data"]["bssid"]
        .as_str()
        .unwrap_or_else(|| panic!("{service} did not report {iface} BSSID: {response}"));
    let mut bssid = [0u8; 6];
    for (byte, text) in bssid.iter_mut().zip(bssid_text.split(':')) {
        *byte = u8::from_str_radix(text, 16)
            .unwrap_or_else(|_| panic!("invalid wlan0 BSSID {bssid_text:?}"));
    }
    assert_eq!(
        bssid_text.split(':').count(),
        6,
        "invalid wlan0 BSSID {bssid_text:?}"
    );
    let channel = response["data"]["channel"]
        .as_u64()
        .and_then(|value| u8::try_from(value).ok())
        .filter(|channel| (1..=14).contains(channel))
        .unwrap_or_else(|| panic!("{service} did not report {iface} channel: {response}"));
    (bssid, channel)
}

/// E2E consumes managed host radio fixtures. It may inspect their state but
/// must never bring an interface up/down, recreate a monitor, or retune it.
fn require_host_iface_up(service: &str, iface: &str) {
    let status = mesh_rpc_typed(
        service,
        "wifi.interface.status",
        &lmesh_wifi::api::InterfaceStatusRequest {
            iface: Some(iface.to_owned()),
        },
    );
    let link = status["data"]["link"]["stdout"]
        .as_str()
        .unwrap_or_else(|| panic!("{service} did not report {iface} link state: {status}"));
    let flags = link
        .split('<')
        .nth(1)
        .and_then(|rest| rest.split('>').next())
        .unwrap_or_default();
    assert!(
        flags.split(',').any(|flag| flag == "UP"),
        "{service} fixture {iface} is down: {status}"
    );
}

fn wifi_raw_check(
    service: &str,
    iface: &str,
    destination: String,
    nonce: u64,
    timeout_ms: u64,
    tx_rate_mbps: u8,
    tx_variant: &str,
    rx_variant: &str,
) -> serde_json::Value {
    mesh_rpc_typed(
        service,
        "wifi.raw.check",
        &lmesh_wifi::api::RawCheckRequest {
            iface: Some(iface.to_owned()),
            channel: Some(6),
            destination,
            nonce: Some(nonce),
            timeout_ms: Some(timeout_ms),
            tx_rate_mbps: Some(tx_rate_mbps),
            tx_variant: Some(tx_variant.to_owned()),
            rx_variant: Some(rx_variant.to_owned()),
            expected_peer: None,
        },
    )
}

fn wifi_raw_iperf(
    service: &str,
    iface: &str,
    destination: String,
    bytes: u64,
    packet_size: u16,
    timeout_ms: u64,
    tx_rate_mbps: u8,
    tx_variant: &str,
    rx_variant: &str,
) -> serde_json::Value {
    mesh_rpc_typed(
        service,
        "wifi.raw.iperf",
        &lmesh_wifi::api::RawIperfRequest {
            iface: Some(iface.to_owned()),
            channel: Some(6),
            destination,
            bytes: Some(bytes),
            packet_size: Some(packet_size),
            timeout_ms: Some(timeout_ms),
            tx_rate_mbps: Some(tx_rate_mbps),
            tx_variant: Some(tx_variant.to_owned()),
            rx_variant: Some(rx_variant.to_owned()),
            expected_peer: None,
        },
    )
}

fn wifi_raw_check_for_peer(
    service: &str,
    iface: &str,
    destination: String,
    expected_peer: String,
    nonce: u64,
    timeout_ms: u64,
    tx_rate_mbps: u8,
    tx_variant: &str,
    rx_variant: &str,
) -> serde_json::Value {
    mesh_rpc_typed(
        service,
        "wifi.raw.check",
        &lmesh_wifi::api::RawCheckRequest {
            iface: Some(iface.to_owned()),
            channel: Some(6),
            destination,
            nonce: Some(nonce),
            timeout_ms: Some(timeout_ms),
            tx_rate_mbps: Some(tx_rate_mbps),
            tx_variant: Some(tx_variant.to_owned()),
            rx_variant: Some(rx_variant.to_owned()),
            expected_peer: Some(expected_peer),
        },
    )
}

fn wifi_raw_iperf_for_peer(
    service: &str,
    iface: &str,
    destination: String,
    expected_peer: String,
    bytes: u64,
    packet_size: u16,
    timeout_ms: u64,
    tx_rate_mbps: u8,
    tx_variant: &str,
    rx_variant: &str,
) -> serde_json::Value {
    mesh_rpc_typed(
        service,
        "wifi.raw.iperf",
        &lmesh_wifi::api::RawIperfRequest {
            iface: Some(iface.to_owned()),
            channel: Some(6),
            destination,
            bytes: Some(bytes),
            packet_size: Some(packet_size),
            timeout_ms: Some(timeout_ms),
            tx_rate_mbps: Some(tx_rate_mbps),
            tx_variant: Some(tx_variant.to_owned()),
            rx_variant: Some(rx_variant.to_owned()),
            expected_peer: Some(expected_peer),
        },
    )
}

/// Invoke a supervised host service through its existing Unix socket.
///
/// A fully numeric component/method pair uses framed tagged CBOR; everything
/// else uses JSON-RPC, never the former flat JSONL dialect. This explicit
/// `Value` variant is only for unreviewed operations that do not yet have a
/// reviewed Rust request struct. Each request owns a short socket connection
/// so concurrent capture/probe rows cannot serialize behind one subscription
/// stream; no AP or service process is created here.
fn mesh_rpc_value(service: &str, method: &str, params: serde_json::Value) -> serde_json::Value {
    mesh_rpc_value_at(
        service,
        method,
        params,
        &format!("/run/mesh/{service}/mesh.sock"),
    )
}

/// Same request policy as [`mesh_rpc_value`], with an explicit path for local
/// codec tests. Production E2E calls retain the supervised mesh-init socket.
fn mesh_rpc_value_at(
    service: &str,
    method: &str,
    params: serde_json::Value,
    socket_path: &str,
) -> serde_json::Value {
    let catalog = control_catalog(service);
    let mut record = catalog
        .record_from_value(method, &params)
        .unwrap_or_else(|error| panic!("build {service} {method}: {error}"));
    record.id = Some(serde_json::json!(1));
    let tagged_cbor = uses_tagged_cbor(&record);
    let encoded = if tagged_cbor {
        encode_stream_frame(
            &encode_record(&record)
                .unwrap_or_else(|error| panic!("encode CBOR {service} {method}: {error}")),
        )
        .unwrap_or_else(|error| panic!("frame CBOR {service} {method}: {error}"))
    } else {
        let mut flat = catalog.to_jsonl(&record);
        let flat = flat
            .as_object_mut()
            .expect("catalog JSON conversion must be an object");
        let rpc_method = flat.remove("method").expect("catalog JSON has method");
        let id = flat.remove("id").expect("catalog JSON has id");
        serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": rpc_method,
            "params": flat,
        }))
        .unwrap_or_else(|error| panic!("encode JSON-RPC {service} {method}: {error}"))
    };
    let mut last_error = None;
    for _ in 0..6 {
        match UnixStream::connect(socket_path) {
            Ok(mut stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(20)))
                    .expect("set mesh socket read timeout");
                stream
                    .set_write_timeout(Some(Duration::from_secs(20)))
                    .expect("set mesh socket write timeout");
                let write = if tagged_cbor {
                    stream.write_all(&encoded).and_then(|_| stream.flush())
                } else {
                    stream
                        .write_all(&encoded)
                        .and_then(|_| stream.write_all(b"\n"))
                        .and_then(|_| stream.flush())
                };
                if let Err(error) = write {
                    last_error = Some(format!("write {socket_path}: {error}"));
                    continue;
                }
                let response = if tagged_cbor {
                    read_cbor_response(&mut stream, service, method)
                } else {
                    read_json_rpc_response(&mut stream, service, method)
                };
                let response = match response {
                    Ok(response) => response,
                    Err(error) => {
                        last_error = Some(format!("read {socket_path}: {error}"));
                        continue;
                    }
                };
                assert!(
                    response.get("success").and_then(serde_json::Value::as_bool) != Some(false),
                    "mesh {service} {method} failed: {response}"
                );
                return response;
            }
            Err(error) => {
                last_error = Some(format!("connect {socket_path}: {error}"));
                thread::sleep(Duration::from_millis(250));
            }
        }
    }
    panic!(
        "mesh {service} {method} failed after retries: {}",
        last_error.unwrap_or_default()
    );
}

/// Only a catalog-selected pair of numeric identifiers is eligible for CBOR.
/// Named CBOR would create a third compatibility dialect, so unreviewed
/// commands intentionally use JSON-RPC until their API.md fields are stable.
fn uses_tagged_cbor(record: &TaggedRecord) -> bool {
    matches!(
        (&record.component, &record.method),
        (NameOrTag::Tag(_), NameOrTag::Tag(_))
    )
}

fn control_catalog(service: &str) -> &'static TaggedCatalog {
    match service {
        "lmesh" => &LMESH_CATALOG,
        "lmesh-wifi" => &LMESH_WIFI_CATALOG,
        _ => panic!("no installed generated catalog for host service {service:?}"),
    }
}

fn read_cbor_response(
    stream: &mut UnixStream,
    service: &str,
    method: &str,
) -> Result<serde_json::Value, String> {
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|error| format!("read CBOR header: {error}"))?;
    let len = u32::from_be_bytes(header) as usize;
    let mut frame = Vec::with_capacity(len + 4);
    frame.extend_from_slice(&header);
    frame.resize(len + 4, 0);
    stream
        .read_exact(&mut frame[4..])
        .map_err(|error| format!("read CBOR frame: {error}"))?;
    let response = decode_record(
        decode_stream_frame(&frame).map_err(|error| format!("decode CBOR frame: {error}"))?,
    )
    .map_err(|error| format!("decode CBOR record: {error}"))?;
    response.result.ok_or_else(|| {
        format!(
            "{service} {method} returned CBOR error {}",
            response.error.unwrap_or(serde_json::Value::Null)
        )
    })
}

fn read_json_rpc_response(
    stream: &mut UnixStream,
    service: &str,
    method: &str,
) -> Result<serde_json::Value, String> {
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .map_err(|error| format!("read JSON-RPC line: {error}"))?;
    let response: serde_json::Value = serde_json::from_str(line.trim()).map_err(|error| {
        format!("decode JSON-RPC {service} {method}: {error}; response={line:?}")
    })?;
    if let Some(error) = response.get("error") {
        return Err(format!("JSON-RPC error: {error}"));
    }
    Ok(response.get("result").cloned().unwrap_or(response))
}

/// Reviewed CBOR replies retain a `data` wrapper, while legacy JSON-RPC
/// replies return their `result` directly. History is intentionally available
/// through both during the migration, so E2E must inspect the semantic events
/// rather than mistake that envelope difference for missing RF delivery.
fn history_events(response: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
    response
        .get("data")
        .unwrap_or(response)
        .get("events")
        .and_then(serde_json::Value::as_array)
}

#[test]
fn host_control_catalog_selects_cbor_only_for_reviewed_methods() {
    let status = control_catalog("lmesh-wifi")
        .record_from_value("wifi.ap.status", &serde_json::json!({"iface": "wlan0"}))
        .expect("reviewed status method builds");
    assert!(uses_tagged_cbor(&status));

    let lmesh_status = control_catalog("lmesh")
        .record_from_value("wifi.ap.status", &serde_json::json!({"iface": "wlan1"}))
        .expect("merged lmesh Wi-Fi status method builds");
    assert!(uses_tagged_cbor(&lmesh_status));

    let raw_send = control_catalog("lmesh-wifi")
        .record_from_value(
            "wifi.raw.send",
            &serde_json::json!({"iface": "wlan0", "channel": 6, "payload": "probe"}),
        )
        .expect("reviewed raw send method builds");
    assert!(uses_tagged_cbor(&raw_send));

    let management_capture = control_catalog("lmesh")
        .record_from_value(
            "wifi.mgmt.capture",
            &serde_json::json!({"iface": "wlan1", "channel": 6}),
        )
        .expect("reviewed management capture method builds");
    assert!(uses_tagged_cbor(&management_capture));

    let unreviewed = control_catalog("lmesh-wifi")
        .record_from_value(
            "wifi.experimental.inspect",
            &serde_json::json!({"iface": "wlan0"}),
        )
        .expect("unreviewed inspection method builds");
    assert!(!uses_tagged_cbor(&unreviewed));
}

fn codec_test_socket(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "dmesh-{name}-{}-{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_nanos(),
    ))
}

#[test]
fn host_control_cbor_request_and_response_use_framed_numeric_records() {
    let path = codec_test_socket("cbor");
    let listener = UnixListener::bind(&path).expect("bind local CBOR test socket");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept CBOR test request");
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).expect("read request header");
        let length = u32::from_be_bytes(header) as usize;
        let mut frame = header.to_vec();
        frame.resize(length + 4, 0);
        stream
            .read_exact(&mut frame[4..])
            .expect("read request frame");
        let record = decode_record(decode_stream_frame(&frame).expect("decode request frame"))
            .expect("decode request record");
        assert!(matches!(record.component, NameOrTag::Tag(5)));
        assert!(matches!(record.method, NameOrTag::Tag(1)));
        assert_eq!(
            record.env.get(&NameOrTag::Tag(1)),
            Some(&serde_json::json!("wlan0"))
        );
        let response = mesh::wire::response_ok(
            record.id.expect("request id"),
            serde_json::json!({"success": true, "data": {"codec": "cbor"}}),
        );
        let frame = encode_stream_frame(&encode_record(&response).expect("encode response"))
            .expect("frame response");
        stream.write_all(&frame).expect("write CBOR response");
    });

    let response = mesh_rpc_typed_at(
        "lmesh-wifi",
        "wifi.ap.status",
        &lmesh_wifi::api::ApStatusRequest {
            iface: Some("wlan0".to_owned()),
        },
        path.to_str().expect("UTF-8 socket path"),
    );
    assert_eq!(response["data"]["codec"], "cbor");
    server.join().expect("CBOR test server panicked");
    std::fs::remove_file(path).expect("remove CBOR test socket");
}

#[test]
fn host_control_unreviewed_inspection_request_and_response_use_json_rpc() {
    let path = codec_test_socket("json-rpc");
    let listener = UnixListener::bind(&path).expect("bind local JSON-RPC test socket");
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept JSON-RPC test request");
        let mut line = String::new();
        let mut reader = BufReader::new(stream.try_clone().expect("clone test stream"));
        reader.read_line(&mut line).expect("read JSON-RPC request");
        let request: serde_json::Value =
            serde_json::from_str(&line).expect("decode JSON-RPC request");
        assert_eq!(request["jsonrpc"], "2.0");
        assert_eq!(request["method"], "wifi.experimental.inspect");
        assert_eq!(request["params"]["iface"], "wlan0");
        let mut stream = stream;
        writeln!(
            stream,
            "{}",
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": request["id"].clone(),
                "result": {"success": true, "data": {"codec": "json-rpc"}},
            })
        )
        .expect("write JSON-RPC response");
    });

    let response = mesh_rpc_value_at(
        "lmesh-wifi",
        "wifi.experimental.inspect",
        serde_json::json!({"iface": "wlan0"}),
        path.to_str().expect("UTF-8 socket path"),
    );
    assert_eq!(response["data"]["codec"], "json-rpc");
    server.join().expect("JSON-RPC test server panicked");
    std::fs::remove_file(path).expect("remove JSON-RPC test socket");
}

#[test]
#[ignore = "requires the supervised lmesh/lmesh-wifi host radios"]
fn host_host_nan_sync_and_sd_e2e() {
    // Manual equivalence, for the one-time fixture proof before changing this
    // row. The automated test below is the permanent version: it builds the
    // same SDF from the shared Rust encoder, sends it once, and asserts the
    // peer's semantic receipt rather than relying on a shell transcript.
    //
    //   mesh lmesh wifi.rawnan.status iface=wlan1
    //   mesh lmesh-wifi wifi.raw.send iface=wlan0 channel=6 \
    //     tx_variant=monitor tx_rate_mbps=6 frame_hex=<build_nan_publish_sdf>
    //   mesh lmesh messages.history keys=wifi.rawnan.discovery limit=64
    //
    // The active-subscribe half similarly corresponds to
    // `build_nan_usd_sdf`; its response is a DW-gated NAN Follow-up, not an
    // ESP-NOW/vendor action or a host-interface lifecycle operation.
    // wlan0 is the associated/AP fixture and wlan1 is the unassociated
    // monitor fixture.  Neither radio is started, stopped, retuned, or
    // otherwise reconfigured here: the receiver only opens a bounded socket
    // on its permanent monitor.
    require_host_iface_up("lmesh-wifi", "wlan0");
    require_host_iface_up("lmesh", "wlan1mon");
    let listen = mesh_rpc_typed(
        "lmesh",
        "wifi.rawnan.listen",
        &lmesh_wifi::api::RawNanListenRequest {
            iface: Some("wlan1".to_owned()),
            channel: Some(6),
            listen_sec: Some(5),
        },
    );
    assert_eq!(
        listen["data"]["ok"].as_bool(),
        Some(true),
        "NAN listener: {listen}"
    );

    // Android normally supplies a NAN cluster beacon. If Android is absent,
    // an ESP AP configured at the 500-TU fallback interval can supply it.
    // The host AP is deliberately not a fallback: this test must not pretend
    // an ordinary host beacon is a NAN clock or reconfigure any host radio.
    let source = interface_mac("wlan0");
    // History is a long-lived diagnostic ring. Scope every assertion to this
    // probe epoch so yesterday's identical transport.start CBOR or follow-up
    // cannot satisfy a fresh on-air NAN test.
    let probe_started_ms = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("wall clock after Unix epoch")
        .as_millis() as u64;
    let deadline = Instant::now() + Duration::from_secs(5);
    let nan_sync = loop {
        let status = mesh_rpc_typed(
            "lmesh",
            "wifi.rawnan.status",
            &lmesh_wifi::api::RawNanStatusRequest {
                iface: Some("wlan1".to_owned()),
            },
        );
        if status["data"]["sync_bssid"].as_str().is_some()
            && status["data"]["last_beacon_tsf_us"].as_u64().unwrap_or(0) != 0
        {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "wlan1 did not observe an Android or ESP NAN timing beacon: {status}"
        );
        thread::sleep(Duration::from_millis(100));
    };
    eprintln!("firmware-e2e row=host-host-nan sync={nan_sync}");

    // The startup service owns a real active-Publish descriptor. Prove that
    // its queued CBOR announce was emitted from a synchronized DW before
    // injecting any bespoke E2E SDF below; otherwise a manual frame could
    // hide a regression in the production periodic-publish path.
    let default_publish_deadline = Instant::now() + Duration::from_secs(3);
    let default_publish = loop {
        let status = mesh_rpc_typed(
            "lmesh",
            "wifi.rawnan.status",
            &lmesh_wifi::api::RawNanStatusRequest {
                iface: Some("wlan1".to_owned()),
            },
        );
        let active = &status["data"]["active_publish"];
        if active["enabled"].as_bool() == Some(true)
            && active["pending"].as_bool() == Some(false)
            && active["last_sent_ms"].as_u64().unwrap_or(0) != 0
        {
            break status;
        }
        assert!(
            Instant::now() < default_publish_deadline,
            "wlan1 default active Publish did not transmit in a synchronized DW: {status}"
        );
        thread::sleep(Duration::from_millis(100));
    };
    eprintln!("firmware-e2e row=host-host-nan default_publish={default_publish}");

    // The active-subscribe/publish Service Info is a CBOR control command,
    // not text or a second discovery protocol: `{1: control,
    // 2: transport.start, 5: {1: nan}}`.
    let command = [0xa3, 1, 1, 2, 4, 5, 0xa1, 1, 6];
    let mut source_mac = [0u8; 6];
    for (dst, text) in source_mac.iter_mut().zip(source.split(':')) {
        *dst = u8::from_str_radix(text, 16).expect("wlan0 MAC byte");
    }
    let cluster_bssid = nan_sync["data"]["sync_bssid"]
        .as_str()
        .expect("NAN timing BSSID")
        .to_owned();
    let mut cluster_mac = [0u8; 6];
    for (dst, text) in cluster_mac.iter_mut().zip(cluster_bssid.split(':')) {
        *dst = u8::from_str_radix(text, 16).expect("NAN timing BSSID byte");
    }
    let frame = dmesh_rawnan::build_nan_publish_sdf(
        dmesh_rawnan::NAN_DISCOVERY_MAC,
        source_mac,
        cluster_mac,
        dmesh_rawnan::DMESH_SERVICE_ID,
        1,
        &command,
    );
    let publish_hex = hex(&frame);
    let send_publish = || {
        mesh_rpc_typed(
            "lmesh-wifi",
            "wifi.raw.send",
            &lmesh_wifi::api::RawSendRequest {
                iface: Some("wlan0".to_owned()),
                channel: Some(6),
                // The permanent active monitor is the proven on-air action
                // lane. `wifi.raw.send` only consumes it; it never recreates
                // or retunes host radio state during this E2E row.
                tx_variant: Some("monitor".to_owned()),
                tx_rate_mbps: Some(6),
                frame_hex: Some(publish_hex.clone()),
            },
        )
    };
    eprintln!(
        "firmware-e2e row=host-host-nan publish source={source} cluster={cluster_bssid} frame_hex={publish_hex}"
    );
    let sd = send_publish();
    assert!(
        sd.get("data")
            .and_then(|value| value.get("ok"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        "host NAN SDF injection failed: {sd}"
    );
    let command_hex = hex(&command);
    // Do not treat a single 512-TU DW as a deadline. The paired ESP and
    // Android configurations can legitimately select DW8, roughly 4.2 s;
    // poll through two opportunities and leave evidence of the last history
    // response if the permanent listeners did not observe the active SDF.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut next_publish = Instant::now() + Duration::from_millis(1_000);
    let mut publishes = 1_u8;
    let (delivered, received) = loop {
        let received = mesh_rpc_value(
            "lmesh",
            "messages.history",
            serde_json::json!({"keys": "wifi.rawnan.discovery", "limit": 64}),
        );
        let delivered = history_events(&received).is_some_and(|events| {
            events.iter().any(|event| {
                event["ts_millis"]
                    .as_u64()
                    .is_some_and(|ts| ts >= probe_started_ms)
                    && event["value"]["peer"].as_str() == Some(source.as_str())
                    && event["value"]["service_info_hex"].as_str() == Some(command_hex.as_str())
            })
        });
        if delivered || Instant::now() >= deadline {
            break (delivered, received);
        }
        // Active publish is periodic in production. Re-send the identical
        // bounded CBOR Service Info over several 512-TU opportunities so a
        // single monitor-frame loss cannot turn the semantic test into a
        // flaky one-shot RF test. This does not alter either host interface.
        if Instant::now() >= next_publish && publishes < 5 {
            let retry = send_publish();
            assert_eq!(
                retry["data"]["ok"].as_bool(),
                Some(true),
                "host NAN SDF retry failed: {retry}"
            );
            publishes += 1;
            next_publish += Duration::from_millis(1_000);
        }
        thread::sleep(Duration::from_millis(250));
    };
    assert!(
        delivered,
        "wlan1 did not receive the NAN SDF/CBOR command from wlan0 after {publishes} active publishes: {received}"
    );

    // The companion active-subscribe row verifies the distinct SDEA carrier
    // for custom SSI. It is intentionally a second on-air frame: a peer may
    // choose DW8, so never infer SDEA support from the preceding Publish.
    let active_subscribe = dmesh_rawnan::build_nan_usd_sdf(
        dmesh_rawnan::NAN_DISCOVERY_MAC,
        source_mac,
        dmesh_rawnan::DMESH_SERVICE_ID,
        7,
        0x11,
        &command,
    );
    let active_subscribe_tx = mesh_rpc_typed(
        "lmesh-wifi",
        "wifi.raw.send",
        &lmesh_wifi::api::RawSendRequest {
            iface: Some("wlan0".to_owned()),
            channel: Some(6),
            // See the publish row above: consume the already-prepared active
            // monitor and do not alter host radio lifecycle.
            tx_variant: Some("monitor".to_owned()),
            tx_rate_mbps: Some(6),
            frame_hex: Some(hex(&active_subscribe)),
        },
    );
    assert!(
        active_subscribe_tx["data"]["ok"].as_bool() == Some(true),
        "host NAN active-subscribe injection failed: {active_subscribe_tx}"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let active_subscribe_hex = hex(&command);
    let (active_subscribe_seen, active_subscribe_events) = loop {
        let events = mesh_rpc_value(
            "lmesh",
            "messages.history",
            serde_json::json!({"keys": "wifi.rawnan.discovery", "limit": 64}),
        );
        let seen = history_events(&events).is_some_and(|items| {
            items.iter().any(|event| {
                event["ts_millis"]
                    .as_u64()
                    .is_some_and(|ts| ts >= probe_started_ms)
                    && event["value"]["active_subscribe"]["service_info_hex"].as_str()
                        == Some(active_subscribe_hex.as_str())
            })
        });
        if seen || Instant::now() >= deadline {
            break (seen, events);
        }
        thread::sleep(Duration::from_millis(250));
    };
    assert!(
        active_subscribe_seen,
        "wlan1 did not recover custom active-subscribe SDEA Service Info: {active_subscribe_events}"
    );
    // The subscriber replies once on its permanent monitor; wait through the
    // return DW rather than treating the transmitter's local write as proof.
    let deadline = Instant::now() + Duration::from_secs(10);
    let (followup_seen, followup_events) = loop {
        let events = mesh_rpc_value(
            "lmesh-wifi",
            "messages.history",
            serde_json::json!({"keys": "wifi.rawnan.discovery", "limit": 64}),
        );
        let seen = history_events(&events).is_some_and(|items| {
            items.iter().any(|event| {
                event["ts_millis"]
                    .as_u64()
                    .is_some_and(|ts| ts >= probe_started_ms)
                    && event["value"]["followup"]["msg_type"].as_u64() == Some(7)
                    && event["value"]["followup"]["payload_hex"].as_str()
                        == Some(active_subscribe_hex.as_str())
            })
        });
        if seen || Instant::now() >= deadline {
            break (seen, events);
        }
        thread::sleep(Duration::from_millis(250));
    };
    assert!(
        followup_seen,
        "wlan0 did not receive the active-subscribe NAN follow-up: {followup_events}"
    );
}

#[test]
#[ignore = "requires an Android DMesh service already publishing NAN on channel 6"]
fn host_observes_android_nan_announce_e2e() {
    // Manual equivalent (read-only; no host-interface lifecycle operation):
    //
    //   mesh lmesh wifi.rawnan.status iface=wlan1
    //   mesh lmesh messages.history keys=wifi.rawnan.discovery limit=128
    //
    // Android's Wi-Fi Aware service continuously publishes its DMesh announce
    // and service descriptor. The permanent wlan1 monitor must report both a
    // fresh announce and its enclosing DMesh SDF; this proves raw host
    // observation of the Android on-air format, not merely Android's own
    // framework callback history.
    require_host_iface_up("lmesh", "wlan1mon");
    let started_ms = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("wall clock after Unix epoch")
        .as_millis() as u64;
    let deadline = Instant::now() + Duration::from_secs(10);
    let (observed, history) = loop {
        let status = mesh_rpc_typed(
            "lmesh",
            "wifi.rawnan.status",
            &lmesh_wifi::api::RawNanStatusRequest {
                iface: Some("wlan1".to_owned()),
            },
        );
        let announce_peers = status["data"]["observed_announces"]
            .as_array()
            .map(|announces| {
                announces
                    .iter()
                    .filter_map(|item| item["peer"].as_str().map(str::to_owned))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let history = mesh_rpc_value(
            "lmesh",
            "messages.history",
            serde_json::json!({"keys": "wifi.rawnan.discovery", "limit": 128}),
        );
        let observed = !announce_peers.is_empty()
            && history_events(&history).is_some_and(|events| {
                events.iter().any(|event| {
                    event["ts_millis"]
                        .as_u64()
                        .is_some_and(|ts| ts >= started_ms)
                        && event["value"]["service_id"].as_str()
                            == Some(hex(&dmesh_rawnan::DMESH_SERVICE_ID).as_str())
                        && event["value"]["announce"].is_object()
                })
            });
        if observed || Instant::now() >= deadline {
            break (observed, history);
        }
        thread::sleep(Duration::from_millis(250));
    };
    assert!(
        observed,
        "wlan1 did not observe a fresh Android DMesh NAN announce/SDF: {history}"
    );
}

#[test]
#[ignore = "requires the supervised lmesh/lmesh-wifi host radios"]
fn host_host_now_check_e2e() {
    // Equivalent command:
    //   mesh lmesh wifi.raw.check iface=wlan1 channel=6 \
    //     destination=<wlan0 MAC> nonce=... timeout_ms=5000 \
    //     tx_rate_mbps=6 tx_variant=monitor rx_variant=nl80211
    // This is the always-on connectionless NOW sanity row.  Keep it separate
    // from IPERF so a throughput regression cannot be hidden by a successful
    // bootstrap/echo exchange.
    // Resolve the peer at test time.  The supervised development service may
    // recreate wlan1 with a different locally-administered MAC; keeping the
    // old lab address here makes the automated check silently transmit to a
    // nonexistent peer.
    // The supervised AP and its permanent monitor are fixtures. This test
    // wlan0 is the stable AP fixture; wlan1mon is lmesh's AP-off NOW
    // transport. The test only consumes their existing radio state.
    require_host_iface_up("lmesh-wifi", "wlan0");
    require_host_iface_up("lmesh", "wlan1mon");
    // ESP-NOW-compatible bootstrap uses broadcast Address-1. The remote
    // dispatcher returns its response to the sender's Address-2, so do not
    // substitute the monitor VIF's unicast MAC here.
    let destination = e2e_now_destination();
    let mut last = serde_json::Value::Null;
    for attempt in 0..3 {
        let result = wifi_raw_check(
            "lmesh",
            "wlan1",
            destination.clone(),
            0x4e4f_5700_u64 + attempt,
            5_000,
            e2e_now_rate() as u8,
            &e2e_now_tx_variant(),
            "monitor",
        );
        let data = result.get("data").unwrap_or(&result);
        if data.get("ok").and_then(serde_json::Value::as_bool) == Some(true)
            && data
                .get("rx_packets")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
                > 0
        {
            return;
        }
        last = result;
    }
    panic!("NOW check failed after retries: {last}");
}

#[test]
#[ignore = "requires the supervised lmesh/lmesh-wifi host radios"]
fn host_host_now_monitor_capture_e2e() {
    // RF-level diagnostic equivalent:
    //   mesh lmesh wifi.mgmt.capture iface=wlan1 channel=6 capture_ms=5000
    //   mesh lmesh-wifi wifi.raw.check iface=wlan0 channel=6 destination=<wlan1>
    // Run the capture and probe concurrently; this intentionally does not
    // install the QUIC dispatcher, so it isolates monitor RX/TX from service
    // dispatch and reports whether any action frame reached the second radio.
    let destination = e2e_now_destination();
    // Capture and probe the permanently provisioned monitor; no test-owned
    // interface, channel, AP, or monitor lifecycle is allowed here.
    let capture_thread = thread::spawn(move || {
        mesh_rpc_value(
            "lmesh",
            "wifi.mgmt.capture",
            serde_json::json!({"iface": "wlan1", "channel": 6, "capture_ms": 5000, "max_frames": 256, "active": false}),
        )
    });
    thread::sleep(Duration::from_millis(500));
    let probe = mesh_rpc_value(
        "lmesh-wifi",
        "wifi.raw.check",
        serde_json::json!({
            "iface": "wlan0", "channel": 6, "destination": destination, "nonce": 131074,
            "timeout_ms": 3000, "tx_rate_mbps": e2e_now_rate(),
            "tx_variant": "monitor", "rx_variant": "monitor",
        }),
    );
    let capture = capture_thread.join().expect("capture thread");
    let frame_count = capture
        .get("data")
        .and_then(|v| v.get("frame_count"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let action_count = capture
        .get("data")
        .and_then(|v| v.get("frames"))
        .and_then(serde_json::Value::as_array)
        .map(|frames| {
            frames
                .iter()
                .filter(|frame| {
                    frame
                        .get("frame_subtype")
                        .and_then(serde_json::Value::as_u64)
                        == Some(13)
                })
                .count() as u64
        })
        .unwrap_or(0);
    let sender_mac = interface_mac("wlan0");
    let sender_action_count = capture
        .get("data")
        .and_then(|v| v.get("frames"))
        .and_then(serde_json::Value::as_array)
        .map(|frames| {
            frames
                .iter()
                .filter(|frame| {
                    frame
                        .get("frame_subtype")
                        .and_then(serde_json::Value::as_u64)
                        == Some(13)
                })
                .filter(|frame| {
                    frame.get("source").and_then(serde_json::Value::as_str)
                        == Some(sender_mac.as_str())
                })
                .count() as u64
        })
        .unwrap_or(0);
    let probe_ok = probe
        .get("data")
        .and_then(|v| v.get("ok"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    eprintln!(
        "NOW monitor diagnostic probe_ok={probe_ok} frames={frame_count} actions={action_count} sender_actions={sender_action_count} sender_mac={sender_mac}"
    );
    assert!(
        frame_count > 0 && sender_action_count > 0,
        "monitor saw frames={frame_count} actions={action_count} sender_actions={sender_action_count}, but no sender RF action: probe={probe}"
    );
}

#[test]
#[ignore = "requires the supervised lmesh/lmesh-wifi host radios"]
fn host_host_now_raw_frame_injection_e2e() {
    // Captured valid NOW action frame, with source 00:c0:ca:b8:79:cc and
    // receiver wlan1 as Address-1. This bypasses QUIC and the action builder
    // so the row proves only monitor-mode RF injection and capture.
    let frame_hex = "d0000000ffffffffffff00c0cab879ccffffffffffff90aa7f18fe3404024000000f0000140000c00001a01def9db909800400008004000000";
    let tx_variant =
        std::env::var("DMESH_E2E_RAW_TX_VARIANT").unwrap_or_else(|_| "action".to_owned());
    // Use the permanent monitor/AP fixtures exactly as provisioned.
    let capture_thread = thread::spawn(|| {
        mesh_rpc_value(
            "lmesh",
            "wifi.mgmt.capture",
            serde_json::json!({"iface": "wlan1", "channel": 6, "capture_ms": 4000, "max_frames": 128, "active": false}),
        )
    });
    thread::sleep(Duration::from_millis(500));
    let send = mesh_rpc_typed(
        "lmesh-wifi",
        "wifi.raw.send",
        &lmesh_wifi::api::RawSendRequest {
            iface: Some("wlan0".to_owned()),
            channel: Some(6),
            tx_variant: Some(tx_variant),
            tx_rate_mbps: Some(e2e_now_rate() as u8),
            frame_hex: Some(frame_hex.to_owned()),
        },
    );
    let capture = capture_thread.join().expect("capture thread");
    let sender_frames = capture
        .get("data")
        .and_then(|v| v.get("frames"))
        .and_then(serde_json::Value::as_array)
        .map(|frames| {
            frames
                .iter()
                .filter(|frame| {
                    frame.get("source").and_then(serde_json::Value::as_str)
                        == Some("00:c0:ca:b8:79:cc")
                })
                .count()
        })
        .unwrap_or(0);
    assert!(
        send.get("data")
            .and_then(|v| v.get("ok"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        "raw NOW injection failed: {send}"
    );
    assert!(
        sender_frames > 0,
        "raw NOW frame did not reach receiver: send={send}; sender_frames={sender_frames}"
    );
}

#[test]
#[ignore = "requires the supervised lmesh/lmesh-wifi host radios"]
fn host_host_now_iperf_e2e() {
    // Equivalent command:
    //   mesh lmesh-wifi wifi.raw.iperf iface=wlan0 channel=6 \
    //     destination=74:19:f8:17:de:65 bytes=65536 packet_size=1100 \
    //     timeout_ms=10000 tx_rate_mbps=6 tx_variant=monitor rx_variant=monitor
    // Keep this as a real completion assertion: a bootstrap ACK plus one
    // stream packet is not a throughput result.
    // AP/channel state is owned by mesh-init and remains untouched.
    require_host_iface_up("lmesh-wifi", "wlan0");
    require_host_iface_up("lmesh", "wlan1mon");
    thread::sleep(Duration::from_secs(2));
    // Host monitor delivery is proven with ESP-NOW's broadcast Address-1;
    // keep the peer MAC only in Address-2/QUIC path identity.
    let destination = e2e_now_destination();
    thread::sleep(Duration::from_secs(2));
    let mut sanity = serde_json::Value::Null;
    for attempt in 0..3_u64 {
        sanity = mesh_rpc_value(
            "lmesh-wifi",
            "wifi.raw.check",
            serde_json::json!({
                "iface": "wlan0", "channel": 6, "destination": destination,
                "nonce": 131073 + attempt, "timeout_ms": 5000,
                "tx_rate_mbps": e2e_now_rate(), "tx_variant": e2e_now_tx_variant(),
                "rx_variant": e2e_now_rx_variant(),
            }),
        );
        if sanity
            .get("data")
            .and_then(|value| value.get("ok"))
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        {
            break;
        }
        thread::sleep(Duration::from_millis(500));
    }
    assert!(
        sanity
            .get("data")
            .and_then(|value| value.get("ok"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        "NOW sanity check failed before IPERF: {sanity}; receiver metrics={}; dispatch history={}",
        mesh_rpc_typed(
            "lmesh",
            "wifi.raw.metrics",
            &lmesh_wifi::api::RawMetricsRequest {
                iface: Some("wlan1".to_owned())
            }
        ),
        mesh_rpc_typed(
            "lmesh",
            "messages.history",
            &lmesh::api::LmeshMessagesHistoryRequest {
                keys: Some("wifi.raw.dispatch".to_owned()),
                limit: Some(20)
            }
        ),
    );
    let result = wifi_raw_iperf(
        "lmesh-wifi",
        "wlan0",
        destination,
        e2e_now_bytes(),
        u16::try_from(e2e_now_packet_size()).expect("NOW packet size fits u16"),
        e2e_now_timeout_ms(),
        e2e_now_rate() as u8,
        &e2e_now_tx_variant(),
        &e2e_now_rx_variant(),
    );
    let data = result.get("data").unwrap_or(&result);
    if data.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        let history = mesh_rpc_typed(
            "lmesh",
            "wifi.raw.metrics",
            &lmesh_wifi::api::RawMetricsRequest {
                iface: Some("wlan1".to_owned()),
            },
        );
        let sender_metrics = mesh_rpc_typed(
            "lmesh-wifi",
            "wifi.raw.metrics",
            &lmesh_wifi::api::RawMetricsRequest {
                iface: Some("wlan0".to_owned()),
            },
        );
        let dispatch = mesh_rpc_typed(
            "lmesh",
            "messages.history",
            &lmesh::api::LmeshMessagesHistoryRequest {
                keys: Some("wifi.raw.dispatch".to_owned()),
                limit: Some(40),
            },
        );
        panic!(
            "NOW IPERF did not complete: {result}; sender metrics={sender_metrics}; receiver metrics={history}; dispatch={dispatch}"
        );
    }
    assert_eq!(
        data.get("bytes").and_then(serde_json::Value::as_u64),
        Some(e2e_now_bytes()),
        "NOW IPERF byte count: {result}"
    );
    let bps = data
        .get("bps")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    eprintln!(
        "host-host NOW IPERF result={result} receiver_metrics={} dispatch_tail={}",
        mesh_rpc_typed(
            "lmesh",
            "wifi.raw.metrics",
            &lmesh_wifi::api::RawMetricsRequest {
                iface: Some("wlan1".to_owned())
            }
        ),
        mesh_rpc_typed(
            "lmesh",
            "messages.history",
            &lmesh::api::LmeshMessagesHistoryRequest {
                keys: Some("wifi.raw.dispatch".to_owned()),
                limit: Some(8)
            }
        ),
    );
    assert!(
        bps > e2e_now_min_bps(),
        "NOW IPERF throughput is implausibly low: {result}"
    );
}

#[test]
#[ignore = "requires the supervised lmesh/lmesh-wifi host radios"]
fn host_host_now_reverse_iperf_e2e() {
    // Equivalent command:
    //   mesh lmesh wifi.raw.iperf iface=wlan1 channel=6 \
    //     destination=00:c0:ca:b8:79:cc bytes=65536 packet_size=1100 \
    //     timeout_ms=10000 tx_rate_mbps=6 tx_variant=monitor rx_variant=monitor
    let destination = "ff:ff:ff:ff:ff:ff".to_owned();
    // The reverse row consumes the permanent monitor/AP fixtures only.
    require_host_iface_up("lmesh-wifi", "wlan0");
    require_host_iface_up("lmesh", "wlan1mon");
    thread::sleep(Duration::from_secs(1));
    let result = wifi_raw_iperf(
        "lmesh",
        "wlan1",
        destination,
        e2e_now_bytes(),
        u16::try_from(e2e_now_packet_size()).expect("NOW packet size fits u16"),
        e2e_now_timeout_ms(),
        e2e_now_rate() as u8,
        "monitor",
        "monitor",
    );
    let data = result.get("data").unwrap_or(&result);
    if data.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        let metrics = mesh_rpc_typed(
            "lmesh-wifi",
            "wifi.raw.metrics",
            &lmesh_wifi::api::RawMetricsRequest {
                iface: Some("wlan0".to_owned()),
            },
        );
        panic!("reverse NOW IPERF did not complete: {result}; receiver metrics={metrics}");
    }
    eprintln!(
        "host-host reverse NOW IPERF result={result} receiver_metrics={}",
        mesh_rpc_typed(
            "lmesh-wifi",
            "wifi.raw.metrics",
            &lmesh_wifi::api::RawMetricsRequest {
                iface: Some("wlan0".to_owned())
            }
        ),
    );
    assert_eq!(
        data.get("ok").and_then(serde_json::Value::as_bool),
        Some(true),
        "reverse NOW IPERF did not complete: {result}"
    );
    assert_eq!(
        data.get("bytes").and_then(serde_json::Value::as_u64),
        Some(e2e_now_bytes()),
        "reverse NOW IPERF byte count: {result}"
    );
}

fn udp6_transfer_bytes() -> u64 {
    match std::env::var("DMESH_E2E_UDP6_BYTES") {
        Ok(value) => value.parse::<u64>().unwrap_or_else(|error| {
            panic!("DMESH_E2E_UDP6_BYTES must be an unsigned byte count, got {value:?}: {error}")
        }),
        Err(std::env::VarError::NotPresent) => E2E_UDP6_DEFAULT_BYTES,
        Err(error) => panic!("read DMESH_E2E_UDP6_BYTES: {error}"),
    }
}

/// Sustained row follows the short request/response sanity pass in the same
/// generic device test. It deliberately has a separate knob so callers can
/// retain the 64 KiB first-response signal while increasing only the
/// throughput sample.
fn udp6_sustained_bytes() -> u64 {
    match std::env::var("DMESH_E2E_UDP6_SUSTAINED_BYTES") {
        Ok(value) => value.parse::<u64>().unwrap_or_else(|error| {
            panic!(
                "DMESH_E2E_UDP6_SUSTAINED_BYTES must be an unsigned byte count, got {value:?}: {error}"
            )
        }),
        Err(std::env::VarError::NotPresent) => 1024 * 1024,
        Err(error) => panic!("read DMESH_E2E_UDP6_SUSTAINED_BYTES: {error}"),
    }
}

async fn udp_iperf_row(
    label: &str,
    bind: SocketAddr,
    peer: SocketAddr,
    cid: ConnectionId,
    bytes: u64,
) {
    assert!(bytes > 0, "DMESH_E2E_UDP6_BYTES must be nonzero");
    let before_mem_kib = mem_available_kib();
    let mut client = timeout(Duration::from_secs(5), UdpClient::connect(bind, peer, cid))
        .await
        .unwrap_or_else(|_| panic!("{label} bootstrap deadline"))
        .unwrap_or_else(|error| panic!("{label} bootstrap: {error:#}"));
    let mut request = [0u8; 64];
    let request_len = encode_iperf_service_request(
        IperfServiceRequest::new(bytes, E2E_UDP6_PACKET_SIZE),
        &mut request,
    )
    .unwrap_or_else(|| panic!("{label} IPERF request encoding"));
    let started_at = Instant::now();
    let first = timeout(
        Duration::from_secs(5),
        client.request_stream_frame(FIRST_CLIENT_BIDI_STREAM_ID, &request[..request_len], true),
    )
    .await
    .unwrap_or_else(|_| panic!("{label} first response deadline"))
    .unwrap_or_else(|error| panic!("{label} IPERF request: {error:#}"));
    let first_response_us = started_at.elapsed().as_micros();
    let mut ranges = Vec::new();
    let mut received = record_logical_stream_bytes(&mut ranges, &first);
    let mut finished = first.fin;
    let mut previous_receive = Instant::now();
    let mut gaps = [0_u64; 6];
    // The raw Ethernet bearer can reorder physical frames. The QUIC-lite
    // stream offset, not receive order, defines completion and goodput.
    while !finished || received < bytes {
        let remaining = E2E_UDP6_TRANSFER_DEADLINE
            .checked_sub(started_at.elapsed())
            .unwrap_or_else(|| {
                panic!("{label} transfer deadline: bytes={received}/{bytes} fin={finished}")
            });
        let frame = timeout(
            Duration::from_secs(5).min(remaining),
            client.recv_stream_frame(),
        )
        .await
        .unwrap_or_else(|_| {
            panic!("{label} receive deadline: bytes={received}/{bytes} fin={finished}")
        })
        .unwrap_or_else(|error| panic!("{label} stream receive: {error:#}"));
        let gap_us = previous_receive.elapsed().as_micros() as u64;
        previous_receive = Instant::now();
        gaps[match gap_us {
            0..=999 => 0,
            1_000..=4_999 => 1,
            5_000..=9_999 => 2,
            10_000..=24_999 => 3,
            25_000..=49_999 => 4,
            _ => 5,
        }] += 1;
        received = received.saturating_add(record_logical_stream_bytes(&mut ranges, &frame));
        finished |= frame.fin;
    }
    let elapsed_us = started_at.elapsed().as_micros().max(1) as u64;
    let bps = received.saturating_mul(8_000_000) / elapsed_us;
    let after_mem_kib = mem_available_kib();
    let stats = client.transport_stats();
    eprintln!(
        "firmware-e2e row={label} kind=iperf bytes={received} elapsed_us={elapsed_us} first_response_us={first_response_us} bps={bps} packet={E2E_UDP6_PACKET_SIZE} history=512 deferred_receive_credit=false host_mem_available_kib={before_mem_kib:?}->{after_mem_kib:?} gaps_us=<1ms:{},1-5ms:{},5-10ms:{},10-25ms:{},25-50ms:{},>=50ms:{} transport=received:{} sent:{} duplicate:{} reorder:{} missing:{} retransmitted:{} loss_gap:{} loss_time:{} loss_events:{} loss_retx:{} pto_retx:{} ack:{}",
        gaps[0],
        gaps[1],
        gaps[2],
        gaps[3],
        gaps[4],
        gaps[5],
        stats.received_datagrams,
        stats.sent_datagrams,
        stats.duplicate_datagrams,
        stats.out_of_order_datagrams,
        stats.inferred_missing_packets,
        stats.retransmitted_datagrams,
        stats.loss_packet_threshold_datagrams,
        stats.loss_time_threshold_datagrams,
        stats.loss_events,
        stats.loss_retransmitted_datagrams,
        stats.pto_retransmitted_datagrams,
        stats.ack_datagrams,
    );
    assert_eq!(received, bytes, "{label} logical byte count");
    client
        .close(0)
        .await
        .unwrap_or_else(|error| panic!("{label} close: {error:#}"));
}

async fn host_to_lmesh_wifi_iperf() {
    // This exercises the already-running stable host service, rather than
    // launching a private benchmark listener. It proves lmesh-wifi carries
    // the shared dmesh-server IPERF handler and never restarts its AP.
    udp_iperf_row(
        "host loopback->lmesh-wifi",
        "127.0.0.1:0".parse().expect("loopback bind"),
        format!("127.0.0.1:{STABLE_WIFI_UDP_PORT}")
            .parse()
            .expect("stable lmesh-wifi listener"),
        ConnectionId::new(0x48_4F_5354).expect("nonzero host baseline CID"),
        udp6_transfer_bytes(),
    )
    .await;
}

async fn host_to_e6_udp6_iperf() {
    host_to_device_udp6_iperf("host wlan0->e6 raw-udp6", E6_MAC, 0xE6_0D_0601).await;
}

async fn host_to_e7_udp6_iperf() {
    host_to_device_udp6_iperf("host wlan0->e7 raw-udp6", E7_MAC, 0xE7_0D_0601).await;
}

/// Target-neutral scoped link-local endpoint for the focused UDP6 gate.
///
/// The endpoint is supplied separately from the USB path because a test may
/// use a Recovery or Main image on any board. Keep the interface scope: IPv6
/// link-local routing is otherwise ambiguous on a multi-radio host.
fn udp6_peer_from_env() -> SocketAddr {
    let value = std::env::var("DMESH_E2E_UDP6_IP")
        .expect("DMESH_E2E_UDP6_IP must be a scoped link-local address, e.g. fe80::...%wlan0");
    let (address, scope) = value
        .trim_matches(['[', ']'])
        .split_once('%')
        .unwrap_or_else(|| panic!("DMESH_E2E_UDP6_IP must include %<interface>: {value:?}"));
    let address = address
        .parse::<Ipv6Addr>()
        .unwrap_or_else(|error| panic!("DMESH_E2E_UDP6_IP address {address:?}: {error}"));
    let scope_id = scope
        .parse::<u32>()
        .unwrap_or_else(|_| interface_index(scope));
    SocketAddr::V6(SocketAddrV6::new(address, RAW_UDP6_PORT, 0, scope_id))
}

/// Prove that Main exposes the same minimal tagged-control surface as
/// Recovery before enabling any Main-only radio or power policy.
///
/// Equivalent command shape (the test serializes this as tagged CBOR):
///
/// ```text
/// dmesh-cli <e7-uart> settings.list
/// ```
///
/// This deliberately does not configure an SSID, start STA, or alter NVS.
/// It is the regression gate for the Recovery-core control surface carried by
/// Main while optional modules remain dormant.
#[test]
#[ignore = "requires e7 Main flashed and exclusive UART ownership"]
fn firmware_e7_main_common_control_surface() {
    let mut e7 = DeviceSession::open(serial_from_env("DMESH_E2E_E7"), None).unwrap();
    e7.set_history_limit(128);
    control_request(&mut e7, ControlRequest::SettingsList, 0xE7_43_54_4C);
}

/// Read the shared radio snapshot without changing e7 state. This is the
/// post-failure evidence companion for the Main UDP6 E2E row: it separates
/// NDP/association from raw Ethernet callback delivery before a retry alters
/// any radio configuration.
#[test]
#[ignore = "requires e7 Main UART and exclusive UART ownership"]
fn firmware_e7_main_radio_snapshot() {
    let mut e7 = DeviceSession::open(serial_from_env("DMESH_E2E_E7"), None).unwrap();
    e7.set_history_limit(128);
    let radio = snapshot(&mut e7, RAW_WIFI_METHOD_SNAPSHOT);
    eprintln!("firmware-e2e row=e7-main-radio-snapshot {radio:?}");
    e7.assert_healthy().unwrap();
}

/// Focused host-to-device UDP6 performance gate.
///
/// The board and image are deliberately not encoded in this test. Run the
/// same row against Recovery or Main by supplying its USB control path and
/// scoped link-local address:
///
/// ```text
/// DMESH_E2E_USB=/dev/serial/by-id/... \
/// DMESH_E2E_UDP6_IP=fe80::16c1:9fff:fee4:5d48%wlan0 \
/// DMESH_E2E_NOW=2 \
/// cargo test -p dmesh-cli --test firmware_e2e firmware_udp6_performance -- --ignored --nocapture
/// ```
///
/// Repeat with the default (omit `DMESH_E2E_NOW`) or `DMESH_E2E_NOW=0`; both
/// rows keep NAN DW capture off and must retain the same raw-UDP6 service
/// behavior and comparable throughput.
#[test]
#[ignore = "requires DMESH_E2E_USB, DMESH_E2E_UDP6_IP, and the supervised wlan0 AP"]
fn firmware_udp6_performance() {
    let mut device = DeviceSession::open(serial_from_env("DMESH_E2E_USB"), None).unwrap();
    device.set_history_limit(128);
    let ssid = wlan0_ssid();
    let now_enabled = e2e_now_enabled();
    let sta_driver_tx = e2e_sta_driver_tx();
    configure_sta_for_wlan0_with_now(&mut device, &ssid, now_enabled, sta_driver_tx, 0xF0_6000);
    let radio = wait_for_associated_channel_6_with_driver_tx(&mut device, sta_driver_tx);
    assert_eq!(
        radio.sta_driver_tx,
        Some(sta_driver_tx),
        "focused UDP6 row must report its requested STA TX path"
    );
    assert_eq!(radio.promiscuous, Some(false));
    assert_eq!(radio.dw_capturing, Some(false));
    eprintln!(
        "firmware-e2e row=host-to-device-udp6 now={now_enabled} sta_driver_tx={sta_driver_tx}"
    );
    let peer = udp6_peer_from_env();
    let bind = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 3338, 0, 0));
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("focused UDP6 runtime")
        .block_on(async {
            eprintln!(
                "firmware-e2e row=host-to-device-udp6-short peer={peer} bytes={}",
                udp6_transfer_bytes(),
            );
            udp_iperf_row(
                "host wlan0->device raw-udp6 short",
                bind,
                peer,
                ConnectionId::new(0xF0_0D_0601).expect("nonzero short UDP6 CID"),
                udp6_transfer_bytes(),
            )
            .await;
            eprintln!(
                "firmware-e2e row=host-to-device-udp6-sustained peer={peer} bytes={}",
                udp6_sustained_bytes(),
            );
            udp_iperf_row(
                "host wlan0->device raw-udp6 sustained",
                // The short association's CLOSE ACK can still be in flight.
                // Use a fresh host source port for the independent sustained
                // connection so its endpoint cannot decode that old packet.
                // The device keeps the reply UDP port from each received
                // datagram; its bearer identity remains the peer MAC.
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
                peer,
                ConnectionId::new(0xF0_0D_0602).expect("nonzero sustained UDP6 CID"),
                udp6_sustained_bytes(),
            )
            .await;
        });
}

/// Select the explicit-off UDP6 baseline when requested. The ordinary test
/// path does not mention NOW: `transport.start` defaults it on.
fn e2e_now_enabled() -> bool {
    match std::env::var("DMESH_E2E_NOW").as_deref() {
        Err(_) | Ok("0" | "1") => true,
        Ok("2" | "off") => false,
        Ok(value) => panic!("DMESH_E2E_NOW must be 0, 1, 2, or off, got {value:?}"),
    }
}

/// The normal associated-STA measurement uses ESP-IDF's Ethernet handoff.
/// The raw-802.11 station path is an explicit diagnostic A/B only; it is not
/// the default result reported for STA+NOW.
fn e2e_sta_driver_tx() -> bool {
    match std::env::var("DMESH_E2E_STA_DRIVER_TX").as_deref() {
        Err(_) | Ok("1" | "on") => true,
        Ok("0" | "off") => false,
        Ok(value) => panic!("DMESH_E2E_STA_DRIVER_TX must be 0, 1, on, or off, got {value:?}"),
    }
}

async fn host_to_device_udp6_iperf(label: &str, mac: [u8; 6], cid: u64) {
    // This is equivalent to the historic CLI form:
    // dmesh-cli 'udp://[fe80::16c1:9fff:fee5:9800%wlan0]:3339' --iperf-bytes 65536
    // The Rust test uses the same UdpClient/service schema directly, so it
    // does not rely on a retired CLI argument grammar or restart lmesh-wifi.
    let bytes = udp6_transfer_bytes();
    let ifindex = interface_index("wlan0");
    let peer = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(quic_lite::raw_udp6::link_local_from_mac(mac)),
        RAW_UDP6_PORT,
        0,
        ifindex,
    ));
    // Match `dmesh-cli udp://…`: raw UDP6 replies are path-bound by the
    // firmware dispatcher, so an ephemeral source port can make a retry look
    // like a different bearer path after a previous interrupted run.  Port
    // 3338 is reserved for the host test/client and is distinct from host
    // listeners (3336/3337) and the firmware bearer (3339).
    let bind = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 3338, 0, 0));
    udp_iperf_row(
        label,
        bind,
        peer,
        ConnectionId::new(cid).expect("nonzero e2e UDP6 CID"),
        bytes,
    )
    .await;
}

/// Focused STA UDP6 performance gate. Unlike [`firmware_transport_matrix`],
/// this leaves both devices associated to the supervised host AP and measures
/// their independent host-to-device raw-UDP6 IPERF services. It deliberately
/// does not enable NOW, NAN, APSTA, ROC, or an unassociated hold, so a result
/// is directly comparable across AP adapters.
#[test]
#[ignore = "requires the e6/e7 radio lab and exclusive UART ownership"]
fn firmware_sta_udp6_performance() {
    let mut e6 = DeviceSession::open(serial_from_env("DMESH_E2E_E6"), None).unwrap();
    let mut e7 = DeviceSession::open(serial_from_env("DMESH_E2E_E7"), None).unwrap();
    e6.set_history_limit(4_096);
    e7.set_history_limit(4_096);

    let ssid = wlan0_ssid();
    configure_sta_for_wlan0(&mut e6, &ssid, 0xE6_6100);
    configure_sta_for_wlan0(&mut e7, &ssid, 0xE7_6100);
    wait_for_associated_channel_6(&mut e6);
    wait_for_associated_channel_6(&mut e7);

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("STA performance UDP6 runtime")
        .block_on(async {
            host_to_lmesh_wifi_iperf().await;
            host_to_e6_udp6_iperf().await;
            host_to_e7_udp6_iperf().await;
        });
}

/// Run the same compact `SERVICE_ECHO` handler over raw UDP6.  It deliberately
/// creates a fresh association per sample, matching the action check's
/// bootstrap/response scope; the worker is run concurrently with the action
/// probe so a UDP6 regression cannot be hidden by a quiet radio.
async fn host_to_e6_udp6_echo_checks(samples: u64) -> Vec<Result<u128, String>> {
    let ifindex = interface_index("wlan0");
    let peer = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(quic_lite::raw_udp6::link_local_from_mac(E6_MAC)),
        RAW_UDP6_PORT,
        0,
        ifindex,
    ));
    // Keep echo/check probes on the same stable host raw-UDP6 path as IPERF.
    // The device records the reply path per association; an ephemeral port
    // would turn each retry into a new path and make failures non-diagnostic.
    let bind = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 3338, 0, 0));
    let mut results = Vec::with_capacity(samples as usize);
    for sample in 0..samples {
        let started = Instant::now();
        let result = async {
            let cid = ConnectionId::new(0xE6_0E_1000 + sample)
                .ok_or_else(|| "UDP6 echo CID".to_owned())?;
            let mut client = timeout(Duration::from_secs(5), UdpClient::connect(bind, peer, cid))
                .await
                .map_err(|_| "UDP6 echo bootstrap deadline".to_owned())?
                .map_err(|error| format!("UDP6 echo bootstrap: {error:#}"))?;
            let nonce = (0x5544_5036_0000_0000u64 | sample).to_be_bytes();
            let mut request = [0u8; 9];
            request[0] = SERVICE_ECHO;
            request[1..].copy_from_slice(&nonce);
            let response = timeout(
                Duration::from_secs(5),
                client.request_stream(FIRST_CLIENT_BIDI_STREAM_ID, &request, true),
            )
            .await
            .map_err(|_| "UDP6 echo response deadline".to_owned())?
            .map_err(|error| format!("UDP6 echo response: {error:#}"))?;
            if response.1 != nonce {
                return Err(format!("UDP6 echo nonce mismatch sample={sample}"));
            }
            Ok(started.elapsed().as_micros())
        }
        .await;
        results.push(result);
    }
    results
}

/// Count only new application bytes. Wi-Fi/raw-UDP retransmissions may repeat
/// a complete stream frame after an ACK is lost; physical frame count is a
/// separate transport metric and must not inflate IPERF goodput.
fn record_logical_stream_bytes(ranges: &mut Vec<(u64, u64)>, frame: &ReceivedStream) -> u64 {
    let start = frame.offset;
    let end = start.saturating_add(frame.data.len() as u64);
    if start == end {
        return 0;
    }
    let before = ranges
        .iter()
        .map(|(range_start, range_end)| range_end - range_start)
        .sum::<u64>();
    ranges.push((start, end));
    ranges.sort_unstable_by_key(|(range_start, _)| *range_start);
    let mut merged = Vec::with_capacity(ranges.len());
    for (range_start, range_end) in ranges.drain(..) {
        if let Some((_, previous_end)) = merged.last_mut()
            && range_start <= *previous_end
        {
            *previous_end = (*previous_end).max(range_end);
        } else {
            merged.push((range_start, range_end));
        }
    }
    let after = merged
        .iter()
        .map(|(range_start, range_end)| range_end - range_start)
        .sum::<u64>();
    *ranges = merged;
    after.saturating_sub(before)
}

fn complete_action_iperf(
    client: &mut DeviceSession,
    source: &mut DeviceSession,
    peer: [u8; 6],
    label: &str,
) -> (
    dmesh_server::raw_wifi::RawWifiSnapshot,
    dmesh_server::raw_wifi::RawWifiSnapshot,
) {
    snapshot(client, RAW_WIFI_METHOD_RESET_COUNTERS);
    snapshot(source, RAW_WIFI_METHOD_RESET_COUNTERS);
    let request = RawWifiIperfRequest {
        peer,
        bytes: E2E_ACTION_IPERF_BYTES,
        packet_size: E2E_UDP6_PACKET_SIZE,
        timeout_ms: 20_000,
    };
    let mut wire = [0u8; 64];
    let used = encode_raw_wifi_iperf_request(request, &mut wire).expect("action IPERF request");
    let initial = radio_request(client, &wire[..used]);
    assert_eq!(
        initial.raw_service_active,
        Some(true),
        "{label} did not start"
    );
    let started = Instant::now();
    let complete = loop {
        assert!(
            started.elapsed() < Duration::from_secs(25),
            "{label} action IPERF deadline; last={initial:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
        let snapshot = snapshot(client, RAW_WIFI_METHOD_SNAPSHOT);
        if snapshot.raw_service_active == Some(false)
            && snapshot.raw_service_bytes == Some(E2E_ACTION_IPERF_BYTES as u32)
        {
            break snapshot;
        }
    };
    let source_snapshot = snapshot(source, RAW_WIFI_METHOD_SNAPSHOT);
    let elapsed_us = complete
        .raw_service_elapsed_us
        .expect("action IPERF elapsed");
    let bps = E2E_ACTION_IPERF_BYTES.saturating_mul(8_000_000) / u64::from(elapsed_us.max(1));
    eprintln!(
        "firmware-e2e row={label} kind=action-iperf bytes={} elapsed_us={} bps={} source=({}) client=({})",
        E2E_ACTION_IPERF_BYTES,
        elapsed_us,
        bps,
        snapshot_summary(&source_snapshot),
        snapshot_summary(&complete),
    );
    assert_eq!(
        complete.raw_service_bytes,
        Some(E2E_ACTION_IPERF_BYTES as u32)
    );
    assert_eq!(complete.counters.raw_client_receive_errors, 0);
    assert!(
        source_snapshot.counters.rx_parser_accepted > 0,
        "{label} source did not parse input"
    );
    (source_snapshot, complete)
}

#[test]
fn logical_stream_bytes_ignore_duplicate_and_reordered_frames() {
    let mut ranges = Vec::new();
    let frame = |offset, length| ReceivedStream {
        id: FIRST_CLIENT_BIDI_STREAM_ID,
        offset,
        fin: false,
        data: vec![0; length],
    };
    assert_eq!(record_logical_stream_bytes(&mut ranges, &frame(8, 8)), 8);
    assert_eq!(record_logical_stream_bytes(&mut ranges, &frame(0, 8)), 8);
    assert_eq!(record_logical_stream_bytes(&mut ranges, &frame(8, 8)), 0);
    assert_eq!(record_logical_stream_bytes(&mut ranges, &frame(4, 12)), 0);
    assert_eq!(ranges, vec![(0, 16)]);
}

fn radio_request(
    session: &mut DeviceSession,
    request: &[u8],
) -> dmesh_server::raw_wifi::RawWifiSnapshot {
    // A USB-JTAG device may still be printing its reset backlog when the
    // suite obtains its single owner. Retry this idempotent snapshot/control
    // request, retaining the same session and without reopening/resetting it.
    for _ in 0..3 {
        let matched = session
            .request_direct_record_until(request, COMMAND_TIMEOUT, |event| matches!(
                event,
                DeviceSessionEvent::DirectRecord(record) if decode_raw_wifi_snapshot(record).is_ok()
            ))
            .unwrap_or_else(|error| panic!("{} radio request: {error}", session.path()));
        if matched {
            // `matched` proves this request appended a decodable snapshot.
            // Some focused fixtures retain only a very small serial history,
            // so a length-based slice can be evicted between the match and
            // this lookup. Take the latest decodable record instead; it is
            // still causally guarded by the just-completed matcher.
            let response = session
                .recent_events()
                .filter_map(|event| match event {
                    DeviceSessionEvent::DirectRecord(record) => {
                        decode_raw_wifi_snapshot(record).ok()
                    }
                    _ => None,
                })
                .last()
                .expect("matched snapshot record remains in bounded history");
            session.assert_healthy().unwrap();
            return response.1;
        }
    }
    let recent = session
        .recent_events()
        .filter_map(|event| match event {
            DeviceSessionEvent::DirectRecord(record) => Some(format!(
                "{} ({:?})",
                hex(record),
                decode_raw_wifi_snapshot(record).err()
            )),
            _ => None,
        })
        .take(24)
        .collect::<Vec<_>>();
    panic!(
        "{} did not return a decodable radio response after retries; direct records={recent:?}",
        session.path()
    )
}

/// Send one correlated common control request through the direct UART bearer.
///
/// This stays below QUIC-lite on purpose: it is the bootstrap operation that
/// makes the raw UDP6 bearer available.  The response must still use the
/// canonical tagged envelope and preserve the correlation ID, so it exercises
/// the same control schema as direct UDP6, NAN, and action messages.
fn control_request(session: &mut DeviceSession, request: ControlRequest<'_>, id: u64) {
    let mut wire = [0u8; 128];
    let used = control::encode_request(request, Some(id), &mut wire)
        .unwrap_or_else(|| panic!("encode common control request"));
    let history_before = session.recent_events().len();
    let matched = session
        .request_direct_record_until(&wire[..used], COMMAND_TIMEOUT, |event| {
            matches!(
                event,
                DeviceSessionEvent::DirectRecord(record)
                    if decode_tagged_record(record).is_some_and(|response| {
                        response.id == Some(id)
                            && response.result.is_some()
                            && response.error.is_none()
                    })
            )
        })
        .unwrap_or_else(|error| panic!("{} control request: {error}", session.path()));
    assert!(
        matched,
        "{} did not return tagged control response id={id}; records={:?}",
        session.path(),
        session
            .recent_events()
            .skip(history_before)
            .filter_map(|event| match event {
                DeviceSessionEvent::DirectRecord(record) => Some(hex(record)),
                _ => None,
            })
            .collect::<Vec<_>>(),
    );
    session.assert_healthy().unwrap();
}

/// Query the managed AP owner, then send one volatile UART radio-mode command.
/// It never writes an SSID to NVS: NAN Service Info will use this exact
/// `transport.start` payload when it becomes the initiator.
fn configure_sta_for_wlan0(session: &mut DeviceSession, ssid: &str, id_base: u64) {
    let (bssid, channel) = wlan0_bssid_channel();
    control_request(
        session,
        ControlRequest::TransportStart {
            kind: TransportKind::Sta,
            config: dmesh_server::control::TransportConfig {
                ssid: Some(ssid.as_bytes()),
                bssid: Some(bssid),
                channel: Some(channel),
                // e6's current open wlan0 AP advertises a legacy basic rate;
                // keep that association prerequisite explicit for the shared
                // UDP6/NOW comparison rather than inheriting a radio-lab PHY
                // preference from a prior epoch.
                sta_11b_rates_disabled: Some(false),
                ..dmesh_server::control::TransportConfig::default()
            },
        },
        id_base,
    );
}

/// Configure the focused STA performance row through the same tagged control
/// schema used by UART, NAN SD, and future host adapters. `transport.start`
/// holds the entire immutable radio epoch, so its replacement is explicit.
fn configure_sta_for_wlan0_with_now(
    session: &mut DeviceSession,
    ssid: &str,
    now_enabled: bool,
    sta_driver_tx: bool,
    id_base: u64,
) {
    let (bssid, channel) = wlan0_bssid_channel();
    control_request(
        session,
        ControlRequest::TransportStart {
            kind: TransportKind::Sta,
            config: dmesh_server::control::TransportConfig {
                ssid: Some(ssid.as_bytes()),
                bssid: Some(bssid),
                channel: Some(channel),
                now: Some(if now_enabled { 0 } else { 2 }),
                sta_driver_tx: Some(sta_driver_tx),
                nan_dw_interval: Some(0),
                // The shared host AP still advertises a legacy basic rate.
                // Retain the proven association prerequisite for the NOW
                // row as well; this does not affect the later raw/NOW rate.
                sta_11b_rates_disabled: Some(false),
                ..dmesh_server::control::TransportConfig::default()
            },
        },
        id_base,
    );
}

fn configure_nan_for_channel(session: &mut DeviceSession, channel: u8, id: u64) {
    control_request(
        session,
        ControlRequest::TransportStart {
            kind: TransportKind::Nan,
            config: dmesh_server::control::TransportConfig {
                channel: Some(channel),
                now: Some(0),
                nan_dw_interval: Some(0),
                ..dmesh_server::control::TransportConfig::default()
            },
        },
        id,
    );
    // `transport.start` acknowledges after committing the complete immutable
    // profile; Wi-Fi then performs its owned replacement asynchronously. Drain
    // that bounded transition before the first snapshot so its diagnostics and
    // channel state cannot be confused with the synchronous CBOR acceptance.
    session
        .poll(Duration::from_millis(750))
        .unwrap_or_else(|error| panic!("{} NAN/NOW transition: {error}", session.path()));
}

/// Put e6 in the NAN+NOW receiver state used before an Android active-Publish
/// carries a CBOR `transport.start`. Manual equivalent is a UART
/// transport.start with `{mode:nan, channel:6, now:0, nan_dw_interval:1}`;
/// this test owns only e6's volatile radio profile and never mutates host
/// wlan0/wlan1 state.
#[test]
#[ignore = "requires flashed e6 and exclusive UART ownership"]
fn firmware_e6_nan_sd_transport_receiver() {
    let mut e6 = DeviceSession::open(serial_from_env("DMESH_E2E_E6"), None).unwrap();
    control_request(
        &mut e6,
        ControlRequest::TransportStart {
            kind: TransportKind::Nan,
            config: dmesh_server::control::TransportConfig {
                channel: Some(6),
                now: Some(0),
                nan_dw_interval: Some(1),
                ..dmesh_server::control::TransportConfig::default()
            },
        },
        0xE6_4E_414E,
    );
    // Replacing a failed STA epoch has to stop/deinitialize its driver before
    // NAN+NOW can claim the radio again. Keep this longer than the boot-only
    // path; a three-second deadline turns a correct clean replacement into a
    // flaky test failure.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let snapshot = snapshot(&mut e6, RAW_WIFI_METHOD_SNAPSHOT);
        if snapshot.channel == Some(6) && snapshot.nan_dw_interval == Some(1) {
            assert_eq!(snapshot.sta_associated, Some(false));
            break;
        }
        assert!(
            Instant::now() < deadline,
            "e6 did not enable NAN DW capture: {}",
            snapshot_summary(&snapshot)
        );
        thread::sleep(Duration::from_millis(100));
    }
}

/// Android is the control plane for this row: it starts a fresh local-only
/// AP, publishes the complete volatile STA declaration as active NAN service
/// info, and e6 replaces its NAN-only radio setup with that STA setup.  The
/// test never changes wlan0/wlan1; their permanently-running monitors merely
/// remain available to the lab.
///
/// Manual equivalent (after putting e6 in the NAN DW receiver state):
///
/// ```sh
/// adb -s "$DMESH_E2E_ANDROID" shell content call \
///   --uri content://com.github.costinm.dmesh.lm.shell --method command \
///   --arg 'wifi.transport.start mode=nan ap=0'
/// adb -s "$DMESH_E2E_ANDROID" shell content call \
///   --uri content://com.github.costinm.dmesh.lm.shell --method command \
///   --arg 'wifi.transport.start mode=nan ap=1'
/// ```
#[test]
#[ignore = "requires flashed e6 plus an Android DMesh service with Wi-Fi Aware enabled"]
fn android_nan_sd_starts_e6_sta() {
    let mut e6 = DeviceSession::open(serial_from_env("DMESH_E2E_E6"), None).unwrap();
    control_request(
        &mut e6,
        ControlRequest::TransportStart {
            kind: TransportKind::Nan,
            config: dmesh_server::control::TransportConfig {
                channel: Some(6),
                now: Some(0),
                nan_dw_interval: Some(1),
                ..dmesh_server::control::TransportConfig::default()
            },
        },
        0xE6_414E_01,
    );
    let receiver_deadline = Instant::now() + Duration::from_secs(4);
    loop {
        let radio = snapshot(&mut e6, RAW_WIFI_METHOD_SNAPSHOT);
        if radio.channel == Some(6) && radio.nan_dw_interval == Some(1) {
            assert_eq!(radio.sta_associated, Some(false));
            break;
        }
        assert!(
            Instant::now() < receiver_deadline,
            "e6 did not enter NAN DW receiver state: {}",
            snapshot_summary(&radio)
        );
        thread::sleep(Duration::from_millis(100));
    }
    // Let the active-publish update cross at least one complete DW after the
    // receiver confirms capture is enabled.
    thread::sleep(Duration::from_millis(750));

    let before_android_ap_sd = snapshot(&mut e6, RAW_WIFI_METHOD_SNAPSHOT);
    let android = std::env::var("DMESH_E2E_ANDROID")
        .expect("DMESH_E2E_ANDROID must name the Android adb serial");
    for command in [
        "wifi.transport.start mode=nan ap=0",
        "wifi.transport.start mode=nan ap=1",
    ] {
        let shell_command = format!(
            "content call --uri content://com.github.costinm.dmesh.lm.shell --method command --arg '{command}'"
        );
        let output = Command::new("adb")
            // One remote shell argument preserves the complete command
            // string, including `mode` and `ap`; separate adb arguments drop
            // the second key/value before the content provider parses it.
            .args(["-s", &android, "shell", &shell_command])
            .output()
            .expect("adb content command");
        assert!(
            output.status.success(),
            "Android transport command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    // The Android local-hotspot callback is the only place that constructs
    // and publishes its ephemeral SSID/passphrase control record. Require E6
    // to copy that SD before trying to associate; a content-provider result
    // or a filtered Android history query is not evidence that the AP started.
    let sd_deadline = Instant::now() + Duration::from_secs(12);
    loop {
        let radio = snapshot(&mut e6, RAW_WIFI_METHOD_SNAPSHOT);
        if radio
            .counters
            .delta_since(before_android_ap_sd.counters)
            .nan_service_info_enqueued
            != 0
        {
            break;
        }
        assert!(
            Instant::now() < sd_deadline,
            "Android local AP did not emit its NAN transport.start SD: {}",
            snapshot_summary(&radio)
        );
        thread::sleep(Duration::from_millis(250));
    }

    // Active publish and its closest discovery window are asynchronous.  A
    // completed association is the only acceptance criterion: Android's local
    // command acknowledgement and its service-info callback do not prove e6
    // received the SD or replaced its previous radio mode.
    let association_timeout_secs = std::env::var("DMESH_E2E_NAN_SD_STA_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(25);
    let deadline = Instant::now() + Duration::from_secs(association_timeout_secs);
    loop {
        let radio = snapshot(&mut e6, RAW_WIFI_METHOD_SNAPSHOT);
        if radio.sta_associated == Some(true) {
            eprintln!(
                "android->e6 NAN SD association: {}",
                snapshot_summary(&radio)
            );
            assert_eq!(radio.channel, Some(6));
            break;
        }
        assert!(
            Instant::now() < deadline,
            "e6 did not associate after Android NAN transport.start SD: {}",
            snapshot_summary(&radio)
        );
        thread::sleep(Duration::from_millis(250));
    }
}

/// Android control-plane adapter gate. This does not change host radio state:
/// it asks Android for an app-scoped attachment to the already-running wlan0
/// AP, proves Android emitted the correctly targeted `requested` event, then
/// returns it to NAN-only. `available` versus `unavailable` is an Android
/// policy/concurrency measurement and is intentionally reported separately.
///
/// Manual equivalent:
/// ```sh
/// adb -s "$DMESH_E2E_ANDROID" shell content call \
///   --uri content://com.github.costinm.dmesh.lm.shell --method command \
///   --arg 'wifi.transport.start mode=sta ssid=<wlan0-ssid> bssid=<wlan0-bssid> ap=0'
/// ```
#[test]
#[ignore = "requires the Android DMesh service and the pre-existing wlan0 AP"]
fn android_transport_start_requests_wlan0_sta() {
    let android = std::env::var("DMESH_E2E_ANDROID")
        .expect("DMESH_E2E_ANDROID must name the Android adb serial");
    let ssid = wlan0_ssid();
    let (bssid, _) = wlan0_bssid_channel();
    let bssid = bssid
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    let command = format!(
        "content call --uri content://com.github.costinm.dmesh.lm.shell --method command \\
         --arg 'wifi.transport.start mode=sta ssid={ssid} bssid={bssid} ap=0'"
    );
    let output = Command::new("adb")
        .args(["-s", &android, "shell", &command])
        .output()
        .expect("Android STA transport.start");
    assert!(
        output.status.success(),
        "Android STA transport.start failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    thread::sleep(Duration::from_millis(250));
    let history = Command::new("adb")
        .args([
            "-s",
            &android,
            "shell",
            "content call --uri content://com.github.costinm.dmesh.lm.shell --method command \\
             --arg 'history durationMs=1000 limit=8 keys=all'",
        ])
        .output()
        .expect("Android STA transport history");
    let history = String::from_utf8_lossy(&history.stdout);
    assert!(
        history.contains("net.StaAttach")
            && history.contains("\"state\":\"requested\"")
            && history.contains(&bssid),
        "Android did not issue the targeted STA request: {history}"
    );
    let detach = "content call --uri content://com.github.costinm.dmesh.lm.shell --method command \\
                  --arg 'wifi.transport.start mode=nan ap=0'";
    let output = Command::new("adb")
        .args(["-s", &android, "shell", detach])
        .output()
        .expect("Android NAN detach");
    assert!(output.status.success(), "Android NAN detach failed");
}

/// Verified Android-to-E6 NAN control row using the already-running open
/// wlan0 AP. Unlike the local-hotspot row above, this isolates the common
/// active-Publish CBOR mechanism from Android's optional AP lifecycle: the
/// Android shell tells its primary `dmesh` publisher to carry this exact
/// `transport.start`, and E6 must associate to the host AP after receiving
/// it in a NAN discovery window. No host interface is created, restarted, or
/// reconfigured.
///
/// Manual equivalent:
///
/// ```sh
/// adb -s "$DMESH_E2E_ANDROID" shell content call \
///   --uri content://com.github.costinm.dmesh.lm.shell --method command \
///   --arg 'wifi.nan.sd cbor_hex=<canonical transport.start>'
/// ```
#[test]
#[ignore = "requires flashed e6, Android Wi-Fi Aware, and the pre-existing wlan0 AP"]
fn android_nan_sd_sta_declaration_associates_e6_wlan0() {
    let mut e6 = DeviceSession::open(serial_from_env("DMESH_E2E_E6"), None).unwrap();
    let android = std::env::var("DMESH_E2E_ANDROID")
        .expect("DMESH_E2E_ANDROID must name the Android adb serial");
    // A preceding Android/AP row may have left a temporary active-Publish
    // descriptor on air. Clear it before arming E6 so this row alone owns the
    // NAN SD that selects host wlan0.
    let output = Command::new("adb")
        .args([
            "-s",
            &android,
            "shell",
            "content call --uri content://com.github.costinm.dmesh.lm.shell --method command \\
             --arg 'wifi.nan.sd clear'",
        ])
        .output()
        .expect("clear Android NAN SD");
    assert!(output.status.success(), "clear Android NAN SD failed");
    thread::sleep(Duration::from_millis(750));
    control_request(
        &mut e6,
        ControlRequest::TransportStart {
            kind: TransportKind::Nan,
            config: dmesh_server::control::TransportConfig {
                channel: Some(6),
                now: Some(0),
                nan_dw_interval: Some(1),
                ..dmesh_server::control::TransportConfig::default()
            },
        },
        0xE6_414E_02,
    );
    let receive_deadline = Instant::now() + Duration::from_secs(4);
    loop {
        let radio = snapshot(&mut e6, RAW_WIFI_METHOD_SNAPSHOT);
        if radio.nan_dw_interval == Some(1) && radio.sta_associated == Some(false) {
            break;
        }
        assert!(
            Instant::now() < receive_deadline,
            "e6 did not enter the Android SD receive state: {}",
            snapshot_summary(&radio)
        );
        thread::sleep(Duration::from_millis(100));
    }

    let before_sd = snapshot(&mut e6, RAW_WIFI_METHOD_SNAPSHOT);

    let ssid = wlan0_ssid();
    let (bssid, channel) = wlan0_bssid_channel();
    let request = ControlRequest::TransportStart {
        kind: TransportKind::Sta,
        config: dmesh_server::control::TransportConfig {
            ssid: Some(ssid.as_bytes()),
            // A NAN SD already carries the AP identity. Supplying it makes
            // this the intended direct-association path, not a scan-time
            // measurement hidden inside the control-plane test.
            bssid: Some(bssid),
            channel: Some(channel),
            // Keep this target identical to the proven UART STA setup: the
            // current open wlan0 AP advertises a legacy basic rate.
            sta_11b_rates_disabled: Some(false),
            sta_driver_tx: Some(true),
            now: Some(0),
            nan_dw_interval: Some(0),
            // E6's current proven STA profile retains its local AP while it
            // attaches to wlan0. AP-off STA is a separate capability row;
            // do not turn this NAN-control interoperability gate into that
            // unvalidated topology change.
            ap: Some(1),
            ..dmesh_server::control::TransportConfig::default()
        },
    };
    let mut wire = [0u8; 128];
    let used = control::encode_request(request, None, &mut wire)
        .expect("canonical Android NAN transport.start");
    let command = format!(
        "content call --uri content://com.github.costinm.dmesh.lm.shell --method command --arg 'wifi.nan.sd cbor_hex={}'",
        hex(&wire[..used])
    );
    let output = Command::new("adb")
        // Keep the complete remote command in one ADB-shell argument. ADB
        // otherwise re-splits `--arg wifi.nan.sd cbor_hex=...`, dropping the
        // named CBOR value before Android's content provider sees it.
        .args(["-s", &android, "shell", &command])
        .output()
        .expect("Android NAN SD command");
    assert!(
        output.status.success(),
        "Android NAN SD command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // An Android active Publish may repeat this descriptor in every suitable
    // discovery window. Send one explicit duplicate as well: the firmware
    // must acknowledge the identical complete profile without allocating a
    // new STA epoch or tearing down the association it is about to create.
    let output = Command::new("adb")
        .args(["-s", &android, "shell", &command])
        .output()
        .expect("duplicate Android NAN SD command");
    assert!(
        output.status.success(),
        "duplicate Android NAN SD command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // An Android active Publish can repeat in successive discovery windows.
    // Require the E6 callback to recognize and copy the exact DMesh Service
    // Info before testing the slower STA replacement; this keeps a receive
    // parser/pool failure distinct from association timing.
    let ingress_deadline = Instant::now() + Duration::from_secs(12);
    loop {
        let radio = snapshot(&mut e6, RAW_WIFI_METHOD_SNAPSHOT);
        let delta = radio.counters.delta_since(before_sd.counters);
        if delta.nan_service_info_enqueued != 0 {
            break;
        }
        assert!(
            Instant::now() < ingress_deadline,
            "e6 did not enqueue Android primary DMesh SD: {}",
            snapshot_summary(&radio)
        );
        thread::sleep(Duration::from_millis(250));
    }

    // The current E6 BSSID-directed association observation is around 11 s.
    // Keep this functional NAN-SD gate above that while the dedicated STA
    // timing row reports and tightens the connection-phase regression.
    let association_timeout_secs = std::env::var("DMESH_E2E_NAN_SD_STA_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(25);
    let deadline = Instant::now() + Duration::from_secs(association_timeout_secs);
    let associated_radio = loop {
        let radio = snapshot(&mut e6, RAW_WIFI_METHOD_SNAPSHOT);
        if radio.sta_associated == Some(true) {
            eprintln!(
                "Android NAN SD -> e6 host STA: {}",
                snapshot_summary(&radio)
            );
            assert_eq!(radio.channel, Some(6));
            break radio;
        }
        assert!(
            Instant::now() < deadline,
            "e6 did not associate from Android primary DMesh SD within {association_timeout_secs}s: {}",
            snapshot_summary(&radio)
        );
        thread::sleep(Duration::from_millis(250));
    };
    // This row is the first persistent pair baseline: it proves Android NAN
    // Service Info reached E6 and records the completed directed STA timing.
    // Later UDP6/NOW rows add their own throughput and latency fields rather
    // than replacing this control-plane evidence.
    record_pair_probe(
        &android_node_identity(&android),
        &e6_node_identity(),
        PairProbeStatus {
            peer: String::new(),
            test: "android_nan_sd_to_e6_sta_wlan0".to_owned(),
            last_result: "passed".to_owned(),
            last_seen_unix_ms: 0,
            nan_service_info: Some(true),
            sta_associated: associated_radio.sta_associated,
            association_ms: associated_radio.sta_connect_to_associated_ms,
            rssi_dbm: associated_radio.sta_ap_rssi_dbm,
            throughput_bps: None,
            latency_us: None,
        },
    );

    // This pure-STA declaration deliberately requests `nan_dw_interval=0`.
    // It therefore cannot receive a follow-up NAN SD while associated. The
    // host control plane replaces it with the normal unassociated NAN state;
    // a later STA+NAN row will exercise an in-band SD replacement with a
    // nonzero DW interval.
    control_request(
        &mut e6,
        ControlRequest::TransportStart {
            kind: TransportKind::Nan,
            config: dmesh_server::control::TransportConfig {
                channel: Some(6),
                now: Some(0),
                nan_dw_interval: Some(1),
                ap: Some(1),
                ..dmesh_server::control::TransportConfig::default()
            },
        },
        0xE6_414E_03,
    );

    let revert_deadline = Instant::now() + Duration::from_secs(12);
    loop {
        let radio = snapshot(&mut e6, RAW_WIFI_METHOD_SNAPSHOT);
        if radio.sta_associated == Some(false) && radio.nan_dw_interval == Some(1) {
            eprintln!(
                "host transport.start -> e6 returned to NAN: {}",
                snapshot_summary(&radio)
            );
            break;
        }
        assert!(
            Instant::now() < revert_deadline,
            "e6 did not return to NAN after host transport.start: {}",
            snapshot_summary(&radio)
        );
        thread::sleep(Duration::from_millis(250));
    }
}

/// Inject one complete raw action through the same direct-CBOR raw-radio
/// handler used by operator tooling. The receiver test intentionally does not
/// await a text acknowledgement: each send is followed by its own snapshot.
fn send_raw_action(session: &mut DeviceSession, frame: &[u8], interface: RawWifiInterface) {
    let mut wire = [0u8; 1600];
    let mut encoder = Encoder::new(&mut wire);
    encoder.map(7).unwrap();
    encoder.uint(0).unwrap();
    encoder.uint(1).unwrap();
    encoder.uint(1).unwrap();
    encoder.bytes_value(frame).unwrap();
    encoder.uint(2).unwrap();
    encoder.uint(6).unwrap();
    encoder.uint(3).unwrap();
    encoder
        .uint(match interface {
            RawWifiInterface::Ap => 2,
            _ => 1,
        })
        .unwrap();
    encoder.uint(4).unwrap();
    encoder.boolean(false).unwrap();
    encoder.uint(5).unwrap();
    encoder.uint(0).unwrap();
    encoder.uint(6).unwrap();
    encoder.boolean(false).unwrap();
    let used = encoder.len();
    drop(encoder);
    session.send_direct_record(&wire[..used]).unwrap();
}

const ROC_SUSTAINED_WINDOW: Duration = Duration::from_secs(4);
const ROC_SUSTAINED_WINDOW_MS: u16 = 4_000;
const ROC_SUSTAINED_ACTION_INTERVAL: Duration = Duration::from_millis(50);
const ROC_MIN_OBSERVED_PERCENT: u64 = 75;

/// ROC-only receiver proof: private NOW dispatcher disabled, idle STA on
/// channel 6, then send valid NOW and NAN public actions for a full four-second
/// ROC dwell. The final snapshot reports the action receive ratio and the
/// non-promiscuous vendor-IE beacon observation during the same interval.
///
/// ROC delivers management *actions*, not beacons.  Beacons arrive through
/// ESP-IDF's vendor-IE callback, so this row deliberately keeps those two
/// independent receive proofs visible while DW/promiscuous capture is off.
/// Equivalent manual commands are the `raw_wifi` CBOR TX records generated
/// here, after `radio.control {25:4000,26:false,27:false}`. Repeating ROC
/// leases are deliberately not part of this quality row: ESP-IDF completion,
/// rather than a nominal timer, must own a future reissue.
fn roc_only_unassociated_action_matrix(
    e6: &mut DeviceSession,
    e7: &mut DeviceSession,
    e6_ap_mac: [u8; 6],
) {
    let control = RawWifiControlRequest {
        channel: Some(6),
        raw_sta_mode: Some(RawWifiStaMode::MainStyle),
        promiscuous: Some(false),
        dw_policy: Some(RawWifiDwPolicy::Disabled),
        roc_listen_ms: Some(ROC_SUSTAINED_WINDOW_MS),
        roc_loop: Some(false),
        action_dispatcher: Some(false),
        ..RawWifiControlRequest::default()
    };
    let mut control_wire = [0u8; 96];
    let used = encode_raw_wifi_control_request(control, &mut control_wire).unwrap();
    let before = radio_request(e6, &control_wire[..used]);
    assert_eq!(before.sta_associated, Some(false));
    assert_eq!(before.promiscuous, Some(false));
    let mut now = [0u8; 64];
    let now_len = dmesh_rawnan::espnow::encode_action_frame(
        &mut now, [0xff; 6], e6_ap_mac, [0xff; 6], b"roc-now",
    )
    .unwrap();
    let nan = dmesh_rawnan::build_nan_publish_sdf(
        dmesh_rawnan::NAN_DISCOVERY_MAC,
        e6_ap_mac,
        [0xff; 6],
        [0; 6],
        1,
        b"roc-nan",
    );
    let started = Instant::now();
    let mut sent_actions = 0u32;
    while started.elapsed() < ROC_SUSTAINED_WINDOW {
        send_raw_action(e7, &now[..now_len], RawWifiInterface::Sta);
        send_raw_action(e7, &nan, RawWifiInterface::Sta);
        sent_actions = sent_actions.saturating_add(2);
        thread::sleep(ROC_SUSTAINED_ACTION_INTERVAL);
    }
    let snapshot_len =
        encode_raw_wifi_snapshot_request(RAW_WIFI_METHOD_SNAPSHOT, &mut control_wire).unwrap();
    let snapshot = radio_request(e6, &control_wire[..snapshot_len]);
    let delta = snapshot.counters.delta_since(before.counters);
    let observed_actions = delta
        .roc_espnow_actions
        .saturating_add(delta.roc_nan_actions);
    let observed_percent = u64::from(observed_actions)
        .saturating_mul(100)
        .checked_div(u64::from(sent_actions))
        .unwrap_or(0);
    eprintln!(
        "firmware-e2e row=unassociated-roc-only dwell_ms={} sent_actions={} observed_actions={} observed_percent={} now={} nan={} other={} requests={} failures={} vendor_beacon_ies={} vendor_nan_beacon_ies={} vendor_other_ies={}",
        ROC_SUSTAINED_WINDOW_MS,
        sent_actions,
        observed_actions,
        observed_percent,
        delta.roc_espnow_actions,
        delta.roc_nan_actions,
        delta.roc_other_actions,
        delta.roc_action_listen_requests,
        delta.roc_action_listen_failures,
        delta.vendor_beacon_ies,
        delta.vendor_nan_beacon_ies,
        delta.vendor_other_ies,
    );
    assert!(
        delta.roc_action_listen_requests >= 1,
        "ROC request was not accepted: {delta:?}"
    );
    assert_eq!(
        delta.roc_action_listen_failures, 0,
        "ROC request failed: {delta:?}"
    );
    assert!(
        observed_percent >= ROC_MIN_OBSERVED_PERCENT,
        "ROC action reception below {ROC_MIN_OBSERVED_PERCENT}%: sent={sent_actions} observed={observed_actions} delta={delta:?}"
    );
    let restore = RawWifiControlRequest {
        roc_loop: Some(false),
        action_dispatcher: Some(true),
        ..RawWifiControlRequest::default()
    };
    let used = encode_raw_wifi_control_request(restore, &mut control_wire).unwrap();
    let _ = radio_request(e6, &control_wire[..used]);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn snapshot_summary(snapshot: &dmesh_server::raw_wifi::RawWifiSnapshot) -> String {
    let service_bps = raw_service_bps(snapshot);
    format!(
        "ch={:?} sta={:?} rssi_dbm={:?} prom={:?} dw={:?}/{:?} ap={:?} active={:?} assoc_phase_ms={:?} disconnect_reason={:?} tx={}/{} rx_dispatch={} parsed={} nan={}/{}/{} service_info={}/{}/{} bootstrap={} stream={} client_errors={} raw_bytes={:?} raw_elapsed_us={:?} raw_bps={service_bps:?} roc={}/{}/{} last_error={:?}",
        snapshot.channel,
        snapshot.sta_associated,
        snapshot.sta_ap_rssi_dbm,
        snapshot.promiscuous,
        snapshot.dw_capturing,
        snapshot.nan_dw_interval,
        snapshot.ap_active,
        snapshot.raw_service_active,
        snapshot.sta_connect_to_associated_ms,
        snapshot.sta_last_disconnect_reason,
        snapshot.counters.tx_driver_accepted,
        snapshot.counters.tx_attempted,
        snapshot.counters.rx_driver_dispatch,
        snapshot.counters.rx_parser_accepted,
        snapshot.counters.nan_beacons,
        snapshot.counters.nan_sdfs,
        snapshot.counters.nan_followups,
        snapshot.counters.nan_service_info_matched,
        snapshot.counters.nan_service_info_enqueued,
        snapshot.counters.nan_service_info_dropped,
        snapshot.counters.raw_client_bootstrap_acks,
        snapshot.counters.raw_client_stream_packets,
        snapshot.counters.raw_client_receive_errors,
        snapshot.raw_service_bytes,
        snapshot.raw_service_elapsed_us,
        snapshot.counters.roc_action_listen_requests,
        snapshot.counters.roc_action_listen_failures,
        snapshot.counters.roc_action_frames,
        snapshot.last_raw_client_error,
    )
}

/// Device-side goodput derived from the shared raw-service client's monotonic
/// elapsed timer. A check response is intentionally tiny, so its number is a
/// progress/latency diagnostic; bulk IPERF rows use the same fields for a
/// meaningful throughput result.
fn raw_service_bps(snapshot: &dmesh_server::raw_wifi::RawWifiSnapshot) -> Option<u64> {
    let bytes = u64::from(snapshot.raw_service_bytes?);
    let elapsed_us = u64::from(snapshot.raw_service_elapsed_us?);
    if bytes == 0 || elapsed_us == 0 {
        None
    } else {
        Some(bytes.saturating_mul(8_000_000) / elapsed_us)
    }
}

fn snapshot(session: &mut DeviceSession, method: u64) -> dmesh_server::raw_wifi::RawWifiSnapshot {
    let mut request = [0u8; 16];
    let used = encode_raw_wifi_snapshot_request(method, &mut request).expect("snapshot method");
    radio_request(session, &request[..used])
}

fn enable_normal_dw(session: &mut DeviceSession) -> dmesh_server::raw_wifi::RawWifiSnapshot {
    // The shared encoder emits {1:4, 2:72, 5:{10:false, 11:0}}: control,
    // promiscuous off,
    // DW policy normal. It deliberately leaves an associated STA's channel
    // unchanged; the driver rightfully rejects an on-channel STA retune.
    let control = RawWifiControlRequest {
        // A prior failed matrix row can leave a volatile APSTA owner or an
        // unassociated STA hold behind. Restore the same reusable baseline
        // on every suite invocation; this does not write NVS or reopen UART.
        ap_mode: Some(RawWifiApMode::Disabled),
        sta_state: Some(RawWifiStaState::Reconnect),
        interface: Some(RawWifiInterface::Auto),
        action_destination_broadcast: Some(false),
        promiscuous: Some(false),
        dw_policy: Some(RawWifiDwPolicy::Normal),
        ..RawWifiControlRequest::default()
    };
    let mut request = [0u8; 64];
    let used = encode_raw_wifi_control_request(control, &mut request).unwrap();
    let snapshot = radio_request(session, &request[..used]);
    assert_eq!(snapshot.promiscuous, Some(false));
    snapshot
}

fn set_action_mac_ack(
    session: &mut DeviceSession,
    enabled: bool,
) -> dmesh_server::raw_wifi::RawWifiSnapshot {
    let control = RawWifiControlRequest {
        mac_ack: Some(enabled),
        ..RawWifiControlRequest::default()
    };
    let mut request = [0u8; 64];
    let used =
        encode_raw_wifi_control_request(control, &mut request).expect("MAC ACK control request");
    let snapshot = radio_request(session, &request[..used]);
    assert_eq!(snapshot.mac_ack, Some(enabled));
    snapshot
}

fn wait_for_associated_channel_6(
    session: &mut DeviceSession,
) -> dmesh_server::raw_wifi::RawWifiSnapshot {
    wait_for_associated_channel_6_matching(session, None)
}

/// A transport start replaces an asynchronous radio epoch. Association and
/// channel alone can still describe the previous epoch, so performance A/Bs
/// must wait for the requested egress selection as well.
fn wait_for_associated_channel_6_with_driver_tx(
    session: &mut DeviceSession,
    sta_driver_tx: bool,
) -> dmesh_server::raw_wifi::RawWifiSnapshot {
    wait_for_associated_channel_6_matching(session, Some(sta_driver_tx))
}

fn wait_for_associated_channel_6_matching(
    session: &mut DeviceSession,
    expected_sta_driver_tx: Option<bool>,
) -> dmesh_server::raw_wifi::RawWifiSnapshot {
    // `wifi_esp::init_sta` uses a bounded 50-second association window. A
    // UART/NAN start must be allowed to complete that first radio epoch before
    // this test classifies the AP target or NOW setup as broken.
    let association_started = Instant::now();
    let deadline = association_started + Duration::from_secs(65);
    let mut observed = snapshot(session, RAW_WIFI_METHOD_SNAPSHOT);
    while !(observed.sta_associated == Some(true)
        && observed.channel == Some(6)
        && expected_sta_driver_tx.is_none_or(|expected| observed.sta_driver_tx == Some(expected)))
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(100));
        observed = snapshot(session, RAW_WIFI_METHOD_SNAPSHOT);
    }
    // Snapshots are requested on every poll and would swamp the useful UART
    // history here. Keep only decoded non-radio-control records: these carry
    // the Wi-Fi owner's mode/start diagnostics and the correlated start reply.
    let diagnostics = session
        .recent_events()
        .filter_map(|event| match event {
            DeviceSessionEvent::DirectRecord(record) => {
                if let Some(response) = decode_tagged_record(record) {
                    (!matches!(
                        (response.component, response.method),
                        (
                            Some(dmesh_server::tagged::Name::Tag(4)),
                            Some(dmesh_server::tagged::Name::Tag(73))
                        )
                    ))
                    .then(|| format!("{response:?}"))
                } else {
                    core::str::from_utf8(record)
                        .ok()
                        .map(|text| format!("status={text}"))
                }
            }
            _ => None,
        })
        .take(16)
        .collect::<Vec<_>>();
    assert_eq!(
        observed.sta_associated,
        Some(true),
        "{} did not reassociate before the action matrix: {observed:?}; UART history={diagnostics:?}",
        session.path(),
    );
    assert_eq!(
        observed.channel,
        Some(6),
        "{} did not return to lab channel 6 before the action matrix: {observed:?}",
        session.path()
    );
    if let Some(expected) = expected_sta_driver_tx {
        assert_eq!(
            observed.sta_driver_tx,
            Some(expected),
            "{} did not apply requested STA TX path before the performance row: {observed:?}",
            session.path(),
        );
    }
    eprintln!(
        "STA association settled device={} bssid-directed elapsed_ms={} channel={:?} diagnostics={diagnostics:?}",
        session.path(),
        association_started.elapsed().as_millis(),
        observed.channel,
    );
    observed
}

/// A directed STA start must not depend on observing the AP's next beacon.
/// The AP identity comes from the supervised owner and is carried in the one
/// UART `transport.start` CBOR record as SSID, BSSID, and channel. Select the
/// 500-TU lab AP without changing test code through
/// `DMESH_E2E_AP_SERVICE=lmesh DMESH_E2E_AP_IFACE=wlan1`.
#[test]
#[ignore = "requires flashed e6 and an already-running supervised AP; never changes host radio state"]
fn firmware_e6_bssid_directed_sta_association() {
    let mut e6 = DeviceSession::open(serial_from_env("DMESH_E2E_E6"), None).unwrap();
    e6.set_history_limit(1_024);
    // Do not let an already-associated epoch satisfy the first snapshot. The
    // timing gate begins only after the device has proved the normal default
    // NAN+NOW/unassociated state.
    configure_nan_for_channel(&mut e6, 6, 0xE6_B5_50F0);
    wait_for_unassociated_channel_6(&mut e6);
    let ssid = wlan0_ssid();
    let started = Instant::now();
    configure_sta_for_wlan0_with_now(&mut e6, &ssid, true, true, 0xE6_B5_5100);
    // A failed association must not strand the device in a partial STA epoch.
    // Restore the default NAN+NOW personality before re-raising the detailed
    // association assertion from the common wait helper.
    let association = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wait_for_associated_channel_6_with_driver_tx(&mut e6, true)
    }));
    let snapshot = match association {
        Ok(snapshot) => snapshot,
        Err(payload) => {
            configure_nan_for_channel(&mut e6, 6, 0xE6_B5_5101);
            wait_for_unassociated_channel_6(&mut e6);
            std::panic::resume_unwind(payload);
        }
    };
    let elapsed = started.elapsed();
    let max_ms = std::env::var("DMESH_E2E_BSSID_CONNECT_MAX_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(500);
    eprintln!(
        "firmware-e2e row=e6 bssid-directed-association epoch_elapsed_ms={} connect_phase_ms={:?} max_ms={} state=({})",
        elapsed.as_millis(),
        snapshot.sta_connect_to_associated_ms,
        max_ms,
        snapshot_summary(&snapshot),
    );
    let connect_phase_ms = snapshot
        .sta_connect_to_associated_ms
        .expect("e6 did not report ESP-IDF connect-to-CONNECTED timing");
    let within_bound = u64::from(connect_phase_ms) <= max_ms;
    // Restore the default NAN+NOW epoch before reporting a timing regression,
    // so an expected/diagnostic failure cannot leave the board associated.
    configure_nan_for_channel(&mut e6, 6, 0xE6_B5_5101);
    wait_for_unassociated_channel_6(&mut e6);
    assert!(
        within_bound,
        "BSSID-directed connect phase took {connect_phase_ms} ms (limit {max_ms} ms); full epoch took {} ms: {snapshot:?}",
        elapsed.as_millis(),
    );
}

fn wait_for_unassociated_channel_6(
    session: &mut DeviceSession,
) -> dmesh_server::raw_wifi::RawWifiSnapshot {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut observed = snapshot(session, RAW_WIFI_METHOD_SNAPSHOT);
    while !(observed.sta_associated == Some(false) && observed.channel == Some(6))
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(100));
        observed = snapshot(session, RAW_WIFI_METHOD_SNAPSHOT);
    }
    let diagnostics = session
        .recent_events()
        .filter_map(|event| match event {
            DeviceSessionEvent::DirectRecord(record) => {
                if let Some(response) = decode_tagged_record(record) {
                    (!matches!(
                        (response.component, response.method),
                        (
                            Some(dmesh_server::tagged::Name::Tag(4)),
                            Some(dmesh_server::tagged::Name::Tag(73))
                        )
                    ))
                    .then(|| format!("{response:?}"))
                } else {
                    core::str::from_utf8(record).ok().map(str::to_owned)
                }
            }
            _ => None,
        })
        .take(24)
        .collect::<Vec<_>>();
    assert_eq!(
        observed.sta_associated,
        Some(false),
        "unassociated NOW mode: {observed:?}; UART history={diagnostics:?}"
    );
    assert_eq!(
        observed.channel,
        Some(6),
        "unassociated NOW channel: {observed:?}; UART history={diagnostics:?}"
    );
    observed
}

fn start_espnow_check(
    session: &mut DeviceSession,
    peer: [u8; 6],
    nonce: u64,
) -> dmesh_server::raw_wifi::RawWifiSnapshot {
    // Exact direct-PPP request, rendered by the shared encoder rather than a
    // The shared encoder emits `{1:4,2:75,5:{17:h'E6_MAC',18:nonce,19:5000}}`.
    // The same CBOR body may be sent to the registered hardware stream
    // handler; direct PPP keeps radio matrix setup independent of QUIC/UART
    // stream admission while retaining the identical handler schema.
    let mut request = [0u8; 64];
    let used = encode_raw_wifi_check_request(
        RawWifiCheckRequest {
            peer,
            nonce,
            timeout_ms: 5_000,
        },
        &mut request,
    )
    .expect("valid bounded check request");
    radio_request(session, &request[..used])
}

/// Run one bounded raw-action service check. Each attempt is a fresh
/// association (the nonce drives a fresh local CID), so this exercises the
/// normal QUIC-lite recovery path without reopening either UART or rebooting
/// a device. An occasional ESP action-TX rejection is RF/driver evidence, not
/// success; the row fails with all attempt snapshots if no complete response
/// arrives within this small, explicit retry budget.
fn complete_action_check(
    initiator: &mut DeviceSession,
    responder: &mut DeviceSession,
    peer: [u8; 6],
    nonce: u64,
    label: &str,
) -> (
    dmesh_server::raw_wifi::RawWifiSnapshot,
    dmesh_server::raw_wifi::RawWifiSnapshot,
) {
    let mut attempts = Vec::new();
    for attempt in 0..3u64 {
        snapshot(initiator, RAW_WIFI_METHOD_RESET_COUNTERS);
        snapshot(responder, RAW_WIFI_METHOD_RESET_COUNTERS);
        // `check` is deliberately a one-request/one-response liveness probe.
        // Measure time to the first completed client counter sample rather
        // than two fixed-duration UART polls. This is a bounded completion
        // latency (25 ms sampling granularity), not bulk throughput; the
        // separately parameterized IPERF rows own goodput measurements.
        let started_at = Instant::now();
        let started = start_espnow_check(initiator, peer, nonce + attempt);
        if started.raw_service_active != Some(true) {
            let source = snapshot(responder, RAW_WIFI_METHOD_SNAPSHOT);
            attempts.push((source, started));
            continue;
        }
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        let mut client = snapshot(initiator, RAW_WIFI_METHOD_SNAPSHOT);
        while client.counters.raw_client_stream_packets == 0
            && client.counters.raw_client_receive_errors == 0
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(25));
            client = snapshot(initiator, RAW_WIFI_METHOD_SNAPSHOT);
        }
        let source = snapshot(responder, RAW_WIFI_METHOD_SNAPSHOT);
        if client.counters.raw_client_stream_packets > 0
            && client.counters.raw_client_receive_errors == 0
        {
            eprintln!(
                "firmware-e2e row={label} kind=raw-check attempt={} completion_latency_us={} device_raw_bytes={:?} device_raw_elapsed_us={:?} device_raw_bps={:?} source=(ch={:?} sta={:?} prom={:?} ap={:?} tx={}/{} rx_dispatch={} parsed={}) client=(ch={:?} sta={:?} prom={:?} tx={}/{} bootstrap={} stream={} receive_errors={} last_error={:?})",
                attempt + 1,
                started_at.elapsed().as_micros(),
                client.raw_service_bytes,
                client.raw_service_elapsed_us,
                raw_service_bps(&client),
                source.channel,
                source.sta_associated,
                source.promiscuous,
                source.ap_active,
                source.counters.tx_driver_accepted,
                source.counters.tx_attempted,
                source.counters.rx_driver_dispatch,
                source.counters.rx_parser_accepted,
                client.channel,
                client.sta_associated,
                client.promiscuous,
                client.counters.tx_driver_accepted,
                client.counters.tx_attempted,
                client.counters.raw_client_bootstrap_acks,
                client.counters.raw_client_stream_packets,
                client.counters.raw_client_receive_errors,
                client.last_raw_client_error,
            );
            return (source, client);
        }
        attempts.push((source, client));
    }
    let attempts = attempts
        .iter()
        .enumerate()
        .map(|(index, (source, client))| {
            format!(
                "attempt={} source=({}) client=({})",
                index + 1,
                snapshot_summary(source),
                snapshot_summary(client),
            )
        })
        .collect::<Vec<_>>();
    panic!(
        "{label} did not complete after {} fresh associations: {attempts:?}",
        attempts.len()
    );
}

/// Focused STA+NOW gate for the default transport profile. Both devices use a
/// plain STA start; NAN DW capture remains off. This proves that e6 accepts
/// and originates an action-bearer exchange without special NOW setup.
#[test]
#[ignore = "requires flashed e6/e7 firmware, the supervised wlan0 AP, and exclusive UART ownership"]
fn firmware_sta_now_e6_e7() {
    let mut e6 = DeviceSession::open(serial_from_env("DMESH_E2E_E6"), None).unwrap();
    let mut e7 = DeviceSession::open(serial_from_env("DMESH_E2E_E7"), None).unwrap();
    e6.set_history_limit(4_096);
    e7.set_history_limit(4_096);

    let ssid = wlan0_ssid();
    configure_sta_for_wlan0(&mut e6, &ssid, 0xE6_6E00);
    configure_sta_for_wlan0(&mut e7, &ssid, 0xE7_6E00);
    let e6_mode = wait_for_associated_channel_6(&mut e6);
    let e7_mode = wait_for_associated_channel_6(&mut e7);
    for (name, mode) in [("e6", e6_mode), ("e7", e7_mode)] {
        assert_eq!(mode.sta_associated, Some(true), "{name} STA association");
        assert_eq!(
            mode.promiscuous,
            Some(false),
            "{name} must not be promiscuous"
        );
        assert_eq!(mode.dw_capturing, Some(false), "{name} NAN DW must be off");
    }

    let (e6_source, e7_client) =
        complete_action_check(&mut e7, &mut e6, E6_MAC, 0xE6_6E01, "STA+NOW e7->e6");
    assert!(
        e6_source.counters.rx_driver_dispatch > 0,
        "e6 did not dispatch NOW"
    );
    assert!(
        e6_source.counters.rx_parser_accepted > 0,
        "e6 did not parse NOW"
    );
    assert!(
        e7_client.counters.raw_client_stream_packets > 0,
        "e7 did not receive the e6 response"
    );
    assert_eq!(e7_client.counters.raw_client_receive_errors, 0);

    let (e7_source, e6_client) =
        complete_action_check(&mut e6, &mut e7, E7_MAC, 0xE6_6E02, "STA+NOW e6->e7");
    assert!(
        e7_source.counters.rx_driver_dispatch > 0,
        "e7 did not dispatch NOW"
    );
    assert!(
        e7_source.counters.rx_parser_accepted > 0,
        "e7 did not parse NOW"
    );
    assert!(
        e6_client.counters.raw_client_stream_packets > 0,
        "e6 did not receive the e7 response"
    );
    assert_eq!(e6_client.counters.raw_client_receive_errors, 0);
}

/// Host-to-e6 action-bearer IPERF using the same raw QUIC-lite client as the
/// firmware. The host keeps the established broadcast Address-1 action mode;
/// e6 binds replies to the host action source. This is deliberately distinct
/// from the raw-UDP6 performance row.
#[test]
#[ignore = "requires flashed e6 firmware, the supervised wlan0 AP, and exclusive e6 UART ownership"]
fn firmware_host_to_e6_now_iperf() {
    let mut e6 = DeviceSession::open(serial_from_env("DMESH_E2E_E6"), None).unwrap();
    e6.set_history_limit(4_096);
    let ap_service = e2e_ap_service();
    let ap_iface = e2e_ap_iface();
    let ssid = wlan0_ssid();
    let unassociated = std::env::var("DMESH_E2E_UNASSOCIATED_NOW").ok().as_deref() == Some("1");
    let mode = if unassociated {
        configure_nan_for_channel(&mut e6, 6, 0xE6_6F10);
        wait_for_unassociated_channel_6(&mut e6)
    } else {
        configure_sta_for_wlan0(&mut e6, &ssid, 0xE6_6F00);
        wait_for_associated_channel_6(&mut e6)
    };
    assert_eq!(mode.sta_associated, Some(!unassociated));
    assert_eq!(mode.promiscuous, Some(false));
    assert_eq!(mode.dw_capturing, Some(false));
    snapshot(&mut e6, RAW_WIFI_METHOD_RESET_COUNTERS);

    // Keep the action health exchange distinct from bulk transfer. A large
    // run is meaningful only after the current radio epoch has answered a
    // complete NOW request/response without changing host infrastructure.
    let e6_peer = "14:c1:9f:e5:98:00".to_owned();
    let check = wifi_raw_check_for_peer(
        &ap_service,
        &ap_iface,
        "ff:ff:ff:ff:ff:ff".to_owned(),
        e6_peer.clone(),
        0xE6_6F11,
        e2e_now_timeout_ms(),
        e2e_now_rate() as u8,
        &e2e_now_tx_variant(),
        &e2e_now_rx_variant(),
    );
    let e6_after_check = snapshot(&mut e6, RAW_WIFI_METHOD_SNAPSHOT);
    eprintln!(
        "firmware-e2e row=host->e6-now-check result={check} e6=({})",
        snapshot_summary(&e6_after_check)
    );
    assert_eq!(
        check
            .get("data")
            .and_then(|data| data.get("ok"))
            .and_then(serde_json::Value::as_bool),
        Some(true),
        "host->e6 NOW short check failed before IPERF: {check}; e6={e6_after_check:?}"
    );

    let bytes = e2e_now_bytes();
    let result = wifi_raw_iperf_for_peer(
        &ap_service,
        &ap_iface,
        "ff:ff:ff:ff:ff:ff".to_owned(),
        e6_peer,
        bytes,
        // Firmware action ingress uses the shared 1,100-byte transport MTU.
        // A single common bound prevents the host action client from sending
        // a final datagram the e6 responder cannot complete.
        E2E_UDP6_PACKET_SIZE,
        e2e_now_timeout_ms(),
        e2e_now_rate() as u8,
        &e2e_now_tx_variant(),
        &e2e_now_rx_variant(),
    );
    let data = result.get("data").unwrap_or(&result);
    let e6_after = snapshot(&mut e6, RAW_WIFI_METHOD_SNAPSHOT);
    eprintln!(
        "firmware-e2e row=host->e6-now-iperf result={result} e6=({})",
        snapshot_summary(&e6_after)
    );
    assert_eq!(
        data.get("ok").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        data.get("bytes").and_then(serde_json::Value::as_u64),
        Some(bytes)
    );
    assert!(
        e6_after.counters.rx_driver_dispatch > 0,
        "e6 did not dispatch host NOW frames: {e6_after:?}"
    );
    assert!(
        e6_after.counters.rx_parser_accepted > 0,
        "e6 did not parse host NOW frames: {e6_after:?}"
    );
}

/// Alternate complete radio epochs on e7/Main without changing host radio
/// infrastructure.  Each `transport.start` replaces the prior Wi-Fi owner:
/// NAN is the unassociated NAN+NOW control-plane state, while STA is the
/// associated STA+NAN+NOW state (DW disabled for this NOW reachability gate).
/// The elapsed time is command acceptance through the first snapshot that
/// proves the requested state, rather than merely UART CBOR acknowledgement.
#[test]
#[ignore = "requires flashed e7 Main, supervised wlan0 AP, and exclusive e7 UART ownership"]
fn firmware_e7_nan_now_sta_transition_cycles() {
    let mut e7 = DeviceSession::open(serial_from_env("DMESH_E2E_E7"), None).unwrap();
    e7.set_history_limit(4_096);
    let cycles = std::env::var("DMESH_E2E_TRANSITION_CYCLES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(3)
        .clamp(1, 8);
    let ssid = wlan0_ssid();
    let e7_peer = "14:c1:9f:e4:5d:48".to_owned();
    let ap_service = e2e_ap_service();
    let ap_iface = e2e_ap_iface();
    let mut checks = Vec::new();

    for cycle in 0..cycles {
        let nan_started = Instant::now();
        configure_nan_for_channel(&mut e7, 6, 0xE7_4E_0000 + cycle * 16);
        let nan = wait_for_unassociated_channel_6(&mut e7);
        let nan_elapsed = nan_started.elapsed();
        let nan_check = wifi_raw_check_for_peer(
            &ap_service,
            &ap_iface,
            "ff:ff:ff:ff:ff:ff".to_owned(),
            e7_peer.clone(),
            0xE7_4E_0001 + cycle * 16,
            5_000,
            6,
            "monitor",
            "monitor",
        );
        let nan_ok = nan_check["data"]["ok"].as_bool() == Some(true);
        eprintln!(
            "firmware-e2e row=e7 transition={} mode=nan-now settled_ms={} state=({}) host_now_ok={} check={}",
            cycle,
            nan_elapsed.as_millis(),
            snapshot_summary(&nan),
            nan_ok,
            nan_check,
        );
        checks.push(("nan-now", cycle, nan_ok, nan_check));

        let sta_started = Instant::now();
        configure_sta_for_wlan0_with_now(&mut e7, &ssid, true, true, 0xE7_4E_0008 + cycle * 16);
        let sta = wait_for_associated_channel_6_with_driver_tx(&mut e7, true);
        let sta_elapsed = sta_started.elapsed();
        let sta_check = wifi_raw_check_for_peer(
            &ap_service,
            &ap_iface,
            "ff:ff:ff:ff:ff:ff".to_owned(),
            e7_peer.clone(),
            0xE7_4E_0009 + cycle * 16,
            5_000,
            6,
            "monitor",
            "monitor",
        );
        let sta_ok = sta_check["data"]["ok"].as_bool() == Some(true);
        eprintln!(
            "firmware-e2e row=e7 transition={} mode=sta-nan-now settled_ms={} state=({}) host_now_ok={} check={}",
            cycle,
            sta_elapsed.as_millis(),
            snapshot_summary(&sta),
            sta_ok,
            sta_check,
        );
        checks.push(("sta-nan-now", cycle, sta_ok, sta_check));
    }

    // Restore the normal boot personality even when a reachability assertion
    // below fails, so this diagnostic test cannot leave the device associated.
    let restore_started = Instant::now();
    configure_nan_for_channel(&mut e7, 6, 0xE7_4E_FFF0);
    let restored = wait_for_unassociated_channel_6(&mut e7);
    eprintln!(
        "firmware-e2e row=e7 transition=restore mode=nan-now settled_ms={} state=({})",
        restore_started.elapsed().as_millis(),
        snapshot_summary(&restored),
    );

    let failed = checks
        .iter()
        .filter(|(_, _, ok, _)| !ok)
        .map(|(mode, cycle, _, result)| format!("cycle={cycle} mode={mode} result={result}"))
        .collect::<Vec<_>>();
    assert!(failed.is_empty(), "host->e7 NOW checks failed: {failed:?}");
}

#[test]
#[ignore = "requires the e6/e7 radio lab and exclusive UART ownership"]
fn firmware_transport_matrix() {
    // CLI equivalent preflight (the suite keeps both ports open instead):
    // The shared snapshot encoder emits component 4 / method 73. Keep this
    // test constructor-based so an envelope change cannot leave a stale hex
    // reproduction command behind.
    let mut e6 = DeviceSession::open(serial_from_env("DMESH_E2E_E6"), None).unwrap();
    let mut e7 = DeviceSession::open(serial_from_env("DMESH_E2E_E7"), None).unwrap();
    // A direct radio response is not tagged with a request ID. Keep the
    // entire single-session matrix history so each typed response is selected
    // after its own send boundary, not from an older UART callback.
    e6.set_history_limit(4_096);
    e7.set_history_limit(4_096);

    // The host-owned probe is the common setup primitive for the matrix and
    // eventual control-plane UI: it places e6 and e7 in independent complete
    // modes before any bearer row, then records their NAN/DW/RSSI baseline.
    // It never asks either ESP to implement a probe service.
    let ssid = wlan0_ssid();
    let (ap_bssid, _) = wlan0_bssid_channel();
    let _baseline = probe(
        &mut e6,
        &mut e7,
        ProbeRequest {
            request_id: 0x4553_0000,
            source: ProbeEndpoint {
                kind: ProbeEndpointKind::Esp,
                node: E6_MAC,
                mode: ProbeMode::STA_NAN_NOW,
                bssid: Some(ap_bssid),
            },
            target: ProbeEndpoint {
                kind: ProbeEndpointKind::Esp,
                node: E7_MAC,
                mode: ProbeMode::STA_NAN_NOW,
                bssid: Some(ap_bssid),
            },
            test_nan: true,
            test_now: true,
            test_udp6: true,
            short_bytes: E2E_UDP6_PACKET_SIZE.into(),
            long_bytes: E2E_UDP6_DEFAULT_BYTES as u32,
            measure_mode_switch: true,
        },
        &ssid,
        0xE6_6200,
        0xE7_6200,
    );
    enable_normal_dw(&mut e6);
    enable_normal_dw(&mut e7);

    // Permanent preflight: both devices are associated STA on channel 6,
    // normal NAN DW policy is enabled, and continuous promiscuous capture is
    // off.  Run a matching UDP6 `SERVICE_ECHO` worker concurrently: action
    // loss/latency is meaningful only when the raw IPv6 bearer stays healthy.
    let mac_ack = action_mac_ack();
    set_action_mac_ack(&mut e6, mac_ack);
    set_action_mac_ack(&mut e7, mac_ack);
    let action_samples = action_check_repeats();
    let udp_echo_worker = thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("UDP6 echo runtime")
            .block_on(host_to_e6_udp6_echo_checks(
                action_samples.saturating_mul(2),
            ))
    });
    for sample in 0..action_samples {
        let nonce = 0x4553_0001 + sample.saturating_mul(2);
        let (e6_after, e7_after) = complete_action_check(
            &mut e7,
            &mut e6,
            E6_MAC,
            nonce,
            &format!("STA e7->e6 sample={sample} mac_ack={mac_ack}"),
        );
        assert!(
            e7_after.counters.tx_attempted > 0,
            "e7 did not issue a NOW action"
        );
        assert!(
            e6_after.counters.rx_driver_dispatch > 0,
            "e6 did not dispatch a NOW action"
        );
        assert!(
            e6_after.counters.rx_parser_accepted > 0,
            "e6 did not accept the raw service packet"
        );
        assert!(
            e7_after.counters.raw_client_stream_packets > 0,
            "e7 did not receive the check stream response"
        );
        assert_eq!(
            e7_after.counters.raw_client_receive_errors, 0,
            "e7 check client rejected a response"
        );

        // Reverse direction proves Recovery owns the same client state
        // machine, not merely the smaller receiver canary.
        let (e7_reverse, e6_reverse) = complete_action_check(
            &mut e6,
            &mut e7,
            E7_MAC,
            nonce + 1,
            &format!("STA e6->e7 sample={sample} mac_ack={mac_ack}"),
        );
        assert!(
            e6_reverse.counters.tx_attempted > 0,
            "e6 did not issue a NOW action"
        );
        assert!(
            e7_reverse.counters.rx_driver_dispatch > 0,
            "e7 did not dispatch a NOW action"
        );
        assert!(
            e7_reverse.counters.rx_parser_accepted > 0,
            "e7 did not accept the raw service packet"
        );
        assert!(
            e6_reverse.counters.raw_client_stream_packets > 0,
            "e6 did not receive the check stream response"
        );
        assert_eq!(
            e6_reverse.counters.raw_client_receive_errors, 0,
            "e6 check client rejected a response"
        );
    }
    let udp_echo = udp_echo_worker.join().expect("UDP6 echo worker panicked");
    let udp_echo_failures = udp_echo.iter().filter(|result| result.is_err()).count();
    let mut udp_echo_latencies = udp_echo
        .iter()
        .filter_map(|result| result.as_ref().ok())
        .copied()
        .collect::<Vec<_>>();
    udp_echo_latencies.sort_unstable();
    eprintln!(
        "firmware-e2e row=concurrent-udp6-echo samples={} failures={} min_us={:?} median_us={:?} max_us={:?} mac_ack={mac_ack}",
        udp_echo.len(),
        udp_echo_failures,
        udp_echo_latencies.first(),
        udp_echo_latencies.get(udp_echo_latencies.len() / 2),
        udp_echo_latencies.last(),
    );
    assert_eq!(
        udp_echo_failures, 0,
        "concurrent UDP6 echo failures: {udp_echo:?}"
    );

    // Bulk counterpart of the liveness check above. Keep it opt-in while the
    // C6 action bootstrap retry path is characterized.
    if action_iperf_enabled() {
        let (_e6_bulk, e7_bulk) =
            complete_action_iperf(&mut e7, &mut e6, E6_MAC, "STA e7->e6 NOW bulk");
        assert_eq!(
            e7_bulk.raw_service_bytes,
            Some(E2E_ACTION_IPERF_BYTES as u32)
        );
    }

    // No IPERF row may run until the same current radio configuration has
    // completed the bounded raw-action SERVICE_ECHO check in both directions.
    // Keep the UART sessions open while the host then proves the running
    // lmesh-wifi service and uses its normal IPv6 socket path to e6. This
    // avoids restarting lmesh-wifi or leasing another device-console
    // connection between the sanity check and throughput measurement.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("e2e UDP6 runtime")
        .block_on(async {
            host_to_lmesh_wifi_iperf().await;
            host_to_e6_udp6_iperf().await;
        });

    // APSTA row: e6 Recovery enables its volatile, no-lwIP open AP on the
    // same channel while e7 remains the associated STA. This confirms that a
    // Wi-Fi stop/start re-registers the global NOW action receiver and that
    // an AP beacon owner does not require promiscuous receive for the action
    // bearer. It does not yet assert e7's STA association *to e6's AP*;
    // that requires a separate runtime STA-profile selection handler.
    let ap = RawWifiControlRequest {
        channel: Some(6),
        ap_mode: Some(RawWifiApMode::Open),
        ap_beacon_tu: Some(500),
        promiscuous: Some(false),
        dw_policy: Some(RawWifiDwPolicy::Normal),
        ..RawWifiControlRequest::default()
    };
    let mut request = [0u8; 64];
    let used = encode_raw_wifi_control_request(ap, &mut request).unwrap();
    let e6_ap = radio_request(&mut e6, &request[..used]);
    assert_eq!(
        e6_ap.ap_active,
        Some(true),
        "e6 did not enter APSTA: {e6_ap:?}"
    );
    assert_eq!(
        e6_ap.channel,
        Some(6),
        "e6 APSTA changed lab channel: {e6_ap:?}"
    );
    let (e6_ap_after, e7_ap_after) =
        complete_action_check(&mut e7, &mut e6, E6_MAC, 0x4553_0003, "APSTA e7->e6");
    assert!(
        e7_ap_after.counters.raw_client_stream_packets > 0,
        "e7 did not complete an APSTA NOW check; e6={e6_ap_after:?}; e7={e7_ap_after:?}"
    );
    assert_eq!(
        e7_ap_after.counters.raw_client_receive_errors, 0,
        "e7 rejected an APSTA response; e6={e6_ap_after:?}; e7={e7_ap_after:?}"
    );

    // Choose e6's AP link identity for the following connectionless row.
    // This is a live `radio.control` setting shared by direct PPP and QUIC
    // handlers, rather than a lab-only alternate bearer.  The response must
    // come from the AP when its peer is an idle, unassociated STA.
    let ap_egress = RawWifiControlRequest {
        interface: Some(RawWifiInterface::Ap),
        // ROC's `allow_broadcast` admission is specifically for broadcast
        // Address-1.  Keep the request on the normal directed action path,
        // but make APSTA replies broadcast for the idle-STA receive test.
        action_destination_broadcast: Some(true),
        ..RawWifiControlRequest::default()
    };
    let used = encode_raw_wifi_control_request(ap_egress, &mut request).unwrap();
    let e6_ap_egress = radio_request(&mut e6, &request[..used]);
    assert_eq!(
        e6_ap_egress.tx_interface,
        Some(RawWifiInterface::Ap),
        "e6 did not select AP action egress: {e6_ap_egress:?}"
    );
    assert_eq!(e6_ap_egress.action_destination_broadcast, Some(true));
    let e6_ap_mac = e6_ap_egress
        .ap_mac
        .expect("e6 APSTA snapshot did not expose the AP MAC");
    assert_ne!(e6_ap_mac, [0; 6], "e6 exposed an invalid AP MAC");

    // Connectionless row: keep e6's APSTA beacon/timebase owner, but put e7
    // into the common Main-style raw STA hold. This is deliberately not an
    // association-to-e6 test: the STA is disconnected, remains on channel 6,
    // and proves that NOW traffic does not depend on an infrastructure link
    // or promiscuous receive. Disable NAN DW only for this row so its bounded
    // capture cannot obscure the non-promiscuous assertion.
    let unassociated = RawWifiControlRequest {
        channel: Some(6),
        raw_sta_mode: Some(RawWifiStaMode::MainStyle),
        promiscuous: Some(false),
        dw_policy: Some(RawWifiDwPolicy::Disabled),
        ..RawWifiControlRequest::default()
    };
    let used = encode_raw_wifi_control_request(unassociated, &mut request).unwrap();
    let e7_unassociated = radio_request(&mut e7, &request[..used]);
    assert_eq!(
        e7_unassociated.sta_associated,
        Some(false),
        "e7 did not enter unassociated STA hold: {e7_unassociated:?}"
    );
    assert_eq!(
        e7_unassociated.promiscuous,
        Some(false),
        "e7 enabled promiscuous receive in unassociated NOW row: {e7_unassociated:?}"
    );
    roc_only_unassociated_action_matrix(&mut e7, &mut e6, e6_ap_mac);
}

/// Focused ROC decision test. e6 runs the newly flashed Recovery receiver;
/// e7 only supplies the established raw action transmitter, so this can run
/// before a Main image update. Reproduce with the normal ignored-test command
/// and the same two `DMESH_E2E_E*` serial paths.
#[test]
#[ignore = "requires the e6/e7 radio lab and exclusive UART ownership"]
fn firmware_roc_only_unassociated_actions() {
    let mut e6 = DeviceSession::open(serial_from_env("DMESH_E2E_E6"), None).unwrap();
    let mut e7 = DeviceSession::open(serial_from_env("DMESH_E2E_E7"), None).unwrap();
    e6.set_history_limit(1024);
    e7.set_history_limit(1024);
    roc_only_unassociated_action_matrix(&mut e6, &mut e7, E7_MAC);
}

/// Same four-second ROC receive-quality row with Main as receiver and
/// Recovery as transmitter. Keeping this separate from the full matrix makes
/// Main/Recovery driver-lifecycle divergences immediately visible.
#[test]
#[ignore = "requires the e6/e7 radio lab and exclusive UART ownership"]
fn firmware_main_roc_only_unassociated_actions() {
    let mut e6 = DeviceSession::open(serial_from_env("DMESH_E2E_E6"), None).unwrap();
    let mut e7 = DeviceSession::open(serial_from_env("DMESH_E2E_E7"), None).unwrap();
    e6.set_history_limit(1024);
    e7.set_history_limit(1024);
    roc_only_unassociated_action_matrix(&mut e7, &mut e6, E6_MAC);
}
