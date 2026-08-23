//! Hardware matrix for the shared raw UDP6/NOW transport.
//!
//! This is intentionally one ignored test: it holds one UART owner for e6
//! and one for e7 for the entire matrix rather than reopening USB serial for
//! each case. Run only on the lab host after both images are flashed and have
//! remained booted for at least 20 seconds; the suite never flashes, resets,
//! or starts/stops host Wi-Fi interfaces.
//!
//! ```sh
//! DMESH_E2E_CONFIG=target/e2e-devices.toml \
//! scripts/build.sh firmware-e2e
//! ```

use dmesh_cli::{DeviceSession, DeviceSessionEvent};
use dmesh_cli::prober::{E2eConfig, E2eDeviceConfig, E2ePairConfig};
use dmesh_server::cbor::Encoder;
use dmesh_server::probe::{
    PairProbeRequest, ProbeApResult, ProbeDeviceDescriptor, ProbeEndpoint, ProbeEndpointKind,
    ProbeMeasurement, ProbeMode, ProbeModeResult, ProbeRequest, ProbeResponse, ProbeScanResult,
    ProbeUdp6AssociationResult,
    PROBE_CAP_AP, PROBE_CAP_NAN, PROBE_CAP_NOW, PROBE_CAP_STA, PROBE_CAP_UDP6,
    full_pair_probe_requests,
};
use dmesh_server::raw_wifi::{
    RAW_WIFI_METHOD_RESET_COUNTERS, RAW_WIFI_METHOD_SNAPSHOT, RawWifiApMode, RawWifiBearer, RawWifiCheckRequest,
    RawWifiControlRequest, RawWifiDwPolicy, RawWifiInterface, RawWifiIperfRequest, RawWifiStaMode,
    RawWifiStaState, decode_raw_wifi_snapshot, encode_raw_wifi_check_request,
    encode_raw_wifi_control_request, encode_raw_wifi_iperf_request,
    encode_raw_wifi_snapshot_request,
};
use dmesh_server::{
    announce::{ANNOUNCE_SLEEP_PENDING, ANNOUNCE_TRANSITION_BEGIN, ANNOUNCE_TRANSITION_COMPLETE, ANNOUNCE_WAKE, decode_announce},
    control::{self, Request as ControlRequest, TransportKind},
    iperf::{IperfServiceRequest, encode_iperf_service_request},
    tagged::decode as decode_tagged_record,
    udp::{ReceivedStream, UdpClient},
};
use mesh::{
    cbor::{decode_record, decode_stream_frame, encode_record, encode_stream_frame},
    tagged::{NameOrTag, TaggedCatalog, TaggedRecord},
};
use quic_lite::{ConnectionId, FIRST_CLIENT_BIDI_STREAM_ID, SERVICE_ECHO, SERVICE_STATUS};
use serde::{Deserialize, Serialize};
use std::{
    any::Any,
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

fn load_e2e_config() -> Option<E2eConfig> {
    let requested = std::path::PathBuf::from(std::env::var_os("DMESH_E2E_CONFIG")?);
    // Cargo runs integration tests from the package directory. Operators use
    // repository-relative descriptors through scripts/build.sh, so resolve a
    // relative path against the environment's checkout root when it is not
    // already valid from the package working directory.
    let path = if requested.is_absolute() || requested.exists() {
        requested
    } else if let Some(root) = std::env::var_os("DMESH_REPO") {
        std::path::PathBuf::from(root).join(requested)
    } else {
        requested
    };
    Some(E2eConfig::from_path(&path).unwrap_or_else(|error| panic!("{error}")))
}

fn configured_device<'a>(config: &'a E2eConfig, name: &str) -> &'a E2eDeviceConfig {
    config.require_device(name).unwrap_or_else(|error| panic!("{error}"))
}

fn configured_pair<'a>(config: &'a E2eConfig, name: &str) -> &'a E2ePairConfig {
    config
        .pairs
        .iter()
        .find(|pair| pair.name == name)
        .unwrap_or_else(|| panic!("configured pair {name} is missing"))
}

fn configured_mac(device: &E2eDeviceConfig) -> [u8; 6] {
    let text = device
        .mac
        .as_deref()
        .unwrap_or_else(|| panic!("configured device {} needs mac", device.name));
    parse_mac_text(text, &device.name)
}

fn configured_nan_mac(device: &E2eDeviceConfig) -> [u8; 6] {
    let text = device.nan_mac.as_deref().or(device.mac.as_deref()).unwrap_or_else(|| {
        panic!("configured device {} needs mac or nan_mac", device.name)
    });
    parse_mac_text(text, &format!("{} nan_mac", device.name))
}

fn parse_mac_text(text: &str, name: &str) -> [u8; 6] {
    let hex = text.replace(':', "");
    assert_eq!(hex.len(), 12, "device {} has invalid mac {text:?}", name);
    let mut mac = [0_u8; 6];
    for (index, byte) in mac.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .unwrap_or_else(|_| panic!("device {} has invalid mac {text:?}", name));
    }
    mac
}

fn configured_mode(device: &E2eDeviceConfig) -> ProbeMode {
    let transport_kind = match device.baseline.as_str() {
        "nan" => 6,
        "sta" => 1,
        other => panic!("device {} has unsupported baseline {other:?}", device.name),
    };
    ProbeMode {
        transport_kind,
        now: device.now.unwrap_or(if device.supports_now { 0 } else { 2 }),
        nan_dw_interval: device.nan_dw_interval.unwrap_or(0),
        ndp: device.ndp.unwrap_or(false),
        ap: device.ap.unwrap_or(false),
    }
}

fn configured_endpoint(device: &E2eDeviceConfig) -> ProbeEndpoint {
    ProbeEndpoint {
        kind: match device.kind.as_str() {
            "host" => ProbeEndpointKind::Host,
            "android" => ProbeEndpointKind::Android,
            "esp" => ProbeEndpointKind::Esp,
            other => panic!("unsupported configured endpoint kind {other:?}"),
        },
        node: device.mac.as_deref().map(|_| configured_mac(device)).unwrap_or([0; 6]),
        mode: configured_mode(device),
        bssid: device
            .bssid
            .as_deref()
            .map(|text| parse_mac_text(text, &format!("{} bssid", device.name))),
    }
}

/// Translate a file/discovery descriptor into the portable pair-probe
/// descriptor.  The file may provide lab-only serial access, but capability
/// selection itself is independent of serial and board names.
fn configured_probe_descriptor(device: &E2eDeviceConfig) -> ProbeDeviceDescriptor {
    let mut capabilities = 0;
    if device.supports_nan {
        capabilities |= PROBE_CAP_NAN;
    }
    if device.supports_now {
        capabilities |= PROBE_CAP_NOW;
    }
    if device.supports_sta {
        capabilities |= PROBE_CAP_STA;
    }
    if device.supports_ap {
        capabilities |= PROBE_CAP_AP;
    }
    if device.supports_udp6 {
        capabilities |= PROBE_CAP_UDP6;
    }
    ProbeDeviceDescriptor {
        endpoint: configured_endpoint(device),
        capabilities,
    }
}

fn configured_pair_tests(config: &E2eConfig, source: &str, target: &str) -> Vec<String> {
    config
        .pairs
        .iter()
        .find(|pair| pair.source == source && pair.target == target)
        .map(|pair| pair.tests.clone())
        .unwrap_or_else(|| vec!["nan".to_owned(), "udp6-iperf".to_owned(), "now-short".to_owned(), "now-iperf".to_owned()])
}

/// Load the actual generic-prober input. Device descriptors remain separate:
/// their MACs are injected immediately before execution so a request can be
/// reused for any compatible pair without embedding board names.
fn configured_pair_probe_requests(
    config: &E2eConfig,
    source: &E2eDeviceConfig,
    target: &E2eDeviceConfig,
) -> Vec<PairProbeRequest> {
    if let Ok(json) = std::env::var("DMESH_E2E_PROBE_REQUEST_JSON") {
        let request = serde_json::from_str(&json).unwrap_or_else(|error| {
            panic!("DMESH_E2E_PROBE_REQUEST_JSON must be a ProbeRequest: {error}")
        });
        return vec![PairProbeRequest {
            request,
            source: configured_probe_descriptor(source),
            target: configured_probe_descriptor(target),
        }];
    }
    let tests = configured_pair_tests(config, &source.name, &target.name);
    let source_descriptor = configured_probe_descriptor(source);
    let target_descriptor = configured_probe_descriptor(target);
    // The main integration entry intentionally ignores the legacy per-pair
    // list and characterizes every jointly supported mode.  A non-empty list
    // is only honored by the explicit JSON narrow-request escape hatch above;
    // retain parsing for backwards-compatible descriptor validation.
    let _legacy_tests = tests;
    full_pair_probe_requests(
        0x4D_50_1000,
        source_descriptor,
        target_descriptor,
        4 * 1024,
        u32::try_from(e2e_now_bytes()).expect("configured probe bytes fit u32"),
    )
}

fn descriptor_with_probe_mode(device: &E2eDeviceConfig, mode: ProbeMode) -> E2eDeviceConfig {
    let mut selected = device.clone();
    selected.baseline = if mode.transport_kind == 1 { "sta" } else { "nan" }.to_owned();
    selected.now = Some(mode.now);
    selected.nan_dw_interval = Some(mode.nan_dw_interval);
    selected.ndp = Some(mode.ndp);
    selected.ap = Some(mode.ap);
    selected
}

fn mac_text(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("wall clock after Unix epoch")
        .as_millis() as u64
}

/// Encode the complete mode requested by a file descriptor. The resulting
/// bytes are the same tagged control record accepted by UART, UDP6, and NAN;
/// this adapter sends them through host NAN so a sleepy endpoint never needs a
/// serial session just to enter the probe mode.
fn descriptor_transport_wire(
    device: &E2eDeviceConfig,
    ssid: &str,
    host_bssid: [u8; 6],
    id: u64,
) -> Vec<u8> {
    let mut wire = [0u8; 128];
    // The current host control-plane fixture is channel 6. A future
    // descriptor can add an explicit channel field; never infer one from the
    // first byte of a BSSID.
    let channel = Some(6);
    let now = device.now.unwrap_or(if device.supports_now { 0 } else { 2 });
    let (kind, config) = if device.baseline == "sta" {
        (
            TransportKind::Sta,
            dmesh_server::control::TransportConfig {
                ssid: Some(ssid.as_bytes()),
                bssid: Some(host_bssid),
                channel,
                now: Some(now),
                nan_dw_interval: Some(device.nan_dw_interval.unwrap_or(0)),
                ap: Some(if device.ap.unwrap_or(false) { 1 } else { 0 }),
                uart: Some(0),
                sta_11b_rates_disabled: Some(false),
                ..dmesh_server::control::TransportConfig::default()
            },
        )
    } else {
        (
            TransportKind::Nan,
            dmesh_server::control::TransportConfig {
                channel,
                now: Some(now),
                nan_dw_interval: Some(device.nan_dw_interval.unwrap_or(1)),
                ap: Some(if device.ap.unwrap_or(false) { 1 } else { 0 }),
                uart: Some(0),
                ..dmesh_server::control::TransportConfig::default()
            },
        )
    };
    let used = control::encode_request(
        ControlRequest::TransportStart { kind, config },
        Some(id),
        &mut wire,
    )
    .expect("descriptor transport.start fits the control MTU");
    wire[..used].to_vec()
}

fn host_nan_send(frame: &[u8]) {
    let response = mesh_rpc_typed(
        &e2e_nan_service(),
        "wifi.raw.send",
        &lmesh_wifi::api::RawSendRequest {
            iface: Some(e2e_nan_iface()),
            channel: Some(6),
            tx_variant: Some("monitor".to_owned()),
            tx_rate_mbps: Some(6),
            frame_hex: Some(hex(frame)),
        },
    );
    assert_eq!(
        response["data"]["ok"].as_bool(),
        Some(true),
        "host NAN injection failed: {response}"
    );
}

/// Both supervised host controllers preserve the same raw-NAN payload but
/// use their established JSON-RPC envelopes (`data` for lmesh-wifi, `result`
/// for lmesh). Keep that difference at this outer test adapter boundary.
fn controller_data(response: &serde_json::Value) -> &serde_json::Value {
    response
        .get("data")
        .or_else(|| response.get("result"))
        .unwrap_or(response)
}

/// Decode a bounded hexadecimal payload from the controller's NAN receipt
/// history. Follow-up payloads are the original tagged-CBOR handler result,
/// not a host-specific JSON conversion.
fn decode_history_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).ok())
        .collect()
}

/// Send one normal numeric raw-radio request through an active NAN Subscribe
/// and wait for its correlated directed Follow-up. This is the production
/// probe control path: it consumes the already-running host monitor and never
/// opens UART or reconfigures the control-plane interface.
fn host_nan_raw_request(
    target: [u8; 6],
    request: &[u8],
    expected_method: u64,
    timeout: Duration,
) -> dmesh_server::raw_wifi::RawWifiSnapshot {
    let iface = e2e_nan_iface();
    let host_mac = parse_mac_text(&interface_mac(&iface), &iface);
    let frame = dmesh_rawnan::build_nan_usd_sdf(
        target,
        host_mac,
        dmesh_rawnan::DMESH_SERVICE_ID,
        7,
        0x11,
        request,
    );
    let peer = mac_text(target);
    let started_ms = unix_now_ms();
    let deadline = Instant::now() + timeout;
    let mut sends = 0_u8;
    loop {
        host_nan_send(&frame);
        sends = sends.saturating_add(1);
        thread::sleep(Duration::from_millis(200));
        let status = mesh_rpc_typed(
            &e2e_nan_service(),
            "wifi.rawnan.status",
            &lmesh_wifi::api::RawNanStatusRequest {
                iface: Some(iface.clone()),
            },
        );
        let response = controller_data(&status)["followups"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|entry| {
                entry["last_seen_ms"].as_u64().unwrap_or(0) >= started_ms
                    && entry["peer"].as_str() == Some(peer.as_str())
            })
            .find_map(|entry| {
                let hex = entry["followup"]["payload_hex"].as_str()?;
                let bytes = decode_history_hex(hex)?;
                let (method, snapshot) = decode_raw_wifi_snapshot(&bytes).ok()?;
                (method == expected_method).then_some(snapshot)
            });
        if let Some(snapshot) = response {
            return snapshot;
        }
        assert!(
            Instant::now() < deadline,
            "NAN raw request method={expected_method} target={peer} did not return a directed snapshot after {sends} SDEAs: {status}"
        );
        thread::sleep(Duration::from_millis(300));
    }
}

/// Query a device's normal raw-radio snapshot through NAN. This is used both
/// immediately after a mode replacement and while awaiting a device-pair
/// transfer; it is deliberately the same registered handler as QUIC/UART.
fn host_nan_snapshot(target: [u8; 6]) -> dmesh_server::raw_wifi::RawWifiSnapshot {
    let mut request = [0u8; 32];
    let used = encode_raw_wifi_snapshot_request(RAW_WIFI_METHOD_SNAPSHOT, &mut request)
        .expect("raw snapshot request");
    host_nan_raw_request(
        target,
        &request[..used],
        RAW_WIFI_METHOD_SNAPSHOT,
        Duration::from_secs(8),
    )
}

/// Select the host radio used for the initial NAN rendezvous.  Production
/// control normally uses wlan0; the lmesh development cluster is commonly on
/// wlan1, so the generic prober must not bake either topology into its test.
fn e2e_nan_iface() -> String {
    std::env::var("DMESH_E2E_NAN_IFACE").unwrap_or_else(|_| "wlan0".to_owned())
}

fn e2e_nan_service() -> String {
    std::env::var("DMESH_E2E_NAN_SERVICE").unwrap_or_else(|_| "lmesh-wifi".to_owned())
}

fn host_nan_peer_seen(status: &serde_json::Value, mac: [u8; 6], started_ms: u64) -> bool {
    let expected = mac_text(mac);
    let data = controller_data(status);
    data["discovered_devices"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|entry| {
            entry["peer"].as_str() == Some(expected.as_str())
                && entry["last_seen_ms"].as_u64().unwrap_or(0) >= started_ms
        })
        || data["followups"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|entry| {
                entry["peer"].as_str() == Some(expected.as_str())
                    && entry["last_seen_ms"].as_u64().unwrap_or(0) >= started_ms
            })
}

fn host_nan_peer_seen_any(status: &serde_json::Value, macs: &[[u8; 6]], started_ms: u64) -> bool {
    macs.iter().copied().any(|mac| host_nan_peer_seen(status, mac, started_ms))
}

/// Send each descriptor's mode command to both endpoints through the host
/// NAN control plane. This is the production-shaped sleepy-device bootstrap:
/// no UART is opened, and the gate accepts either an advertisement observed by
/// wlan0 or the follow-up generated by an active Subscribe.
fn host_nan_activate_pair(
    source: &E2eDeviceConfig,
    target: &E2eDeviceConfig,
    source_mac: [u8; 6],
    target_mac: [u8; 6],
    timeout: Duration,
) {
    let nan_iface = e2e_nan_iface();
    let nan_service = e2e_nan_service();
    let host_mac = parse_mac_text(&interface_mac(&nan_iface), &nan_iface);
    // NAN transport is independent from the AP used by a requested STA
    // epoch. A wlan1 NAN controller can therefore carry the wlan0 AP's
    // SSID/BSSID in its SDEA; only an all-NAN request may use the controller
    // MAC placeholder without querying an AP owner.
    let needs_sta_target = source.baseline == "sta" || target.baseline == "sta";
    let (host_bssid, ssid) = if nan_iface == "wlan0" || needs_sta_target {
        let (bssid, _) = wlan0_bssid_channel();
        (bssid, wlan0_ssid())
    } else {
        (host_mac, String::new())
    };
    let source_wire = descriptor_transport_wire(source, &ssid, host_bssid, 0x4D_50_1001);
    let target_wire = descriptor_transport_wire(target, &ssid, host_bssid, 0x4D_50_1002);
    let started_ms = unix_now_ms();
    let source_subscribe = dmesh_rawnan::build_nan_usd_sdf(
        source_mac,
        host_mac,
        dmesh_rawnan::DMESH_SERVICE_ID,
        7,
        0x11,
        &source_wire,
    );
    let target_subscribe = dmesh_rawnan::build_nan_usd_sdf(
        target_mac,
        host_mac,
        dmesh_rawnan::DMESH_SERVICE_ID,
        7,
        0x11,
        &target_wire,
    );
    // A device may still be APSTA (NAN address = AP MAC) or already be in a
    // NAN-only epoch (NAN address = base/STA MAC). Send the same tagged
    // transport.start to both aliases so activation is independent of the
    // endpoint's previous radio personality.
    let source_base_subscribe = dmesh_rawnan::build_nan_usd_sdf(
        configured_mac(source),
        host_mac,
        dmesh_rawnan::DMESH_SERVICE_ID,
        7,
        0x11,
        &source_wire,
    );
    let target_base_subscribe = dmesh_rawnan::build_nan_usd_sdf(
        configured_mac(target),
        host_mac,
        dmesh_rawnan::DMESH_SERVICE_ID,
        7,
        0x11,
        &target_wire,
    );
    let deadline = Instant::now() + timeout;
    // An explicit 40-second diagnostic budget must genuinely wait for the
    // NAN clock source.  The old immediate `expect` made the documented
    // override ineffective and turned a cold-cluster observation into a
    // misleading test panic before any endpoint activation was attempted.
    let cluster = loop {
        let status = mesh_rpc_typed(
            &nan_service,
            "wifi.rawnan.status",
            &lmesh_wifi::api::RawNanStatusRequest {
                iface: Some(nan_iface.clone()),
            },
        );
        if let Some(cluster) = controller_data(&status)["sync_bssid"].as_str() {
            let waited = unix_now_ms().saturating_sub(started_ms);
            if waited > 9_000 {
                eprintln!("firmware-e2e NAN cluster wait warning elapsed_ms={waited}");
            }
            break cluster.to_owned();
        }
        if Instant::now() >= deadline {
            panic!("host NAN cluster did not become ready within {timeout:?}");
        }
        thread::sleep(Duration::from_millis(250));
    };
    let cluster_mac = parse_mac_text(&cluster, "NAN cluster");
    let source_publish = dmesh_rawnan::build_nan_publish_sdf(
        dmesh_rawnan::NAN_DISCOVERY_MAC,
        host_mac,
        cluster_mac,
        dmesh_rawnan::DMESH_SERVICE_ID,
        1,
        &source_wire,
    );
    let target_publish = dmesh_rawnan::build_nan_publish_sdf(
        dmesh_rawnan::NAN_DISCOVERY_MAC,
        host_mac,
        cluster_mac,
        dmesh_rawnan::DMESH_SERVICE_ID,
        1,
        &target_wire,
    );
    // APSTA exposes NAN using the AP MAC, while a NAN-only transition uses
    // the base/STA MAC. Accept both identities across the transition; the
    // descriptor's nan_mac remains the initial directed target.
    let source_identities = [source_mac, configured_mac(source)];
    let target_identities = [target_mac, configured_mac(target)];
    while Instant::now() < deadline {
        host_nan_send(&source_subscribe);
        host_nan_send(&target_subscribe);
        host_nan_send(&source_base_subscribe);
        host_nan_send(&target_base_subscribe);
        host_nan_send(&source_publish);
        host_nan_send(&target_publish);
        // Poll twice per NAN DW so a response near the boundary is not
        // hidden behind an unnecessary half-second host-side delay.
        thread::sleep(Duration::from_millis(250));
        let status = mesh_rpc_typed(
            &nan_service,
            "wifi.rawnan.status",
            &lmesh_wifi::api::RawNanStatusRequest {
                iface: Some(nan_iface.clone()),
            },
        );
        if host_nan_peer_seen_any(&status, &source_identities, started_ms)
            && host_nan_peer_seen_any(&status, &target_identities, started_ms)
        {
            eprintln!(
                "firmware-e2e row=pair-nan-activation source={} target={} elapsed_ms={}",
                source.name,
                target.name,
                unix_now_ms().saturating_sub(started_ms),
            );
            return;
        }
    }
    panic!(
        "host NAN activation did not observe both endpoints within {:?}: source={} target={}",
        timeout, source.name, target.name
    );
}

fn host_udp6_status(mac: [u8; 6], cid: u64) -> Result<(), String> {
    let ifindex = interface_index("wlan0");
    let peer = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(quic_lite::raw_udp6::link_local_from_mac(mac)),
        RAW_UDP6_PORT,
        0,
        ifindex,
    ));
    let bind = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 3338, 0, 0));
    let mut last = "UDP6 status did not start".to_owned();
    for attempt in 0..3u64 {
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("UDP6 status runtime")
            .block_on(async {
                let mut client = timeout(
                    Duration::from_secs(2),
                    UdpClient::connect(bind, peer, ConnectionId::new(cid + attempt).unwrap()),
                )
                .await
                .map_err(|_| "UDP6 bootstrap timeout".to_owned())?
                .map_err(|error| format!("UDP6 bootstrap: {error:#}"))?;
                timeout(
                    Duration::from_secs(5),
                    client.request_stream(FIRST_CLIENT_BIDI_STREAM_ID, &[SERVICE_STATUS], true),
                )
                .await
                .map_err(|_| "UDP6 status timeout".to_owned())
                .map(|_| ())
            });
        match result {
            Ok(()) => return Ok(()),
            Err(error) => {
                last = error;
                thread::sleep(Duration::from_millis(250));
            }
        }
    }
    Err(last)
}

fn run_android_udp_cli(target: &str, args: &[&str]) -> std::process::Output {
    let cli = std::env::var_os("DMESH_E2E_CLI")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/debug/dmesh-cli")
        });
    Command::new(cli)
        .arg(format!("udp://{target}:3336"))
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("run Android UDP CLI {target}: {error}"))
}

fn configured_android_udp_target() -> (String, String) {
    if let Some(config) = load_e2e_config() {
        let device_name = if let Ok(pair_name) = std::env::var("DMESH_E2E_PAIR") {
            let pair = configured_pair(&config, &pair_name);
            [pair.source.as_str(), pair.target.as_str()]
                .into_iter()
                .find(|name| configured_device(&config, name).kind == "android")
                .unwrap_or_else(|| panic!("pair {pair_name} has no Android endpoint"))
                .to_owned()
        } else {
            std::env::var("DMESH_E2E_ANDROID_DEVICE")
                .expect("DMESH_E2E_ANDROID_DEVICE or DMESH_E2E_PAIR is required with DMESH_E2E_CONFIG")
        };
        let device = configured_device(&config, &device_name);
        assert_eq!(device.kind, "android", "configured device {device_name} is not Android");
        let serial = device
            .serial
            .clone()
            .unwrap_or_else(|| panic!("Android device {device_name} needs serial"));
        let ipv4 = device
            .ipv4
            .clone()
            .unwrap_or_else(|| panic!("Android device {device_name} needs ipv4 for UDP E2E"));
        return (serial, ipv4);
    }
    (
        std::env::var("DMESH_E2E_ANDROID_SERIAL")
            .expect("DMESH_E2E_ANDROID_SERIAL is required without DMESH_E2E_CONFIG"),
        std::env::var("DMESH_E2E_ANDROID_IPV4")
            .expect("DMESH_E2E_ANDROID_IPV4 is required without DMESH_E2E_CONFIG"),
    )
}

#[test]
#[ignore = "requires an Android DMesh service reachable over IPv4 UDP"]
fn android_udp_handlers_and_iperf() {
    let (serial, target) = configured_android_udp_target();
    let services = run_android_udp_cli(&target, &["--services"]);
    assert!(
        services.status.success(),
        "Android {serial} handler inventory failed: stdout={} stderr={}",
        String::from_utf8_lossy(&services.stdout),
        String::from_utf8_lossy(&services.stderr)
    );
    let inventory = String::from_utf8_lossy(&services.stdout);
    for handler in [
        "object", "echo", "status", "handlers", "iperf", "metrics", "events", "control",
        "log-watch",
    ] {
        assert!(
            inventory.contains(&format!(":{handler}")),
            "Android {serial} omitted handler {handler:?}: {inventory}"
        );
    }

    for (service, args) in [
        ("status", vec!["--service", "status"]),
        ("metrics", vec!["--service", "metrics"]),
        ("events", vec!["--service", "events", "--body-hex", "73696e63653d30"]),
        ("log-watch", vec!["--service", "log-watch", "--log-records", "4"]),
    ] {
        let args = args.iter().copied().collect::<Vec<_>>();
        let response = run_android_udp_cli(&target, &args);
        assert!(
            response.status.success(),
            "Android {serial} {service} handler failed: stdout={} stderr={}",
            String::from_utf8_lossy(&response.stdout),
            String::from_utf8_lossy(&response.stderr)
        );
    }

    let response = run_android_udp_cli(&target, &["--iperf-bytes", "65536"]);
    assert!(
        response.status.success(),
        "Android {serial} IPERF failed: stdout={} stderr={}",
        String::from_utf8_lossy(&response.stdout),
        String::from_utf8_lossy(&response.stderr)
    );
    assert!(
        String::from_utf8_lossy(&response.stdout).contains("dmesh_cli_iperf_result"),
        "Android {serial} IPERF returned no completion record: {}",
        String::from_utf8_lossy(&response.stdout)
    );
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct PairProbeStatus {
    peer: String,
    test: String,
    last_result: String,
    last_seen_unix_ms: u64,
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

/// One attempted control or data-plane operation from the comprehensive
/// prober.  A failed row is retained rather than panicking immediately so an
/// operator gets the complete pair/bearer matrix from one bounded run.
#[derive(Clone, Debug, Serialize)]
struct PairProbeOutcome {
    row: String,
    bearer: String,
    succeeded: bool,
    /// A missing NAN clock is fatal only when the descriptor asks to probe a
    /// sleepy endpoint. Active devices are still expected to answer NOW.
    required: bool,
    detail: String,
}

fn panic_detail(error: Box<dyn Any + Send>) -> String {
    if let Some(text) = error.downcast_ref::<&str>() {
        (*text).to_owned()
    } else if let Some(text) = error.downcast_ref::<String>() {
        text.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

fn emit_pair_probe_outcomes(source: &E2eDeviceConfig, target: &E2eDeviceConfig, outcomes: &[PairProbeOutcome]) {
    // This is deliberately one machine-readable final record. Individual
    // diagnostic messages remain useful live, but a control plane needs a
    // complete list of successes and failures to characterize a pair.
    eprintln!(
        "firmware-e2e pair-probe-report={}",
        serde_json::json!({
            "source": source.name,
            "target": target.name,
            "sleepy": source.sleepy || target.sleepy,
            "outcomes": outcomes,
        })
    );
}

/// A node-local capability observation. Unlike a pair row, an Android SoftAP
/// result or a passive channel-6 scan is meaningful before a second endpoint
/// is selected. Pair probes consume this stored evidence rather than silently
/// assuming that every Android supports the same AP mode.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct NodeCapabilityStatus {
    last_result: String,
    last_seen_unix_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    soft_ap: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_ap_count: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_channel6_ap_count: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_dmesh_ap_count: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_dmesh: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct NodeStatus {
    schema_version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity: Option<NodeIdentity>,
    #[serde(default)]
    pairs: BTreeMap<String, PairProbeStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capability: Option<NodeCapabilityStatus>,
}

fn node_store_root() -> std::path::PathBuf {
    std::env::var_os("DMESH_E2E_NODES_DIR")
        .map(std::path::PathBuf::from)
        // Cargo executes an integration-test binary from the package
        // directory. Keep the default evidence store at the workspace root,
        // rather than creating a different `nodes/` tree per test crate.
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("nodes")
        })
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_millis()
        .try_into()
        .expect("Unix millisecond timestamp exceeds u64")
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

/// Send one JSON-RPC-shaped Android control request. The shell provider keeps
/// the response in a Bundle, but the embedded `response` field is a complete
/// `MsgFrame` JSON line with the same request id.
fn android_json_command(serial: &str, request: serde_json::Value) -> String {
    let shell_command = format!(
        "content call --uri content://com.github.costinm.dmesh.lm.shell --method command --arg '{}'",
        request
    );
    let output = Command::new("adb")
        .args(["-s", serial, "shell", &shell_command])
        .output()
        .expect("Android content command");
    assert!(
        output.status.success(),
        "Android command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Read the Rust-owned cross-bearer inventory through the privileged Android
/// shell adapter.  The returned JSON is deliberately not parsed into an
/// Android-specific structure: the probe only needs to establish that a new
/// UDP-multicast observation crossed the P2P link.
fn android_known_devices(serial: &str, request_id: &str) -> String {
    android_json_command(
        serial,
        serde_json::json!({
            "id": request_id,
            "method": "radio.devices",
        }),
    )
}

fn udp_multicast_observation_count(inventory: &str) -> usize {
    inventory.match_indices("udp_multicast").count()
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
                capability: None,
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

/// Persist a node-local scan/AP result alongside pair results. This is kept
/// separate so a capability probe never fabricates a peer relationship.
fn record_node_capability(node: &NodeIdentity, mut capability: NodeCapabilityStatus) {
    let root = node_store_root();
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
            capability: None,
        });
    let now = unix_millis();
    capability.last_seen_unix_ms = now;
    status.schema_version = 1;
    status.identity = Some(node.clone());
    status.capability = Some(capability.clone());
    let encoded = toml::to_string_pretty(&status)
        .unwrap_or_else(|error| panic!("encode node status {}: {error}", node.name));
    fs::write(&status_path, encoded)
        .unwrap_or_else(|error| panic!("write node status {}: {error}", status_path.display()));
    let event = serde_json::json!({
        "schema_version": 1,
        "at_unix_ms": now,
        "node": node,
        "capability": capability,
    });
    let mut history = OpenOptions::new().create(true).append(true)
        .open(directory.join("history.jsonl"))
        .unwrap_or_else(|error| panic!("open node history {}: {error}", node.name));
    writeln!(history, "{event}")
        .unwrap_or_else(|error| panic!("append node history {}: {error}", node.name));
}

fn json_string_field(response: &str, name: &str) -> Option<String> {
    let prefix = format!("\"{name}\":\"");
    let value = response.split_once(&prefix)?.1;
    Some(value.split_once('"')?.0.to_owned())
}

fn response_state_started(response: &str) -> bool {
    response.contains("\"state\":\"started\"")
}

fn last_dmesh_rssi(response: &str) -> Option<i8> {
    let candidate = json_string_field(response, "dmesh")?;
    candidate.rsplit_once(':')?.1.parse().ok()
}

/// Execute the Android-only capability portion of a first-class probe. This
/// is intentionally controller code: Android only receives ordinary local
/// `wifi.transport.start` and `wifi.scan` requests, while ESP
/// endpoints never need a probe service. The caller can combine this result
/// with its normal A-to-B NAN/NOW/UDP rows.
struct AndroidCapabilityProbeExecution {
    response: ProbeResponse,
    // The fixed-size ProbeResponse keeps only a count/RSSI. Per-node test
    // evidence retains the bounded SSID@BSSID:RSSI list for later analysis.
    scan_dmesh: Option<String>,
}

fn android_capability_probe_response(
    serial: &str,
    request: ProbeRequest,
) -> AndroidCapabilityProbeExecution {
    assert_eq!(request.source.kind, ProbeEndpointKind::Android);
    let mut source_mode = ProbeModeResult {
        attempted: true,
        succeeded: true,
        ..ProbeModeResult::default()
    };
    let mut source_scan = ProbeScanResult::default();
    let mut scan_dmesh = None;

    if request.test_soft_ap {
        let start = android_json_command(
            serial,
            serde_json::json!({
                "id": format!("probe-{}-soft-ap", request.request_id),
                "method": "wifi.transport.start",
                "data": {"mode": "nan", "ap": "1"},
            }),
        );
        let stop = android_json_command(
            serial,
            serde_json::json!({
                "id": format!("probe-{}-soft-ap-stop", request.request_id),
                "method": "wifi.transport.start",
                "data": {"mode": "nan", "ap": "0"},
            }),
        );
        assert!(start.contains("wifi.transport.result"), "missing SoftAP result: {start}");
        assert!(stop.contains("wifi.transport.result"), "missing SoftAP stop result: {stop}");
        source_mode.soft_ap = ProbeApResult {
            attempted: true,
            succeeded: response_state_started(&start),
            ..ProbeApResult::default()
        };
    }

    if request.test_scan {
        let scan = android_json_command(
            serial,
            serde_json::json!({
                "id": format!("probe-{}-scan", request.request_id),
                "method": "wifi.scan",
                "data": {"reason": "probe"},
            }),
        );
        assert!(scan.contains("wifi.scan.result"), "missing Android scan result: {scan}");
        source_scan = ProbeScanResult {
            attempted: true,
            succeeded: json_string_field(&scan, "ok").as_deref() == Some("1"),
            ap_count: json_string_field(&scan, "count").and_then(|value| value.parse().ok()),
            channel6_ap_count: json_string_field(&scan, "channel6_count")
                .and_then(|value| value.parse().ok()),
            dmesh_ap_count: json_string_field(&scan, "dmesh_count")
                .and_then(|value| value.parse().ok()),
            last_dmesh_rssi_dbm: last_dmesh_rssi(&scan),
        };
        scan_dmesh = json_string_field(&scan, "dmesh");
    }

    AndroidCapabilityProbeExecution {
        response: ProbeResponse {
            request_id: request.request_id,
            source_mode,
            target_mode: ProbeModeResult::default(),
            nan: ProbeMeasurement { attempted: request.test_nan, ..ProbeMeasurement::default() },
            nan_data: ProbeMeasurement {
                attempted: request.test_nan_data,
                ..ProbeMeasurement::default()
            },
            now: ProbeMeasurement { attempted: request.test_now, ..ProbeMeasurement::default() },
            udp6_association: ProbeUdp6AssociationResult {
                attempted: request.test_udp6_association,
                ..ProbeUdp6AssociationResult::default()
            },
            udp6: ProbeMeasurement { attempted: request.test_udp6, ..ProbeMeasurement::default() },
            source_scan,
            target_scan: ProbeScanResult::default(),
            recommendation: 0,
        },
        scan_dmesh,
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
    // A ProbeRequest is the complete desired radio epoch. Do not route it
    // through convenience helpers that silently choose NOW, DW, or AP values:
    // a production controller must be able to exercise every explicit mode
    // bit against the same two descriptors.
    let (kind, config) = match mode.transport_kind {
        6 => (
            TransportKind::Nan,
            dmesh_server::control::TransportConfig {
                channel: Some(6),
                now: Some(mode.now),
                nan_dw_interval: Some(mode.nan_dw_interval),
                ndp: Some(u8::from(mode.ndp)),
                ap: Some(if mode.ap { 1 } else { 0 }),
                ..dmesh_server::control::TransportConfig::default()
            },
        ),
        1 => {
            let (bssid, channel) = wlan0_bssid_channel();
            (
                TransportKind::Sta,
                dmesh_server::control::TransportConfig {
                    ssid: Some(ssid.as_bytes()),
                    bssid: Some(bssid),
                    channel: Some(channel),
                    now: Some(mode.now),
                    nan_dw_interval: Some(mode.nan_dw_interval),
                    ndp: Some(u8::from(mode.ndp)),
                    ap: Some(if mode.ap { 1 } else { 0 }),
                    // The supervised AP may advertise a legacy basic rate;
                    // this is an association prerequisite, not a ProbeMode
                    // bit, so keep it fixed for every request row.
                    sta_11b_rates_disabled: Some(false),
                    ..dmesh_server::control::TransportConfig::default()
                },
            )
        }
        unsupported => panic!("unsupported control-plane probe mode {unsupported}"),
    };
    control_request(session, ControlRequest::TransportStart { kind, config }, request_id);
    // Radio lab rows are allowed to disable the private action dispatcher or
    // leave a ROC lease behind.  A descriptor-driven probe must restore the
    // normal NOW ingress before measuring the bearer, otherwise a prior
    // focused test can make host/device action traffic disappear silently.
    restore_probe_action_path(session);
}

fn restore_probe_action_path(session: &mut DeviceSession) {
    let control = RawWifiControlRequest {
        action_dispatcher: Some(true),
        interface: Some(RawWifiInterface::Auto),
        // Broadcast Address-1 is the interoperable unassociated NOW mode;
        // the peer identity remains in the QUIC payload and response path.
        action_destination_broadcast: Some(true),
        dw_policy: Some(RawWifiDwPolicy::Normal),
        ..RawWifiControlRequest::default()
    };
    let mut request = [0u8; 64];
    let used = encode_raw_wifi_control_request(control, &mut request)
        .expect("probe action-path control fits the radio MTU");
    let _ = radio_request(session, &request[..used]);
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
        "firmware-e2e row=probe setup source_mode={:?} target_mode={:?} nan={} nan_data={} now={} udp6={} source=({}) target=({})",
        request.source.mode,
        request.target.mode,
        request.test_nan,
        request.test_nan_data,
        request.test_now,
        request.test_udp6,
        snapshot_summary(&source_snapshot),
        snapshot_summary(&target_snapshot),
    );
    (source_snapshot, target_snapshot)
}

/// Execute one complete generic pair request. The device descriptors supply
/// physical identity/capability; `ProbeRequest` alone supplies every radio
/// personality and bearer condition. This is the reusable control-plane
/// boundary used by the test matrix and future production evaluators.
fn nan_control_identity(device: &E2eDeviceConfig, mode: ProbeMode) -> [u8; 6] {
    // APSTA presents its AP/NAN identity, while a NAN-only or STA-only epoch
    // uses the base/STA identity. This is adapter address selection, not a
    // board-name rule; the device descriptor supplies both observed values.
    if mode.ap {
        configured_nan_mac(device)
    } else {
        configured_mac(device)
    }
}

/// Wait for a device-originated transfer to finish, using only the normal
/// NAN raw snapshot response. A failed transfer must not be mistaken for
/// accepted control: require both an inactive client and the requested byte
/// count from the initiating device.
fn wait_for_nan_iperf(
    control_target: [u8; 6],
    expected_bytes: u64,
    label: &str,
) -> dmesh_server::raw_wifi::RawWifiSnapshot {
    let deadline = Instant::now() + E2E_UDP6_TRANSFER_DEADLINE;
    loop {
        let snapshot = host_nan_snapshot(control_target);
        if snapshot.raw_service_active == Some(false)
            && u64::from(snapshot.raw_service_bytes.unwrap_or(0)) >= expected_bytes
        {
            let elapsed = u64::from(snapshot.raw_service_elapsed_us.unwrap_or(0));
            assert!(elapsed != 0, "{label}: completed transfer lacks elapsed time");
            eprintln!(
                "firmware-e2e row=pair-iperf label={label} bytes={} elapsed_us={} bps={}",
                snapshot.raw_service_bytes.unwrap_or(0),
                elapsed,
                u64::from(snapshot.raw_service_bytes.unwrap_or(0)).saturating_mul(8_000_000) / elapsed,
            );
            return snapshot;
        }
        assert!(
            Instant::now() < deadline,
            "{label}: NAN snapshot did not prove {expected_bytes} completed bytes: {snapshot:?}"
        );
    }
}

/// Execute a complete ESP-to-ESP request using NAN for every control and
/// result transaction. UART is intentionally absent: it may be observed by a
/// separate diagnostic, but it cannot make an action/UDP pair probe pass.
fn run_esp_pair_probe_via_nan(
    source: &E2eDeviceConfig,
    target: &E2eDeviceConfig,
    request: ProbeRequest,
) {
    let source_mode = descriptor_with_probe_mode(source, request.source.mode);
    let target_mode = descriptor_with_probe_mode(target, request.target.mode);
    host_nan_activate_pair(
        &source_mode,
        &target_mode,
        nan_control_identity(source, request.source.mode),
        nan_control_identity(target, request.target.mode),
        Duration::from_secs(10),
    );
    wait_for_stable_control_plane_devices(source, target, Duration::from_secs(10));
    let source_control = nan_control_identity(source, request.source.mode);
    let target_control = nan_control_identity(target, request.target.mode);
    let source_ready = host_nan_snapshot(source_control);
    let target_ready = host_nan_snapshot(target_control);
    if request.source.mode.transport_kind == 1 {
        assert_eq!(source_ready.sta_associated, Some(true), "source STA readiness");
    }
    if request.target.mode.transport_kind == 1 {
        assert_eq!(target_ready.sta_associated, Some(true), "target STA readiness");
    }

    if request.test_now {
        let check = RawWifiCheckRequest {
            peer: configured_mac(target),
            nonce: request.request_id + 0x10,
            timeout_ms: 8_000,
        };
        let mut wire = [0u8; 64];
        let used = encode_raw_wifi_check_request(check, &mut wire).expect("NOW check wire");
        let admitted = host_nan_raw_request(
            source_control,
            &wire[..used],
            dmesh_server::raw_wifi::RAW_WIFI_METHOD_CHECK,
            Duration::from_secs(8),
        );
        assert_eq!(admitted.raw_service_active, Some(true), "NOW check admission");
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            let snapshot = host_nan_snapshot(source_control);
            if snapshot.raw_service_active == Some(false)
                && snapshot.counters.raw_client_stream_packets != 0
            {
                break;
            }
            assert!(Instant::now() < deadline, "NOW check did not complete: {snapshot:?}");
        }
    }

    // The explicit bearer selector keeps the final STA+NOW bulk regression a
    // real NOW run instead of silently selecting UDP6 merely because STA is
    // associated. Associated AP/STA rows below separately select UDP6.
    let run_bulk = |initiator: &E2eDeviceConfig,
                    control: [u8; 6],
                    peer: [u8; 6],
                    bytes: u64,
                    bearer: RawWifiBearer,
                    label: &str| {
        let request = RawWifiIperfRequest {
            peer,
            bytes,
            packet_size: E2E_UDP6_PACKET_SIZE,
            timeout_ms: 30_000,
            bearer,
        };
        let mut wire = [0u8; 64];
        let used = encode_raw_wifi_iperf_request(request, &mut wire).expect("IPERF request");
        let admitted = host_nan_raw_request(
            control,
            &wire[..used],
            dmesh_server::raw_wifi::RAW_WIFI_METHOD_IPERF,
            Duration::from_secs(8),
        );
        assert_eq!(admitted.raw_service_active, Some(true), "{label}: IPERF admission");
        let _ = initiator; // documents that `control` is that endpoint's NAN identity.
        wait_for_nan_iperf(control, bytes, label);
    };
    if request.test_now {
        if request.short_bytes > 1 {
            run_bulk(source, source_control, configured_mac(target), u64::from(request.short_bytes), RawWifiBearer::Now, "NOW short");
        }
        if request.long_bytes != 0 {
            run_bulk(target, target_control, configured_mac(source), u64::from(request.long_bytes), RawWifiBearer::Now, "NOW long");
        }
    }
    if request.test_udp6 {
        // The associated target is the client and the source is the open AP;
        // neither payload crosses the host control plane.
        if request.short_bytes > 1 {
            run_bulk(target, target_control, configured_mac(source), u64::from(request.short_bytes), RawWifiBearer::Udp6, "UDP6 short");
        }
        if request.long_bytes != 0 {
            run_bulk(target, target_control, configured_mac(source), u64::from(request.long_bytes), RawWifiBearer::Udp6, "UDP6 long");
        }
    }
}

fn run_esp_pair_probe(
    source_session: &mut DeviceSession,
    target_session: &mut DeviceSession,
    source: &E2eDeviceConfig,
    target: &E2eDeviceConfig,
    mut request: ProbeRequest,
) {
    assert_eq!(request.source.kind, ProbeEndpointKind::Esp);
    assert_eq!(request.target.kind, ProbeEndpointKind::Esp);
    // Descriptors, not a test's board spelling, own stable device identity.
    request.source.node = configured_mac(source);
    request.target.node = configured_mac(target);

    let ssid = wlan0_ssid();
    let _ = probe(
        source_session,
        target_session,
        request,
        &ssid,
        request.request_id + 1,
        request.request_id + 2,
    );

    // NOW is optional capability. A request can ask for it, but an endpoint
    // that cannot provide it makes the row explicitly skipped rather than a
    // false device-pair failure.
    if request.test_now && source.supports_now && target.supports_now {
        let (target_after, source_after) = complete_action_check(
            source_session,
            target_session,
            configured_mac(target),
            request.request_id + 3,
            &format!("pair request={} {} -> {} NOW", request.request_id, source.name, target.name),
        );
        assert!(target_after.counters.rx_parser_accepted > 0);
        assert!(source_after.counters.raw_client_stream_packets > 0);
        let (source_after, target_after) = complete_action_check(
            target_session,
            source_session,
            configured_mac(source),
            request.request_id + 4,
            &format!("pair request={} {} -> {} NOW", request.request_id, target.name, source.name),
        );
        assert!(source_after.counters.rx_parser_accepted > 0);
        assert!(target_after.counters.raw_client_stream_packets > 0);

        if request.short_bytes > 1 {
            let _ = complete_action_iperf_bytes(
                source_session,
                target_session,
                configured_mac(target),
                u64::from(request.short_bytes),
                &format!("pair request={} {} -> {} NOW short", request.request_id, source.name, target.name),
            );
        }
        if request.long_bytes != 0 {
            let _ = complete_action_iperf_bytes(
                target_session,
                source_session,
                configured_mac(source),
                u64::from(request.long_bytes),
                &format!("pair request={} {} -> {} NOW long", request.request_id, target.name, source.name),
            );
        }
    } else if request.test_now {
        eprintln!(
            "firmware-e2e row=pair-now-skipped request={} source={} supports_now={} target={} supports_now={}",
            request.request_id, source.name, source.supports_now, target.name, target.supports_now
        );
    }

    if request.test_udp6 {
        for (device, mac, cid) in [
            (source, configured_mac(source), request.request_id + 5),
            (target, configured_mac(target), request.request_id + 6),
        ] {
            assert_eq!(device.baseline, "sta", "UDP6 requires a STA descriptor");
            host_udp6_status(mac, cid)
                .unwrap_or_else(|error| panic!("pair {} UDP6 status failed: {error}", device.name));
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("pair UDP6 runtime");
        if request.short_bytes > 1 {
            runtime.block_on(host_to_device_udp6_iperf_bytes(
                &format!("pair request={} {} UDP6 short", request.request_id, source.name),
                configured_mac(source),
                request.request_id + 7,
                u64::from(request.short_bytes),
            ));
        }
        if request.long_bytes != 0 {
            runtime.block_on(host_to_device_udp6_iperf_bytes(
                &format!("pair request={} {} UDP6 long", request.request_id, target.name),
                configured_mac(target),
                request.request_id + 8,
                u64::from(request.long_bytes),
            ));
        }
    }
}

/// Execute the host-to-ESP portion of the common probe contract.  The host is
/// the controller and therefore has no UART mode-setting step; the ESP still
/// receives the same complete mode replacement and the bearer rows are
/// selected entirely by `ProbeRequest`.
fn host_to_esp_now_probe(
    e6: &mut DeviceSession,
    request: ProbeRequest,
    ssid: &str,
    service: &str,
    iface: &str,
) -> ProbeResponse {
    assert_eq!(request.source.kind, ProbeEndpointKind::Host);
    assert_eq!(request.target.kind, ProbeEndpointKind::Esp);
    assert!(request.test_now, "host-to-ESP probe requires NOW");

    configure_probe_endpoint(e6, request.target.mode, ssid, request.request_id);
    let target_snapshot = match request.target.mode.transport_kind {
        6 => wait_for_unassociated_channel_6(e6),
        1 => wait_for_associated_channel_6(e6),
        unsupported => panic!("unsupported host-to-ESP probe mode {unsupported}"),
    };
    snapshot(e6, RAW_WIFI_METHOD_RESET_COUNTERS);

    let expected_peer = request
        .target
        .node
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    // Directed action is the safer default for the ESP private callback;
    // broadcast remains available for interoperability experiments and can
    // be selected explicitly with DMESH_E2E_NOW_DESTINATION=broadcast.
    let destination = std::env::var("DMESH_E2E_NOW_DESTINATION")
        .ok()
        .filter(|value| value != "broadcast")
        .unwrap_or_else(|| expected_peer.clone());
    let mut now = ProbeMeasurement {
        attempted: true,
        ..ProbeMeasurement::default()
    };

    if request.short_bytes != 0 {
        let check = wifi_raw_check_for_peer(
            service,
            iface,
            destination.clone(),
            expected_peer.clone(),
            request.request_id,
            e2e_now_timeout_ms(),
            e2e_now_rate() as u8,
            &e2e_now_tx_variant(),
            &e2e_now_rx_variant(),
        );
        now.succeeded = check
            .get("data")
            .and_then(|data| data.get("ok"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        now.tx_packets = check
            .get("data")
            .and_then(|data| data.get("tx_packets"))
            .and_then(serde_json::Value::as_u64)
            .map(|value| value as u32);
        now.rx_packets = check
            .get("data")
            .and_then(|data| data.get("rx_packets"))
            .and_then(serde_json::Value::as_u64)
            .map(|value| value as u32);
        if !now.succeeded {
            eprintln!("firmware-e2e probe host->esp NOW short result={check}");
        }
    }

    if request.long_bytes != 0 && now.succeeded {
        let result = wifi_raw_iperf_for_peer(
            service,
            iface,
            destination,
            expected_peer,
            u64::from(request.long_bytes),
            u16::try_from(e2e_now_packet_size()).expect("NOW packet size fits u16"),
            e2e_now_timeout_ms(),
            e2e_now_rate() as u8,
            &e2e_now_tx_variant(),
            &e2e_now_rx_variant(),
        );
        let data = result.get("data").unwrap_or(&result);
        now.succeeded = data
            .get("ok")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        now.bytes = data.get("bytes").and_then(serde_json::Value::as_u64);
        now.elapsed_us = data
            .get("elapsed_us")
            .and_then(serde_json::Value::as_u64);
        now.tx_packets = data
            .get("tx_packets")
            .and_then(serde_json::Value::as_u64)
            .map(|value| value as u32);
        now.rx_packets = data
            .get("rx_packets")
            .and_then(serde_json::Value::as_u64)
            .map(|value| value as u32);
        if !now.succeeded {
            eprintln!("firmware-e2e probe host->esp NOW long result={result}");
        }
    }

    let target_after = snapshot(e6, RAW_WIFI_METHOD_SNAPSHOT);
    eprintln!(
        "firmware-e2e row=host->esp-now-probe request={} target=({}) result={now:?}",
        request.request_id,
        snapshot_summary(&target_after),
    );
    ProbeResponse {
        request_id: request.request_id,
        source_mode: ProbeModeResult {
            attempted: true,
            succeeded: true,
            associated: Some(false),
            ..ProbeModeResult::default()
        },
        target_mode: ProbeModeResult {
            attempted: true,
            succeeded: true,
            associated: target_snapshot.sta_associated,
            ..ProbeModeResult::default()
        },
        nan: ProbeMeasurement {
            attempted: request.test_nan,
            ..ProbeMeasurement::default()
        },
        nan_data: ProbeMeasurement {
            attempted: request.test_nan_data,
            ..ProbeMeasurement::default()
        },
        now,
        udp6_association: ProbeUdp6AssociationResult {
            attempted: request.test_udp6_association,
            target_ready: target_snapshot.sta_associated == Some(true),
            ..ProbeUdp6AssociationResult::default()
        },
        udp6: ProbeMeasurement {
            attempted: request.test_udp6,
            ..ProbeMeasurement::default()
        },
        source_scan: ProbeScanResult::default(),
        target_scan: ProbeScanResult::default(),
        recommendation: 0,
    }
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

/// Select the initial NAN discovery budget from the host control plane. A
/// recent cluster beacon on the selected NAN interface makes the normal
/// five-second rendezvous expectation valid. Without one, the active-device
/// executor records the NAN failure and attempts NOW. Sleepy descriptors make
/// the same missing-clock observation fatal only after every applicable row
/// has been collected; an explicit timeout override diagnoses cold clusters.
fn nan_wake_timeout_from_host() -> Option<Duration> {
    if let Ok(value) = std::env::var("DMESH_E2E_NAN_WAKE_TIMEOUT_SECS") {
        let seconds = value.parse::<u64>().unwrap_or_else(|error| {
            panic!("DMESH_E2E_NAN_WAKE_TIMEOUT_SECS must be seconds: {value:?}: {error}")
        });
        assert!(seconds > 0, "DMESH_E2E_NAN_WAKE_TIMEOUT_SECS must be nonzero");
        return Some(Duration::from_secs(seconds));
    }
    let status = match std::panic::catch_unwind(|| {
        mesh_rpc_typed(
            &e2e_nan_service(),
            "wifi.rawnan.status",
            &lmesh_wifi::api::RawNanStatusRequest {
                iface: Some(e2e_nan_iface()),
            },
        )
    }) {
        Ok(status) => status,
        Err(_) => {
            eprintln!("firmware-e2e NAN wake skipped: selected host NAN status unavailable");
            return None;
        }
    };
    let cluster = status["data"]["sync_bssid"].as_str();
    let age_ms = status["data"]["sync_age_ms"].as_u64();
    if cluster.is_some() && age_ms.is_some_and(|age| age <= 10_000) {
        eprintln!("firmware-e2e NAN wake host cluster={cluster:?} age_ms={age_ms:?} timeout_s=5");
        Some(Duration::from_secs(5))
    } else {
        eprintln!(
            "firmware-e2e NAN wake skipped: no recent host NAN cluster (cluster={cluster:?} age_ms={age_ms:?}); set DMESH_E2E_NAN_WAKE_TIMEOUT_SECS=40 to diagnose cold/no-cluster behavior"
        );
        None
    }
}

/// Check the regular raw-action/NOW service without assuming a NAN cluster.
/// This uses the same QUIC-lite status handler as other transport clients;
/// it neither changes the host's radio mode nor reconfigures either endpoint.
/// It is called once per active endpoint only after NAN rendezvous is known
/// unavailable, so it is a fallback observation rather than a polling tick.
fn host_now_status(device: &E2eDeviceConfig, nonce: u64) -> Result<serde_json::Value, String> {
    let response = std::panic::catch_unwind(|| {
        mesh_rpc_typed(
            "lmesh-wifi",
            "wifi.raw.check",
            &lmesh_wifi::api::WifiRawCheckRequest {
                iface: Some("wlan0".to_owned()),
                channel: Some(6),
                destination: hex(&configured_mac(device)),
                nonce: Some(nonce),
                timeout_ms: Some(5_000),
                tx_rate_mbps: Some(6),
                tx_variant: Some("monitor".to_owned()),
                rx_variant: Some("monitor".to_owned()),
                expected_peer: Some(hex(&configured_mac(device))),
            },
        )
    })
    .map_err(panic_detail)?;
    let data = controller_data(&response).clone();
    if data["ok"].as_bool() == Some(true) {
        Ok(data)
    } else {
        Err(data.to_string())
    }
}

/// Read the stable control plane's durable discovery inventory.  This is
/// deliberately `lmesh-wifi`/`wlan0` even when a row uses `wlan1` as a test
/// radio: the test radio may change its own NAN/STA epoch, whereas the stable
/// control plane must remain observational and must never be mode-switched by
/// a pair probe.
fn stable_control_plane_inventory() -> serde_json::Value {
    mesh_rpc_typed(
        "lmesh-wifi",
        "wifi.rawnan.status",
        &lmesh_wifi::api::RawNanStatusRequest {
            iface: Some("wlan0".to_owned()),
        },
    )
}

fn discovered_device_id(device: &E2eDeviceConfig) -> String {
    configured_mac(device)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Require the two selected descriptors to appear in wlan0's live discovery
/// database before interpreting any mode/bearer result.  This also makes the
/// inventory useful as a fleet selector: callers can count `device_class`
/// values (ESP, Android, Host) without retaining board-specific test names.
fn wait_for_stable_control_plane_devices(
    source: &E2eDeviceConfig,
    target: &E2eDeviceConfig,
    timeout: Duration,
) {
    let wanted = [discovered_device_id(source), discovered_device_id(target)];
    let deadline = Instant::now() + timeout;
    loop {
        let status = stable_control_plane_inventory();
        let devices = status["data"]["discovered_devices"]
            .as_array()
            .or_else(|| status["discovered_devices"].as_array())
            .cloned()
            .unwrap_or_default();
        let found = wanted
            .iter()
            .filter(|id| devices.iter().any(|entry| entry["id"].as_str() == Some(id.as_str())))
            .count();
        if found == wanted.len() {
            let esp = devices.iter().filter(|entry| entry["announce"]["device_class"].as_u64() == Some(1)).count();
            let android = devices.iter().filter(|entry| entry["announce"]["device_class"].as_u64() == Some(3)).count();
            let hosts = devices.iter().filter(|entry| entry["announce"]["device_class"].as_u64() == Some(2)).count();
            eprintln!(
                "firmware-e2e stable-discovery source={} target={} inventory esp={} android={} host={}",
                source.name, target.name, esp, android, hosts
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "stable wlan0 discovery did not contain both selected endpoints: wanted={wanted:?} found={found} inventory={devices:?}"
        );
        thread::sleep(Duration::from_millis(100));
    }
}

/// Ask the regular `lmesh-wifi` handler for the full pair matrix after NAN
/// activation has populated wlan0's durable inventory.  The integration test
/// deliberately does not re-create the matrix from its descriptor file: that
/// would let a stale lab capability claim diverge from the production control
/// plane's selection decision.
fn stable_control_plane_pair_plan(
    source: &E2eDeviceConfig,
    target: &E2eDeviceConfig,
) -> Vec<PairProbeRequest> {
    let response = mesh_rpc_typed(
        "lmesh-wifi",
        "wifi.probe.plan",
        &lmesh_wifi::api::ProbePlanRequest {
            iface: Some("wlan0".to_owned()),
            source_id: discovered_device_id(source),
            target_id: discovered_device_id(target),
            short_bytes: Some(4 * 1024),
            long_bytes: Some(u32::try_from(e2e_now_bytes()).expect("probe bytes fit u32")),
        },
    );
    let data = response
        .get("data")
        .cloned()
        .unwrap_or_else(|| panic!("wifi.probe.plan missing data: {response}"));
    assert_eq!(data["control_plane_mode_changed"], false);
    serde_json::from_value(data["rows"].clone())
        .unwrap_or_else(|error| panic!("wifi.probe.plan returned invalid rows: {error}; data={data}"))
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
    // Android's Wi-Fi Aware service continuously publishes its DMesh service
    // descriptor. The permanent monitor must report a fresh DMesh SDF. Some
    // Android builds use the legacy bounded descriptor and therefore cannot
    // populate the newer decoded `announce` object; the on-air service
    // descriptor is still the discovery proof required by this row.
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
        let history = mesh_rpc_value(
            "lmesh",
            "messages.history",
            serde_json::json!({"keys": "wifi.rawnan.discovery", "limit": 128}),
        );
        let observed = status["data"]["sync_bssid"].as_str().is_some()
            && history_events(&history).is_some_and(|events| {
                events.iter().any(|event| {
                    event["ts_millis"]
                        .as_u64()
                        .is_some_and(|ts| ts >= started_ms)
                        && event["value"]["service_id"].as_str()
                            == Some(hex(&dmesh_rawnan::DMESH_SERVICE_ID).as_str())
                        && event["value"]["service_info_hex"]
                            .as_str()
                            .is_some_and(|value| !value.is_empty())
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
    host_to_device_udp6_iperf_bytes(label, mac, cid, udp6_transfer_bytes()).await;
}

/// Run one bounded host-to-device UDP6 transfer at the size selected by a
/// generic ProbeRequest. The host remains the controller; both descriptors
/// still receive the same requested STA radio epoch before this is called.
async fn host_to_device_udp6_iperf_bytes(label: &str, mac: [u8; 6], cid: u64, bytes: u64) {
    // This is equivalent to the historic CLI form:
    // dmesh-cli 'udp://[fe80::16c1:9fff:fee5:9800%wlan0]:3339' --iperf-bytes 65536
    // The Rust test uses the same UdpClient/service schema directly, so it
    // does not rely on a retired CLI argument grammar or restart lmesh-wifi.
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
    complete_action_iperf_bytes(client, source, peer, E2E_ACTION_IPERF_BYTES, label)
}

/// Run one raw-action IPERF row at the exact size in a ProbeRequest. The
/// command/check rows run separately, so this measures only completed stream
/// bytes and reports device-observed elapsed time/goodput.
fn complete_action_iperf_bytes(
    client: &mut DeviceSession,
    source: &mut DeviceSession,
    peer: [u8; 6],
    bytes: u64,
    label: &str,
) -> (
    dmesh_server::raw_wifi::RawWifiSnapshot,
    dmesh_server::raw_wifi::RawWifiSnapshot,
) {
    snapshot(client, RAW_WIFI_METHOD_RESET_COUNTERS);
    snapshot(source, RAW_WIFI_METHOD_RESET_COUNTERS);
    let request = RawWifiIperfRequest {
        peer,
        bytes,
        packet_size: E2E_UDP6_PACKET_SIZE,
        timeout_ms: 20_000,
        bearer: RawWifiBearer::Now,
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
            && snapshot.raw_service_bytes == Some(bytes as u32)
        {
            break snapshot;
        }
    };
    let source_snapshot = snapshot(source, RAW_WIFI_METHOD_SNAPSHOT);
    let elapsed_us = complete
        .raw_service_elapsed_us
        .expect("action IPERF elapsed");
    let bps = bytes.saturating_mul(8_000_000) / u64::from(elapsed_us.max(1));
    eprintln!(
        "firmware-e2e row={label} kind=action-iperf bytes={} elapsed_us={} bps={} source=({}) client=({})",
        bytes,
        elapsed_us,
        bps,
        snapshot_summary(&source_snapshot),
        snapshot_summary(&complete),
    );
    assert_eq!(
        complete.raw_service_bytes,
        Some(bytes as u32)
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

/// Collect transition markers from the UART owner with host-side receipt
/// timestamps. The firmware emits the same records on NAN/NOW/UDP6, but UART
/// is the deterministic timing reference even while the radio is about to
/// sleep. A missing interval after `sleep_pending` is therefore expected;
/// silence before that marker is a failure signal rather than a sleep result.
fn collect_transition_markers(
    session: &mut DeviceSession,
    timeout: Duration,
    start_index: usize,
) -> Vec<(Instant, u64)> {
    let deadline = Instant::now() + timeout;
    // The caller snapshots this before sending the transition command;
    // correlated replies and markers may arrive in the same UART poll.
    let mut seen = start_index;
    let mut markers = Vec::new();
    while Instant::now() < deadline {
        let _ = session.poll(Duration::from_millis(50));
        let received_at = Instant::now();
        let events = session.recent_events().skip(seen).cloned().collect::<Vec<_>>();
        seen += events.len();
        for event in events {
            if let DeviceSessionEvent::DirectRecord(record) = event {
                if let Some(announce) = decode_announce(&record) {
                    if matches!(
                        announce.kind,
                        ANNOUNCE_TRANSITION_BEGIN
                            | ANNOUNCE_SLEEP_PENDING
                            | ANNOUNCE_TRANSITION_COMPLETE
                            | ANNOUNCE_WAKE
                    ) {
                        markers.push((received_at, announce.kind));
                    }
                }
            }
        }
    }
    markers
}

/// Timing probe for one active -> sleepy edge. The same collector is used by
/// the full NAN wake cycle: each subsequent active-STA and sleepy request is
/// sent by the appropriate bearer, while the UART marker stream remains the
/// authoritative ordering/timing ledger.
#[test]
#[ignore = "requires flashed active e7; set DMESH_E2E_TRANSITIONS=1"]
fn firmware_e7_transition_markers_timing() {
    if std::env::var("DMESH_E2E_TRANSITIONS").ok().as_deref() != Some("1") {
        return;
    }
    let mut e7 = DeviceSession::open(serial_from_env("DMESH_E2E_E7"), None).unwrap();
    e7.set_history_limit(512);
    let history_before = e7.recent_events().len();
    control_request(
        &mut e7,
        ControlRequest::TransportStart {
            kind: TransportKind::Nan,
            config: dmesh_server::control::TransportConfig {
                channel: Some(6),
                nan_dw_interval: Some(8),
                now: Some(2),
                ap: Some(0),
                uart: Some(0),
                ..dmesh_server::control::TransportConfig::default()
            },
        },
        0xE7_7A00_01,
    );
    let started = Instant::now();
    let markers = collect_transition_markers(&mut e7, Duration::from_secs(2), history_before);
    let kinds = markers.iter().map(|(_, kind)| *kind).collect::<Vec<_>>();
    assert!(kinds.contains(&ANNOUNCE_TRANSITION_BEGIN), "missing transition begin: {kinds:?}");
    assert!(kinds.contains(&ANNOUNCE_SLEEP_PENDING), "missing sleep pending: {kinds:?}");
    let pending = markers
        .iter()
        .find(|(_, kind)| *kind == ANNOUNCE_SLEEP_PENDING)
        .map(|(at, _)| at.duration_since(started))
        .unwrap();
    assert!(
        pending <= Duration::from_secs(1),
        "sleep marker timing was not observed promptly"
    );
}

/// Ask sleepy e7 to enter the channel-6 NAN/AP profile through e6's active
/// Subscribe SDEA path. This is an operator-facing diagnostic: sender-side
/// acceptance is not proof, so it prints e7's direct radio snapshot when USB
/// remains available and leaves AP advertisement/association to the caller.
#[test]
#[ignore = "requires e6 and e7; sends e7 a NAN/AP activation message"]
fn firmware_e6_activates_e7_nan_ap() {
    let mut e6 = DeviceSession::open(serial_from_env("DMESH_E2E_E6"), None).unwrap();
    control_request(
        &mut e6,
        ControlRequest::TransportStart {
            kind: TransportKind::Nan,
            config: dmesh_server::control::TransportConfig {
                channel: Some(6),
                nan_dw_interval: Some(1),
                now: Some(1),
                ap: Some(1),
                uart: Some(1),
                ..dmesh_server::control::TransportConfig::default()
            },
        },
        0xE6_7A10_01,
    );
    let request = ControlRequest::TransportStart {
        kind: TransportKind::Nan,
        config: dmesh_server::control::TransportConfig {
            channel: Some(6),
            nan_dw_interval: Some(1),
            now: Some(1),
            ap: Some(1),
            uart: Some(1),
            ..dmesh_server::control::TransportConfig::default()
        },
    };
    let mut wire = [0u8; 128];
    let used = control::encode_request(request, None, &mut wire).unwrap();
    for destination in [E7_MAC, dmesh_rawnan::NAN_DISCOVERY_MAC] {
        let frame = dmesh_rawnan::build_nan_usd_sdf(
            destination,
            E6_MAC,
            dmesh_rawnan::DMESH_SERVICE_ID,
            7,
            0x11,
            &wire[..used],
        );
        send_raw_action(&mut e6, &frame, RawWifiInterface::Sta);
    }
    thread::sleep(Duration::from_secs(2));
    drop(e6);

    match DeviceSession::open(serial_from_env("DMESH_E2E_E7"), None) {
        Ok(mut e7) => {
            let radio = snapshot(&mut e7, RAW_WIFI_METHOD_SNAPSHOT);
            eprintln!("e7 NAN/AP activation snapshot: {}", snapshot_summary(&radio));
        }
        Err(error) => eprintln!("e7 UART unavailable after NAN/AP activation: {error}"),
    }
}

/// Recovery-only NAN wake retry. This deliberately does not open e7's UART:
/// once e7 is asleep, USB may be unavailable. Repeated active-Subscribe SDEA
/// frames must wake it and restore its active STA profile.
#[test]
#[ignore = "set DMESH_E2E_NAN_WAKE_RETRY=1; requires e6 and sleepy e7"]
fn firmware_e6_repeats_active_nan_wake() {
    if std::env::var("DMESH_E2E_NAN_WAKE_RETRY").ok().as_deref() != Some("1") {
        return;
    }
    let wake_timeout = match nan_wake_timeout_from_host() {
        Some(timeout) => timeout,
        None => return,
    };
    let test_started = Instant::now();
    let mut e6 = DeviceSession::open(serial_from_env("DMESH_E2E_E6"), None).unwrap();
    control_request(
        &mut e6,
        ControlRequest::TransportStart {
            kind: TransportKind::Nan,
            config: dmesh_server::control::TransportConfig {
                channel: Some(6),
                nan_dw_interval: Some(1),
                now: Some(0),
                ap: Some(1),
                uart: Some(1),
                ..dmesh_server::control::TransportConfig::default()
            },
        },
        0xE6_7A00_01,
    );
    // Once sleepy, wake with an active-Subscribe SDEA carrying a complete
    // STA profile. UART is optional after this point; UDP6 status is the
    // authoritative proof that remote control was restored.
    let ssid = wlan0_ssid();
    let (bssid, channel) = wlan0_bssid_channel();
    let active = ControlRequest::TransportStart {
        kind: TransportKind::Sta,
        config: dmesh_server::control::TransportConfig {
            ssid: Some(ssid.as_bytes()),
            bssid: Some(bssid),
            channel: Some(channel),
            nan_dw_interval: Some(0),
            now: Some(0),
            ap: Some(0),
            uart: Some(1),
            ..dmesh_server::control::TransportConfig::default()
        },
    };
    let mut wire = [0u8; 128];
    let used = control::encode_request(active, None, &mut wire).unwrap();
    // Sleepy wake is an active-Subscribe exchange: the command belongs in
    // the SDEA, and the target answers with a directed NAN Follow-up. A
    // Publish SDF carries SSI in the wrong place for this wake path.
    let frame = dmesh_rawnan::build_nan_usd_sdf(
        E7_MAC,
        E6_MAC,
        dmesh_rawnan::DMESH_SERVICE_ID,
        7,
        0x11,
        &wire[..used],
    );
    // Some NAN peers only accept the active-Subscribe SDF at the discovery
    // multicast address and use the service target inside the SDEA. Keep one
    // bounded broadcast fallback in the same five-second wake cadence.
    let broadcast_frame = dmesh_rawnan::build_nan_usd_sdf(
        dmesh_rawnan::NAN_DISCOVERY_MAC,
        E6_MAC,
        dmesh_rawnan::DMESH_SERVICE_ID,
        7,
        0x11,
        &wire[..used],
    );
    // A cold sleepy boot may take the specified 30-second unsynchronized
    // backoff before its next five-second NAN receive window. Keep the
    // control retries bounded, but long enough to observe that first retry.
    let deadline = Instant::now() + wake_timeout;
    while Instant::now() < deadline {
        send_raw_action(&mut e6, &frame, RawWifiInterface::Sta);
        send_raw_action(&mut e6, &broadcast_frame, RawWifiInterface::Sta);
        thread::sleep(Duration::from_millis(600));
    }
    drop(e6);
    // Sender-side injection is not wake evidence. The only required proof is
    // that the remote SUT answers a normal UDP6 status request after NAN.
    let ifindex = interface_index("wlan0");
    let peer = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(quic_lite::raw_udp6::link_local_from_mac(E7_MAC)),
        RAW_UDP6_PORT,
        0,
        ifindex,
    ));
    let bind = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 3338, 0, 0));
    // The NAN command is accepted before the STA association and raw UDP6
    // service are fully ready. Keep each probe bounded, but retry during the
    // asynchronous bring-up so a late NDP/QUIC response is not mistaken for
    // a failed NAN wake.
    let status_deadline = Instant::now() + Duration::from_secs(15);
    let mut status = Err("UDP6 wake status probe did not start".to_owned());
    while Instant::now() < status_deadline {
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let mut client = timeout(
                    Duration::from_secs(2),
                    UdpClient::connect(
                        bind,
                        peer,
                        ConnectionId::new(0xE6_7A00_02).unwrap(),
                    ),
                )
                .await
                .map_err(|_| "UDP6 wake bootstrap timeout".to_owned())?
                .map_err(|error| format!("UDP6 wake bootstrap: {error:#}"))?;
                timeout(
                    Duration::from_secs(5),
                    client.request_stream(FIRST_CLIENT_BIDI_STREAM_ID, &[SERVICE_STATUS], true),
                )
                .await
                .map_err(|_| "UDP6 wake status timeout".to_owned())
            });
        if result.is_ok() {
            status = result;
            break;
        }
        status = result;
        thread::sleep(Duration::from_millis(250));
    }
    assert!(
        status.is_ok(),
        "NAN wake produced no remote UDP6 status response: {status:?}"
    );
    let elapsed = test_started.elapsed();
    if elapsed > Duration::from_secs(9) {
        eprintln!(
            "WARNING: sleepy NAN wake took {:.1}s; verify the NAN cluster was synchronized",
            elapsed.as_secs_f32(),
        );
    }
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
                // This focused associated NOW row deliberately disables DW
                // capture so it isolates the action bearer.
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
                // Active NAN/NOW is the normal discovery/control-plane
                // personality. DW=0 is reserved for low-level lab tests;
                // the shared prober must leave the endpoint discoverable
                // while it measures the NOW bearer.
                nan_dw_interval: Some(1),
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
///   --arg '{"id":"android-ap-off","method":"wifi.transport.start","data":{"mode":"nan","ap":"0"}}'
/// adb -s "$DMESH_E2E_ANDROID" shell content call \
///   --uri content://com.github.costinm.dmesh.lm.shell --method command \
///   --arg '{"id":"android-ap-on","method":"wifi.transport.start","data":{"mode":"nan","ap":"1"}}'
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
    for (id, ap) in [("android-ap-off", "0"), ("android-ap-on", "1")] {
        let command = serde_json::json!({
            "id": id,
            "method": "wifi.transport.start",
            "data": {"mode": "nan", "ap": ap},
        });
        let response = android_json_command(&android, command);
        if ap == "1" {
            assert!(
                response_state_started(&response),
                "Android P2P Group Owner did not start: {response}"
            );
        }
    }
    // The Android P2P group-info callback is the only place that constructs
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
            "Android P2P Group Owner did not emit its NAN transport.start SD: {}",
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
///   --arg '{"id":"android-sta","method":"wifi.transport.start","data":{"mode":"sta","ssid":"<wlan0-ssid>","bssid":"<wlan0-bssid>","ap":"0"}}'
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
    let request = serde_json::json!({
        "id": "android-sta",
        "method": "wifi.transport.start",
        "data": {"mode": "sta", "ssid": ssid, "bssid": bssid, "ap": "0"},
    });
    let command = format!(
        "content call --uri content://com.github.costinm.dmesh.lm.shell --method command \\
         --arg '{}'",
        request
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
                  --arg '{\"id\":\"android-sta-detach\",\"method\":\"wifi.transport.start\",\"data\":{\"mode\":\"nan\",\"ap\":\"0\"}}'";
    let output = Command::new("adb")
        .args(["-s", &android, "shell", detach])
        .output()
        .expect("Android NAN detach");
    assert!(output.status.success(), "Android NAN detach failed");
}

/// Pixel 7 API-37 coexistence gate: E6 owns an open channel-6 AP while the
/// phone has a BSSID-directed STA request, yet Android NAN remains live
/// enough to publish the common CBOR Service Info. This does not change host
/// WLAN infrastructure.
///
/// Manual equivalent: start E6 `radio.control channel=6 ap_mode=open`, then
/// send Pixel 7 `wifi.transport.start mode=sta ssid=DIRECT-...-dmesh
/// bssid=<e6-ap-mac> ap=0`, followed by `wifi.nan.sd cbor_hex=<record>`.
#[test]
#[ignore = "requires flashed e6 and Pixel 7 Android 17 service; exclusive e6 UART ownership"]
fn android_sta_to_e6_open_ap_keeps_nan_sd() {
    let mut e6 = DeviceSession::open(serial_from_env("DMESH_E2E_E6"), None).unwrap();
    let android = std::env::var("DMESH_E2E_ANDROID")
        .expect("DMESH_E2E_ANDROID must name the Pixel 7 adb serial");
    control_request(&mut e6, ControlRequest::TransportStart {
        kind: TransportKind::Nan,
        config: dmesh_server::control::TransportConfig {
            channel: Some(6), now: Some(0), nan_dw_interval: Some(1), ap: Some(1),
            ..dmesh_server::control::TransportConfig::default()
        },
    }, 0xE6_4150_37);
    let deadline = Instant::now() + Duration::from_secs(6);
    let ap = loop {
        let snapshot = snapshot(&mut e6, RAW_WIFI_METHOD_SNAPSHOT);
        if snapshot.ap_active == Some(true) && snapshot.sta_associated == Some(false)
            && snapshot.nan_dw_interval == Some(1) { break snapshot; }
        assert!(Instant::now() < deadline, "e6 NAN+AP start: {}", snapshot_summary(&snapshot));
        thread::sleep(Duration::from_millis(200));
    };
    assert_eq!(ap.ap_active, Some(true), "e6 AP start: {ap:?}");
    assert_eq!(ap.channel, Some(6), "e6 AP channel: {ap:?}");
    let mac = ap.ap_mac.expect("e6 AP MAC");
    let ssid = format!("DIRECT-{:02X}{:02X}{:02X}-dmesh", mac[3], mac[4], mac[5]);
    let bssid = mac.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(":");
    let attach = android_json_command(&android, serde_json::json!({
        "id": "pixel7-e6-ap-sta",
        "method": "wifi.transport.start",
        "data": {"mode": "sta", "ssid": ssid, "bssid": bssid, "ap": "0"},
    }));
    assert!(attach.contains("ap_stopped"), "Android STA request: {attach}");
    thread::sleep(Duration::from_secs(3));

    let before = snapshot(&mut e6, RAW_WIFI_METHOD_SNAPSHOT);
    let cbor = ControlRequest::TransportStart {
        kind: TransportKind::Nan,
        config: dmesh_server::control::TransportConfig {
            channel: Some(6), now: Some(0), nan_dw_interval: Some(1),
            ..dmesh_server::control::TransportConfig::default()
        },
    };
    let mut wire = [0u8; 128];
    let used = control::encode_request(cbor, None, &mut wire).unwrap();
    let command = format!(
        "content call --uri content://com.github.costinm.dmesh.lm.shell --method command --arg 'wifi.nan.sd cbor_hex={}'",
        hex(&wire[..used])
    );
    let output = Command::new("adb").args(["-s", &android, "shell", &command])
        .output().expect("Pixel 7 NAN SD command");
    assert!(output.status.success(), "Pixel 7 NAN SD: {}", String::from_utf8_lossy(&output.stderr));
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        let after = snapshot(&mut e6, RAW_WIFI_METHOD_SNAPSHOT);
        if after.counters.delta_since(before.counters).nan_service_info_enqueued != 0 {
            eprintln!("Pixel7 STA->e6 AP retained NAN SD: {}", snapshot_summary(&after));
            break;
        }
        assert!(Instant::now() < deadline, "e6 did not receive Pixel7 NAN SD while AP owner: {}", snapshot_summary(&after));
        thread::sleep(Duration::from_millis(250));
    }
    let _ = android_json_command(&android, serde_json::json!({
        "id": "pixel7-e6-ap-detach", "method": "wifi.transport.start",
        "data": {"mode": "nan", "ap": "0"},
    }));
}

/// Exercise Android's Wi-Fi Direct Group Owner capability without modifying
/// host Wi-Fi. NAN remains discovery/timing; this AP is only the optional
/// associated high-rate bearer.
///
/// Manual equivalent:
///
/// ```sh
/// adb -s "$DMESH_E2E_ANDROID" shell content call \
///   --uri content://com.github.costinm.dmesh.lm.shell --method command \
///   --arg '{"id":"soft-ap","method":"wifi.transport.start","data":{"mode":"nan","ap":"1"}}'
/// ```
#[test]
#[ignore = "requires an Android DMesh service; does not start/stop host WLAN"]
fn android_ap_capability_probe() {
    let android = std::env::var("DMESH_E2E_ANDROID")
        .expect("DMESH_E2E_ANDROID must name the Android adb serial");
    let identity = android_node_identity(&android);
    let execution = android_capability_probe_response(
        &android,
        ProbeRequest {
            request_id: 0x414e_4452_0001,
            source: ProbeEndpoint {
                kind: ProbeEndpointKind::Android,
                node: [0; 6],
                mode: ProbeMode::NAN_NOW,
                bssid: None,
            },
            // This local capability row intentionally does not manufacture a
            // peer result. A later pair runner fills the target/bearer rows.
            target: ProbeEndpoint {
                kind: ProbeEndpointKind::Host,
                node: [0; 6],
                mode: ProbeMode::NAN_NOW,
                bssid: None,
            },
            test_nan: false,
            test_nan_data: false,
            test_now: false,
            test_udp6_association: false,
            test_udp6: false,
            test_scan: true,
            test_soft_ap: true,
            short_bytes: 0,
            long_bytes: 0,
            measure_mode_switch: false,
        },
    );
    let response = execution.response;
    eprintln!(
        "firmware-e2e row=android-ap-capability node={} response={response:?}",
        identity.name,
    );
    assert!(response.source_mode.soft_ap.attempted);
    assert!(response.source_scan.attempted && response.source_scan.succeeded);
    record_node_capability(
        &identity,
        NodeCapabilityStatus {
            last_result: "android_ap_capability_probe".to_owned(),
            last_seen_unix_ms: 0,
            soft_ap: Some(response.source_mode.soft_ap.succeeded),
            scan_ap_count: response.source_scan.ap_count,
            scan_channel6_ap_count: response.source_scan.channel6_ap_count,
            scan_dmesh_ap_count: response.source_scan.dmesh_ap_count,
            scan_dmesh: execution.scan_dmesh,
        },
    );
}

/// First live Android-to-Android UDP6-association row. Pixel 7 is the
/// fixed-channel P2P GO and Pixel 3a is an ordinary WPA2 STA client; this is
/// intentionally the same AP/P2P/STA shape used for ESP clients, not a
/// special Android data path. The controller requires both apps to observe a
/// fresh `ff02::5227:5227` announce before it may use a learned scoped IPv6
/// address for a one-way datagram, QUIC-lite, or IPERF.
///
/// Manual equivalent:
/// ```sh
/// adb -s "$DMESH_E2E_ANDROID_P7" shell content call \
///   --uri content://com.github.costinm.dmesh.lm.shell --method command \
///   --arg '{"id":"p7-go","method":"wifi.transport.start","data":{"mode":"nan","ap":"1"}}'
/// adb -s "$DMESH_E2E_ANDROID_P3A" shell content call \
///   --uri content://com.github.costinm.dmesh.lm.shell --method command \
///   --arg '{"id":"p3-sta","method":"wifi.transport.start","data":{"mode":"sta","ssid":"DIRECT-dm-dmesh","passphrase":"untrusted-open-mode","ap":"0"}}'
/// adb -s "$DMESH_E2E_ANDROID_P7" shell content call \
///   --uri content://com.github.costinm.dmesh.lm.shell --method command \
///   --arg '{"id":"p7-devices","method":"radio.devices"}'
/// ```
#[test]
#[ignore = "requires Pixel 7 and Pixel 3a DMesh services; no host WLAN changes"]
fn android_p2p_udp6_association_probe() {
    let pixel7 = std::env::var("DMESH_E2E_ANDROID_P7")
        .expect("DMESH_E2E_ANDROID_P7 must name the Pixel 7 adb serial");
    let pixel3a = std::env::var("DMESH_E2E_ANDROID_P3A")
        .expect("DMESH_E2E_ANDROID_P3A must name the Pixel 3a adb serial");
    let source = android_node_identity(&pixel7);
    let target = android_node_identity(&pixel3a);
    let request = ProbeRequest {
        request_id: 0x5037_5033_0001,
        source: ProbeEndpoint {
            kind: ProbeEndpointKind::Android,
            node: [0; 6],
            mode: ProbeMode { ap: true, ..ProbeMode::NAN_NOW },
            bssid: None,
        },
        target: ProbeEndpoint {
            kind: ProbeEndpointKind::Android,
            node: [0; 6],
            mode: ProbeMode::STA_NAN_NOW,
            bssid: None,
        },
        test_nan: false,
        test_nan_data: false,
        test_now: false,
        test_udp6_association: true,
        test_udp6: true,
        test_scan: false,
        test_soft_ap: false,
        short_bytes: 1_100,
        long_bytes: 64 * 1024,
        measure_mode_switch: true,
    };

    // Ensure the GO command does not inherit a stale temporary group. The
    // app waits for the P2P disconnect action plus requestGroupInfo(null).
    let _ = android_json_command(&pixel7, serde_json::json!({
        "id": "p7-p2p-clean", "method": "wifi.transport.start",
        "data": {"mode": "nan", "ap": "0"},
    }));
    let before_source = android_known_devices(&pixel7, "p7-devices-before");
    let before_target = android_known_devices(&pixel3a, "p3-devices-before");
    let source_before_multicast = udp_multicast_observation_count(&before_source);
    let target_before_multicast = udp_multicast_observation_count(&before_target);

    let go_started = android_json_command(&pixel7, serde_json::json!({
        "id": "p7-go", "method": "wifi.transport.start",
        "data": {"mode": "nan", "ap": "1"},
    }));
    let source_ready = response_state_started(&go_started);
    let associated_started = Instant::now();
    let client_result = if source_ready {
        android_json_command(&pixel3a, serde_json::json!({
            "id": "p3-sta", "method": "wifi.transport.start",
            "data": {
                "mode": "sta", "ssid": "DIRECT-dm-dmesh",
                "passphrase": "untrusted-open-mode", "ap": "0",
            },
        }))
    } else {
        "GO did not start; client request not issued".to_owned()
    };
    let target_ready = client_result.contains("\"state\":\"associated\"");

    // GO creation announces once before the client is connected. Reissue the
    // identical immutable GO request after the client's onAvailable callback
    // so the source sends the shared CBOR announce onto the new P2P link.
    if target_ready {
        let _ = android_json_command(&pixel7, serde_json::json!({
            "id": "p7-go-announce", "method": "wifi.transport.start",
            "data": {"mode": "nan", "ap": "1"},
        }));
    }

    let deadline = Instant::now() + Duration::from_secs(12);
    let (source_inventory, target_inventory, multicast_ok) = loop {
        let source_inventory = android_known_devices(&pixel7, "p7-devices-after");
        let target_inventory = android_known_devices(&pixel3a, "p3-devices-after");
        let source_seen = udp_multicast_observation_count(&source_inventory) > source_before_multicast;
        let target_seen = udp_multicast_observation_count(&target_inventory) > target_before_multicast;
        if source_seen && target_seen {
            break (source_inventory, target_inventory, true);
        }
        if Instant::now() >= deadline {
            break (source_inventory, target_inventory, false);
        }
        thread::sleep(Duration::from_millis(250));
    };
    let association_elapsed = u32::try_from(associated_started.elapsed().as_millis()).ok();
    let response = ProbeResponse {
        request_id: request.request_id,
        source_mode: ProbeModeResult {
            attempted: true, succeeded: source_ready, ap_active: Some(source_ready),
            ..ProbeModeResult::default()
        },
        target_mode: ProbeModeResult {
            attempted: true, succeeded: target_ready, associated: Some(target_ready),
            elapsed_us: association_elapsed.map(|value| u64::from(value) * 1_000),
            ..ProbeModeResult::default()
        },
        nan: ProbeMeasurement::default(),
        nan_data: ProbeMeasurement::default(),
        now: ProbeMeasurement::default(),
        udp6_association: ProbeUdp6AssociationResult {
            attempted: true,
            source_ready,
            target_ready,
            multicast: ProbeMeasurement { attempted: true, succeeded: multicast_ok, ..ProbeMeasurement::default() },
            // These stages are intentionally not attempted until multicast
            // yields a scoped IPv6 peer address. The next executor change
            // sends raw datagram, QUIC-lite, and IPERF using that observation.
            one_way: ProbeMeasurement::default(),
            quic_lite: ProbeMeasurement::default(),
            iperf: ProbeMeasurement::default(),
        },
        udp6: ProbeMeasurement { attempted: true, succeeded: multicast_ok, ..ProbeMeasurement::default() },
        source_scan: ProbeScanResult::default(),
        target_scan: ProbeScanResult::default(),
        recommendation: if multicast_ok { 3 } else { 0 },
    };
    record_pair_probe(&source, &target, PairProbeStatus {
        peer: String::new(), test: "udp6-association".to_owned(),
        last_result: format!("{response:?}; go={go_started}; client={client_result}; source_inventory={source_inventory}; target_inventory={target_inventory}"),
        last_seen_unix_ms: 0, sta_associated: Some(target_ready),
        association_ms: association_elapsed, ..PairProbeStatus::default()
    });

    let _ = android_json_command(&pixel3a, serde_json::json!({
        "id": "p3-p2p-clean", "method": "wifi.transport.start",
        "data": {"mode": "nan", "ap": "0"},
    }));
    let _ = android_json_command(&pixel7, serde_json::json!({
        "id": "p7-p2p-clean", "method": "wifi.transport.start",
        "data": {"mode": "nan", "ap": "0"},
    }));
    assert!(source_ready, "Pixel 7 P2P GO did not start: {go_started}");
    assert!(target_ready, "Pixel 3a did not associate to Pixel 7 P2P GO: {client_result}");
    assert!(multicast_ok,
        "P2P association did not yield bidirectional UDP6 multicast; source={source_inventory}; target={target_inventory}");
}

/// Prove the Android Wi-Fi Direct Group Owner path with the same volatile WPA2
/// profile E6 receives from UART or NAN SD.  This intentionally bypasses NAN
/// for the association itself: it isolates Android SoftAP plus Recovery STA
/// compatibility from OEM NAN/AP concurrency, while still using the common
/// `transport.start` control record.  It does not create, stop, or alter a
/// host Wi-Fi interface.
///
/// Manual equivalent:
/// ```sh
/// adb -s "$DMESH_E2E_ANDROID" shell content call \
///   --uri content://com.github.costinm.dmesh.lm.shell --method command \
///   --arg '{"id":"android-e6-ap","method":"wifi.transport.start","data":{"mode":"nan","ap":"1"}}'
/// # Send the returned ssid/passphrase in a UART transport.start {mode: sta}
/// # record to E6, then wait for `sta_associated=true` in wifi.raw snapshot.
/// ```
#[test]
#[ignore = "requires flashed e6 and an Android DMesh service; leaves host WLAN untouched"]
fn android_p2p_go_uart_associates_e6() {
    let android = std::env::var("DMESH_E2E_ANDROID")
        .expect("DMESH_E2E_ANDROID must name the Android adb serial");
    let stop = serde_json::json!({
        "id": "android-e6-ap-off",
        "method": "wifi.transport.start",
        "data": {"mode": "nan", "ap": "0"},
    });
    let _ = android_json_command(&android, stop);
    let start = android_json_command(
        &android,
        serde_json::json!({
            "id": "android-e6-ap",
            "method": "wifi.transport.start",
            "data": {"mode": "nan", "ap": "1"},
        }),
    );
    assert!(
        response_state_started(&start),
        "Android Wi-Fi Direct Group Owner did not start: {start}"
    );
    let ssid = json_string_field(&start, "ssid")
        .filter(|value| !value.is_empty())
        .expect("Android Wi-Fi Direct Group Owner omitted SSID");
    let passphrase = json_string_field(&start, "passphrase");

    let outcome = (|| {
        let mut e6 = DeviceSession::open(serial_from_env("DMESH_E2E_E6"), None).unwrap();
        control_request(
            &mut e6,
            ControlRequest::TransportStart {
                kind: TransportKind::Sta,
                config: dmesh_server::control::TransportConfig {
                    ssid: Some(ssid.as_bytes()),
                    passphrase: passphrase.as_deref().map(str::as_bytes),
                    now: Some(0),
                    ap: Some(0),
                    ..dmesh_server::control::TransportConfig::default()
                },
            },
            0xE6_4150_01,
        );
        let association_started = Instant::now();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let radio = snapshot(&mut e6, RAW_WIFI_METHOD_SNAPSHOT);
            if radio.sta_associated == Some(true) {
                eprintln!(
                    "Android Wi-Fi Direct Group Owner -> E6 association elapsed_ms={} {}",
                    association_started.elapsed().as_millis(),
                    snapshot_summary(&radio),
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "E6 did not associate to Android Wi-Fi Direct Group Owner ssid={ssid}: {}",
                snapshot_summary(&radio)
            );
            thread::sleep(Duration::from_millis(250));
        }
        // Return the board to its boot personality as part of this row. This
        // also proves that the WPA-associated epoch is cleanly replaced by
        // unassociated NAN+NOW rather than merely losing the Android AP.
        control_request(
            &mut e6,
            ControlRequest::TransportStart {
                kind: TransportKind::Nan,
                config: dmesh_server::control::TransportConfig {
                    channel: Some(6),
                    now: Some(0),
                    nan_dw_interval: Some(0),
                    ap: Some(1),
                    ..dmesh_server::control::TransportConfig::default()
                },
            },
            0xE6_4150_02,
        );
        let restore_deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let radio = snapshot(&mut e6, RAW_WIFI_METHOD_SNAPSHOT);
            if radio.sta_associated == Some(false) && radio.channel == Some(6) {
                break;
            }
            assert!(
                Instant::now() < restore_deadline,
                "E6 did not return to its unassociated NAN+NOW setup: {}",
                snapshot_summary(&radio)
            );
            thread::sleep(Duration::from_millis(250));
        }
    })();
    let _ = android_json_command(&android, serde_json::json!({
        "id": "android-e6-ap-cleanup",
        "method": "wifi.transport.start",
        "data": {"mode": "nan", "ap": "0"},
    }));
    outcome
}

/// Verify the current Android LocalOnly AP as an ordinary WPA2 STA target.
/// This intentionally excludes P2P and NAN: it answers only whether Recovery
/// can associate with the framework-supplied SSID/passphrase over 2.4 GHz.
///
/// Manual equivalent:
/// ```sh
/// adb -s "$DMESH_E2E_ANDROID" shell content call \
///   --uri content://com.github.costinm.dmesh.lm.shell --method command \
///   --arg '{"id":"pixel7-local-ap","method":"wifi.localap.start"}'
/// # Send the returned ssid/passphrase in a UART transport.start {mode: sta}
/// # record to E6, then wait for `sta_associated=true`.
/// ```
#[test]
#[ignore = "requires flashed e6 and Pixel 7 Android 17; exclusive e6 UART ownership"]
fn pixel7_local_ap_uart_associates_e6() {
    let android = std::env::var("DMESH_E2E_ANDROID")
        .expect("DMESH_E2E_ANDROID must name the Pixel 7 adb serial");
    let start = android_json_command(
        &android,
        serde_json::json!({
            "id": "pixel7-local-ap",
            "method": "wifi.localap.start",
        }),
    );
    assert!(response_state_started(&start), "Pixel 7 LocalOnly AP did not start: {start}");
    let ssid = json_string_field(&start, "ssid")
        .filter(|value| !value.is_empty())
        .expect("Pixel 7 LocalOnly AP omitted SSID");
    let passphrase = json_string_field(&start, "passphrase")
        .filter(|value| !value.is_empty())
        .expect("Pixel 7 LocalOnly AP omitted passphrase");

    let result = (|| {
        let mut e6 = DeviceSession::open(serial_from_env("DMESH_E2E_E6"), None).unwrap();
        control_request(
            &mut e6,
            ControlRequest::TransportStart {
                kind: TransportKind::Sta,
                config: dmesh_server::control::TransportConfig {
                    ssid: Some(ssid.as_bytes()),
                    passphrase: Some(passphrase.as_bytes()),
                    now: Some(0),
                    ap: Some(0),
                    // The Android AP selects its own 2.4-GHz channel. Do not
                    // supply a BSSID or channel until the control result has
                    // a verified operating-frequency field.
                    sta_11b_rates_disabled: Some(false),
                    ..dmesh_server::control::TransportConfig::default()
                },
            },
            0xE6_4C_4F_01,
        );
        let began = Instant::now();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let radio = snapshot(&mut e6, RAW_WIFI_METHOD_SNAPSHOT);
            if radio.sta_associated == Some(true) {
                eprintln!(
                    "Pixel7 LocalOnly AP -> E6 association elapsed_ms={} {}",
                    began.elapsed().as_millis(),
                    snapshot_summary(&radio),
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "E6 did not associate to Pixel 7 LocalOnly AP ssid={ssid}: {}",
                snapshot_summary(&radio)
            );
            thread::sleep(Duration::from_millis(250));
        }
        control_request(
            &mut e6,
            ControlRequest::TransportStart {
                kind: TransportKind::Nan,
                config: dmesh_server::control::TransportConfig {
                    channel: Some(6), now: Some(0), nan_dw_interval: Some(0), ap: Some(0),
                    ..dmesh_server::control::TransportConfig::default()
                },
            },
            0xE6_4C_4F_02,
        );
    })();
    let _ = android_json_command(&android, serde_json::json!({
        "id": "pixel7-local-ap-stop", "method": "wifi.localap.stop",
    }));
    // LocalOnly reservation close is asynchronous and Android does not call
    // the app's onStopped callback for an app-initiated close. The platform
    // adapter waits 10 seconds for wlan2 teardown and retries attachment every
    // five seconds. Require the hardware iface rather than treating the shell
    // command as teardown proof.
    let restore_deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let output = Command::new("adb")
            .args(["-s", &android, "shell", "dumpsys", "wifiaware"])
            .output()
            .expect("Pixel 7 Wi-Fi Aware status");
        let status = String::from_utf8_lossy(&output.stdout);
        if status.contains("mWifiNanIface:") && !status.contains("mWifiNanIface: null") {
            break;
        }
        assert!(
            Instant::now() < restore_deadline,
            "Pixel 7 did not restore NAN after LocalOnly AP: {status}"
        );
        thread::sleep(Duration::from_millis(500));
    }
    result
}

/// Exercise Android's public API-29 P2P Group Owner configuration as a
/// legacy WPA2 AP: the controller knows the selected SSID/passphrase, so no
/// NAN or P2P Service Discovery credential exchange is needed for E7.
///
/// Manual equivalent:
/// ```sh
/// adb -s "$DMESH_E2E_ANDROID_P3A" shell content call \
///   --uri content://com.github.costinm.dmesh.lm.shell --method command \
///   --arg '{"id":"pixel3a-p2p-e7","method":"wifi.transport.start","data":{"mode":"nan","ap":"1"}}'
/// # Send the returned SSID/passphrase as UART transport.start {mode: sta}
/// # to E7 and wait for sta_associated=true; then send mode:nan,ap:0 to both.
/// ```
#[test]
#[ignore = "requires flashed e7 Main and Pixel 3a; exclusive e7 UART ownership"]
fn pixel3a_fixed_p2p_go_uart_associates_e7() {
    let android = std::env::var("DMESH_E2E_ANDROID_P3A")
        .expect("DMESH_E2E_ANDROID_P3A must name the Pixel 3a adb serial");
    let start = android_json_command(
        &android,
        serde_json::json!({
            "id": "pixel3a-p2p-e7",
            "method": "wifi.transport.start",
            "data": {"mode": "nan", "ap": "1"},
        }),
    );
    assert!(response_state_started(&start), "Pixel 3a P2P GO did not start: {start}");
    let ssid = json_string_field(&start, "ssid").expect("Pixel 3a P2P GO omitted SSID");
    let passphrase = json_string_field(&start, "passphrase")
        .expect("Pixel 3a P2P GO omitted passphrase");
    assert_eq!(ssid, "DIRECT-dm-dmesh");
    assert_eq!(passphrase, "untrusted-open-mode");

    let result = (|| {
        let mut e7 = DeviceSession::open(serial_from_env("DMESH_E2E_E7"), None).unwrap();
        control_request(
            &mut e7,
            ControlRequest::TransportStart {
                kind: TransportKind::Sta,
                config: dmesh_server::control::TransportConfig {
                    ssid: Some(ssid.as_bytes()),
                    passphrase: Some(passphrase.as_bytes()),
                    now: Some(0), ap: Some(0), sta_11b_rates_disabled: Some(false),
                    ..dmesh_server::control::TransportConfig::default()
                },
            },
            0xE7_5032_01,
        );
        let began = Instant::now();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let radio = snapshot(&mut e7, RAW_WIFI_METHOD_SNAPSHOT);
            if radio.sta_associated == Some(true) {
                eprintln!(
                    "Pixel3a fixed P2P GO -> E7 association elapsed_ms={} {}",
                    began.elapsed().as_millis(), snapshot_summary(&radio),
                );
                assert_eq!(radio.channel, Some(6));
                break;
            }
            assert!(Instant::now() < deadline,
                "E7 did not associate to Pixel 3a fixed P2P GO: {}", snapshot_summary(&radio));
            thread::sleep(Duration::from_millis(250));
        }
        control_request(
            &mut e7,
            ControlRequest::TransportStart {
                kind: TransportKind::Nan,
                config: dmesh_server::control::TransportConfig {
                    channel: Some(6), now: Some(0), nan_dw_interval: Some(0), ap: Some(0),
                    ..dmesh_server::control::TransportConfig::default()
                },
            },
            0xE7_5032_02,
        );
    })();
    let stop = android_json_command(&android, serde_json::json!({
        "id": "pixel3a-p2p-e7-stop",
        "method": "wifi.transport.start",
        "data": {"mode": "nan", "ap": "0"},
    }));
    assert!(stop.contains("\"state\":\"ap_stopped\""),
        "Pixel 3a P2P GO did not stop: {stop}");
    result
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

/// Opt-in Main sleepy transition probe. It keeps the canary active by default;
/// when enabled, it sends a NAN profile into DW8 sleep and wakes it with an
/// active-Subscribe NAN profile from the Recovery reference. UDP6 status is
/// the authoritative post-wake check; USB/JTAG UART is only best-effort crash
/// and dual-delivery evidence when that optional interface remains available.
#[test]
#[ignore = "set DMESH_E2E_SLEEPY=1; requires e6/e7 and a NAN-capable host"]
fn firmware_e7_sleepy_nan_roundtrip() {
    if std::env::var("DMESH_E2E_SLEEPY").ok().as_deref() != Some("1") {
        eprintln!("firmware-e2e sleepy row skipped; set DMESH_E2E_SLEEPY=1");
        return;
    }
    let mut e7_bootstrap = if std::env::var("DMESH_E2E_SLEEPY_BOOTSTRAP_UART").ok().as_deref()
        == Some("1")
    {
        Some(DeviceSession::open(serial_from_env("DMESH_E2E_E7"), None).unwrap())
    } else {
        None
    };
    let mut e6 = DeviceSession::open(serial_from_env("DMESH_E2E_E6"), None).unwrap();
    e6.set_history_limit(256);
    // Optional local bootstrap only. Once the SUT is active, all sleepy
    // control, wake, and status assertions use remote bearers; UART is never
    // required after the device enters sleepy mode.
    if let Some(e7) = e7_bootstrap.as_mut() {
        e7.set_history_limit(256);
        configure_sta_for_wlan0_with_now(e7, &wlan0_ssid(), true, true, 0xE7_5EE0_00);
        let _ = wait_for_associated_channel_6_with_driver_tx(e7, true);
    }
    // e6 Main is the NAN action sender for the remaining remote flow.
    configure_nan_for_channel(&mut e6, 6, 0xE6_5EE0_01);
    let ssid = wlan0_ssid();
    let (bssid, channel) = wlan0_bssid_channel();
    let active = ControlRequest::TransportStart {
        kind: TransportKind::Sta,
        config: dmesh_server::control::TransportConfig {
            ssid: Some(ssid.as_bytes()),
            bssid: Some(bssid),
            channel: Some(channel),
            nan_dw_interval: Some(0),
            now: Some(0),
            ap: Some(0),
            uart: Some(1),
            sta_11b_rates_disabled: Some(false),
            ..dmesh_server::control::TransportConfig::default()
        },
    };
    let mut active_wire = [0u8; 128];
    let active_used = control::encode_request(active, None, &mut active_wire).unwrap();
    let active_frame = dmesh_rawnan::build_nan_usd_sdf(
        E7_MAC,
        E6_MAC,
        dmesh_rawnan::DMESH_SERVICE_ID,
        7,
        0x11,
        &active_wire[..active_used],
    );
    if e7_bootstrap.is_none() {
        let active_deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < active_deadline {
            send_raw_action(&mut e6, &active_frame, RawWifiInterface::Sta);
            thread::sleep(Duration::from_millis(600));
        }
    }
    // Association is owned asynchronously by the SUT. The UDP6 bootstrap
    // below is the readiness gate; make a few bounded attempts because the
    // raw service may still be replacing its association after NAN control.
    let sleepy = ControlRequest::TransportStart {
        kind: TransportKind::Nan,
        config: dmesh_server::control::TransportConfig {
            channel: Some(6),
            nan_dw_interval: Some(8),
            now: Some(2),
            ap: Some(0),
            uart: Some(0),
            ..dmesh_server::control::TransportConfig::default()
        },
    };
    let mut sleepy_wire = [0u8; 128];
    let sleepy_used = control::encode_request(sleepy, Some(0xE7_5EE0_01), &mut sleepy_wire).unwrap();
    let control_ifindex = interface_index("wlan0");
    let control_peer = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(quic_lite::raw_udp6::link_local_from_mac(E7_MAC)),
        RAW_UDP6_PORT,
        0,
        control_ifindex,
    ));
    let control_bind = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 3338, 0, 0));
    let mut udp_control = Err("UDP6 sleepy control did not start".to_owned());
    for _attempt in 0..3 {
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let mut client = timeout(
                    Duration::from_secs(2),
                    UdpClient::connect(
                        control_bind,
                        control_peer,
                        ConnectionId::new(0xE7_5EE0_01).unwrap(),
                    ),
                )
                .await
                .map_err(|_| "UDP6 control bootstrap timeout".to_owned())?
                .map_err(|error| format!("UDP6 control bootstrap: {error:#}"))?;
                timeout(
                    Duration::from_secs(5),
                    client.request_stream(
                        FIRST_CLIENT_BIDI_STREAM_ID,
                        &sleepy_wire[..sleepy_used],
                        true,
                    ),
                )
                .await
                .map_err(|_| "UDP6 sleepy control timeout".to_owned())?
                .map(|_| ())
                .map_err(|error| format!("UDP6 sleepy control: {error:#}"))
            });
        if result.is_ok() {
            udp_control = result;
            break;
        }
        udp_control = result;
        thread::sleep(Duration::from_millis(250));
    }
    if let Err(error) = udp_control {
        // Keep the remote UDP6 assertion visible, but permit a manually
        // bootstrapped run to continue when the freshly associated raw path
        // has not opened yet.  The later NAN wake still must produce the
        // authoritative remote UDP6 status response.
        if std::env::var("DMESH_E2E_SLEEPY_UART_CONTROL_FALLBACK").ok().as_deref()
            == Some("1")
        {
            let e7 = e7_bootstrap
                .as_mut()
                .expect("UART sleepy-control fallback requires e7 bootstrap");
            control_request(
                e7,
                ControlRequest::TransportStart {
                    kind: TransportKind::Nan,
                    config: dmesh_server::control::TransportConfig {
                        channel: Some(6),
                        nan_dw_interval: Some(8),
                        now: Some(2),
                        ap: Some(0),
                        uart: Some(0),
                        ..dmesh_server::control::TransportConfig::default()
                    },
                },
                0xE7_5EE0_02,
            );
        } else {
            panic!("UDP6 sleepy control was not acknowledged: Err({error:?})");
        }
    }
    let wake = ControlRequest::TransportStart {
        kind: TransportKind::Sta,
        config: dmesh_server::control::TransportConfig {
            ssid: Some(ssid.as_bytes()),
            bssid: Some(bssid),
            channel: Some(channel),
            nan_dw_interval: Some(0),
            now: Some(0),
            ap: Some(0),
            uart: Some(1),
            sta_11b_rates_disabled: Some(false),
            ..dmesh_server::control::TransportConfig::default()
        },
    };
    let mut wire = [0u8; 128];
    let used = control::encode_request(wake, None, &mut wire).unwrap();
    let frame = dmesh_rawnan::build_nan_usd_sdf(
        E7_MAC,
        E6_MAC,
        dmesh_rawnan::DMESH_SERVICE_ID,
        7,
        0x11,
        &wire[..used],
    );
    let broadcast_frame = dmesh_rawnan::build_nan_usd_sdf(
        dmesh_rawnan::NAN_DISCOVERY_MAC,
        E6_MAC,
        dmesh_rawnan::DMESH_SERVICE_ID,
        7,
        0x11,
        &wire[..used],
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        send_raw_action(&mut e6, &frame, RawWifiInterface::Sta);
        send_raw_action(&mut e6, &broadcast_frame, RawWifiInterface::Sta);
        thread::sleep(Duration::from_millis(600));
    }
    drop(e6);
    // The remote UDP6 status query is authoritative; no UART/JTAG probe is
    // required and sleepy USB disappearance is expected.
    let status_ifindex = interface_index("wlan0");
    let status_peer = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(quic_lite::raw_udp6::link_local_from_mac(E7_MAC)),
        RAW_UDP6_PORT,
        0,
        status_ifindex,
    ));
    let status_bind = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 3338, 0, 0));
    // NAN wake is accepted before the STA association and raw UDP6 service
    // are necessarily ready. Keep the control timeout bounded at five
    // seconds, but retry the remote status probe across the asynchronous
    // association window instead of treating the first bootstrap miss as a
    // failed NAN transition.
    let status_deadline = Instant::now() + Duration::from_secs(15);
    let mut status = Err("UDP6 status probe did not start".to_owned());
    while Instant::now() < status_deadline {
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let mut client = timeout(
                    Duration::from_secs(2),
                    UdpClient::connect(
                        status_bind,
                        status_peer,
                        ConnectionId::new(0xE7_5EE0_02).unwrap(),
                    ),
                )
                .await
                .map_err(|_| "UDP6 bootstrap timeout".to_owned())?
                .map_err(|error| format!("UDP6 bootstrap: {error:#}"))?;
                timeout(
                    Duration::from_secs(5),
                    client.request_stream(FIRST_CLIENT_BIDI_STREAM_ID, &[SERVICE_STATUS], true),
                )
                .await
                .map_err(|_| "UDP6 status timeout".to_owned())
            });
        if result.is_ok() {
            status = result;
            break;
        }
        status = result;
        thread::sleep(Duration::from_millis(250));
    }
    assert!(status.is_ok(), "e7 did not become remotely active over UDP6: {status:?}");
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
        // ROC is a receive-only unassociated lab epoch.  Disable the default
        // Main AP first; ESP-IDF rejects ROC leases while AP+STA owns the
        // channel, which would otherwise mask the receiver test itself.
        ap_mode: Some(RawWifiApMode::Disabled),
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
/// firmware. Directed Address-1 is the default for the ESP private callback;
/// broadcast remains an explicit environment override. This is deliberately
/// distinct from the raw-UDP6 performance row.
#[test]
#[ignore = "requires flashed e6 firmware, the supervised wlan0 AP, and exclusive e6 UART ownership"]
fn firmware_host_to_e6_now_iperf() {
    let mut e6 = DeviceSession::open(serial_from_env("DMESH_E2E_E6"), None).unwrap();
    e6.set_history_limit(4_096);
    let ssid = wlan0_ssid();
    let unassociated = std::env::var("DMESH_E2E_UNASSOCIATED_NOW").ok().as_deref() == Some("1");
    let target_mode = if unassociated {
        ProbeMode::NAN_NOW
    } else {
        ProbeMode::STA_NAN_NOW
    };
    let (host_bssid, _) = wlan0_bssid_channel();
    let bytes = e2e_now_bytes();
    let response = host_to_esp_now_probe(
        &mut e6,
        ProbeRequest {
            request_id: if unassociated { 0xE6_6F10 } else { 0xE6_6F00 },
            source: ProbeEndpoint {
                kind: ProbeEndpointKind::Host,
                node: host_bssid,
                mode: ProbeMode::STA_NAN_NOW,
                bssid: Some(host_bssid),
            },
            target: ProbeEndpoint {
                kind: ProbeEndpointKind::Esp,
                node: E6_MAC,
                mode: target_mode,
                bssid: if unassociated { None } else { Some(host_bssid) },
            },
            test_nan: false,
            test_nan_data: false,
            test_now: true,
            test_udp6_association: false,
            test_udp6: false,
            test_scan: false,
            test_soft_ap: false,
            short_bytes: 1,
            long_bytes: u32::try_from(bytes).expect("probe byte count fits u32"),
            measure_mode_switch: true,
        },
        &ssid,
        &e2e_ap_service(),
        &e2e_ap_iface(),
    );
    let after = snapshot(&mut e6, RAW_WIFI_METHOD_SNAPSHOT);
    assert!(response.now.succeeded, "host->e6 NOW probe failed: {response:?}");
    assert_eq!(response.now.bytes, Some(bytes));
    assert!(after.counters.rx_driver_dispatch > 0, "e6 did not dispatch host NOW frames: {after:?}");
    assert!(after.counters.rx_parser_accepted > 0, "e6 did not parse host NOW frames: {after:?}");
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

/// Run the configured pair list. This is the name-independent matrix entry
/// point; legacy device-specific rows remain available for focused bring-up.
#[test]
#[ignore = "requires DMESH_E2E_CONFIG, the configured radio lab, and exclusive UART ownership"]
fn firmware_configured_pairs() {
    let config = load_e2e_config().expect("set DMESH_E2E_CONFIG for the configured matrix");
    let selected = std::env::var("DMESH_E2E_PAIRS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        });
    if let Some(selected) = &selected {
        for name in selected {
            configured_pair(&config, name);
        }
    }
    for pair in &config.pairs {
        if selected
            .as_ref()
            .is_some_and(|names| !names.iter().any(|name| *name == pair.name))
        {
            continue;
        }
        let source = configured_device(&config, &pair.source);
        let target = configured_device(&config, &pair.target);
        if source.kind != "esp" || target.kind != "esp" {
            // Android and host endpoints have their own platform adapters;
            // their configured rows are consumed by those adapters rather
            // than being silently treated as UART ESP sessions here.
            continue;
        }
        let source_path = source
            .serial
            .as_deref()
            .expect("configured ESP source needs serial");
        let target_path = target
            .serial
            .as_deref()
            .expect("configured ESP target needs serial");
        let mut source_session = DeviceSession::open(source_path, None).unwrap();
        let mut target_session = DeviceSession::open(target_path, None).unwrap();
        source_session.set_history_limit(4_096);
        target_session.set_history_limit(4_096);
        let request = ProbeRequest {
            request_id: 0x4d41_0000 + pair.name.len() as u64,
            source: configured_endpoint(source),
            target: configured_endpoint(target),
            test_nan: pair.tests.iter().any(|test| test == "nan"),
            test_nan_data: false,
            test_now: pair.tests.iter().any(|test| test.starts_with("now-")),
            test_udp6_association: pair.tests.iter().any(|test| test == "udp6-association"),
            test_udp6: pair.tests.iter().any(|test| test == "udp6-iperf"),
            test_scan: pair.tests.iter().any(|test| test == "scan"),
            test_soft_ap: false,
            short_bytes: if pair.tests.iter().any(|test| test == "now-short") {
                1
            } else {
                0
            },
            long_bytes: if pair.tests.iter().any(|test| test == "now-iperf") {
                u32::try_from(e2e_now_bytes()).expect("configured probe bytes fit u32")
            } else {
                0
            },
            measure_mode_switch: true,
        };
        let ssid = wlan0_ssid();
        let _ = probe(
            &mut source_session,
            &mut target_session,
            request,
            &ssid,
            request.request_id + 1,
            request.request_id + 2,
        );
        enable_normal_dw(&mut source_session);
        enable_normal_dw(&mut target_session);

        // NOW is a capability intersection: do not manufacture a failure for
        // a pair where either configured endpoint lacks the bearer.
        if source.supports_now && target.supports_now && request.test_now {
            let (target_after, source_after) = complete_action_check(
                &mut source_session,
                &mut target_session,
                configured_mac(target),
                request.request_id + 3,
                &format!("configured pair {} {} -> {} NOW", pair.name, source.name, target.name),
            );
            assert!(target_after.counters.rx_parser_accepted > 0);
            assert!(source_after.counters.raw_client_stream_packets > 0);

            let (source_after, target_after) = complete_action_check(
                &mut target_session,
                &mut source_session,
                configured_mac(source),
                request.request_id + 4,
                &format!("configured pair {} {} -> {} NOW", pair.name, target.name, source.name),
            );
            assert!(source_after.counters.rx_parser_accepted > 0);
            assert!(target_after.counters.raw_client_stream_packets > 0);

            if pair.tests.iter().any(|test| test == "now-iperf") {
                let (_, source_client) = complete_action_iperf(
                    &mut source_session,
                    &mut target_session,
                    configured_mac(target),
                    &format!("configured pair {} {} -> {} NOW bulk", pair.name, source.name, target.name),
                );
                assert_eq!(source_client.raw_service_bytes, Some(E2E_ACTION_IPERF_BYTES as u32));
                let (_, target_client) = complete_action_iperf(
                    &mut target_session,
                    &mut source_session,
                    configured_mac(source),
                    &format!("configured pair {} {} -> {} NOW bulk", pair.name, target.name, source.name),
                );
                assert_eq!(target_client.raw_service_bytes, Some(E2E_ACTION_IPERF_BYTES as u32));
            }
        }
    }
}

/// Discovery-selected two-device prober. `DMESH_E2E_CONFIG` supplies only
/// local adapter details such as optional serial diagnostics; endpoint choice
/// is by advertised NAN identity, never a board nickname. Set both
/// `DMESH_E2E_SOURCE_ID` and `DMESH_E2E_TARGET_ID` when the config has more
/// than two ESP descriptors. With exactly two ESP descriptors, the config is
/// unambiguous and no pair selection variables are needed. The test then
/// proves that both identities are actually present in stable `wlan0`
/// discovery before using either optional serial adapter.
///
/// The initial NAN discovery defaults to five seconds when host wlan0 reports
/// a recent cluster, and can be diagnostically extended with
/// `DMESH_E2E_NAN_WAKE_TIMEOUT_SECS=40`.
#[test]
#[ignore = "requires DMESH_E2E_CONFIG, optional discovery IDs, host wlan0 NAN, and remote UDP6"]
fn firmware_pair_prober() {
    let Some(config) = load_e2e_config() else {
        // `scripts/build.sh firmware-e2e` compiles this ignored hardware
        // target on ordinary developer hosts.  A missing lab descriptor is a
        // skipped live run, not a source failure; an explicitly supplied
        // descriptor still fails strictly if its selection is invalid.
        eprintln!("firmware-e2e skipped: set DMESH_E2E_CONFIG for the pair prober");
        return;
    };
    let source_id = std::env::var("DMESH_E2E_SOURCE_ID").ok();
    let target_id = std::env::var("DMESH_E2E_TARGET_ID").ok();
    let (source, target) = config
        .select_esp_pair(source_id.as_deref(), target_id.as_deref())
        .unwrap_or_else(|error| panic!("pair selection: {error}"));
    let source_name = &source.name;
    let target_name = &target.name;
    assert_eq!(source.kind, "esp", "pair prober currently requires ESP source descriptors");
    assert_eq!(target.kind, "esp", "pair prober currently requires ESP target descriptors");
    let source_nan_mac = configured_nan_mac(source);
    let target_nan_mac = configured_nan_mac(target);
    let sleepy = source.sleepy || target.sleepy;
    let mut outcomes = Vec::new();
    let nan_timeout = nan_wake_timeout_from_host();
    // Activate both endpoints in the common NAN control personality first.
    // The regular wlan0 `wifi.probe.plan` handler selects every subsequent
    // row from live advertised capability after the discovery proof below.
    let source_mode = descriptor_with_probe_mode(
        source,
        ProbeMode {
            transport_kind: 6,
            now: source.now.unwrap_or(if source.supports_now { 0 } else { 2 }),
            nan_dw_interval: 1,
            ndp: false,
            ap: false,
        },
    );
    let target_mode = descriptor_with_probe_mode(
        target,
        ProbeMode {
            transport_kind: 6,
            now: target.now.unwrap_or(if target.supports_now { 0 } else { 2 }),
            nan_dw_interval: 1,
            ndp: false,
            ap: false,
        },
    );
    // Initial control normally uses NAN SDEA, even when the requested final
    // mode is STA. A host that cannot currently observe a NAN cluster records
    // that failed bearer row and then checks the active devices over NOW.
    let nan_ready = match nan_timeout {
        Some(timeout) => match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            host_nan_activate_pair(
                &source_mode,
                &target_mode,
                source_nan_mac,
                target_nan_mac,
                timeout,
            );
            wait_for_stable_control_plane_devices(source, target, timeout);
        })) {
            Ok(()) => {
                outcomes.push(PairProbeOutcome {
                    row: "initial-activation".to_owned(),
                    bearer: "nan-sdea".to_owned(),
                    succeeded: true,
                    required: sleepy,
                    detail: "host cluster and both endpoint announcements observed".to_owned(),
                });
                true
            }
            Err(error) => {
                outcomes.push(PairProbeOutcome {
                    row: "initial-activation".to_owned(),
                    bearer: "nan-sdea".to_owned(),
                    succeeded: false,
                    required: sleepy,
                    detail: panic_detail(error),
                });
                false
            }
        },
        None => {
            outcomes.push(PairProbeOutcome {
                row: "initial-activation".to_owned(),
                bearer: "nan-sdea".to_owned(),
                succeeded: false,
                required: sleepy,
                detail: "wlan0 has no recent NAN cluster".to_owned(),
            });
            false
        }
    };

    if !nan_ready {
        // NOW is the active Main fallback, not an emulated NAN result. Each
        // independent status exchange proves the same registered service
        // handler can be reached even though the host NAN monitor is silent.
        for (index, device) in [source, target].into_iter().enumerate() {
            if !device.supports_now {
                outcomes.push(PairProbeOutcome {
                    row: format!("now-status-{}", device.name),
                    bearer: "now".to_owned(),
                    succeeded: false,
                    required: false,
                    detail: "descriptor does not advertise NOW".to_owned(),
                });
                continue;
            }
            match host_now_status(device, 0x4d50_4e4f_0000 + index as u64) {
                Ok(result) => outcomes.push(PairProbeOutcome {
                    row: format!("now-status-{}", device.name),
                    bearer: "now".to_owned(),
                    succeeded: true,
                    required: true,
                    detail: result.to_string(),
                }),
                Err(error) => outcomes.push(PairProbeOutcome {
                    row: format!("now-status-{}", device.name),
                    bearer: "now".to_owned(),
                    succeeded: false,
                    required: true,
                    detail: error,
                }),
            }
        }
        emit_pair_probe_outcomes(source, target, &outcomes);
        assert!(
            outcomes.iter().all(|outcome| !outcome.required || outcome.succeeded),
            "required pair-probe rows failed; see firmware-e2e pair-probe-report"
        );
        return;
    }

    let requests = if std::env::var_os("DMESH_E2E_PROBE_REQUEST_JSON").is_some() {
        configured_pair_probe_requests(&config, source, target)
    } else {
        match std::panic::catch_unwind(|| stable_control_plane_pair_plan(source, target)) {
            Ok(rows) => rows,
            Err(error) => {
                outcomes.push(PairProbeOutcome {
                    row: "matrix-plan".to_owned(),
                    bearer: "control-plane".to_owned(),
                    succeeded: false,
                    required: false,
                    detail: format!("live handler unavailable; local capability fallback: {}", panic_detail(error)),
                });
                configured_pair_probe_requests(&config, source, target)
            }
        }
    };
    if requests.is_empty() {
        outcomes.push(PairProbeOutcome {
            row: "matrix-plan".to_owned(),
            bearer: "control-plane".to_owned(),
            succeeded: false,
            required: true,
            detail: "pair has no jointly supported probe row".to_owned(),
        });
    }
    for pair_request in requests {
        let request = pair_request.request;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_esp_pair_probe_via_nan(source, target, request)
        }));
        outcomes.push(PairProbeOutcome {
            row: format!("request-{}", request.request_id),
            bearer: if request.test_udp6 { "nan-control+udp6" } else if request.test_now { "nan-control+now" } else { "nan-control" }.to_owned(),
            succeeded: result.is_ok(),
            required: true,
            detail: result.err().map(panic_detail).unwrap_or_else(|| format!(
                "source={source_name} target={target_name} nan={} udp6={} now={}",
                request.test_nan,
                request.test_udp6,
                request.test_now && source.supports_now && target.supports_now,
            )),
        });
    }
    emit_pair_probe_outcomes(source, target, &outcomes);
    assert!(
        outcomes.iter().all(|outcome| !outcome.required || outcome.succeeded),
        "required pair-probe rows failed; see firmware-e2e pair-probe-report"
    );
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
            test_nan_data: false,
            test_now: true,
            test_udp6_association: true,
            test_udp6: true,
            test_scan: true,
            test_soft_ap: false,
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

    // APSTA row: e6 Main enables its volatile, no-lwIP open AP on the
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

/// Focused ROC decision test. e6 runs the newly flashed Main receiver;
/// e7 only supplies the established raw action transmitter, so this can run
/// before another Main image update. Reproduce with the normal ignored-test command
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
