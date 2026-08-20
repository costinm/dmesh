//! Hardware matrix for the shared raw UDP6/NOW transport.
//!
//! This is intentionally one ignored test: it holds one UART owner for e6
//! and one for e7 for the entire matrix rather than reopening USB serial for
//! each case. Run only on the lab host after both images are flashed:
//!
//! ```sh
//! DMESH_E2E_E6=/dev/serial/by-id/...98:00-if00 \
//! DMESH_E2E_E7=/dev/serial/by-id/...5D:48-if00 \
//! cargo test -p dmesh-cli --test firmware_e2e -- --ignored --nocapture
//! ```

use dmesh_cli::{DeviceSession, DeviceSessionEvent};
use dmesh_server::raw_wifi::{
    RAW_WIFI_METHOD_RESET_COUNTERS, RAW_WIFI_METHOD_SNAPSHOT, RawWifiApMode, RawWifiCheckRequest,
    RawWifiControlRequest, RawWifiDwPolicy, RawWifiInterface, RawWifiIperfRequest, RawWifiStaMode,
    RawWifiStaState, decode_raw_wifi_snapshot, encode_raw_wifi_check_request,
    encode_raw_wifi_control_request, encode_raw_wifi_iperf_request,
    encode_raw_wifi_snapshot_request,
};
use dmesh_server::cbor::Encoder;
use dmesh_server::{
    iperf::{IperfServiceRequest, encode_iperf_service_request},
    udp::{ReceivedStream, UdpClient},
};
use quic_lite::{ConnectionId, FIRST_CLIENT_BIDI_STREAM_ID, SERVICE_ECHO};
use std::{
    collections::BTreeMap,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    thread,
    time::{Duration, Instant},
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
const E2E_UDP6_PACKET_SIZE: u16 = 1_136;
const E2E_UDP6_TRANSFER_DEADLINE: Duration = Duration::from_secs(45);
const E2E_ACTION_IPERF_BYTES: u64 = 64 * 1024;

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
        Err(std::env::VarError::NotPresent) => 1200,
        Err(error) => panic!("read DMESH_E2E_NOW_PACKET_SIZE: {error}"),
    }
}

fn e2e_now_bytes() -> u64 {
    std::env::var("DMESH_E2E_NOW_BYTES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8_192)
        .clamp(256, 1_048_576)
}

fn e2e_now_destination() -> String {
    if matches!(std::env::var("DMESH_E2E_NOW_A1").as_deref(), Ok("peer" | "unicast")) {
        interface_mac("wlan1")
    } else {
        "ff:ff:ff:ff:ff:ff".to_owned()
    }
}

fn e2e_now_tx_variant() -> String {
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

/// Invoke a supervised host service through its existing JSONL Unix socket.
/// This is the same wire surface used by the `mesh` crate/client, but avoids
/// spawning a CLI process for every packet test. Each request owns a short
/// socket connection so concurrent capture/probe rows cannot serialize behind
/// one subscription stream; no AP or service process is created here.
fn mesh_rpc(service: &str, method: &str, args: &[&str]) -> serde_json::Value {
    let mut params = BTreeMap::new();
    for arg in args {
        let (key, value) = arg.split_once('=').unwrap_or((arg, "true"));
        params.insert(key.to_owned(), text_json_value(value));
    }
    let mut request = serde_json::Map::new();
    request.insert("method".to_owned(), serde_json::json!(method));
    for (key, value) in params {
        request.insert(key, value);
    }
    let encoded = serde_json::to_string(&request).expect("encode mesh JSONL request");
    let socket_path = format!("/run/mesh/{service}/mesh.sock");
    let mut last_error = None;
    for _ in 0..6 {
        match UnixStream::connect(&socket_path) {
            Ok(mut stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(20)))
                    .expect("set mesh socket read timeout");
                stream
                    .set_write_timeout(Some(Duration::from_secs(20)))
                    .expect("set mesh socket write timeout");
                if let Err(error) = writeln!(stream, "{encoded}").and_then(|_| stream.flush()) {
                    last_error = Some(format!("write {socket_path}: {error}"));
                    continue;
                }
                let mut line = String::new();
                if let Err(error) = BufReader::new(stream).read_line(&mut line) {
                    last_error = Some(format!("read {socket_path}: {error}"));
                    continue;
                }
                let response: serde_json::Value = serde_json::from_str(line.trim())
                    .unwrap_or_else(|error| panic!("decode mesh {service} {method}: {error}; response={line:?}"));
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
    panic!("mesh {service} {method} failed after retries: {}", last_error.unwrap_or_default());
}

fn text_json_value(value: &str) -> serde_json::Value {
    if value.eq_ignore_ascii_case("true") {
        return serde_json::Value::Bool(true);
    }
    if value.eq_ignore_ascii_case("false") {
        return serde_json::Value::Bool(false);
    }
    if value.eq_ignore_ascii_case("null") || value.eq_ignore_ascii_case("none") {
        return serde_json::Value::Null;
    }
    if let Ok(number) = value.parse::<i64>() {
        return serde_json::json!(number);
    }
    if let Ok(number) = value.parse::<f64>() {
        return serde_json::json!(number);
    }
    serde_json::Value::String(value.to_owned())
}

#[test]
#[ignore = "requires the supervised lmesh/lmesh-wifi host radios"]
fn host_host_nan_sync_and_sd_e2e() {
    // Equivalent commands:
    //   mesh lmesh-wifi wifi.rawnan.status iface=wlan0
    //   mesh lmesh wifi.rawnan.status iface=wlan1
    //   mesh lmesh-wifi wifi.rawnan.ping iface=wlan0 channel=6 \
    //     destination=74:19:f8:17:de:65 bssid=<cluster> payload=ping wait_ms=2000
    // Both host services must observe the same NAN cluster before the SD
    // action is sent; otherwise a successful TX would only prove monitor
    // injection, not host-to-host discovery alignment.
    // Status is passive; explicitly arm both monitor listeners as part of
    // the suite so this row never depends on a previous manual experiment.
    for (service, iface) in [("lmesh-wifi", "wlan0"), ("lmesh", "wlan1")] {
        let listen = mesh_rpc(
            service,
            "wifi.raw.listen",
            &["channel=6", "listen_sec=10", &format!("iface={iface}"), "rx_variant=monitor"],
        );
        assert!(
            listen.get("success").and_then(serde_json::Value::as_bool) == Some(true),
            "{service} NAN listener setup failed: {listen}"
        );
    }
    let deadline = Instant::now() + Duration::from_secs(8);
    let (wlan0, wlan1) = loop {
        let wlan0 = mesh_rpc("lmesh-wifi", "wifi.rawnan.status", &["iface=wlan0"]);
        let wlan1 = mesh_rpc("lmesh", "wifi.rawnan.status", &["iface=wlan1"]);
        let ready = |value: &serde_json::Value| {
            value
                .get("data")
                .and_then(|data| data.get("cluster_bssid"))
                .and_then(serde_json::Value::as_str)
                .is_some_and(|cluster| !cluster.is_empty())
        };
        if ready(&wlan0) && ready(&wlan1) || Instant::now() >= deadline {
            break (wlan0, wlan1);
        }
        thread::sleep(Duration::from_millis(250));
    };
    let first = wlan0
        .get("data")
        .and_then(|value| value.get("cluster_bssid"))
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .expect("wlan0 did not synchronize on a NAN cluster");
    let second = wlan1
        .get("data")
        .and_then(|value| value.get("cluster_bssid"))
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .expect("wlan1 did not synchronize on a NAN cluster");
    assert_eq!(first, second, "host radios selected different NAN clusters");
    for status in [&wlan0, &wlan1] {
        assert!(
            status
                .get("data")
                .and_then(|value| value.get("last_beacon_tsf_us"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
                > 0,
            "NAN beacon timestamp was not observed: {status}"
        );
    }
    let bssid_arg = format!("bssid={first}");
    let sd_args = [
        "iface=wlan0".to_owned(),
        "channel=6".to_owned(),
        "destination=74:19:f8:17:de:65".to_owned(),
        bssid_arg,
        "payload=ping".to_owned(),
        "wait_ms=2000".to_owned(),
    ];
    let sd_refs = sd_args.iter().map(String::as_str).collect::<Vec<_>>();
    let sd = mesh_rpc("lmesh-wifi", "wifi.rawnan.ping", &sd_refs);
    assert!(
        sd.get("data")
            .and_then(|value| value.get("ok"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        "host NAN SD injection failed: {sd}"
    );
    assert_eq!(
        sd.get("data")
            .and_then(|value| value.get("tx"))
            .and_then(|value| value.get("ok"))
            .and_then(serde_json::Value::as_bool),
        Some(true),
        "host NAN SD TX failed: {sd}"
    );
}

#[test]
#[ignore = "requires the supervised lmesh/lmesh-wifi host radios"]
fn host_host_now_check_e2e() {
    // Equivalent command:
    //   mesh lmesh-wifi wifi.raw.check iface=wlan0 channel=6 \
    //     destination=74:19:f8:17:de:65 nonce=... timeout_ms=5000 \
    //     tx_rate_mbps=6 tx_variant=monitor rx_variant=monitor
    // This is the always-on connectionless NOW sanity row.  Keep it separate
    // from IPERF so a throughput regression cannot be hidden by a successful
    // bootstrap/echo exchange.
    // Resolve the peer at test time.  The supervised development service may
    // recreate wlan1 with a different locally-administered MAC; keeping the
    // old lab address here makes the automated check silently transmit to a
    // nonexistent peer.
    let destination = format!("destination={}", e2e_now_destination());
    // The supervised APs are production fixtures. Do not stop them, retune
    // either interface, or rewrite beacon/HT settings in a transport test.
    // The listener handler only adds/reuses a monitor child on the existing
    // channel; AP ownership remains with lmesh/lmesh-wifi.
    // Reset only the monitor child/QUIC action ledger; wifi.raw.stop does not
    // stop or reconfigure the AP parent.
    for (service, iface) in [("lmesh-wifi", "wlan0"), ("lmesh", "wlan1")] {
        let stopped = mesh_rpc(service, "wifi.raw.stop", &[&format!("iface={iface}")]);
        assert!(stopped.get("success").and_then(serde_json::Value::as_bool).unwrap_or(false), "{service} raw listener reset: {stopped}");
    }
    thread::sleep(Duration::from_millis(500));
    let listen = mesh_rpc(
        "lmesh",
        "wifi.raw.listen",
        &["iface=wlan1", "channel=6", "listen_sec=15", "rx_variant=monitor"],
    );
    assert!(listen.get("success").and_then(serde_json::Value::as_bool).unwrap_or(false), "peer monitor setup: {listen}");
    thread::sleep(Duration::from_millis(500));
    let mut last = serde_json::Value::Null;
    for attempt in 0..3 {
        let nonce = format!("nonce={}", 0x4e4f_5700_u64 + attempt);
        let result = mesh_rpc(
            "lmesh-wifi",
            "wifi.raw.check",
            &[
                "iface=wlan0",
                "channel=6",
                &destination,
                &nonce,
                "timeout_ms=5000",
                &format!("tx_rate_mbps={}", e2e_now_rate()),
                "tx_variant=monitor",
                "rx_variant=monitor",
            ],
        );
        let data = result.get("data").unwrap_or(&result);
        if data.get("ok").and_then(serde_json::Value::as_bool) == Some(true)
            && data.get("rx_packets").and_then(serde_json::Value::as_u64).unwrap_or(0) > 0
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
    let destination = format!("destination={}", e2e_now_destination());
    // Capture and probe the already-running APs. No interface up/down,
    // channel retune, or AP start/stop is permitted in this diagnostic.
    for (service, iface) in [("lmesh-wifi", "wlan0"), ("lmesh", "wlan1")] {
        let stopped = mesh_rpc(service, "wifi.raw.stop", &[&format!("iface={iface}")]);
        assert!(stopped.get("success").and_then(serde_json::Value::as_bool).unwrap_or(false), "{service} raw listener reset: {stopped}");
    }
    thread::sleep(Duration::from_millis(500));
    let capture_thread = thread::spawn(move || {
        mesh_rpc(
            "lmesh",
            "wifi.mgmt.capture",
            &["iface=wlan1", "channel=6", "capture_ms=5000", "max_frames=256", "active=false"],
        )
    });
    thread::sleep(Duration::from_millis(500));
    let destination_arg = format!("destination={destination}");
    let probe = mesh_rpc(
        "lmesh-wifi",
        "wifi.raw.check",
        &[
            "iface=wlan0", "channel=6", &destination_arg, "nonce=131074",
            "timeout_ms=3000", &format!("tx_rate_mbps={}", e2e_now_rate()), "tx_variant=monitor", "rx_variant=monitor",
        ],
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
                .filter(|frame| frame.get("frame_subtype").and_then(serde_json::Value::as_u64) == Some(13))
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
                .filter(|frame| frame.get("frame_subtype").and_then(serde_json::Value::as_u64) == Some(13))
                .filter(|frame| frame.get("source").and_then(serde_json::Value::as_str) == Some(sender_mac.as_str()))
                .count() as u64
        })
        .unwrap_or(0);
    let probe_ok = probe
        .get("data")
        .and_then(|v| v.get("ok"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    eprintln!("NOW monitor diagnostic probe_ok={probe_ok} frames={frame_count} actions={action_count} sender_actions={sender_action_count} sender_mac={sender_mac}");
    assert!(frame_count > 0 && sender_action_count > 0, "monitor saw frames={frame_count} actions={action_count} sender_actions={sender_action_count}, but no sender RF action: probe={probe}");
}

#[test]
#[ignore = "requires the supervised lmesh/lmesh-wifi host radios"]
fn host_host_now_raw_frame_injection_e2e() {
    // Captured valid NOW action frame, with source 00:c0:ca:b8:79:cc and
    // receiver wlan1 as Address-1. This bypasses QUIC and the action builder
    // so the row proves only monitor-mode RF injection and capture.
    let frame_hex = "d0000000ffffffffffff00c0cab879ccffffffffffff90aa7f18fe3404024000000f0000140000c00001a01def9db909800400008004000000";
    let tx_variant = std::env::var("DMESH_E2E_RAW_TX_VARIANT").unwrap_or_else(|_| "action".to_owned());
    // Use the existing APs exactly as configured by mesh-init. Raw injection
    // and capture must not alter AP ownership, channel, beacon, or HT mode.
    for (service, iface) in [("lmesh-wifi", "wlan0"), ("lmesh", "wlan1")] {
        let stopped = mesh_rpc(service, "wifi.raw.stop", &[&format!("iface={iface}")]);
        assert!(stopped.get("success").and_then(serde_json::Value::as_bool).unwrap_or(false), "{service} raw listener reset: {stopped}");
    }
    thread::sleep(Duration::from_millis(500));
    let capture_thread = thread::spawn(|| {
        mesh_rpc("lmesh", "wifi.mgmt.capture", &["iface=wlan1", "channel=6", "capture_ms=4000", "max_frames=128", "active=false"])
    });
    thread::sleep(Duration::from_millis(500));
    let tx_variant_arg = format!("tx_variant={tx_variant}");
    let send = mesh_rpc(
        "lmesh-wifi",
        "wifi.raw.send",
        &["iface=wlan0", "channel=6", &tx_variant_arg, &format!("tx_rate_mbps={}", e2e_now_rate()), &format!("frame_hex={frame_hex}")],
    );
    let capture = capture_thread.join().expect("capture thread");
    let sender_frames = capture
        .get("data")
        .and_then(|v| v.get("frames"))
        .and_then(serde_json::Value::as_array)
        .map(|frames| frames.iter().filter(|frame| frame.get("source").and_then(serde_json::Value::as_str) == Some("00:c0:ca:b8:79:cc")).count())
        .unwrap_or(0);
    assert!(send.get("data").and_then(|v| v.get("ok")).and_then(serde_json::Value::as_bool).unwrap_or(false), "raw NOW injection failed: {send}");
    assert!(sender_frames > 0, "raw NOW frame did not reach receiver: send={send}; sender_frames={sender_frames}");
}

#[test]
#[ignore = "requires the supervised lmesh/lmesh-wifi host radios"]
fn host_host_now_iperf_e2e() {
    // Equivalent command:
    //   mesh lmesh-wifi wifi.raw.iperf iface=wlan0 channel=6 \
    //     destination=74:19:f8:17:de:65 bytes=8192 packet_size=1200 \
    //     timeout_ms=10000 tx_rate_mbps=6 tx_variant=monitor rx_variant=monitor
    // Keep this as a real completion assertion: a bootstrap ACK plus one
    // stream packet is not a throughput result.
    // AP/channel state is owned by mesh-init and remains untouched. The row
    // resets only raw monitor children/QUIC ledgers before opening listeners;
    // this avoids stale CIDs without changing the production AP fixture.
    thread::sleep(Duration::from_secs(2));
    // Host monitor delivery is proven with ESP-NOW's broadcast Address-1;
    // keep the peer MAC only in Address-2/QUIC path identity.
    let destination = format!("destination={}", e2e_now_destination());
    // AP/channel state belongs to the supervised services and is deliberately
    // left untouched. The existing APs are expected to already be on channel
    // 6; this row only opens/reuses the monitor listener for observation.
    for (service, iface) in [("lmesh-wifi", "wlan0"), ("lmesh", "wlan1")] {
        let stopped = mesh_rpc(service, "wifi.raw.stop", &[&format!("iface={iface}")]);
        assert!(stopped.get("success").and_then(serde_json::Value::as_bool).unwrap_or(false), "{service} raw listener reset: {stopped}");
    }
    thread::sleep(Duration::from_millis(500));
    let listen = mesh_rpc(
        "lmesh",
        "wifi.raw.listen",
        &[
            "iface=wlan1",
            "channel=6",
            "listen_sec=15",
            &format!("rx_variant={}", e2e_now_rx_variant()),
        ],
    );
    assert!(listen.get("success").and_then(serde_json::Value::as_bool).unwrap_or(false), "wlan1 monitor setup: {listen}");
    thread::sleep(Duration::from_secs(2));
    let tx_variant_arg = format!("tx_variant={}", e2e_now_tx_variant());
    let rx_variant_arg = format!("rx_variant={}", e2e_now_rx_variant());
    let mut sanity = serde_json::Value::Null;
    for attempt in 0..3_u64 {
        sanity = mesh_rpc(
            "lmesh-wifi",
            "wifi.raw.check",
            &[
                "iface=wlan0",
                "channel=6",
            &destination,
                &format!("nonce={}", 131073 + attempt),
                "timeout_ms=5000",
                &format!("tx_rate_mbps={}", e2e_now_rate()),
                &tx_variant_arg,
                &rx_variant_arg,
            ],
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
        "NOW sanity check failed before IPERF: {sanity}; receiver metrics={}; dispatch history={}; listener={listen}",
        mesh_rpc("lmesh", "wifi.raw.metrics", &["iface=wlan1"]),
        mesh_rpc("lmesh", "messages.history", &["keys=wifi.raw.dispatch", "limit=20"]),
    );
    let result = mesh_rpc(
        "lmesh-wifi",
        "wifi.raw.iperf",
        &[
            "iface=wlan0",
            "channel=6",
            &destination,
            &format!("bytes={}", e2e_now_bytes()),
            &format!("packet_size={}", e2e_now_packet_size()),
            &format!("timeout_ms={}", e2e_now_timeout_ms()),
            &format!("tx_rate_mbps={}", e2e_now_rate()),
            &tx_variant_arg,
            &rx_variant_arg,
        ],
    );
    let data = result.get("data").unwrap_or(&result);
    if data.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        let history = mesh_rpc(
            "lmesh",
            "wifi.raw.metrics",
            &["iface=wlan1"],
        );
        let sender_metrics = mesh_rpc("lmesh-wifi", "wifi.raw.metrics", &["iface=wlan0"]);
        let dispatch = mesh_rpc("lmesh", "messages.history", &["keys=wifi.raw.dispatch", "limit=40"]);
        panic!("NOW IPERF did not complete: {result}; sender metrics={sender_metrics}; receiver metrics={history}; dispatch={dispatch}; listen={listen}");
    }
    assert_eq!(data.get("bytes").and_then(serde_json::Value::as_u64), Some(e2e_now_bytes()), "NOW IPERF byte count: {result}");
    let bps = data.get("bps").and_then(serde_json::Value::as_u64).unwrap_or(0);
    eprintln!(
        "host-host NOW IPERF result={result} receiver_metrics={} dispatch_tail={}",
        mesh_rpc("lmesh", "wifi.raw.metrics", &["iface=wlan1"]),
        mesh_rpc("lmesh", "messages.history", &["keys=wifi.raw.dispatch", "limit=8"]),
    );
    assert!(bps > e2e_now_min_bps(), "NOW IPERF throughput is implausibly low: {result}");
}

#[test]
#[ignore = "requires the supervised lmesh/lmesh-wifi host radios"]
fn host_host_now_reverse_iperf_e2e() {
    // Equivalent command:
    //   mesh lmesh wifi.raw.iperf iface=wlan1 channel=6 \
    //     destination=00:c0:ca:b8:79:cc bytes=8192 packet_size=1200 \
    //     timeout_ms=10000 tx_rate_mbps=6 tx_variant=monitor rx_variant=monitor
    let destination = "ff:ff:ff:ff:ff:ff".to_owned();
    // Keep the existing APs and channel untouched. The reverse row exercises
    // only the raw action/QUIC handlers on the already-running radios.
    for (service, iface) in [("lmesh-wifi", "wlan0"), ("lmesh", "wlan1")] {
        let stopped = mesh_rpc(service, "wifi.raw.stop", &[&format!("iface={iface}")]);
        assert!(stopped.get("success").and_then(serde_json::Value::as_bool).unwrap_or(false), "{service} raw listener reset: {stopped}");
    }
    thread::sleep(Duration::from_millis(500));
    let listen = mesh_rpc("lmesh-wifi", "wifi.raw.listen", &["iface=wlan0", "channel=6", "listen_sec=15", "rx_variant=monitor"]);
    assert!(listen.get("success").and_then(serde_json::Value::as_bool).unwrap_or(false), "wlan0 monitor setup: {listen}");
    thread::sleep(Duration::from_secs(1));
    let destination_arg = format!("destination={destination}");
    let result = mesh_rpc(
        "lmesh",
        "wifi.raw.iperf",
        &[
            "iface=wlan1",
            "channel=6",
            &destination_arg,
            "bytes=8192",
            &format!("packet_size={}", e2e_now_packet_size()),
            &format!("timeout_ms={}", e2e_now_timeout_ms()),
            &format!("tx_rate_mbps={}", e2e_now_rate()),
            "tx_variant=monitor",
            "rx_variant=monitor",
        ],
    );
    let data = result.get("data").unwrap_or(&result);
    if data.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        let metrics = mesh_rpc("lmesh-wifi", "wifi.raw.metrics", &["iface=wlan0"]);
        panic!("reverse NOW IPERF did not complete: {result}; receiver metrics={metrics}");
    }
    eprintln!(
        "host-host reverse NOW IPERF result={result} receiver_metrics={}",
        mesh_rpc("lmesh-wifi", "wifi.raw.metrics", &["iface=wlan0"]),
    );
    assert_eq!(data.get("ok").and_then(serde_json::Value::as_bool), Some(true), "reverse NOW IPERF did not complete: {result}");
    assert_eq!(data.get("bytes").and_then(serde_json::Value::as_u64), Some(8192), "reverse NOW IPERF byte count: {result}");
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
        received = received.saturating_add(record_logical_stream_bytes(&mut ranges, &frame));
        finished |= frame.fin;
    }
    let elapsed_us = started_at.elapsed().as_micros().max(1) as u64;
    let bps = received.saturating_mul(8_000_000) / elapsed_us;
    let after_mem_kib = mem_available_kib();
    eprintln!(
        "firmware-e2e row={label} kind=iperf bytes={received} elapsed_us={elapsed_us} first_response_us={first_response_us} bps={bps} packet={E2E_UDP6_PACKET_SIZE} history=512 ack_frequency=default deferred_receive_credit=false host_mem_available_kib={before_mem_kib:?}->{after_mem_kib:?}",
    );
    assert_eq!(received, bytes, "{label} logical byte count");
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
    // This is equivalent to the historic CLI form:
    // dmesh-cli 'udp://[fe80::16c1:9fff:fee5:9800%wlan0]:3339' --iperf-bytes 65536
    // The Rust test uses the same UdpClient/service schema directly, so it
    // does not rely on a retired CLI argument grammar or restart lmesh-wifi.
    let bytes = udp6_transfer_bytes();
    let ifindex = interface_index("wlan0");
    let peer = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(quic_lite::raw_udp6::link_local_from_mac(E6_MAC)),
        RAW_UDP6_PORT,
        0,
        ifindex,
    ));
    let bind = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, ifindex));
    udp_iperf_row(
        "host wlan0->e6 raw-udp6",
        bind,
        peer,
        ConnectionId::new(0xE6_0D_0601).expect("nonzero e2e UDP6 CID"),
        bytes,
    )
    .await;
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
    let bind = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, ifindex));
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
        let history_before = session.recent_events().len();
        let matched = session
            .request_direct_record_until(request, COMMAND_TIMEOUT, |event| matches!(
                event,
                DeviceSessionEvent::DirectRecord(record) if decode_raw_wifi_snapshot(record).is_ok()
            ))
            .unwrap_or_else(|error| panic!("{} radio request: {error}", session.path()));
        if matched {
            // The matching record was just appended. The suite reserves
            // enough bounded host history for the entire matrix, preserving
            // the causal boundary rather than accepting a stale snapshot.
            let response = session
                .recent_events()
                .skip(history_before)
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
        .collect::<Vec<_>>();
    panic!(
        "{} did not return a decodable radio response after retries; direct records={recent:?}",
        session.path()
    )
}

/// Inject one complete raw action through the same direct-CBOR raw-radio
/// handler used by operator tooling. The receiver test intentionally does not
/// await a text acknowledgement: each send is followed by its own snapshot.
fn send_raw_action(session: &mut DeviceSession, frame: &[u8], interface: RawWifiInterface) {
    let mut wire = [0u8; 1600];
    let mut encoder = Encoder::new(&mut wire);
    encoder.map(7).unwrap();
    encoder.uint(0).unwrap(); encoder.uint(1).unwrap();
    encoder.uint(1).unwrap(); encoder.bytes_value(frame).unwrap();
    encoder.uint(2).unwrap(); encoder.uint(6).unwrap();
    encoder.uint(3).unwrap(); encoder.uint(match interface { RawWifiInterface::Ap => 2, _ => 1 }).unwrap();
    encoder.uint(4).unwrap(); encoder.boolean(false).unwrap();
    encoder.uint(5).unwrap(); encoder.uint(0).unwrap();
    encoder.uint(6).unwrap(); encoder.boolean(false).unwrap();
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
fn roc_only_unassociated_action_matrix(e6: &mut DeviceSession, e7: &mut DeviceSession, e6_ap_mac: [u8; 6]) {
    let control = RawWifiControlRequest {
        channel: Some(6), raw_sta_mode: Some(RawWifiStaMode::MainStyle),
        promiscuous: Some(false), dw_policy: Some(RawWifiDwPolicy::Disabled),
        roc_listen_ms: Some(ROC_SUSTAINED_WINDOW_MS), roc_loop: Some(false), action_dispatcher: Some(false),
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
    ).unwrap();
    let nan = dmesh_rawnan::build_nan_publish_sdf(
        dmesh_rawnan::NAN_DISCOVERY_MAC, e6_ap_mac, [0xff; 6], [0; 6], 1, b"roc-nan",
    );
    let started = Instant::now();
    let mut sent_actions = 0u32;
    while started.elapsed() < ROC_SUSTAINED_WINDOW {
        send_raw_action(e7, &now[..now_len], RawWifiInterface::Sta);
        send_raw_action(e7, &nan, RawWifiInterface::Sta);
        sent_actions = sent_actions.saturating_add(2);
        thread::sleep(ROC_SUSTAINED_ACTION_INTERVAL);
    }
    let snapshot_len = encode_raw_wifi_snapshot_request(RAW_WIFI_METHOD_SNAPSHOT, &mut control_wire).unwrap();
    let snapshot = radio_request(e6, &control_wire[..snapshot_len]);
    let delta = snapshot.counters.delta_since(before.counters);
    let observed_actions = delta.roc_espnow_actions.saturating_add(delta.roc_nan_actions);
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
    assert!(delta.roc_action_listen_requests >= 1, "ROC request was not accepted: {delta:?}");
    assert_eq!(delta.roc_action_listen_failures, 0, "ROC request failed: {delta:?}");
    assert!(observed_percent >= ROC_MIN_OBSERVED_PERCENT, "ROC action reception below {ROC_MIN_OBSERVED_PERCENT}%: sent={sent_actions} observed={observed_actions} delta={delta:?}");
    let restore = RawWifiControlRequest { roc_loop: Some(false), action_dispatcher: Some(true), ..RawWifiControlRequest::default() };
    let used = encode_raw_wifi_control_request(restore, &mut control_wire).unwrap();
    let _ = radio_request(e6, &control_wire[..used]);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn snapshot_summary(snapshot: &dmesh_server::raw_wifi::RawWifiSnapshot) -> String {
    let service_bps = raw_service_bps(snapshot);
    format!(
        "ch={:?} sta={:?} prom={:?} ap={:?} active={:?} tx={}/{} rx_dispatch={} parsed={} bootstrap={} stream={} client_errors={} raw_bytes={:?} raw_elapsed_us={:?} raw_bps={service_bps:?} roc={}/{}/{} last_error={:?}",
        snapshot.channel,
        snapshot.sta_associated,
        snapshot.promiscuous,
        snapshot.ap_active,
        snapshot.raw_service_active,
        snapshot.counters.tx_driver_accepted,
        snapshot.counters.tx_attempted,
        snapshot.counters.rx_driver_dispatch,
        snapshot.counters.rx_parser_accepted,
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
    // CLI equivalent: dmesh-cli "$DMESH_E2E_E6" --direct-hex a200184806a300020af40b00
    // {0:72, 6:{0:2, 10:false, 11:0}} means control, promiscuous off,
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
    let used = encode_raw_wifi_control_request(control, &mut request)
        .expect("MAC ACK control request");
    let snapshot = radio_request(session, &request[..used]);
    assert_eq!(snapshot.mac_ack, Some(enabled));
    snapshot
}

fn wait_for_associated_channel_6(
    session: &mut DeviceSession,
) -> dmesh_server::raw_wifi::RawWifiSnapshot {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut observed = snapshot(session, RAW_WIFI_METHOD_SNAPSHOT);
    while !(observed.sta_associated == Some(true) && observed.channel == Some(6))
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(100));
        observed = snapshot(session, RAW_WIFI_METHOD_SNAPSHOT);
    }
    assert_eq!(
        observed.sta_associated,
        Some(true),
        "{} did not reassociate before the action matrix: {observed:?}",
        session.path()
    );
    assert_eq!(
        observed.channel,
        Some(6),
        "{} did not return to lab channel 6 before the action matrix: {observed:?}",
        session.path()
    );
    observed
}

fn start_espnow_check(
    session: &mut DeviceSession,
    peer: [u8; 6],
    nonce: u64,
) -> dmesh_server::raw_wifi::RawWifiSnapshot {
    // Exact direct-PPP request, rendered by the shared encoder rather than a
    // CLI string: `{0:75,6:{0:5,17:h'E6_MAC',18:nonce,19:5000}}`.
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

#[test]
#[ignore = "requires the e6/e7 radio lab and exclusive UART ownership"]
fn firmware_transport_matrix() {
    // CLI equivalent preflight (the suite keeps both ports open instead):
    // dmesh-cli "$DMESH_E2E_E6" --direct-hex a200184906a0
    // dmesh-cli "$DMESH_E2E_E7" --direct-hex a200184906a0
    let mut e6 = DeviceSession::open(serial_from_env("DMESH_E2E_E6"), None).unwrap();
    let mut e7 = DeviceSession::open(serial_from_env("DMESH_E2E_E7"), None).unwrap();
    // A direct radio response is not tagged with a request ID. Keep the
    // entire single-session matrix history so each typed response is selected
    // after its own send boundary, not from an older UART callback.
    e6.set_history_limit(4_096);
    e7.set_history_limit(4_096);

    // Every later matrix row begins with an explicit counter epoch and ends
    // with a snapshot on these same sessions.  The raw host/device check
    // cases are added below as their host-radio and firmware initiators land.
    enable_normal_dw(&mut e6);
    enable_normal_dw(&mut e7);
    wait_for_associated_channel_6(&mut e6);
    wait_for_associated_channel_6(&mut e7);

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
            .block_on(host_to_e6_udp6_echo_checks(action_samples.saturating_mul(2)))
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
        assert!(e7_after.counters.tx_attempted > 0, "e7 did not issue a NOW action");
        assert!(e6_after.counters.rx_driver_dispatch > 0, "e6 did not dispatch a NOW action");
        assert!(e6_after.counters.rx_parser_accepted > 0, "e6 did not accept the raw service packet");
        assert!(e7_after.counters.raw_client_stream_packets > 0, "e7 did not receive the check stream response");
        assert_eq!(e7_after.counters.raw_client_receive_errors, 0, "e7 check client rejected a response");

        // Reverse direction proves Recovery owns the same client state
        // machine, not merely the smaller receiver canary.
        let (e7_reverse, e6_reverse) = complete_action_check(
            &mut e6,
            &mut e7,
            E7_MAC,
            nonce + 1,
            &format!("STA e6->e7 sample={sample} mac_ack={mac_ack}"),
        );
        assert!(e6_reverse.counters.tx_attempted > 0, "e6 did not issue a NOW action");
        assert!(e7_reverse.counters.rx_driver_dispatch > 0, "e7 did not dispatch a NOW action");
        assert!(e7_reverse.counters.rx_parser_accepted > 0, "e7 did not accept the raw service packet");
        assert!(e6_reverse.counters.raw_client_stream_packets > 0, "e6 did not receive the check stream response");
        assert_eq!(e6_reverse.counters.raw_client_receive_errors, 0, "e6 check client rejected a response");
    }
    let udp_echo = udp_echo_worker.join().expect("UDP6 echo worker panicked");
    let udp_echo_failures = udp_echo.iter().filter(|result| result.is_err()).count();
    let mut udp_echo_latencies = udp_echo.iter().filter_map(|result| result.as_ref().ok()).copied().collect::<Vec<_>>();
    udp_echo_latencies.sort_unstable();
    eprintln!(
        "firmware-e2e row=concurrent-udp6-echo samples={} failures={} min_us={:?} median_us={:?} max_us={:?} mac_ack={mac_ack}",
        udp_echo.len(),
        udp_echo_failures,
        udp_echo_latencies.first(),
        udp_echo_latencies.get(udp_echo_latencies.len() / 2),
        udp_echo_latencies.last(),
    );
    assert_eq!(udp_echo_failures, 0, "concurrent UDP6 echo failures: {udp_echo:?}");

    // Bulk counterpart of the liveness check above. Keep it opt-in while the
    // C6 action bootstrap retry path is characterized.
    if action_iperf_enabled() {
        let (_e6_bulk, e7_bulk) =
            complete_action_iperf(&mut e7, &mut e6, E6_MAC, "STA e7->e6 NOW bulk");
        assert_eq!(e7_bulk.raw_service_bytes, Some(E2E_ACTION_IPERF_BYTES as u32));
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
