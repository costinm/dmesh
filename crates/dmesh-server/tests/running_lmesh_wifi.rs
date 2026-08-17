//! Host-side probe for the managed lmesh-wifi UDP object service.
//!
//! Run explicitly with the service already running:
//! `cargo test -p quic-lite --features udp --test running_lmesh_wifi -- --ignored --nocapture`

use dmesh_server::protocol::{RECORD_MANIFEST, encode_get};
use dmesh_server::udp::UdpClient;
use quic_lite::{FIRST_CLIENT_BIDI_STREAM_ID, SERVICE_OBJECT};
use tokio::time::Instant;
use tokio::time::{Duration, timeout};

#[tokio::test]
#[ignore = "requires the managed lmesh-wifi service and its AP"]
async fn running_lmesh_wifi_returns_a_main_manifest() {
    let mut request = [0u8; 64];
    request[0] = SERVICE_OBJECT;
    let used = encode_get(&mut request[1..], None, 13, 6).expect("encode GET") + 1;
    let mut client = UdpClient::connect(
        "0.0.0.0:0".parse().unwrap(),
        "127.0.0.1:3336".parse().unwrap(),
        quic_lite::ConnectionId::new(1).unwrap(),
    )
    .await
    .expect("connect to managed lmesh-wifi UDP service");
    let (_, response, _) = client
        .request_stream(FIRST_CLIENT_BIDI_STREAM_ID, &request[..used], true)
        .await
        .expect("GET response");
    assert_eq!(response.first().copied(), Some(RECORD_MANIFEST));
    assert!(response.len() >= 5, "manifest record header missing");
}

/// Measures the managed server itself on loopback. This intentionally uses
/// the same UDP client/ACK path as Recovery rather than a raw socket sender.
#[tokio::test]
#[ignore = "requires the managed lmesh-wifi service and its AP"]
async fn running_lmesh_wifi_transfers_complete_object_over_loopback() {
    let mut request = [0u8; 64];
    request[0] = SERVICE_OBJECT;
    let used = encode_get(&mut request[1..], None, 13, 6).expect("encode GET") + 1;
    let mut client = UdpClient::connect(
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:3336".parse().unwrap(),
        quic_lite::ConnectionId::new(2).unwrap(),
    )
    .await
    .expect("connect to managed lmesh-wifi UDP service");
    let started = Instant::now();
    let (_, first, mut finished) = client
        .request_stream(FIRST_CLIENT_BIDI_STREAM_ID, &request[..used], true)
        .await
        .expect("GET response");
    let mut bytes = first.len();
    while !finished {
        let (_, data, fin) = client.recv_stream().await.expect("object stream");
        bytes += data.len();
        finished = fin;
    }
    let elapsed = started.elapsed();
    let mib_per_second = bytes as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0);
    eprintln!(
        "managed lmesh-wifi loopback object bytes={bytes} elapsed_ms={} speed_mib_s={mib_per_second:.3}",
        elapsed.as_millis(),
    );
    assert!(bytes > 1024, "object transfer was unexpectedly small");
}

/// Hardware-only Recovery command-mode proof. The stable lmesh-wifi AP keeps
/// port 3336; this test itself owns the diagnostic telemetry port 3338 and
/// exercises the ESP's separate raw command port 3337. Run after flashing a
/// Recovery image with `stg2:boot_target=2`:
/// `DMESH_RECOVERY_IP=10.78.0.200 cargo test -p quic-lite --features udp --test running_lmesh_wifi recovery_udp_boot_beacon -- --ignored --nocapture`
#[tokio::test]
#[ignore = "requires Recovery command mode on the stable lmesh-wifi AP"]
async fn recovery_udp_boot_beacon_reaches_host_test_scaffold() {
    let recovery = std::env::var("DMESH_RECOVERY_IP")
        .expect("set DMESH_RECOVERY_IP to the Recovery STA address");
    let telemetry = tokio::net::UdpSocket::bind("10.78.0.1:3338")
        .await
        .expect("bind host Recovery telemetry port");
    let command = tokio::net::UdpSocket::bind("10.78.0.1:0")
        .await
        .expect("bind host Recovery command socket");
    command
        .send_to(&[1], format!("{recovery}:3337"))
        .await
        .expect("trigger Recovery status log");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut saw_log = false;
    let mut beacon_requested = false;
    loop {
        let mut packet = [0u8; 1400];
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let (used, peer) = timeout(remaining, telemetry.recv_from(&mut packet))
            .await
            .expect("Recovery telemetry timeout")
            .expect("Recovery telemetry receive");
        assert_eq!(peer.ip().to_string(), recovery);
        match &packet[..used] {
            [0x71, ..] => {
                saw_log = true;
                if !beacon_requested {
                    command
                        .send_to(&[4], format!("{recovery}:3337"))
                        .await
                        .expect("trigger Recovery telemetry beacon");
                    beacon_requested = true;
                }
            }
            [0x70, 1] if saw_log => break,
            other => panic!("unexpected Recovery telemetry {other:02x?}"),
        }
    }
    assert!(saw_log, "Recovery did not mirror UART logs to UDP");
}
