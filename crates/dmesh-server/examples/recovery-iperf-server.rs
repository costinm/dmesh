//! Standalone current-build transport listener for host and firmware IPERF.
//! It intentionally does not own or restart either managed Wi-Fi service.

use dmesh_server::udp::{TransportControl, UdpConfig, run};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let bind = args
        .next()
        .unwrap_or_else(|| "127.0.0.1:3337".to_owned())
        .parse()?;
    let pace_us = args
        .next()
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(0);
    let burst_packets = args
        .next()
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(0);
    let burst_delay_us = args
        .next()
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(0);
    // This is a host performance listener, not a device-memory emulator.
    // Use the largest bounded host ledger by default; device comparisons pass
    // their explicit device window as the fifth argument.
    let history_capacity = args
        .next()
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(512);
    if !(1..=512).contains(&history_capacity) {
        anyhow::bail!("history packets must be in 1..={}", 512);
    }
    // Optional bearer-only DSCP/TOS. 0 keeps the normal best-effort class;
    // 0x88 is AF41/video and is useful only for a reversible WMM comparison.
    let ip_tos = args
        .next()
        .map(|value| u8::from_str_radix(value.trim_start_matches("0x"), 16))
        .transpose()?
        .filter(|value| *value != 0);
    let control = Arc::new(TransportControl::default());
    let reporter = control.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            // Do not emit a progress line for each evolving sender snapshot:
            // terminal I/O changes the host benchmark. The transfer's one
            // final `*_udp_send_summary` carries the aggregate stats instead.
            for error in reporter.take_errors() {
                eprintln!("transport_error {error}");
            }
            for event in reporter.take_events() {
                eprintln!("transport_event {event}");
            }
        }
    });
    run(UdpConfig {
        bind,
        artifact_root: PathBuf::from("target/flash"),
        // Keep object records below the one shared QUIC-lite bearer MTU.
        // UdpConfig's default reserves the framing headroom required by all
        // bearers, including UART and extended vendor-action frames.
        iperf_pace: Duration::from_micros(pace_us),
        iperf_burst_packets: burst_packets,
        iperf_burst_delay: Duration::from_micros(burst_delay_us),
        history_capacity,
        ip_tos,
        control: Some(control),
        ..UdpConfig::default()
    })
    .await
}
