use mesh::tun::{TunDnsHandler, TunUdpHandler, TunUdpPacket};
use mesh_tun::policy::AllowAllPolicy;
use mesh_tun::{MeshTun, MeshTunConfig};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct MockUdpHandler;
#[async_trait::async_trait]
impl TunUdpHandler for MockUdpHandler {
    async fn handle_udp(&self, _packet: TunUdpPacket) {}
}

struct MockDnsHandler;
#[async_trait::async_trait]
impl TunDnsHandler for MockDnsHandler {
    async fn handle_dns(&self, _packet: TunUdpPacket) {}
}

struct RecordingUdpHandler {
    packets: Arc<Mutex<Vec<TunUdpPacket>>>,
}

#[async_trait::async_trait]
impl TunUdpHandler for RecordingUdpHandler {
    async fn handle_udp(&self, packet: TunUdpPacket) {
        self.packets.lock().unwrap().push(packet);
    }
}

fn ipv4_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum += u16::from_be_bytes([byte, 0]) as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn raw_ipv4_udp(
    src: Ipv4Addr,
    src_port: u16,
    dst: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    let checksum = ipv4_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());

    let udp = &mut packet[20..];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[8..].copy_from_slice(payload);
    packet
}

#[tokio::test]
async fn channel_stack_captures_udp_destination_metadata() {
    let config = MeshTunConfig::default();
    let tun = MeshTun::new(config).unwrap();
    let udp_packets = Arc::new(Mutex::new(Vec::new()));
    let udp = Arc::new(RecordingUdpHandler {
        packets: udp_packets.clone(),
    });
    let dns = Arc::new(MockDnsHandler);
    let (_injector, tun_tx, _stack_rx) = tun
        .run_with_channels_and_policy(Arc::new(AllowAllPolicy), udp, dns)
        .await
        .unwrap();

    tun_tx
        .send(raw_ipv4_udp(
            "10.5.0.2".parse().unwrap(),
            49152,
            "198.51.100.7".parse().unwrap(),
            8080,
            b"payload",
        ))
        .await
        .unwrap();

    for _ in 0..50 {
        if !udp_packets.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let packets = udp_packets.lock().unwrap();
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].src_addr, "10.5.0.2".parse::<IpAddr>().unwrap());
    assert_eq!(packets[0].src_port, 49152);
    assert_eq!(
        packets[0].dst_addr,
        "198.51.100.7".parse::<IpAddr>().unwrap()
    );
    assert_eq!(packets[0].dst_port, 8080);
    assert_eq!(packets[0].payload, b"payload");
}

#[tokio::test]
async fn injector_emits_raw_udp_packet() {
    let config = MeshTunConfig::default();
    let tun = MeshTun::new(config).unwrap();
    let udp = Arc::new(MockUdpHandler);
    let dns = Arc::new(MockDnsHandler);
    let (injector, _tun_tx, mut stack_rx) = tun
        .run_with_channels_and_policy(Arc::new(AllowAllPolicy), udp, dns)
        .await
        .unwrap();

    injector
        .inject_udp(
            "198.51.100.7".parse().unwrap(),
            8080,
            "10.5.0.2".parse().unwrap(),
            49152,
            b"reply",
        )
        .await
        .unwrap();

    let packet = tokio::time::timeout(Duration::from_secs(1), stack_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        packet,
        raw_ipv4_udp(
            "198.51.100.7".parse().unwrap(),
            8080,
            "10.5.0.2".parse().unwrap(),
            49152,
            b"reply",
        )
    );
}
