use bytes::Bytes;
use mesh::tun::TunUdpPacket;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub enum TunPacket {
    Udp(TunUdpPacket),
    Tcp(TunTcpPacket),
    Other,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TunTcpPacket {
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub seq: u32,
    pub ack_num: u32,
    pub payload: Bytes,
}

pub fn parse_ip_packet(packet: &[u8]) -> TunPacket {
    if packet.is_empty() {
        return TunPacket::Other;
    }

    match packet[0] >> 4 {
        4 => parse_ipv4_packet(packet),
        6 => parse_ipv6_packet(packet),
        _ => TunPacket::Other,
    }
}

pub fn parse_ip_packet_owned(packet: Vec<u8>) -> TunPacket {
    if packet.is_empty() {
        return TunPacket::Other;
    }

    match packet[0] >> 4 {
        4 => parse_ipv4_packet_owned(packet),
        _ => parse_ip_packet(&packet),
    }
}

pub fn build_ipv4_udp_packet(
    src_addr: Ipv4Addr,
    src_port: u16,
    dst_addr: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, anyhow::Error> {
    let udp_len = 8usize
        .checked_add(payload.len())
        .ok_or_else(|| anyhow::anyhow!("UDP payload too large"))?;
    let total_len = 20usize
        .checked_add(udp_len)
        .ok_or_else(|| anyhow::anyhow!("IPv4 packet too large"))?;
    if total_len > u16::MAX as usize {
        anyhow::bail!("IPv4 packet too large: {total_len}");
    }

    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src_addr.octets());
    packet[16..20].copy_from_slice(&dst_addr.octets());
    let header_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    let udp = &mut packet[20..];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[8..].copy_from_slice(payload);

    Ok(packet)
}

fn parse_ipv4_packet(packet: &[u8]) -> TunPacket {
    if packet.len() < 20 {
        return TunPacket::Other;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 || packet.len() < ihl {
        return TunPacket::Other;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < ihl || packet.len() < total_len {
        return TunPacket::Other;
    }

    let src_addr = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let dst_addr = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    let payload = &packet[ihl..total_len];
    match packet[9] {
        6 => parse_tcp_payload(src_addr, dst_addr, payload),
        17 => parse_udp_payload(src_addr, dst_addr, payload),
        _ => TunPacket::Other,
    }
}

fn parse_ipv4_packet_owned(mut packet: Vec<u8>) -> TunPacket {
    if packet.len() < 20 {
        return TunPacket::Other;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 || packet.len() < ihl {
        return TunPacket::Other;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < ihl || packet.len() < total_len {
        return TunPacket::Other;
    }

    let src_addr = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let dst_addr = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    match packet[9] {
        6 => {
            if total_len < ihl + 20 {
                return TunPacket::Other;
            }
            let tcp = &packet[ihl..total_len];
            let data_offset = usize::from(tcp[12] >> 4) * 4;
            if data_offset < 20 || total_len < ihl + data_offset {
                return TunPacket::Other;
            }
            let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
            let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
            let syn = tcp[13] & 0x02 != 0;
            let ack = tcp[13] & 0x10 != 0;
            let fin = tcp[13] & 0x01 != 0;
            let rst = tcp[13] & 0x04 != 0;
            let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
            let ack_num = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
            packet.truncate(total_len);
            let payload_start = ihl + data_offset;
            let bytes = Bytes::from(packet);
            TunPacket::Tcp(TunTcpPacket {
                src_addr,
                src_port,
                dst_addr,
                dst_port,
                syn,
                ack,
                fin,
                rst,
                seq,
                ack_num,
                payload: bytes.slice(payload_start..total_len),
            })
        }
        _ => parse_ipv4_packet(&packet),
    }
}

pub fn ipv4_header_len(packet: &[u8]) -> Option<usize> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    (ihl >= 20 && packet.len() >= ihl).then_some(ihl)
}

pub fn ipv4_total_len(packet: &[u8]) -> Option<usize> {
    let ihl = ipv4_header_len(packet)?;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    (total_len >= ihl && packet.len() >= total_len).then_some(total_len)
}

pub fn is_ipv4_tcp(packet: &[u8]) -> bool {
    ipv4_header_len(packet).is_some() && packet.get(9) == Some(&6)
}

pub fn ipv4_checksum_valid(packet: &[u8]) -> bool {
    let Some(ihl) = ipv4_header_len(packet) else {
        return false;
    };
    internet_checksum(&packet[..ihl]) == 0
}

pub fn ipv4_tcp_checksum_valid(packet: &[u8]) -> bool {
    if !is_ipv4_tcp(packet) {
        return false;
    }
    let Some(ihl) = ipv4_header_len(packet) else {
        return false;
    };
    let Some(total_len) = ipv4_total_len(packet) else {
        return false;
    };
    if total_len < ihl + 20 {
        return false;
    }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    matches!(ipv4_tcp_checksum(src, dst, &packet[ihl..total_len]), Ok(0))
}

pub fn ip_packet_source(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::new(
                packet[12], packet[13], packet[14], packet[15],
            )))
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&packet[8..24]);
            Some(IpAddr::V6(Ipv6Addr::from(addr)))
        }
        _ => None,
    }
}

pub fn ip_packet_destination(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::new(
                packet[16], packet[17], packet[18], packet[19],
            )))
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&packet[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(addr)))
        }
        _ => None,
    }
}

pub fn ethernet_payload_to_ip(frame: &[u8]) -> Option<(Vec<u8>, [u8; 6])> {
    if frame.len() < 14 {
        return None;
    }
    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&frame[6..12]);
    match u16::from_be_bytes([frame[12], frame[13]]) {
        0x0800 => {
            let payload = &frame[14..];
            let ihl = ipv4_header_len(payload)?;
            let total_len = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
            let packet = if total_len >= ihl && payload.len() >= total_len {
                payload[..total_len].to_vec()
            } else {
                payload.to_vec()
            };
            Some((packet, src_mac))
        }
        0x86dd => {
            let payload = &frame[14..];
            if payload.len() < 40 {
                return None;
            }
            let payload_len = usize::from(u16::from_be_bytes([payload[4], payload[5]]));
            let total_len = 40usize.saturating_add(payload_len);
            let packet = if payload.len() >= total_len {
                payload[..total_len].to_vec()
            } else {
                payload.to_vec()
            };
            Some((packet, src_mac))
        }
        _ => None,
    }
}

pub fn ip_to_ethernet_frame(
    packet: &[u8],
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    min_len: usize,
) -> Result<Vec<u8>, anyhow::Error> {
    let mut frame = Vec::new();
    ip_to_ethernet_frame_into(&mut frame, packet, src_mac, dst_mac, min_len)?;
    Ok(frame)
}

pub fn ip_to_ethernet_frame_into(
    frame: &mut Vec<u8>,
    packet: &[u8],
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    min_len: usize,
) -> Result<(), anyhow::Error> {
    if packet.is_empty() {
        anyhow::bail!("empty IP packet");
    }
    let ethertype = match packet[0] >> 4 {
        4 => 0x0800u16,
        6 => 0x86ddu16,
        version => anyhow::bail!("unsupported IP version in TUN packet: {version}"),
    };

    frame.clear();
    frame.reserve(14 + packet.len());
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(packet);
    if frame.len() < min_len {
        frame.resize(min_len, 0);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn build_ipv4_tcp_packet(
    src_addr: Ipv4Addr,
    src_port: u16,
    dst_addr: Ipv4Addr,
    dst_port: u16,
    flags: u8,
    seq: u32,
    ack: u32,
    payload: &[u8],
) -> Result<Vec<u8>, anyhow::Error> {
    build_ipv4_tcp_packet_with_options(
        src_addr,
        src_port,
        dst_addr,
        dst_port,
        flags,
        seq,
        ack,
        &[],
        payload,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_ipv4_tcp_packet_with_options(
    src_addr: Ipv4Addr,
    src_port: u16,
    dst_addr: Ipv4Addr,
    dst_port: u16,
    flags: u8,
    seq: u32,
    ack: u32,
    options: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, anyhow::Error> {
    if options.len() % 4 != 0 {
        anyhow::bail!("TCP options length must be 32-bit aligned");
    }
    let tcp_header_len = 20usize
        .checked_add(options.len())
        .ok_or_else(|| anyhow::anyhow!("TCP options too large"))?;
    if tcp_header_len > 60 {
        anyhow::bail!("TCP header too large: {tcp_header_len}");
    }
    let tcp_len = tcp_header_len
        .checked_add(payload.len())
        .ok_or_else(|| anyhow::anyhow!("TCP payload too large"))?;
    let total_len = 20usize
        .checked_add(tcp_len)
        .ok_or_else(|| anyhow::anyhow!("IPv4 packet too large"))?;
    if total_len > u16::MAX as usize {
        anyhow::bail!("IPv4 packet too large: {total_len}");
    }

    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&src_addr.octets());
    packet[16..20].copy_from_slice(&dst_addr.octets());
    let ip_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let tcp = &mut packet[20..];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = ((tcp_header_len / 4) as u8) << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&64240u16.to_be_bytes());
    tcp[20..20 + options.len()].copy_from_slice(options);
    tcp[tcp_header_len..].copy_from_slice(payload);
    let tcp_checksum = ipv4_tcp_checksum(src_addr, dst_addr, tcp)?;
    tcp[16..18].copy_from_slice(&tcp_checksum.to_be_bytes());

    Ok(packet)
}

pub fn build_ethernet_ipv4_tcp_frame_with_options(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    min_len: usize,
    src_addr: Ipv4Addr,
    src_port: u16,
    dst_addr: Ipv4Addr,
    dst_port: u16,
    flags: u8,
    seq: u32,
    ack: u32,
    options: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, anyhow::Error> {
    let mut frame = Vec::new();
    build_ethernet_ipv4_tcp_frame_with_options_into(
        &mut frame, src_mac, dst_mac, min_len, src_addr, src_port, dst_addr, dst_port, flags, seq,
        ack, options, payload,
    )?;
    Ok(frame)
}

#[allow(clippy::too_many_arguments)]
pub fn build_ethernet_ipv4_tcp_frame_with_options_into(
    frame: &mut Vec<u8>,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    min_len: usize,
    src_addr: Ipv4Addr,
    src_port: u16,
    dst_addr: Ipv4Addr,
    dst_port: u16,
    flags: u8,
    seq: u32,
    ack: u32,
    options: &[u8],
    payload: &[u8],
) -> Result<(), anyhow::Error> {
    if options.len() % 4 != 0 {
        anyhow::bail!("TCP options length must be 32-bit aligned");
    }
    let tcp_header_len = 20usize
        .checked_add(options.len())
        .ok_or_else(|| anyhow::anyhow!("TCP options too large"))?;
    if tcp_header_len > 60 {
        anyhow::bail!("TCP header too large: {tcp_header_len}");
    }
    let tcp_len = tcp_header_len
        .checked_add(payload.len())
        .ok_or_else(|| anyhow::anyhow!("TCP payload too large"))?;
    let ip_total_len = 20usize
        .checked_add(tcp_len)
        .ok_or_else(|| anyhow::anyhow!("IPv4 packet too large"))?;
    if ip_total_len > u16::MAX as usize {
        anyhow::bail!("IPv4 packet too large: {ip_total_len}");
    }

    // Direct TAP injection already knows the Ethernet destination, so build
    // Ethernet+IP+TCP directly into the caller's scratch buffer. The TAP
    // inject thread reuses this allocation for every packet.
    let frame_len = min_len.max(14 + ip_total_len);
    frame.clear();
    frame.resize(frame_len, 0);
    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    let packet = &mut frame[14..14 + ip_total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&src_addr.octets());
    packet[16..20].copy_from_slice(&dst_addr.octets());
    let ip_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let tcp = &mut packet[20..20 + tcp_len];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = ((tcp_header_len / 4) as u8) << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&64240u16.to_be_bytes());
    tcp[20..20 + options.len()].copy_from_slice(options);
    tcp[tcp_header_len..].copy_from_slice(payload);
    let tcp_checksum = ipv4_tcp_checksum(src_addr, dst_addr, tcp)?;
    tcp[16..18].copy_from_slice(&tcp_checksum.to_be_bytes());

    Ok(())
}

fn parse_ipv6_packet(packet: &[u8]) -> TunPacket {
    if packet.len() < 40 {
        return TunPacket::Other;
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = 40usize.saturating_add(payload_len);
    if packet.len() < total_len {
        return TunPacket::Other;
    }

    let mut src = [0u8; 16];
    src.copy_from_slice(&packet[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&packet[24..40]);
    let src_addr = IpAddr::V6(Ipv6Addr::from(src));
    let dst_addr = IpAddr::V6(Ipv6Addr::from(dst));
    let payload = &packet[40..total_len];
    match packet[6] {
        6 => parse_tcp_payload(src_addr, dst_addr, payload),
        17 => parse_udp_payload(src_addr, dst_addr, payload),
        _ => TunPacket::Other,
    }
}

fn parse_udp_payload(src_addr: IpAddr, dst_addr: IpAddr, payload: &[u8]) -> TunPacket {
    if payload.len() < 8 {
        return TunPacket::Other;
    }
    let udp_len = usize::from(u16::from_be_bytes([payload[4], payload[5]]));
    if udp_len < 8 || payload.len() < udp_len {
        return TunPacket::Other;
    }

    TunPacket::Udp(TunUdpPacket {
        src_addr,
        src_port: u16::from_be_bytes([payload[0], payload[1]]),
        dst_addr,
        dst_port: u16::from_be_bytes([payload[2], payload[3]]),
        payload: payload[8..udp_len].to_vec(),
    })
}

fn parse_tcp_payload(src_addr: IpAddr, dst_addr: IpAddr, payload: &[u8]) -> TunPacket {
    if payload.len() < 20 {
        return TunPacket::Other;
    }
    let data_offset = usize::from(payload[12] >> 4) * 4;
    if payload.len() < data_offset {
        return TunPacket::Other;
    }

    TunPacket::Tcp(TunTcpPacket {
        src_addr,
        src_port: u16::from_be_bytes([payload[0], payload[1]]),
        dst_addr,
        dst_port: u16::from_be_bytes([payload[2], payload[3]]),
        syn: payload[13] & 0x02 != 0,
        ack: payload[13] & 0x10 != 0,
        fin: payload[13] & 0x01 != 0,
        rst: payload[13] & 0x04 != 0,
        seq: u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
        ack_num: u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]),
        payload: Bytes::copy_from_slice(&payload[data_offset..]),
    })
}

fn ipv4_tcp_checksum(
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    tcp_segment: &[u8],
) -> Result<u16, anyhow::Error> {
    if tcp_segment.len() > u16::MAX as usize {
        anyhow::bail!("TCP segment too large: {}", tcp_segment.len());
    }
    // Avoid allocating a pseudo-header buffer on every TCP packet. TCP's
    // checksum is the one's-complement sum of the pseudo-header plus the TCP
    // segment, so we can fold those slices directly in the hot path.
    let mut sum = 0u32;
    add_checksum_bytes(&mut sum, &src_addr.octets());
    add_checksum_bytes(&mut sum, &dst_addr.octets());
    sum += 6;
    sum += tcp_segment.len() as u32;
    add_checksum_bytes(&mut sum, tcp_segment);
    Ok(finish_checksum(sum))
}

pub fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    add_checksum_bytes(&mut sum, bytes);
    finish_checksum(sum)
}

fn add_checksum_bytes(sum: &mut u32, bytes: &[u8]) {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        *sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&byte) = chunks.remainder().first() {
        *sum += u16::from_be_bytes([byte, 0]) as u32;
    }
}

fn finish_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_parse_empty_packet() {
        assert!(matches!(parse_ip_packet(&[]), TunPacket::Other));
    }

    #[test]
    fn test_parse_truncated_ipv4() {
        assert!(matches!(parse_ip_packet(&[0x45; 19]), TunPacket::Other));
    }

    #[test]
    fn test_parse_ipv4_udp_standard() {
        let pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            1234,
            Ipv4Addr::new(10, 0, 0, 2),
            5678,
            b"hello",
        )
        .unwrap();
        match parse_ip_packet(&pkt) {
            TunPacket::Udp(udp) => {
                assert_eq!(udp.src_addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
                assert_eq!(udp.src_port, 1234);
                assert_eq!(udp.dst_addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
                assert_eq!(udp.dst_port, 5678);
                assert_eq!(udp.payload, b"hello");
            }
            _ => panic!("Expected UDP"),
        }
    }

    #[test]
    fn test_parse_ipv4_tcp_syn() {
        let pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            1234,
            Ipv4Addr::new(10, 0, 0, 2),
            5678,
            0x02, // SYN
            100,
            0,
            &[],
        )
        .unwrap();
        match parse_ip_packet(&pkt) {
            TunPacket::Tcp(tcp) => {
                assert_eq!(tcp.src_addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
                assert_eq!(tcp.src_port, 1234);
                assert_eq!(tcp.dst_addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
                assert_eq!(tcp.dst_port, 5678);
                assert!(tcp.syn);
                assert!(!tcp.ack);
                assert!(!tcp.fin);
                assert!(!tcp.rst);
            }
            _ => panic!("Expected TCP"),
        }
    }

    #[test]
    fn test_parse_ipv4_tcp_fin_ack() {
        let pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            1234,
            Ipv4Addr::new(10, 0, 0, 2),
            5678,
            0x11, // FIN | ACK
            100,
            200,
            &[],
        )
        .unwrap();
        match parse_ip_packet(&pkt) {
            TunPacket::Tcp(tcp) => {
                assert!(tcp.fin);
                assert!(tcp.ack);
                assert!(!tcp.syn);
                assert!(!tcp.rst);
            }
            _ => panic!("Expected TCP"),
        }
    }

    #[test]
    fn test_parse_ipv4_with_options() {
        let mut pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            1234,
            Ipv4Addr::new(10, 0, 0, 2),
            5678,
            b"hello",
        )
        .unwrap();
        pkt[0] = 0x46; // IHL = 6
        pkt.insert(20, 0);
        pkt.insert(21, 0);
        pkt.insert(22, 0);
        pkt.insert(23, 0);
        let new_len = (pkt.len() as u16).to_be_bytes();
        pkt[2..4].copy_from_slice(&new_len);
        let new_udp_len = ((pkt.len() - 24) as u16).to_be_bytes();
        pkt[28..30].copy_from_slice(&new_udp_len);
        pkt[10..12].copy_from_slice(&[0, 0]);
        let cs = internet_checksum(&pkt[..24]);
        pkt[10..12].copy_from_slice(&cs.to_be_bytes());

        match parse_ip_packet(&pkt) {
            TunPacket::Udp(udp) => {
                assert_eq!(udp.payload, b"hello");
            }
            _ => panic!("Expected UDP"),
        }
    }

    #[test]
    fn test_parse_ipv6_udp() {
        let mut pkt = vec![0u8; 48];
        pkt[0] = 0x60;
        pkt[6] = 17;
        pkt[4..6].copy_from_slice(&8u16.to_be_bytes());
        pkt[8..24].copy_from_slice(&Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).octets());
        pkt[24..40].copy_from_slice(&Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2).octets());
        pkt[40..42].copy_from_slice(&1234u16.to_be_bytes());
        pkt[42..44].copy_from_slice(&5678u16.to_be_bytes());
        pkt[44..46].copy_from_slice(&8u16.to_be_bytes());
        match parse_ip_packet(&pkt) {
            TunPacket::Udp(udp) => {
                assert_eq!(
                    udp.src_addr,
                    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
                );
                assert_eq!(udp.src_port, 1234);
                assert_eq!(
                    udp.dst_addr,
                    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2))
                );
                assert_eq!(udp.dst_port, 5678);
            }
            _ => panic!("Expected UDP"),
        }
    }

    #[test]
    fn test_parse_ipv6_tcp() {
        let mut pkt = vec![0u8; 60];
        pkt[0] = 0x60;
        pkt[6] = 6;
        pkt[4..6].copy_from_slice(&20u16.to_be_bytes());
        pkt[8..24].copy_from_slice(&Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).octets());
        pkt[24..40].copy_from_slice(&Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2).octets());
        pkt[40..42].copy_from_slice(&1234u16.to_be_bytes());
        pkt[42..44].copy_from_slice(&5678u16.to_be_bytes());
        pkt[53] = 0x12;
        match parse_ip_packet(&pkt) {
            TunPacket::Tcp(tcp) => {
                assert_eq!(
                    tcp.src_addr,
                    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
                );
                assert_eq!(tcp.src_port, 1234);
                assert_eq!(
                    tcp.dst_addr,
                    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2))
                );
                assert_eq!(tcp.dst_port, 5678);
                assert!(tcp.syn);
                assert!(tcp.ack);
            }
            _ => panic!("Expected TCP"),
        }
    }

    #[test]
    fn test_parse_ipv6_truncated() {
        let mut pkt = vec![0u8; 39];
        pkt[0] = 0x60;
        assert!(matches!(parse_ip_packet(&pkt), TunPacket::Other));
    }

    #[test]
    fn test_parse_non_ip_version() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x50;
        assert!(matches!(parse_ip_packet(&pkt), TunPacket::Other));
    }

    #[test]
    fn test_build_ipv4_udp_roundtrip() {
        let pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(192, 168, 1, 1),
            8888,
            Ipv4Addr::new(192, 168, 1, 2),
            9999,
            b"roundtrip",
        )
        .unwrap();
        match parse_ip_packet(&pkt) {
            TunPacket::Udp(udp) => {
                assert_eq!(udp.src_addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
                assert_eq!(udp.src_port, 8888);
                assert_eq!(udp.dst_addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
                assert_eq!(udp.dst_port, 9999);
                assert_eq!(udp.payload, b"roundtrip");
            }
            _ => panic!("Expected UDP"),
        }
    }

    #[test]
    fn test_build_ipv4_udp_max_payload() {
        let max_payload = vec![0u8; 65507];
        let pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(1, 1, 1, 1),
            123,
            Ipv4Addr::new(2, 2, 2, 2),
            456,
            &max_payload,
        );
        assert!(pkt.is_ok());
    }

    #[test]
    fn test_build_ipv4_udp_overflow() {
        let max_payload = vec![0u8; 65508];
        let pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(1, 1, 1, 1),
            123,
            Ipv4Addr::new(2, 2, 2, 2),
            456,
            &max_payload,
        );
        assert!(pkt.is_err());
    }

    #[test]
    fn test_build_ipv4_tcp_with_data() {
        let pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(1, 1, 1, 1),
            123,
            Ipv4Addr::new(2, 2, 2, 2),
            456,
            0x10,
            1,
            2,
            b"tcp data",
        )
        .unwrap();
        assert!(ipv4_checksum_valid(&pkt));
        assert!(ipv4_tcp_checksum_valid(&pkt));
    }

    #[test]
    fn test_build_ethernet_ipv4_tcp_frame_with_data() {
        let frame = build_ethernet_ipv4_tcp_frame_with_options(
            [0x02, 0, 0, 0, 0, 1],
            [0x02, 0, 0, 0, 0, 2],
            60,
            Ipv4Addr::new(1, 1, 1, 1),
            123,
            Ipv4Addr::new(2, 2, 2, 2),
            456,
            0x10,
            1,
            2,
            &[],
            b"tcp data",
        )
        .unwrap();
        assert_eq!(&frame[0..6], &[0x02, 0, 0, 0, 0, 2]);
        assert_eq!(&frame[6..12], &[0x02, 0, 0, 0, 0, 1]);
        assert_eq!(&frame[12..14], &0x0800u16.to_be_bytes());
        let ip = &frame[14..];
        assert!(ipv4_checksum_valid(ip));
        assert!(ipv4_tcp_checksum_valid(ip));
    }

    #[test]
    fn test_ipv4_checksum_valid_known_vector() {
        let header = vec![
            0x45, 0x00, 0x00, 0x28, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x0a, 0x84, 0x0a, 0x00,
            0x00, 0x03, 0x0a, 0x00, 0x00, 0x04,
        ];
        assert!(ipv4_checksum_valid(&header));
    }

    #[test]
    fn test_internet_checksum_odd_length() {
        let data = b"abc";
        let cs = internet_checksum(data);
        assert_ne!(cs, 0);
    }
}
