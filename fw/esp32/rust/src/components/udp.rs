//! ESP32 UDP-over-NAN frame construction.
//!
//! The IPv6/UDP envelope is an ESP adapter concern, not part of the shared
//! NAN wire core.  Keep it isolated so `nan.rs` remains responsible for NAN
//! scheduling and action-frame semantics.

use dmesh_rawnan::FRAME_DATA;

pub fn build_nan_udp_frame(
    destination: [u8; 6],
    source: [u8; 6],
    bssid: [u8; 6],
    payload: &[u8],
) -> Vec<u8> {
    let body_len = payload.len().min(1200);
    let mut frame = Vec::with_capacity(FRAME_DATA + 8 + 40 + 8 + body_len);
    frame.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x86, 0xdd]);
    let src_ip = nan_link_local(source);
    let dst_ip = nan_link_local(destination);
    let udp_len = 8 + body_len;
    frame.extend_from_slice(&[0x60, 0, 0, 0]);
    frame.extend_from_slice(&(udp_len as u16).to_be_bytes());
    frame.extend_from_slice(&[0, 17, 1]);
    frame.extend_from_slice(&src_ip);
    frame.extend_from_slice(&dst_ip);
    frame.extend_from_slice(&4242u16.to_be_bytes());
    frame.extend_from_slice(&4243u16.to_be_bytes());
    frame.extend_from_slice(&(udp_len as u16).to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&payload[..body_len]);
    let checksum = ipv6_udp_checksum(&src_ip, &dst_ip, &frame[FRAME_DATA + 8 + 40..]);
    let checksum_offset = FRAME_DATA + 8 + 40 + 6;
    frame[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());
    frame
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

fn ipv6_udp_checksum(src: &[u8; 16], dst: &[u8; 16], udp: &[u8]) -> u16 {
    let mut sum = 0u32;
    for bytes in [src.as_slice(), dst.as_slice()] {
        for pair in bytes.chunks_exact(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
    }
    sum += udp.len() as u32;
    sum += 17;
    for pair in udp.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
