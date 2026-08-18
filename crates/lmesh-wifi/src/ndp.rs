//! Privileged, read-only NDP wire diagnostics for an owned AP interface.
//!
//! The production transport never needs a host packet socket. This narrow
//! helper exists to prove raw-bearer Neighbor Advertisements while keeping
//! CAP_NET_RAW use in the process that already owns the AP.

use serde_json::{Value, json};
use std::{
    ffi::CString,
    process::Command,
    time::{Duration, Instant},
};

const ETH_P_ALL: u16 = 0x0003;

pub fn clear_neighbor(iface: &str, address: &str) -> Value {
    let address = match address.parse::<std::net::Ipv6Addr>() {
        Ok(address) if address.is_unicast_link_local() => address,
        _ => return json!({"ok": false, "error": "address must be an IPv6 link-local unicast"}),
    };
    // The service's Nix PATH may contain a limited `ip` implementation.
    // Use the system iproute2 binary that owns the full neighbor subcommand.
    let output = match Command::new("/usr/sbin/ip")
        .args(["-6", "neigh", "delete", &address.to_string(), "dev", iface])
        .output()
    {
        Ok(output) => output,
        Err(command_error) => return error("run ip neighbor delete", command_error),
    };
    // A missing entry is already the desired state; all other command errors
    // remain observable to the caller.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let absent = stderr.contains("No such file or directory");
    json!({
        "ok": output.status.success() || absent,
        "iface": iface,
        "address": address.to_string(),
        "absent": absent,
        "stderr": stderr.trim(),
    })
}

/// Install a temporary static neighbor for a raw-bearer diagnostic.
///
/// This deliberately belongs to the AP-owning service: it is not transport
/// behavior and must not be used as a substitute for proving NDP.  It lets an
/// operator isolate multicast reception from the subsequent unicast UDP6
/// data path.
pub fn set_static_neighbor(iface: &str, address: &str, mac_text: &str) -> Value {
    let address = match address.parse::<std::net::Ipv6Addr>() {
        Ok(address) if address.is_unicast_link_local() => address,
        _ => return json!({"ok": false, "error": "address must be an IPv6 link-local unicast"}),
    };
    let mac_bytes = match parse_mac(mac_text) {
        Some(mac) => mac,
        None => return json!({"ok": false, "error": "mac must be six hexadecimal octets"}),
    };
    let mac = mac(mac_bytes);
    let output = match Command::new("/usr/sbin/ip")
        .args([
            "-6",
            "neigh",
            "replace",
            &address.to_string(),
            "lladdr",
            &mac,
            "nud",
            "permanent",
            "dev",
            iface,
        ])
        .output()
    {
        Ok(output) => output,
        Err(command_error) => return error("run ip neighbor replace", command_error),
    };
    json!({
        "ok": output.status.success(),
        "iface": iface,
        "address": address.to_string(),
        "mac": mac,
        "stderr": String::from_utf8_lossy(&output.stderr).trim(),
    })
}

pub fn capture_neighbor_advertisements(iface: &str, wait_ms: u64) -> Value {
    let index = match CString::new(iface)
        .ok()
        .map(|name| unsafe { libc::if_nametoindex(name.as_ptr()) })
    {
        Some(index) if index != 0 => index,
        _ => return json!({"ok": false, "error": format!("unknown interface {iface:?}")}),
    };
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            u16::to_be(ETH_P_ALL) as i32,
        )
    };
    if fd < 0 {
        return error("open AF_PACKET", std::io::Error::last_os_error());
    }
    let mut address: libc::sockaddr_ll = unsafe { core::mem::zeroed() };
    address.sll_family = libc::AF_PACKET as u16;
    address.sll_protocol = u16::to_be(ETH_P_ALL);
    address.sll_ifindex = index as i32;
    let bound = unsafe {
        libc::bind(
            fd,
            (&address as *const libc::sockaddr_ll).cast(),
            core::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if bound != 0 {
        let result = error("bind AF_PACKET", std::io::Error::last_os_error());
        unsafe { libc::close(fd) };
        return result;
    }
    let deadline = Instant::now() + Duration::from_millis(wait_ms.clamp(1, 5_000));
    let mut frames = Vec::new();
    let mut buffer = [0u8; 1600];
    while Instant::now() < deadline {
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(i32::MAX as u128) as i32;
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pollfd, 1, remaining) } <= 0 {
            continue;
        }
        let received = unsafe { libc::recv(fd, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
        if received > 0 {
            if let Some(report) = neighbor_discovery_report(&buffer[..received as usize]) {
                frames.push(report);
            }
        }
    }
    unsafe { libc::close(fd) };
    json!({"ok": true, "iface": iface, "frames": frames})
}

/// Capture NDP advertisements at 802.11 monitor level for an AP-owned
/// interface. This distinguishes a station radio TX problem from host-netdev
/// delivery; it never alters AP or neighbor state.
pub fn capture_monitor_neighbor_advertisements(iface: &str, wait_ms: u64) -> Value {
    let monitor = format!("{iface}mon");
    let index = match CString::new(monitor.as_str())
        .ok()
        .map(|name| unsafe { libc::if_nametoindex(name.as_ptr()) })
    {
        Some(index) if index != 0 => index,
        _ => {
            return json!({"ok": false, "error": format!("monitor interface {monitor:?} is unavailable")});
        }
    };
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            u16::to_be(ETH_P_ALL) as i32,
        )
    };
    if fd < 0 {
        return error("open monitor AF_PACKET", std::io::Error::last_os_error());
    }
    let mut address: libc::sockaddr_ll = unsafe { core::mem::zeroed() };
    address.sll_family = libc::AF_PACKET as u16;
    address.sll_protocol = u16::to_be(ETH_P_ALL);
    address.sll_ifindex = index as i32;
    if unsafe {
        libc::bind(
            fd,
            (&address as *const libc::sockaddr_ll).cast(),
            core::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    } != 0
    {
        let result = error("bind monitor AF_PACKET", std::io::Error::last_os_error());
        unsafe { libc::close(fd) };
        return result;
    }
    let deadline = Instant::now() + Duration::from_millis(wait_ms.clamp(1, 5_000));
    let mut frames = Vec::new();
    let mut observed = 0u64;
    let mut data_frames = 0u64;
    let mut ipv6_llc_frames = 0u64;
    let mut first_data: Option<String> = None;
    let mut first_ipv6_llc: Option<String> = None;
    let mut buffer = [0u8; 2048];
    while Instant::now() < deadline {
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(i32::MAX as u128) as i32;
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pollfd, 1, remaining) } <= 0 {
            continue;
        }
        let received = unsafe { libc::recv(fd, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
        if received > 0 {
            let frame = &buffer[..received as usize];
            observed += 1;
            match monitor_frame_kind(frame) {
                Some((true, ipv6_llc)) => {
                    data_frames += 1;
                    if ipv6_llc {
                        ipv6_llc_frames += 1;
                        if first_ipv6_llc.is_none() {
                            first_ipv6_llc = Some(hex(&frame[..frame.len().min(160)]));
                        }
                    }
                    if first_data.is_none() {
                        first_data = Some(hex(&frame[..frame.len().min(64)]));
                    }
                }
                _ => {}
            }
            if let Some(report) = monitor_neighbor_advertisement_report(frame) {
                frames.push(report);
            }
        }
    }
    unsafe { libc::close(fd) };
    json!({
        "ok": true, "iface": iface, "monitor": monitor, "frames": frames,
        "observed": observed, "data_frames": data_frames,
        "ipv6_llc_frames": ipv6_llc_frames, "first_data_hex": first_data,
        "first_ipv6_llc_hex": first_ipv6_llc,
    })
}

fn error(context: &str, error: std::io::Error) -> Value {
    json!({"ok": false, "error": format!("{context}: {error}")})
}

fn neighbor_discovery_report(frame: &[u8]) -> Option<Value> {
    if let Ok(advertisement) = quic_lite::raw_udp6::parse_neighbor_advertisement(frame) {
        return Some(json!({
            "kind": "advertisement",
            "source_mac": mac(advertisement.source_mac),
            "source_ip": ipv6(advertisement.source_ip),
            "destination_ip": ipv6(advertisement.destination_ip),
            "target_ip": ipv6(advertisement.target_ip),
            "target_mac": mac(advertisement.target_mac),
            "flags": advertisement.flags,
        }));
    }
    let ip = frame.get(14..)?;
    if frame.get(12..14) != Some(&[0x86, 0xdd]) || ip.len() < 48 || ip[0] >> 4 != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([ip[4], ip[5]]) as usize;
    if ip[6] == 17 {
        let source_ip: [u8; 16] = ip.get(8..24)?.try_into().ok()?;
        let destination_ip: [u8; 16] = ip.get(24..40)?.try_into().ok()?;
        let udp = ip.get(40..40 + payload_len)?;
        if udp.len() < 8 || usize::from(u16::from_be_bytes([udp[4], udp[5]])) != udp.len() {
            return None;
        }
        let ether_source: [u8; 6] = frame.get(6..12)?.try_into().ok()?;
        let ether_destination: [u8; 6] = frame.get(0..6)?.try_into().ok()?;
        return Some(json!({
            "kind": "udp6",
            "ether_source": mac(ether_source),
            "ether_destination": mac(ether_destination),
            "source_ip": ipv6(source_ip),
            "destination_ip": ipv6(destination_ip),
            "source_port": u16::from_be_bytes([udp[0], udp[1]]),
            "destination_port": u16::from_be_bytes([udp[2], udp[3]]),
            "payload_len": udp.len() - 8,
            "checksum_valid": quic_lite::raw_udp6::udp_checksum(source_ip, destination_ip, udp) == 0,
        }));
    }
    if ip[6] != 58 {
        return None;
    }
    let icmp = ip.get(40..40 + payload_len)?;
    if icmp.first() != Some(&135) {
        return None;
    }
    let ether_source: [u8; 6] = frame.get(6..12)?.try_into().ok()?;
    let source_ip: [u8; 16] = ip.get(8..24)?.try_into().ok()?;
    let destination_ip: [u8; 16] = ip.get(24..40)?.try_into().ok()?;
    let target_ip: [u8; 16] = icmp.get(8..24)?.try_into().ok()?;
    Some(json!({
        "kind": "solicitation",
        "ether_source": mac(ether_source),
        "source_ip": ipv6(source_ip),
        "destination_ip": ipv6(destination_ip),
        "hop_limit": ip[7],
        "payload_len": payload_len,
        "target_ip": ipv6(target_ip),
        "options_hex": icmp.get(24..).map(hex),
    }))
}

fn monitor_neighbor_advertisement_report(frame: &[u8]) -> Option<Value> {
    let radiotap_len = usize::from(u16::from_le_bytes(frame.get(2..4)?.try_into().ok()?));
    let header = frame.get(radiotap_len..)?;
    let fc = u16::from_le_bytes(header.get(0..2)?.try_into().ok()?);
    if ((fc >> 2) & 0x3) != 2 || (fc & 0x0100) == 0 {
        return None;
    }
    let subtype = (fc >> 4) & 0x0f;
    let mut header_len = 24;
    if subtype & 0x08 != 0 {
        header_len += 2;
    }
    if (fc & 0x8000) != 0 {
        header_len += 4;
    }
    let source_mac: [u8; 6] = header.get(10..16)?.try_into().ok()?;
    let destination_mac: [u8; 6] = header.get(16..22)?.try_into().ok()?;
    let llc = header.get(header_len..header_len + 8)?;
    if llc != [0xaa, 0xaa, 0x03, 0, 0, 0, 0x86, 0xdd] {
        return None;
    }
    let ip = header.get(header_len + 8..)?;
    let mut ethernet = [0u8; 1600];
    let total = 14usize.checked_add(ip.len())?;
    if total > ethernet.len() {
        return None;
    }
    ethernet[..6].copy_from_slice(&destination_mac);
    ethernet[6..12].copy_from_slice(&source_mac);
    ethernet[12..14].copy_from_slice(&[0x86, 0xdd]);
    ethernet[14..total].copy_from_slice(ip);
    let advertisement =
        quic_lite::raw_udp6::parse_neighbor_advertisement(&ethernet[..total]).ok()?;
    Some(json!({
        "kind": "monitor_advertisement",
        "source_mac": mac(advertisement.source_mac),
        "destination_ip": ipv6(advertisement.destination_ip),
        "target_ip": ipv6(advertisement.target_ip),
        "target_mac": mac(advertisement.target_mac),
        "flags": advertisement.flags,
    }))
}

/// Return `(is_80211_data, has_ipv6_llc)` for monitor-capture diagnostics.
fn monitor_frame_kind(frame: &[u8]) -> Option<(bool, bool)> {
    let radiotap_len = usize::from(u16::from_le_bytes(frame.get(2..4)?.try_into().ok()?));
    let header = frame.get(radiotap_len..)?;
    let fc = u16::from_le_bytes(header.get(0..2)?.try_into().ok()?);
    if ((fc >> 2) & 0x3) != 2 {
        return Some((false, false));
    }
    let subtype = (fc >> 4) & 0x0f;
    let mut header_len = 24;
    if subtype & 0x08 != 0 {
        header_len += 2;
    }
    if (fc & 0x8000) != 0 {
        header_len += 4;
    }
    Some((
        true,
        header.get(header_len..header_len + 8) == Some(&[0xaa, 0xaa, 0x03, 0, 0, 0, 0x86, 0xdd]),
    ))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

fn mac(bytes: [u8; 6]) -> String {
    bytes
        .iter()
        .map(|value| format!("{value:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn parse_mac(value: &str) -> Option<[u8; 6]> {
    let octets: Vec<_> = value.split(':').collect();
    if octets.len() != 6 || octets.iter().any(|octet| octet.len() != 2) {
        return None;
    }
    let mut output = [0; 6];
    for (index, octet) in octets.into_iter().enumerate() {
        output[index] = u8::from_str_radix(octet, 16).ok()?;
    }
    Some(output)
}

fn ipv6(bytes: [u8; 16]) -> String {
    std::net::Ipv6Addr::from(bytes).to_string()
}

#[cfg(test)]
mod tests {
    use super::neighbor_discovery_report;
    use quic_lite::raw_udp6::{encode_neighbor_advertisement, encode_udp6, link_local_from_mac};

    #[test]
    fn report_only_accepts_a_valid_neighbor_advertisement() {
        let local_mac = [0x14, 0xc1, 0x9f, 0xe5, 0x98, 0];
        let peer_mac = [0, 0xc0, 0xca, 0xb8, 0x79, 0xcc];
        let mut frame = [0u8; 128];
        let used = encode_neighbor_advertisement(
            &mut frame,
            peer_mac,
            local_mac,
            link_local_from_mac(peer_mac),
            link_local_from_mac(local_mac),
        )
        .unwrap();
        let report = neighbor_discovery_report(&frame[..used]).unwrap();
        assert_eq!(report["target_mac"], "14:c1:9f:e5:98:00");
        frame[60] ^= 1;
        assert!(neighbor_discovery_report(&frame[..used]).is_none());
    }

    #[test]
    fn neighbor_reset_rejects_non_link_local_addresses() {
        let value = super::clear_neighbor("wlan0", "2001:db8::1");
        assert_eq!(value["ok"], false);
    }

    #[test]
    fn static_neighbor_requires_a_six_octet_mac() {
        assert_eq!(
            super::parse_mac("14:c1:9f:e5:98:00"),
            Some([0x14, 0xc1, 0x9f, 0xe5, 0x98, 0])
        );
        assert_eq!(super::parse_mac("14:c1:9f:e5:98"), None);
        assert_eq!(super::parse_mac("14:c1:9f:e5:98:gg"), None);
    }

    #[test]
    fn report_decodes_valid_udp6_return_traffic() {
        let local_mac = [0, 0xc0, 0xca, 0xb8, 0x79, 0xcc];
        let peer_mac = [0x14, 0xc1, 0x9f, 0xe5, 0x98, 0];
        let mut frame = [0u8; 128];
        let used = encode_udp6(
            &mut frame,
            local_mac,
            peer_mac,
            link_local_from_mac(local_mac),
            link_local_from_mac(peer_mac),
            41000,
            3339,
            b"reply",
        )
        .unwrap();
        let report = neighbor_discovery_report(&frame[..used]).unwrap();
        assert_eq!(report["kind"], "udp6");
        assert_eq!(report["checksum_valid"], true);
        assert_eq!(report["destination_port"], 41000);
    }

    #[test]
    fn monitor_report_decodes_station_neighbor_advertisement() {
        let local_mac = [0, 0xc0, 0xca, 0xb8, 0x79, 0xcc];
        let peer_mac = [0x14, 0xc1, 0x9f, 0xe5, 0x98, 0];
        let mut ethernet = [0u8; 128];
        let used = encode_neighbor_advertisement(
            &mut ethernet,
            local_mac,
            peer_mac,
            link_local_from_mac(local_mac),
            link_local_from_mac(peer_mac),
        )
        .unwrap();
        let mut monitor = vec![0u8; 8 + 24 + 8 + used - 14];
        monitor[2..4].copy_from_slice(&8u16.to_le_bytes());
        monitor[8..10].copy_from_slice(&0x0108u16.to_le_bytes());
        monitor[18..24].copy_from_slice(&peer_mac);
        monitor[24..30].copy_from_slice(&local_mac);
        monitor[32..40].copy_from_slice(&[0xaa, 0xaa, 0x03, 0, 0, 0, 0x86, 0xdd]);
        monitor[40..].copy_from_slice(&ethernet[14..used]);
        let report = super::monitor_neighbor_advertisement_report(&monitor).unwrap();
        assert_eq!(report["kind"], "monitor_advertisement");
        assert_eq!(report["target_mac"], "14:c1:9f:e5:98:00");
        assert_eq!(super::monitor_frame_kind(&monitor), Some((true, true)));
    }
}
