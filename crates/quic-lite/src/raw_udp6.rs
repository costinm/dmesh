//! Minimal Ethernet / IPv6 / UDP framing for raw Wi-Fi bearers.
//!
//! This is deliberately a host-tested, `no_std` codec.  It does not know
//! about ESP-IDF callbacks, sockets, neighbor discovery, or QUIC-lite packet
//! contents.  A bearer supplies the local MAC/address and owns peer caching.

pub const ETHERNET_HEADER_LEN: usize = 14;
pub const IPV6_HEADER_LEN: usize = 40;
pub const UDP_HEADER_LEN: usize = 8;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;
pub const ICMPV6_NEIGHBOR_SOLICITATION: u8 = 135;
pub const ICMPV6_NEIGHBOR_ADVERTISEMENT: u8 = 136;
pub const IEEE80211_DATA_TO_DS_HEADER_LEN: usize = 24;
pub const IEEE80211_LLC_SNAP_LEN: usize = 8;
/// Bytes reserved before a raw UDP6 payload on the station data path.
/// A shared packet writer places a QUIC-lite datagram after this prefix and
/// [`encode_station_udp6_prefix`] fills it without moving the payload.
pub const STATION_UDP6_HEADROOM: usize =
    IEEE80211_DATA_TO_DS_HEADER_LEN + IEEE80211_LLC_SNAP_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN;
const ICMPV6_NEIGHBOR_LEN: usize = 24;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    EtherType,
    Version,
    ExtensionHeader,
    Fragment,
    NextHeader,
    Length,
    Destination,
    Port,
    Checksum,
    OutputTooSmall,
}

/// Stable compact diagnostic code for raw IPv6 framing errors.  ESP adapters
/// have only a small direct-record channel, while host tests can assert the
/// exact same parser classification.
pub const fn error_code(error: Error) -> u8 {
    match error {
        Error::Truncated => 1,
        Error::EtherType => 2,
        Error::Version => 3,
        Error::ExtensionHeader => 4,
        Error::Fragment => 5,
        Error::NextHeader => 6,
        Error::Length => 7,
        Error::Destination => 8,
        Error::Port => 9,
        Error::Checksum => 10,
        Error::OutputTooSmall => 11,
    }
}

/// Stable diagnostic label for a rejected wire packet. ESP adapters may render
/// this label, but classification remains host-testable transport logic.
pub const fn error_label(error: Error) -> &'static str {
    match error {
        Error::Truncated => "truncated",
        Error::EtherType => "ethertype",
        Error::Version => "IPv6 version",
        Error::ExtensionHeader => "extension",
        Error::Fragment => "fragment",
        Error::NextHeader => "next header/type",
        Error::Length => "length/option",
        Error::Destination => "destination",
        Error::Port => "port",
        Error::Checksum => "checksum",
        Error::OutputTooSmall => "output",
    }
}

/// Compact direct-record text for an NDP parser rejection.
pub const fn ndp_error_text(error: Error) -> &'static [u8] {
    match error {
        Error::Length => b"ndp rejected length/option",
        Error::Checksum => b"ndp rejected checksum",
        Error::Destination => b"ndp rejected destination",
        _ => b"ndp rejected packet",
    }
}

/// Compact direct-record text for a UDP6 parser rejection.
pub const fn udp6_error_text(error: Error) -> &'static [u8] {
    match error {
        Error::Length => b"udp6 rejected length",
        Error::Checksum => b"udp6 rejected checksum",
        Error::Destination => b"udp6 rejected destination",
        Error::Port => b"udp6 rejected port",
        _ => b"udp6 rejected packet",
    }
}

/// Identify an Ethernet-II IPv6 ICMPv6 frame without accepting it as a valid
/// control message. Used to route it to the bounded NDP parser.
pub fn is_icmpv6_frame(frame: &[u8]) -> bool {
    frame.len() >= ETHERNET_HEADER_LEN + IPV6_HEADER_LEN
        && read_u16(&frame[12..14]) == ETHERTYPE_IPV6
        && frame[ETHERNET_HEADER_LEN] >> 4 == 6
        && frame[ETHERNET_HEADER_LEN + 6] == IPPROTO_ICMPV6
}

/// Wire metadata for an Ethernet-II IPv6 ICMPv6 frame.
///
/// This deliberately performs no NDP validation: callers use it to explain
/// why a frame was rejected by the stricter Neighbor Solicitation parser.
/// Keeping it in the portable framing crate makes the same diagnostics
/// available to host captures and ESP direct-record counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Icmpv6FrameInfo {
    pub hop_limit: u8,
    pub payload_length: u16,
    pub icmp_type: u8,
    pub code: u8,
}

pub fn icmpv6_frame_info(frame: &[u8]) -> Option<Icmpv6FrameInfo> {
    if !is_icmpv6_frame(frame) || frame.len() < ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + 2 {
        return None;
    }
    let ip = &frame[ETHERNET_HEADER_LEN..];
    Some(Icmpv6FrameInfo {
        hop_limit: ip[7],
        payload_length: read_u16(&ip[4..6]),
        icmp_type: ip[IPV6_HEADER_LEN],
        code: ip[IPV6_HEADER_LEN + 1],
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Udp6Packet<'a> {
    pub source_mac: [u8; 6],
    pub destination_mac: [u8; 6],
    pub source_ip: [u8; 16],
    pub destination_ip: [u8; 16],
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: &'a [u8],
}

/// A validated Neighbor Solicitation for `target_ip`.
///
/// This intentionally covers only the link-local unicast discovery exchange
/// needed by the raw bearer. Router discovery, SLAAC, and DAD remain outside
/// this small transport codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NeighborSolicitation {
    pub source_mac: [u8; 6],
    pub source_ip: [u8; 16],
}

/// A validated Neighbor Advertisement, including the target's Ethernet MAC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NeighborAdvertisement {
    pub source_mac: [u8; 6],
    pub source_ip: [u8; 16],
    pub destination_ip: [u8; 16],
    pub target_ip: [u8; 16],
    pub target_mac: [u8; 6],
    pub flags: u32,
}

/// Convert a Wi-Fi MAC into its RFC 4291 modified-EUI-64 link-local address.
pub const fn link_local_from_mac(mac: [u8; 6]) -> [u8; 16] {
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

/// Parse one complete Ethernet-encapsulated, unfragmented UDP6 datagram.
///
/// Only a direct UDP next header is accepted. Extension and fragment headers
/// are intentionally excluded from the first raw Wi-Fi bearer profile.
pub fn parse_udp6<'a>(
    frame: &'a [u8],
    local_ip: [u8; 16],
    destination_port: u16,
) -> Result<Udp6Packet<'a>, Error> {
    parse_udp6_for_destination(frame, local_ip, destination_port)
}

/// Parse one raw UDP6 datagram addressed to a known explicit destination.
///
/// The normal raw bearer uses [`parse_udp6`] with its unicast link-local
/// address. Local-link discovery uses this form with its fixed IPv6 multicast
/// group, retaining the same Ethernet, IPv6, port, and checksum validation.
pub fn parse_udp6_for_destination<'a>(
    frame: &'a [u8],
    expected_destination_ip: [u8; 16],
    destination_port: u16,
) -> Result<Udp6Packet<'a>, Error> {
    if frame.len() < ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN {
        return Err(Error::Truncated);
    }
    if read_u16(&frame[12..14]) != ETHERTYPE_IPV6 {
        return Err(Error::EtherType);
    }
    let ip = &frame[ETHERNET_HEADER_LEN..];
    if ip[0] >> 4 != 6 {
        return Err(Error::Version);
    }
    match ip[6] {
        IPPROTO_UDP => {}
        44 => return Err(Error::Fragment),
        0 | 43 | 50 | 51 | 60 => return Err(Error::ExtensionHeader),
        _ => return Err(Error::NextHeader),
    }
    let payload_len = read_u16(&ip[4..6]) as usize;
    let expected_len = IPV6_HEADER_LEN + payload_len;
    // The driver representation can retain FCS/padding after the IPv6
    // packet, whereas ordinary Ethernet ingress ends exactly at the packet.
    // IPv6's payload length is authoritative; exclude all trailing L2 bytes
    // before parsing UDP.  This accepts no truncated IPv6 packet.
    if payload_len < UDP_HEADER_LEN || ip.len() < expected_len {
        return Err(Error::Length);
    }
    let ip = &ip[..expected_len];
    let source_ip: [u8; 16] = ip[8..24].try_into().map_err(|_| Error::Truncated)?;
    let destination_ip: [u8; 16] = ip[24..40].try_into().map_err(|_| Error::Truncated)?;
    if destination_ip != expected_destination_ip {
        return Err(Error::Destination);
    }
    let udp = &ip[IPV6_HEADER_LEN..];
    let udp_len = read_u16(&udp[4..6]) as usize;
    if udp_len != payload_len || udp_len < UDP_HEADER_LEN {
        return Err(Error::Length);
    }
    let destination = read_u16(&udp[2..4]);
    if destination != destination_port {
        return Err(Error::Port);
    }
    if read_u16(&udp[6..8]) == 0 || udp_checksum(source_ip, destination_ip, udp) != 0 {
        return Err(Error::Checksum);
    }
    Ok(Udp6Packet {
        destination_mac: frame[..6].try_into().map_err(|_| Error::Truncated)?,
        source_mac: frame[6..12].try_into().map_err(|_| Error::Truncated)?,
        source_ip,
        destination_ip,
        source_port: read_u16(&udp[..2]),
        destination_port: destination,
        payload: &udp[UDP_HEADER_LEN..],
    })
}

/// Parse an RFC 4861 Neighbor Solicitation addressed to `local_ip`.
///
/// NDP must use hop limit 255. Requiring a source link-layer option matching
/// the Ethernet source prevents this raw adapter from learning an unrelated
/// MAC address from a malformed request.
pub fn parse_neighbor_solicitation(
    frame: &[u8],
    local_ip: [u8; 16],
) -> Result<NeighborSolicitation, Error> {
    let (source_mac, ip) = parse_ipv6_frame(frame, IPPROTO_ICMPV6)?;
    if ip[7] != 255 || ip.len() < IPV6_HEADER_LEN + ICMPV6_NEIGHBOR_LEN {
        return Err(Error::Length);
    }
    let source_ip: [u8; 16] = ip[8..24].try_into().map_err(|_| Error::Truncated)?;
    let destination_ip: [u8; 16] = ip[24..40].try_into().map_err(|_| Error::Truncated)?;
    let icmp = &ip[IPV6_HEADER_LEN..];
    if icmp[0] != ICMPV6_NEIGHBOR_SOLICITATION || icmp[1] != 0 {
        return Err(Error::NextHeader);
    }
    if internet_checksum(source_ip, destination_ip, IPPROTO_ICMPV6, icmp) != 0 {
        return Err(Error::Checksum);
    }
    if icmp[4..8] != [0; 4] || icmp[8..24] != local_ip {
        return Err(Error::Destination);
    }
    let mut options = &icmp[ICMPV6_NEIGHBOR_LEN..];
    let mut source_link_layer: Option<[u8; 6]> = None;
    while !options.is_empty() {
        if options.len() < 2 || options[1] == 0 {
            return Err(Error::Length);
        }
        let option_len = usize::from(options[1]) * 8;
        if option_len > options.len() {
            return Err(Error::Length);
        }
        if options[0] == 1 && option_len == 8 {
            source_link_layer = Some(options[2..8].try_into().map_err(|_| Error::Length)?);
        }
        options = &options[option_len..];
    }
    // Infrastructure Wi-Fi adaptation can expose the AP's Ethernet source
    // while the NS option retains the original sender MAC. The received L2
    // header is the only address this bearer can reply to, so validate option
    // structure but use that header as the authoritative egress destination.
    let _source_link_layer = source_link_layer;
    // Ordinary resolution uses a non-unspecified source and one of the
    // target's solicited-node multicast addresses. Accepting only that form
    // keeps DAD (which needs an all-nodes multicast advertisement) explicit.
    if source_ip == [0; 16] || !is_solicited_node_multicast(destination_ip, local_ip) {
        return Err(Error::Destination);
    }
    Ok(NeighborSolicitation {
        source_mac,
        source_ip,
    })
}

/// Build a solicited, override Neighbor Advertisement in response to a
/// validated Neighbor Solicitation. The reply is unicast to the requester.
pub fn encode_neighbor_advertisement(
    out: &mut [u8],
    destination_mac: [u8; 6],
    source_mac: [u8; 6],
    destination_ip: [u8; 16],
    source_ip: [u8; 16],
) -> Result<usize, Error> {
    let payload_len = ICMPV6_NEIGHBOR_LEN + 8;
    let total = ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + payload_len;
    if out.len() < total {
        return Err(Error::OutputTooSmall);
    }
    out[..6].copy_from_slice(&destination_mac);
    out[6..12].copy_from_slice(&source_mac);
    out[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
    let ip = &mut out[ETHERNET_HEADER_LEN..total];
    ip[..IPV6_HEADER_LEN].fill(0);
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    ip[6] = IPPROTO_ICMPV6;
    ip[7] = 255;
    ip[8..24].copy_from_slice(&source_ip);
    ip[24..40].copy_from_slice(&destination_ip);
    let icmp = &mut ip[IPV6_HEADER_LEN..];
    // The ESP adapter reuses its fixed TX frame after UDP responses. Clear
    // every ICMPv6 byte before composing the NA so stale code/checksum or
    // option bytes cannot turn a later neighbor response into an invalid
    // packet.
    icmp.fill(0);
    icmp[0] = ICMPV6_NEIGHBOR_ADVERTISEMENT;
    icmp[4..8].copy_from_slice(&0x6000_0000u32.to_be_bytes()); // solicited | override
    icmp[8..24].copy_from_slice(&source_ip);
    icmp[24] = 2; // target link-layer address
    icmp[25] = 1;
    icmp[26..32].copy_from_slice(&source_mac);
    let checksum = internet_checksum(source_ip, destination_ip, IPPROTO_ICMPV6, icmp);
    icmp[2..4].copy_from_slice(&if checksum == 0 { 0xffff } else { checksum }.to_be_bytes());
    Ok(total)
}

/// Wrap an Ethernet-II IPv6 payload in a non-QoS 802.11 STA-to-DS data frame.
/// The Wi-Fi driver supplies the sequence number; this codec owns only the
/// portable header/LLC construction.
pub fn encode_station_ipv6_data_frame(
    out: &mut [u8],
    bssid: [u8; 6],
    station_mac: [u8; 6],
    ethernet: &[u8],
) -> Result<usize, Error> {
    if ethernet.len() < ETHERNET_HEADER_LEN || read_u16(&ethernet[12..14]) != ETHERTYPE_IPV6 {
        return Err(Error::EtherType);
    }
    let total = IEEE80211_DATA_TO_DS_HEADER_LEN
        .checked_add(IEEE80211_LLC_SNAP_LEN)
        .and_then(|length| length.checked_add(ethernet.len() - ETHERNET_HEADER_LEN))
        .ok_or(Error::Length)?;
    if out.len() < total {
        return Err(Error::OutputTooSmall);
    }
    out[..IEEE80211_DATA_TO_DS_HEADER_LEN].fill(0);
    // Frame-control: non-QoS data, To-DS. The ESP driver owns the sequence.
    out[0] = 0x08;
    out[1] = 0x01;
    out[4..10].copy_from_slice(&bssid); // receiver / AP
    out[10..16].copy_from_slice(&station_mac); // transmitter / STA
    out[16..22].copy_from_slice(&ethernet[..6]); // final Ethernet destination
    out[24..32].copy_from_slice(&[0xaa, 0xaa, 0x03, 0, 0, 0, 0x86, 0xdd]);
    out[32..total].copy_from_slice(&ethernet[ETHERNET_HEADER_LEN..]);
    Ok(total)
}

/// Build a complete non-QoS STA-to-DS IPv6/UDP frame without first composing
/// an Ethernet-II frame. Raw STA transmit otherwise copies every payload from
/// an Ethernet scratch buffer into the final 802.11 buffer; AP egress still
/// uses [`encode_udp6`] because its driver consumes Ethernet frames.
pub fn encode_station_udp6_data_frame(
    out: &mut [u8],
    bssid: [u8; 6],
    station_mac: [u8; 6],
    destination_mac: [u8; 6],
    destination_ip: [u8; 16],
    source_ip: [u8; 16],
    destination_port: u16,
    source_port: u16,
    payload: &[u8],
) -> Result<usize, Error> {
    let udp_len = UDP_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(Error::Length)?;
    let ipv6_len = IPV6_HEADER_LEN.checked_add(udp_len).ok_or(Error::Length)?;
    let total = IEEE80211_DATA_TO_DS_HEADER_LEN
        .checked_add(IEEE80211_LLC_SNAP_LEN)
        .and_then(|length| length.checked_add(ipv6_len))
        .ok_or(Error::Length)?;
    if udp_len > u16::MAX as usize || out.len() < total {
        return Err(Error::OutputTooSmall);
    }
    out[..IEEE80211_DATA_TO_DS_HEADER_LEN].fill(0);
    out[0] = 0x08;
    out[1] = 0x01;
    out[4..10].copy_from_slice(&bssid);
    out[10..16].copy_from_slice(&station_mac);
    out[16..22].copy_from_slice(&destination_mac);
    out[24..32].copy_from_slice(&[0xaa, 0xaa, 0x03, 0, 0, 0, 0x86, 0xdd]);
    let ip = &mut out[IEEE80211_DATA_TO_DS_HEADER_LEN + IEEE80211_LLC_SNAP_LEN..total];
    ip[..IPV6_HEADER_LEN].fill(0);
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    ip[6] = IPPROTO_UDP;
    ip[7] = 64;
    ip[8..24].copy_from_slice(&source_ip);
    ip[24..40].copy_from_slice(&destination_ip);
    let udp = &mut ip[IPV6_HEADER_LEN..];
    udp[..2].copy_from_slice(&source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[6..8].fill(0);
    udp[8..].copy_from_slice(payload);
    let checksum = udp_checksum(source_ip, destination_ip, udp);
    udp[6..8].copy_from_slice(&if checksum == 0 { 0xffff } else { checksum }.to_be_bytes());
    Ok(total)
}

/// Fill the raw STA 802.11/IPv6/UDP prefix around a payload already written at
/// [`STATION_UDP6_HEADROOM`]. This is the no-copy companion to a shared
/// `PacketPool::acquire_writer(STATION_UDP6_HEADROOM)` lease.
pub fn encode_station_udp6_prefix(
    frame: &mut [u8],
    payload_len: usize,
    bssid: [u8; 6],
    station_mac: [u8; 6],
    destination_mac: [u8; 6],
    destination_ip: [u8; 16],
    source_ip: [u8; 16],
    destination_port: u16,
    source_port: u16,
) -> Result<usize, Error> {
    let udp_len = UDP_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(Error::Length)?;
    let total = STATION_UDP6_HEADROOM
        .checked_add(payload_len)
        .ok_or(Error::Length)?;
    if udp_len > u16::MAX as usize || frame.len() < total {
        return Err(Error::OutputTooSmall);
    }
    frame[..IEEE80211_DATA_TO_DS_HEADER_LEN].fill(0);
    frame[0] = 0x08;
    frame[1] = 0x01;
    frame[4..10].copy_from_slice(&bssid);
    frame[10..16].copy_from_slice(&station_mac);
    frame[16..22].copy_from_slice(&destination_mac);
    frame[24..32].copy_from_slice(&[0xaa, 0xaa, 0x03, 0, 0, 0, 0x86, 0xdd]);
    let ip = &mut frame[IEEE80211_DATA_TO_DS_HEADER_LEN + IEEE80211_LLC_SNAP_LEN..total];
    ip[..IPV6_HEADER_LEN].fill(0);
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    ip[6] = IPPROTO_UDP;
    ip[7] = 64;
    ip[8..24].copy_from_slice(&source_ip);
    ip[24..40].copy_from_slice(&destination_ip);
    let udp = &mut ip[IPV6_HEADER_LEN..];
    udp[..2].copy_from_slice(&source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[6..8].fill(0);
    let checksum = udp_checksum(source_ip, destination_ip, udp);
    udp[6..8].copy_from_slice(&if checksum == 0 { 0xffff } else { checksum }.to_be_bytes());
    Ok(total)
}

/// Parse one unfragmented Neighbor Advertisement with a target link-layer
/// address option. This is also used by the privileged host diagnostic to
/// prove whether an ESP responder emitted a wire-valid NA.
pub fn parse_neighbor_advertisement(frame: &[u8]) -> Result<NeighborAdvertisement, Error> {
    let (source_mac, ip) = parse_ipv6_frame(frame, IPPROTO_ICMPV6)?;
    if ip[7] != 255 || ip.len() != IPV6_HEADER_LEN + ICMPV6_NEIGHBOR_LEN + 8 {
        return Err(Error::Length);
    }
    let source_ip: [u8; 16] = ip[8..24].try_into().map_err(|_| Error::Truncated)?;
    let destination_ip: [u8; 16] = ip[24..40].try_into().map_err(|_| Error::Truncated)?;
    let icmp = &ip[IPV6_HEADER_LEN..];
    if icmp[0] != ICMPV6_NEIGHBOR_ADVERTISEMENT || icmp[1] != 0 {
        return Err(Error::NextHeader);
    }
    if internet_checksum(source_ip, destination_ip, IPPROTO_ICMPV6, icmp) != 0 {
        return Err(Error::Checksum);
    }
    if icmp[24] != 2 || icmp[25] != 1 {
        return Err(Error::Length);
    }
    let target_ip = icmp[8..24].try_into().map_err(|_| Error::Truncated)?;
    let target_mac = icmp[26..32].try_into().map_err(|_| Error::Truncated)?;
    Ok(NeighborAdvertisement {
        source_mac,
        source_ip,
        destination_ip,
        target_ip,
        target_mac,
        flags: u32::from_be_bytes(icmp[4..8].try_into().map_err(|_| Error::Truncated)?),
    })
}

/// Build one Ethernet-encapsulated UDP6 frame. Returns the written length.
pub fn encode_udp6(
    out: &mut [u8],
    destination_mac: [u8; 6],
    source_mac: [u8; 6],
    destination_ip: [u8; 16],
    source_ip: [u8; 16],
    destination_port: u16,
    source_port: u16,
    payload: &[u8],
) -> Result<usize, Error> {
    let udp_len = UDP_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(Error::Length)?;
    let ipv6_len = IPV6_HEADER_LEN.checked_add(udp_len).ok_or(Error::Length)?;
    let total = ETHERNET_HEADER_LEN
        .checked_add(ipv6_len)
        .ok_or(Error::Length)?;
    if udp_len > u16::MAX as usize || out.len() < total {
        return Err(Error::OutputTooSmall);
    }
    out[..6].copy_from_slice(&destination_mac);
    out[6..12].copy_from_slice(&source_mac);
    out[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
    let ip = &mut out[ETHERNET_HEADER_LEN..total];
    ip[..IPV6_HEADER_LEN].fill(0);
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    ip[6] = IPPROTO_UDP;
    ip[7] = 64;
    ip[8..24].copy_from_slice(&source_ip);
    ip[24..40].copy_from_slice(&destination_ip);
    let udp = &mut ip[IPV6_HEADER_LEN..];
    udp[..2].copy_from_slice(&source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[6..8].fill(0);
    udp[8..].copy_from_slice(payload);
    let checksum = udp_checksum(source_ip, destination_ip, udp);
    udp[6..8].copy_from_slice(&if checksum == 0 { 0xffff } else { checksum }.to_be_bytes());
    Ok(total)
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

/// One's-complement checksum over the RFC 8200 UDP pseudo-header and UDP.
/// A valid complete UDP datagram evaluates to zero.
pub fn udp_checksum(source_ip: [u8; 16], destination_ip: [u8; 16], udp: &[u8]) -> u16 {
    internet_checksum(source_ip, destination_ip, IPPROTO_UDP, udp)
}

fn parse_ipv6_frame<'a>(frame: &'a [u8], next_header: u8) -> Result<([u8; 6], &'a [u8]), Error> {
    if frame.len() < ETHERNET_HEADER_LEN + IPV6_HEADER_LEN {
        return Err(Error::Truncated);
    }
    if read_u16(&frame[12..14]) != ETHERTYPE_IPV6 {
        return Err(Error::EtherType);
    }
    let ip = &frame[ETHERNET_HEADER_LEN..];
    if ip[0] >> 4 != 6 {
        return Err(Error::Version);
    }
    match ip[6] {
        44 => return Err(Error::Fragment),
        0 | 43 | 50 | 51 | 60 => return Err(Error::ExtensionHeader),
        actual if actual != next_header => return Err(Error::NextHeader),
        _ => {}
    }
    let payload_len = read_u16(&ip[4..6]) as usize;
    let expected_len = IPV6_HEADER_LEN + payload_len;
    // See `parse_udp6`: the callback may retain FCS/padding after the
    // IPv6 payload, which must not be treated as an ICMPv6 option.
    if ip.len() < expected_len {
        return Err(Error::Length);
    }
    Ok((
        frame[6..12].try_into().map_err(|_| Error::Truncated)?,
        &ip[..expected_len],
    ))
}

fn is_solicited_node_multicast(destination: [u8; 16], target: [u8; 16]) -> bool {
    destination[..13] == [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff]
        && destination[13..] == target[13..]
}

/// One's-complement checksum over an IPv6 upper-layer pseudo-header.
fn internet_checksum(
    source_ip: [u8; 16],
    destination_ip: [u8; 16],
    next_header: u8,
    payload: &[u8],
) -> u16 {
    let mut sum = 0u32;
    add_words(&mut sum, &source_ip);
    add_words(&mut sum, &destination_ip);
    add_words(&mut sum, &(payload.len() as u32).to_be_bytes());
    add_words(&mut sum, &[0, 0, 0, next_header]);
    add_words(&mut sum, payload);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn add_words(sum: &mut u32, bytes: &[u8]) {
    let mut chunks = bytes.chunks_exact(2);
    for pair in &mut chunks {
        *sum = sum.wrapping_add(u32::from(read_u16(pair)));
    }
    if let [last] = chunks.remainder() {
        *sum = sum.wrapping_add(u32::from(*last) << 8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL_MAC: [u8; 6] = [0x14, 0xc1, 0x9f, 0xe5, 0x98, 0];
    const PEER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];

    #[test]
    fn link_local_uses_modified_eui64() {
        assert_eq!(
            link_local_from_mac(LOCAL_MAC),
            [
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x16, 0xc1, 0x9f, 0xff, 0xfe, 0xe5, 0x98, 0
            ]
        );
    }

    #[test]
    fn raw_error_codes_are_stable_for_bearer_diagnostics() {
        assert_eq!(error_code(Error::EtherType), 2);
        assert_eq!(error_code(Error::Destination), 8);
        assert_eq!(error_code(Error::Checksum), 10);
    }

    #[test]
    fn udp6_round_trip_with_odd_payload_checksum() {
        let local = link_local_from_mac(LOCAL_MAC);
        let peer = link_local_from_mac(PEER_MAC);
        let mut frame = [0u8; 256];
        let used = encode_udp6(
            &mut frame, LOCAL_MAC, PEER_MAC, local, peer, 3339, 41000, b"odd",
        )
        .unwrap();
        let parsed = parse_udp6(&frame[..used], local, 3339).unwrap();
        assert_eq!(parsed.source_mac, PEER_MAC);
        assert_eq!(parsed.source_ip, peer);
        assert_eq!(parsed.source_port, 41000);
        assert_eq!(parsed.payload, b"odd");
        let mut with_fcs = [0u8; 260];
        with_fcs[..used].copy_from_slice(&frame[..used]);
        assert_eq!(
            parse_udp6(&with_fcs[..used + 4], local, 3339)
                .unwrap()
                .payload,
            b"odd"
        );
        assert_eq!(
            parse_udp6(&with_fcs[..used + 16], local, 3339)
                .unwrap()
                .payload,
            b"odd"
        );
    }

    #[test]
    fn explicit_multicast_destination_keeps_udp6_validation() {
        let local = link_local_from_mac(LOCAL_MAC);
        let peer = link_local_from_mac(PEER_MAC);
        let group = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x52, 0x27];
        let mut frame = [0u8; 256];
        let used = encode_udp6(
            &mut frame,
            [0x33, 0x33, 0, 0, 0x52, 0x27],
            PEER_MAC,
            group,
            peer,
            5227,
            5227,
            b"announce",
        )
        .unwrap();
        assert_eq!(
            parse_udp6(&frame[..used], local, 5227),
            Err(Error::Destination)
        );
        let parsed = parse_udp6_for_destination(&frame[..used], group, 5227).unwrap();
        assert_eq!(parsed.payload, b"announce");
    }

    #[test]
    fn rejects_corruption_and_unsupported_ipv6_forms() {
        let local = link_local_from_mac(LOCAL_MAC);
        let peer = link_local_from_mac(PEER_MAC);
        let mut frame = [0u8; 256];
        let used = encode_udp6(
            &mut frame, LOCAL_MAC, PEER_MAC, local, peer, 3339, 41000, b"payload",
        )
        .unwrap();
        frame[ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN] ^= 1;
        assert_eq!(
            parse_udp6(&frame[..used], local, 3339),
            Err(Error::Checksum)
        );
        frame[ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN] ^= 1;
        frame[ETHERNET_HEADER_LEN + 6] = 44;
        assert_eq!(
            parse_udp6(&frame[..used], local, 3339),
            Err(Error::Fragment)
        );
    }

    #[test]
    fn icmpv6_classifier_and_error_labels_are_host_tested() {
        let mut frame = [0u8; ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + 2];
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        frame[14] = 0x60;
        frame[18..20].copy_from_slice(&48u16.to_be_bytes());
        frame[20] = IPPROTO_ICMPV6;
        frame[21] = 255;
        frame[54] = 1;
        frame[55] = 4;
        assert!(is_icmpv6_frame(&frame));
        assert_eq!(
            icmpv6_frame_info(&frame),
            Some(Icmpv6FrameInfo {
                hop_limit: 255,
                payload_length: 48,
                icmp_type: 1,
                code: 4,
            })
        );
        frame[20] = IPPROTO_UDP;
        assert!(!is_icmpv6_frame(&frame));
        assert_eq!(icmpv6_frame_info(&frame), None);
        assert_eq!(error_label(Error::Length), "length/option");
        assert_eq!(ndp_error_text(Error::Checksum), b"ndp rejected checksum");
        assert_eq!(udp6_error_text(Error::Port), b"udp6 rejected port");
    }

    #[test]
    fn neighbor_solicitation_receives_unicast_advertisement() {
        let local = link_local_from_mac(LOCAL_MAC);
        let peer = link_local_from_mac(PEER_MAC);
        let mut request = [0u8; 128];
        let solicited = [
            0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, local[13], local[14], local[15],
        ];
        request[..6].copy_from_slice(&[0x33, 0x33, 0xff, local[13], local[14], local[15]]);
        request[6..12].copy_from_slice(&PEER_MAC);
        request[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        let ip = &mut request[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + 32];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&32u16.to_be_bytes());
        ip[6] = IPPROTO_ICMPV6;
        ip[7] = 255;
        ip[8..24].copy_from_slice(&peer);
        ip[24..40].copy_from_slice(&solicited);
        let icmp = &mut ip[IPV6_HEADER_LEN..];
        icmp[0] = ICMPV6_NEIGHBOR_SOLICITATION;
        icmp[8..24].copy_from_slice(&local);
        icmp[24] = 1;
        icmp[25] = 1;
        icmp[26..32].copy_from_slice(&PEER_MAC);
        let checksum = internet_checksum(peer, solicited, IPPROTO_ICMPV6, icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
        let solicitation = parse_neighbor_solicitation(&request[..86], local).unwrap();
        assert_eq!(solicitation.source_mac, PEER_MAC);
        let mut reply = [0u8; 128];
        let used =
            encode_neighbor_advertisement(&mut reply, PEER_MAC, LOCAL_MAC, peer, local).unwrap();
        assert_eq!(used, 86);
        let ip = &reply[ETHERNET_HEADER_LEN..used];
        assert_eq!(ip[6], IPPROTO_ICMPV6);
        assert_eq!(ip[7], 255);
        assert_eq!(ip[8..24], local);
        assert_eq!(ip[24..40], peer);
        assert_eq!(ip[IPV6_HEADER_LEN], ICMPV6_NEIGHBOR_ADVERTISEMENT);
        assert_eq!(
            internet_checksum(local, peer, IPPROTO_ICMPV6, &ip[IPV6_HEADER_LEN..]),
            0
        );
        assert_eq!(
            parse_neighbor_advertisement(&reply[..used]).unwrap(),
            NeighborAdvertisement {
                source_mac: LOCAL_MAC,
                source_ip: local,
                destination_ip: peer,
                target_ip: local,
                target_mac: LOCAL_MAC,
                flags: 0x6000_0000,
            }
        );
    }

    #[test]
    fn solicitation_accepts_optional_or_extended_nd_options() {
        let local = link_local_from_mac(LOCAL_MAC);
        let peer = link_local_from_mac(PEER_MAC);
        let mut frame = [0u8; 128];
        let solicited = [
            0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, local[13], local[14], local[15],
        ];
        frame[..6].copy_from_slice(&[0x33, 0x33, 0xff, local[13], local[14], local[15]]);
        frame[6..12].copy_from_slice(&PEER_MAC);
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        {
            let ip = &mut frame[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + 40];
            ip[0] = 0x60;
            ip[4..6].copy_from_slice(&40u16.to_be_bytes());
            ip[6] = IPPROTO_ICMPV6;
            ip[7] = 255;
            ip[8..24].copy_from_slice(&peer);
            ip[24..40].copy_from_slice(&solicited);
            let icmp = &mut ip[IPV6_HEADER_LEN..];
            icmp[0] = ICMPV6_NEIGHBOR_SOLICITATION;
            icmp[8..24].copy_from_slice(&local);
            // Unknown valid 8-byte options are ignored; the Ethernet header
            // remains the bearer identity when the source-LL option is absent.
            icmp[24] = 253;
            icmp[25] = 1;
            icmp[32] = 253;
            icmp[33] = 1;
            let checksum = internet_checksum(peer, solicited, IPPROTO_ICMPV6, icmp);
            icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
        }
        assert_eq!(
            parse_neighbor_solicitation(&frame[..94], local)
                .unwrap()
                .source_mac,
            PEER_MAC
        );
        frame[ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + 24] = 1;
        frame[ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + 25] = 1;
        frame[ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + 26
            ..ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + 32]
            .copy_from_slice(&LOCAL_MAC);
        let ip = &mut frame[ETHERNET_HEADER_LEN..94];
        let icmp = &mut ip[IPV6_HEADER_LEN..];
        icmp[2..4].fill(0);
        let checksum = internet_checksum(peer, solicited, IPPROTO_ICMPV6, icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(
            parse_neighbor_solicitation(&frame[..94], local)
                .unwrap()
                .source_mac,
            PEER_MAC
        );
    }

    #[test]
    fn captured_e6_neighbor_advertisement_is_wire_valid() {
        // Captured from e6's raw bearer before esp_wifi_internal_tx().
        let frame = [
            0x00, 0xc0, 0xca, 0xb8, 0x79, 0xcc, 0x14, 0xc1, 0x9f, 0xe5, 0x98, 0x00, 0x86, 0xdd,
            0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x16, 0xc1, 0x9f, 0xff, 0xfe, 0xe5, 0x98, 0x00, 0xfe, 0x80, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0xc0, 0xca, 0xff, 0xfe, 0xb8, 0x79, 0xcc, 0x88, 0x00,
            0xeb, 0xe5, 0x60, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x16, 0xc1, 0x9f, 0xff, 0xfe, 0xe5, 0x98, 0x00, 0x02, 0x01, 0x14, 0xc1, 0x9f, 0xe5,
            0x98, 0x00,
        ];
        let advertisement = parse_neighbor_advertisement(&frame).unwrap();
        assert_eq!(advertisement.source_mac, LOCAL_MAC);
        assert_eq!(advertisement.target_mac, LOCAL_MAC);
        assert_eq!(advertisement.flags, 0x6000_0000);
    }

    #[test]
    fn station_data_frame_wraps_ipv6_without_ethernet_header() {
        let local = link_local_from_mac(LOCAL_MAC);
        let peer = link_local_from_mac(PEER_MAC);
        let mut ethernet = [0u8; 128];
        let ethernet_len =
            encode_neighbor_advertisement(&mut ethernet, PEER_MAC, LOCAL_MAC, peer, local).unwrap();
        let mut wifi = [0u8; 160];
        let used = encode_station_ipv6_data_frame(
            &mut wifi,
            PEER_MAC,
            LOCAL_MAC,
            &ethernet[..ethernet_len],
        )
        .unwrap();
        assert_eq!(&wifi[..2], &[0x08, 0x01]);
        assert_eq!(&wifi[4..10], &PEER_MAC);
        assert_eq!(&wifi[10..16], &LOCAL_MAC);
        assert_eq!(&wifi[16..22], &PEER_MAC);
        assert_eq!(&wifi[24..32], &[0xaa, 0xaa, 0x03, 0, 0, 0, 0x86, 0xdd]);
        assert_eq!(&wifi[32..used], &ethernet[14..ethernet_len]);
    }

    #[test]
    fn station_udp6_frame_matches_ethernet_composition() {
        let local = link_local_from_mac(LOCAL_MAC);
        let peer = link_local_from_mac(PEER_MAC);
        let payload = b"odd";
        let mut ethernet = [0u8; 128];
        let ethernet_len = encode_udp6(
            &mut ethernet,
            PEER_MAC,
            LOCAL_MAC,
            peer,
            local,
            3339,
            4444,
            payload,
        )
        .unwrap();
        let mut expected = [0u8; 160];
        let expected_len = encode_station_ipv6_data_frame(
            &mut expected,
            PEER_MAC,
            LOCAL_MAC,
            &ethernet[..ethernet_len],
        )
        .unwrap();
        let mut direct = [0u8; 160];
        let direct_len = encode_station_udp6_data_frame(
            &mut direct,
            PEER_MAC,
            LOCAL_MAC,
            PEER_MAC,
            peer,
            local,
            3339,
            4444,
            payload,
        )
        .unwrap();
        assert_eq!(direct_len, expected_len);
        assert_eq!(&direct[..direct_len], &expected[..expected_len]);
    }

    #[test]
    fn station_udp6_prefix_preserves_already_serialized_payload() {
        let local = link_local_from_mac(LOCAL_MAC);
        let peer = link_local_from_mac(PEER_MAC);
        let payload = b"write-directly";
        let mut frame = [0xa5; 160];
        frame[STATION_UDP6_HEADROOM..STATION_UDP6_HEADROOM + payload.len()]
            .copy_from_slice(payload);
        let used = encode_station_udp6_prefix(
            &mut frame,
            payload.len(),
            PEER_MAC,
            LOCAL_MAC,
            PEER_MAC,
            peer,
            local,
            3339,
            4444,
        )
        .unwrap();
        assert_eq!(&frame[STATION_UDP6_HEADROOM..used], payload);

        let mut expected = [0u8; 160];
        let expected_len = encode_station_udp6_data_frame(
            &mut expected,
            PEER_MAC,
            LOCAL_MAC,
            PEER_MAC,
            peer,
            local,
            3339,
            4444,
            payload,
        )
        .unwrap();
        assert_eq!(used, expected_len);
        assert_eq!(&frame[..used], &expected[..expected_len]);
    }

    #[test]
    fn neighbor_advertisement_overwrites_a_reused_dirty_buffer() {
        let local = link_local_from_mac(LOCAL_MAC);
        let peer = link_local_from_mac(PEER_MAC);
        let mut frame = [0xa5u8; 128];
        let used =
            encode_neighbor_advertisement(&mut frame, PEER_MAC, LOCAL_MAC, peer, local).unwrap();
        let advertisement = parse_neighbor_advertisement(&frame[..used]).unwrap();
        assert_eq!(advertisement.source_ip, local);
        assert_eq!(advertisement.destination_ip, peer);
        assert_eq!(advertisement.flags, 0x6000_0000);
    }
}
