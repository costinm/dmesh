//! Moved from `lmesh-wifi/src/radio.rs` (see notes/plans/lmesh-wifi-extraction.md).
#![allow(clippy::too_many_arguments)]
use super::*;

pub fn build_open_beacon_head(mac: [u8; 6], ssid: &str, channel: u8) -> Result<Vec<u8>> {
    build_open_beacon_head_with_capability(mac, ssid, channel, 0x0421)
}

pub fn build_open_beacon_head_with_capability(
    mac: [u8; 6],
    ssid: &str,
    channel: u8,
    capability: u16,
) -> Result<Vec<u8>> {
    if ssid.len() > 32 {
        bail!("SSID is too long for 802.11 beacon: {}", ssid.len());
    }
    let mut frame = Vec::with_capacity(48 + ssid.len());
    frame.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&RAW_WIFI_BROADCAST);
    frame.extend_from_slice(&mac);
    frame.extend_from_slice(&mac);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&[0; 8]);
    frame.extend_from_slice(&100_u16.to_le_bytes());
    frame.extend_from_slice(&capability.to_le_bytes());
    frame.extend_from_slice(&esp_open_ap_beacon_head_ies(ssid, channel)?);
    Ok(frame)
}

pub fn build_open_probe_resp(mac: [u8; 6], ssid: &str, channel: u8) -> Result<Vec<u8>> {
    build_open_probe_resp_with_ies(
        mac,
        ssid,
        channel,
        0x0421,
        &esp_open_ap_probe_ies(ssid, channel)?,
    )
}

pub fn build_open_probe_resp_with_ies(
    mac: [u8; 6],
    ssid: &str,
    _channel: u8,
    capability: u16,
    ies: &[u8],
) -> Result<Vec<u8>> {
    if ssid.len() > 32 {
        bail!("SSID is too long for 802.11 probe response: {}", ssid.len());
    }
    let mut frame = Vec::with_capacity(160 + ssid.len());
    frame.extend_from_slice(&[0x50, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&RAW_WIFI_BROADCAST);
    frame.extend_from_slice(&mac);
    frame.extend_from_slice(&mac);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&[0; 8]);
    frame.extend_from_slice(&100_u16.to_le_bytes());
    frame.extend_from_slice(&capability.to_le_bytes());
    frame.extend_from_slice(ies);
    Ok(frame)
}

pub fn build_open_auth_response(ap: [u8; 6], sta: [u8; 6]) -> Vec<u8> {
    let mut frame = mgmt_frame_header(0x0b, sta, ap, ap);
    frame.extend_from_slice(&(NL80211_AUTHTYPE_OPEN_SYSTEM as u16).to_le_bytes());
    frame.extend_from_slice(&2_u16.to_le_bytes());
    frame.extend_from_slice(&0_u16.to_le_bytes());
    frame
}

pub fn build_open_assoc_response(
    ap: [u8; 6],
    sta: [u8; 6],
    aid: u16,
    allow_ht: bool,
    channel: u8,
    ht40: bool,
) -> Vec<u8> {
    let mut frame = mgmt_frame_header(0x01, sta, ap, ap);
    frame.extend_from_slice(&0x0401_u16.to_le_bytes());
    frame.extend_from_slice(&0_u16.to_le_bytes());
    frame.extend_from_slice(&(0xc000 | (aid & 0x3fff)).to_le_bytes());
    frame.push(0x01);
    frame.push(OPEN_AP_OFDM_BASIC_RATES.len() as u8);
    frame.extend_from_slice(&OPEN_AP_OFDM_BASIC_RATES);
    frame.push(0x32);
    frame.push(OPEN_AP_OFDM_EXTENDED_RATES.len() as u8);
    frame.extend_from_slice(&OPEN_AP_OFDM_EXTENDED_RATES);
    // Match the HT20 capability advertised in the beacon. Without an HT
    // Capabilities element in the association response, a station can
    // associate successfully but remain on legacy rates.
    if allow_ht {
        frame.extend_from_slice(&hostapd_open_ap_ht_capability(ht40));
        frame.extend_from_slice(&hostapd_open_ap_ht_operation(channel, ht40));
    }
    frame.extend_from_slice(&hostapd_open_ap_extra_ies());
    // The beacon/probe templates advertise WMM, so the manually generated
    // association response must carry the matching WMM Parameter element too.
    // Without it, Linux reports WMM/WME=no for the station even though the AP
    // beacon contains the element; that disables the normal Wi-Fi QoS/Block
    // ACK path and is especially costly for a direct Wi-Fi transfer.
    frame.extend_from_slice(&wmm_parameter_ie());
    frame
}

pub fn hostapd_open_ap_ht_operation(channel: u8, ht40: bool) -> [u8; 24] {
    let mut ie = [
        0x3d, 22, channel, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    if ht40 {
        ie[3] = 0x05;
    }
    ie
}

pub fn hostapd_open_ap_ht_capability(ht40: bool) -> [u8; 28] {
    let mut ie = HOSTAPD_HT20_CAPABILITY;
    if ht40 {
        ie[2] |= 0x42;
    }
    ie
}

pub fn mgmt_frame_header(subtype: u8, addr1: [u8; 6], addr2: [u8; 6], addr3: [u8; 6]) -> Vec<u8> {
    let frame_control = ((subtype as u16) << 4).to_le_bytes();
    let mut frame = Vec::with_capacity(64);
    frame.extend_from_slice(&frame_control);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&addr1);
    frame.extend_from_slice(&addr2);
    frame.extend_from_slice(&addr3);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame
}

pub fn esp_open_ap_beacon_head_ies(ssid: &str, channel: u8) -> Result<Vec<u8>> {
    if ssid.len() > 32 {
        bail!("SSID is too long for 802.11 IE: {}", ssid.len());
    }
    let mut ies = Vec::with_capacity(32 + ssid.len());
    ies.push(0x00);
    ies.push(ssid.len() as u8);
    ies.extend_from_slice(ssid.as_bytes());
    ies.push(0x01);
    ies.push(OPEN_AP_OFDM_BASIC_RATES.len() as u8);
    ies.extend_from_slice(&OPEN_AP_OFDM_BASIC_RATES);
    ies.push(0x03);
    ies.push(1);
    ies.push(channel);
    Ok(ies)
}

pub fn esp_open_ap_beacon_tail(channel: u8) -> Vec<u8> {
    let mut ies = Vec::with_capacity(92);
    ies.push(0x2a);
    ies.push(1);
    ies.push(0x00);
    ies.push(0x32);
    ies.push(OPEN_AP_OFDM_EXTENDED_RATES.len() as u8);
    ies.extend_from_slice(&OPEN_AP_OFDM_EXTENDED_RATES);
    ies.push(0x2d);
    ies.push(26);
    ies.extend_from_slice(&[
        0x6e, 0x11, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    ies.push(0x3d);
    ies.push(22);
    ies.extend_from_slice(&[
        channel, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    ies.push(0x7f);
    ies.push(9);
    ies.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    ies.push(0xdd);
    ies.push(24);
    ies.extend_from_slice(&[
        0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x04, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4, 0x00,
        0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00,
    ]);
    // Passive P2P presence only.  It keeps the AP discoverable on channel 6
    // without starting a probe, GAS, P2P SD, or group-negotiation exchange.
    // Those stateful frames are controller-triggered Phase-2 work.
    ies.extend_from_slice(&crate::p2p::PASSIVE_DISCOVERY_IE);
    ies
}

/// Replace the static capability-only marker with the complete device/channel
/// advertisement when a real AP MAC is available. Android creates a P2P peer
/// only after it sees Device Info and Listen Channel, not capability alone.
pub fn esp_open_ap_beacon_tail_for_device(mac: [u8; 6], channel: u8) -> Vec<u8> {
    let mut ies = esp_open_ap_beacon_tail(channel);
    let marker = crate::p2p::PASSIVE_DISCOVERY_IE.len();
    ies.truncate(ies.len().saturating_sub(marker));
    let mut p2p = [0u8; 64];
    let used = crate::p2p::encode_discovery_advertisement(&mut p2p, mac, channel)
        .expect("bounded P2P discovery IE");
    ies.extend_from_slice(&p2p[..used]);
    ies
}

pub fn hostapd_open_ap_beacon_tail(channel: u8, ht40: bool) -> Vec<u8> {
    let mut ies = Vec::with_capacity(101);
    ies.push(0x2a);
    ies.push(1);
    ies.push(0x04);
    ies.push(0x32);
    ies.push(OPEN_AP_OFDM_EXTENDED_RATES.len() as u8);
    ies.extend_from_slice(&OPEN_AP_OFDM_EXTENDED_RATES);
    ies.push(0x3b);
    ies.push(2);
    ies.extend_from_slice(&[0x51, 0x00]);
    ies.extend_from_slice(&hostapd_open_ap_ht_capability(ht40));
    ies.extend_from_slice(&hostapd_open_ap_ht_operation(channel, ht40));
    ies.extend_from_slice(&hostapd_open_ap_extra_ies());
    ies.push(0xdd);
    ies.push(24);
    ies.extend_from_slice(&[
        0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x01, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4, 0x00,
        0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00,
    ]);
    // Match the ESP-compatible and hostapd-compatible templates: any DMesh
    // AP passively exposes the same P2P capability marker in beacon and
    // probe-response IEs, while active P2P remains controller initiated.
    ies.extend_from_slice(&crate::p2p::PASSIVE_DISCOVERY_IE);
    ies
}

pub fn hostapd_open_ap_beacon_tail_for_device(mac: [u8; 6], channel: u8, ht40: bool) -> Vec<u8> {
    let mut ies = hostapd_open_ap_beacon_tail(channel, ht40);
    let marker = crate::p2p::PASSIVE_DISCOVERY_IE.len();
    ies.truncate(ies.len().saturating_sub(marker));
    let mut p2p = [0u8; 64];
    let used = crate::p2p::encode_discovery_advertisement(&mut p2p, mac, channel)
        .expect("bounded P2P discovery IE");
    ies.extend_from_slice(&p2p[..used]);
    ies
}

pub fn hostapd_open_ap_probe_ies_for_device(
    ssid: &str,
    mac: [u8; 6],
    channel: u8,
    ht40: bool,
) -> Result<Vec<u8>> {
    let mut ies = esp_open_ap_beacon_head_ies(ssid, channel)?;
    ies.extend_from_slice(&hostapd_open_ap_beacon_tail_for_device(mac, channel, ht40));
    Ok(ies)
}

pub fn hostapd_open_ap_extra_ies() -> [u8; 10] {
    [0x7f, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40]
}

pub fn wmm_parameter_ie() -> [u8; 26] {
    [
        0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x01, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27,
        0xa4, 0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00,
    ]
}

pub fn esp_open_ap_probe_ies(ssid: &str, channel: u8) -> Result<Vec<u8>> {
    let mut ies = esp_open_ap_beacon_head_ies(ssid, channel)?;
    ies.extend_from_slice(&esp_open_ap_beacon_tail(channel));
    Ok(ies)
}

pub fn esp_open_ap_probe_ies_for_device(ssid: &str, mac: [u8; 6], channel: u8) -> Result<Vec<u8>> {
    let mut ies = esp_open_ap_beacon_head_ies(ssid, channel)?;
    ies.extend_from_slice(&esp_open_ap_beacon_tail_for_device(mac, channel));
    Ok(ies)
}

pub fn open_ap_template_lengths(ssid: &str, channel: u8) -> Result<(usize, usize)> {
    let mac = [0; 6];
    Ok((
        build_open_beacon_head(mac, ssid, channel)?.len(),
        build_open_probe_resp(mac, ssid, channel)?.len(),
    ))
}

pub fn default_open_ap_ssid(_iface: &str) -> String {
    "DIRECT-dmesh".to_string()
}
