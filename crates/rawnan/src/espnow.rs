//! ESP-NOW-compatible DMesh data bearer.
//!
//! NAN remains the control plane: beacons synchronize peers, active
//! subscribe/publication discovers the DMesh service, and follow-ups carry
//! short commands or negotiation results. Once peers have synchronized, this
//! module provides the alternate data path for QUIC-like traffic. An adapter
//! may use these frames directly, or use the negotiated service response to
//! activate an AP/STA chain and move QUIC over UDP.
//!
//! The framing is intentionally driver-neutral. ESP32 supplies the native
//! ESP-NOW radio operation; Linux can inject/receive the same vendor action
//! through its monitor/native raw path.

use anyhow::Result;

pub const MAGIC: [u8; 4] = *b"DRX1";
pub const VERSION: u8 = 1;
pub const KIND_RADIO: u8 = 1;
pub const HEADER_LEN: usize = 11;
pub const ACTION_PREFIX: [u8; 4] = [0x7f, 0x18, 0xfe, 0x34];
pub const ACTION_TYPE: u8 = 0x04;
pub const IEEE80211_HEADER_LEN: usize = 24;
/// One QUIC-lite datagram must fit in a single raw action frame.  There is no
/// radio-layer fragmentation: bearers with a smaller real limit must lower
/// the common transport MTU before they are admitted as a path.
pub const MAX_ACTION_PAYLOAD: usize = 1400;

pub fn build_radio_packet(data: &[u8], rssi: i32, snr: f32) -> Result<Vec<u8>> {
    if data.len() > u16::MAX as usize {
        anyhow::bail!(
            "ESP-NOW radio envelope payload is too large: {}",
            data.len()
        );
    }
    let mut frame = Vec::with_capacity(HEADER_LEN + data.len());
    frame.extend_from_slice(&MAGIC);
    frame.extend_from_slice(&[VERSION, KIND_RADIO]);
    frame.extend_from_slice(&(rssi.clamp(i16::MIN as i32, i16::MAX as i32) as i16).to_le_bytes());
    frame.push(snr.round().clamp(i8::MIN as f32, i8::MAX as f32) as i8 as u8);
    frame.extend_from_slice(&(data.len() as u16).to_le_bytes());
    frame.extend_from_slice(data);
    Ok(frame)
}

pub fn action_header() -> [u8; 9] {
    let mut header = [0; 9];
    header[..4].copy_from_slice(&ACTION_PREFIX);
    header[4..8].copy_from_slice(&[0xff; 4]);
    header[8] = ACTION_TYPE;
    header
}

pub fn build_action_frame(
    destination: [u8; 6],
    source: [u8; 6],
    bssid: [u8; 6],
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.len() > MAX_ACTION_PAYLOAD {
        anyhow::bail!(
            "ESP-NOW action payload exceeds single-frame limit {}: {}",
            MAX_ACTION_PAYLOAD,
            payload.len()
        );
    }
    let mut frame = Vec::with_capacity(IEEE80211_HEADER_LEN + 9 + payload.len());
    frame.extend_from_slice(&[0xd0, 0, 0, 0]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&action_header());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Parse a raw-injected ESP-NOW-compatible action frame. The adapter owns
/// monitor metadata and optional FCS removal; this function only validates
/// the portable 802.11/action envelope and returns the complete L2 payload.
pub fn parse_action_frame(frame: &[u8]) -> Option<([u8; 6], &[u8])> {
    if frame.len() < IEEE80211_HEADER_LEN + 9 || frame[0] != 0xd0 {
        return None;
    }
    let source = frame.get(10..16)?.try_into().ok()?;
    let action = frame.get(IEEE80211_HEADER_LEN..)?;
    if action.get(..4) != Some(&ACTION_PREFIX)
        || action.get(8).copied() != Some(ACTION_TYPE)
    {
        return None;
    }
    Some((source, action.get(9..)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_frame_round_trip_preserves_addresses_and_payload() {
        let destination = [1, 2, 3, 4, 5, 6];
        let source = [6, 5, 4, 3, 2, 1];
        let payload = [0x40, 0x01, 0x02, 0x03];
        let frame = build_action_frame(destination, source, destination, &payload).unwrap();

        assert_eq!(parse_action_frame(&frame), Some((source, payload.as_slice())));
    }

    #[test]
    fn action_frame_rejects_foreign_and_oversize_data() {
        assert!(build_action_frame([0; 6], [1; 6], [0; 6], &[0; MAX_ACTION_PAYLOAD + 1]).is_err());
        assert!(parse_action_frame(&[0xd0; IEEE80211_HEADER_LEN + 9]).is_none());
    }
}
