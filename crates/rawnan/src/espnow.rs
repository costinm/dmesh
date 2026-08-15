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
) -> Vec<u8> {
    let body_len = payload.len().min(1400);
    let mut frame = Vec::with_capacity(crate::IEEE80211_HEADER_LEN + 9 + body_len);
    frame.extend_from_slice(&[0xd0, 0, 0, 0]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&action_header());
    frame.extend_from_slice(&payload[..body_len]);
    frame
}
