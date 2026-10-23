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

use alloc::{vec, vec::Vec};
use anyhow::Result;

pub const MAGIC: [u8; 4] = *b"DRX1";
pub const VERSION: u8 = 1;
pub const KIND_RADIO: u8 = 1;
pub const HEADER_LEN: usize = 11;
/// ESP-NOW vendor-action category and Espressif OUI.
pub const ACTION_PREFIX: [u8; 4] = [0x7f, 0x18, 0xfe, 0x34];
pub const ACTION_TYPE: u8 = 0x04;
pub const IEEE80211_HEADER_LEN: usize = 24;
const ACTION_HEADER_LEN: usize = 8;
const VENDOR_IE_ID: u8 = 0xdd;
/// Maximum opaque datagram after the raw vendor envelope.
pub const MAX_ACTION_PAYLOAD: usize = 1500;
const ESPNOW_V2_VERSION: u8 = 2;
/// Action header plus one vendor IE containing a padding byte. Payload follows.
pub const RAW_ACTION_PREFIX_LEN: usize = 16;

/// Failure while encoding a caller-owned ESP-NOW-compatible action frame.
/// This remains allocation- and ESP-independent so firmware and host adapters
/// use exactly the same wire layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionFrameError {
    PayloadTooLarge,
    OutputTooSmall,
}

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
    // `f32::round` is a std-only convenience on the ESP no-std target.
    // Preserve the wire's nearest-integer behavior without pulling in a
    // math runtime for this otherwise portable envelope.
    let rounded_snr = if snr.is_sign_negative() {
        snr - 0.5
    } else {
        snr + 0.5
    };
    frame.push(rounded_snr.clamp(i8::MIN as f32, i8::MAX as f32) as i8 as u8);
    frame.extend_from_slice(&(data.len() as u16).to_le_bytes());
    frame.extend_from_slice(data);
    Ok(frame)
}

pub fn action_header() -> [u8; ACTION_HEADER_LEN] {
    let mut header = [0; ACTION_HEADER_LEN];
    header[..4].copy_from_slice(&ACTION_PREFIX);
    // The random value is required by the ESP-NOW envelope to make relay
    // attacks detectable. The raw adapter may replace this deterministic
    // initial value before injection; parsers do not attach semantics to it.
    header[4..8].copy_from_slice(&[0xff; 4]);
    header
}

pub fn build_action_frame(
    destination: [u8; 6],
    source: [u8; 6],
    bssid: [u8; 6],
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mut frame = vec![0; IEEE80211_HEADER_LEN + RAW_ACTION_PREFIX_LEN + payload.len()];
    let used = encode_action_frame(&mut frame, destination, source, bssid, payload)
        .map_err(|error| anyhow::anyhow!("ESP-NOW action frame: {error:?}"))?;
    frame.truncate(used);
    Ok(frame)
}

/// Encode one vendor action frame into caller-owned storage. This is the API
/// used by no-std firmware paths to avoid an intermediate allocation/copy.
///
/// ESP-NOW uses broadcast address 3 in its normal connectionless form. The
/// raw bearer also permits a caller-selected address 3 for ESP filter
/// experiments with a borrowed NAN BSSID; both endpoints still validate the
/// same vendor-IE payload. See Espressif's frame
/// format: <https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/network/esp_now.html>.
pub fn encode_action_frame(
    out: &mut [u8], destination: [u8; 6], source: [u8; 6], bssid: [u8; 6], payload: &[u8],
) -> core::result::Result<usize, ActionFrameError> {
    if payload.len() > MAX_ACTION_PAYLOAD { return Err(ActionFrameError::PayloadTooLarge); }
    let used = IEEE80211_HEADER_LEN + RAW_ACTION_PREFIX_LEN + payload.len();
    if out.len() < used { return Err(ActionFrameError::OutputTooSmall); }
    out[..IEEE80211_HEADER_LEN].fill(0); out[0] = 0xd0;
    out[4..10].copy_from_slice(&destination); out[10..16].copy_from_slice(&source);
    out[16..22].copy_from_slice(&bssid);
    let action = &mut out[IEEE80211_HEADER_LEN..used];
    action[..8].copy_from_slice(&action_header());
    action[8..16].copy_from_slice(&[VENDOR_IE_ID, 6, 0x18, 0xfe, 0x34, ACTION_TYPE, ESPNOW_V2_VERSION, 0]);
    action[RAW_ACTION_PREFIX_LEN..].copy_from_slice(payload);
    Ok(used)
}

/// Skip the entire vendor IE, including padding. Every following byte belongs
/// to the opaque datagram; monitor adapters remove FCS using capture metadata.
fn action_payload(action: &[u8]) -> Option<&[u8]> {
    if action.get(..4)? != ACTION_PREFIX { return None; }
    let ie = action.get(ACTION_HEADER_LEN..)?;
    if ie.first().copied()? != VENDOR_IE_ID || *ie.get(1)? < 5 ||
        ie.get(2..5)? != &ACTION_PREFIX[1..4] || *ie.get(5)? != ACTION_TYPE ||
        *ie.get(6)? & 0x0f != ESPNOW_V2_VERSION { return None; }
    let payload = ie.get(2 + usize::from(ie[1])..)?;
    (payload.len() <= MAX_ACTION_PAYLOAD).then_some(payload)
}

pub fn parse_action_frame(frame: &[u8]) -> Option<([u8; 6], &[u8])> {
    if *frame.first()? != 0xd0 { return None; }
    Some((frame.get(10..16)?.try_into().ok()?, action_payload(frame.get(IEEE80211_HEADER_LEN..)?)?))
}

pub fn parse_action_frame_into(frame: &[u8], output: &mut [u8]) -> Option<([u8; 6], usize)> {
    let (source, payload) = parse_action_frame(frame)?;
    output.get_mut(..payload.len())?.copy_from_slice(payload);
    Some((source, payload.len()))
}

pub fn parse_action_body_into(action: &[u8], output: &mut [u8]) -> Option<usize> {
    let payload = action_payload(action)?;
    output.get_mut(..payload.len())?.copy_from_slice(payload);
    Some(payload.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_wire_matches_c_firmware_vectors() {
        fn unhex(s: &str) -> Vec<u8> {
            (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect()
        }
        for line in include_str!("../tests/data/espnow-raw-frames.txt").lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let f: Vec<_> = line.split(' ').collect();
            if f[0] == "encode" {
                let n: usize = f[5].parse().unwrap();
                let data: Vec<_> = (0..n).map(|i| (i * 7 + 3) as u8).collect();
                let frame = build_action_frame([1,2,3,4,5,6], [6,5,4,3,2,1], [0xff; 6], &data).unwrap();
                assert_eq!(frame, unhex(f[6]));
            } else {
                let body = unhex(f[1]); let mut out = vec![0; MAX_ACTION_PAYLOAD];
                let got = parse_action_body_into(&body, &mut out);
                if f[2] == "none" { assert_eq!(got, None); }
                else { let n: usize = f[2].parse().unwrap(); assert_eq!(got, Some(n)); assert_eq!(&out[..n], unhex(f[3])); }
            }
        }
    }
    #[test]
    fn raw_envelope_round_trips_every_payload_size() {
        for n in [0, 1, 4, 250, 251, 700, MAX_ACTION_PAYLOAD] {
            let payload: Vec<_> = (0..n).map(|i| (i * 7 + 3) as u8).collect();
            let frame = build_action_frame([1; 6], [2; 6], [0xff; 6], &payload).unwrap();
            assert_eq!(frame.len(), IEEE80211_HEADER_LEN + RAW_ACTION_PREFIX_LEN + n);
            assert_eq!(parse_action_frame(&frame), Some(([2; 6], payload.as_slice())));
            let mut out = vec![0; n];
            assert_eq!(parse_action_body_into(&frame[24..], &mut out), Some(n));
            assert_eq!(out, payload);
        }
    }
    #[test]
    fn padded_ie_is_skipped_and_four_byte_tail_is_payload() {
        let mut action = Vec::from(action_header());
        action.extend_from_slice(&[0xdd, 9, 0x18, 0xfe, 0x34, 4, 2, 1, 2, 3, 4]);
        action.extend_from_slice(b"ping");
        let mut out = [0; 4];
        assert_eq!(parse_action_body_into(&action, &mut out), Some(4));
        assert_eq!(&out, b"ping");
        action[9] = 255;
        assert_eq!(parse_action_body_into(&action, &mut out), None);
    }
    #[test]
    fn malformed_and_oversize_frames_are_refused() {
        assert!(build_action_frame([0; 6], [1; 6], [0xff; 6], &[0; MAX_ACTION_PAYLOAD + 1]).is_err());
        let mut frame = build_action_frame([0; 6], [1; 6], [0xff; 6], b"data").unwrap();
        assert_eq!(parse_action_frame_into(&frame, &mut [0; 3]), None);
        frame[24] = 0;
        assert!(parse_action_frame(&frame).is_none());
    }
}
