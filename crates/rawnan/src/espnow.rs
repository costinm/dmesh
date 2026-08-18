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
const VENDOR_IE_HEADER_LEN: usize = 7;
const VENDOR_IE_ID: u8 = 0xdd;
/// A raw QUIC datagram may span several ESP-NOW v2 vendor IEs. This is our
/// raw bearer envelope only: it does not opt into ESP-IDF peer management,
/// encryption, or its send/receive callbacks.
pub const MAX_ACTION_PAYLOAD: usize = 1400;
const MAX_IE_BODY: usize = 250;
const ESPNOW_V2_VERSION: u8 = 2;

/// Wire layout for the raw QUIC bearer. Both remain one action frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionFrameLayout {
    /// Standard ESP-NOW v2-style sequence of 250-byte vendor IEs.
    V2Elements,
    /// One valid vendor IE followed by the remaining raw QUIC bytes. This is
    /// an ESP receive-filter experiment, not a claim of ESP-NOW API support.
    FirstIeThenTail,
}

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
    let elements = payload.len().div_ceil(MAX_IE_BODY);
    let mut frame = vec![
        0;
        IEEE80211_HEADER_LEN
            + ACTION_HEADER_LEN
            + elements * VENDOR_IE_HEADER_LEN
            + payload.len()
    ];
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
    out: &mut [u8],
    destination: [u8; 6],
    source: [u8; 6],
    bssid: [u8; 6],
    payload: &[u8],
) -> core::result::Result<usize, ActionFrameError> {
    encode_action_frame_with_layout(
        out,
        destination,
        source,
        bssid,
        payload,
        ActionFrameLayout::V2Elements,
    )
}

/// Encode one raw QUIC action frame with an explicitly chosen IE layout.
pub fn encode_action_frame_with_layout(
    out: &mut [u8],
    destination: [u8; 6],
    source: [u8; 6],
    bssid: [u8; 6],
    payload: &[u8],
    layout: ActionFrameLayout,
) -> core::result::Result<usize, ActionFrameError> {
    if payload.len() > MAX_ACTION_PAYLOAD {
        return Err(ActionFrameError::PayloadTooLarge);
    }
    let elements = match layout {
        ActionFrameLayout::V2Elements => payload.len().div_ceil(MAX_IE_BODY),
        ActionFrameLayout::FirstIeThenTail => 1,
    };
    let used =
        IEEE80211_HEADER_LEN + ACTION_HEADER_LEN + elements * VENDOR_IE_HEADER_LEN + payload.len();
    if out.len() < used {
        return Err(ActionFrameError::OutputTooSmall);
    }
    out[..used].fill(0);
    out[..4].copy_from_slice(&[0xd0, 0, 0, 0]);
    out[4..10].copy_from_slice(&destination);
    out[10..16].copy_from_slice(&source);
    out[16..22].copy_from_slice(&bssid);
    let action = &mut out[IEEE80211_HEADER_LEN..used];
    action[..ACTION_HEADER_LEN].copy_from_slice(&action_header());
    let mut payload_offset = 0;
    let mut ie_offset = ACTION_HEADER_LEN;
    while payload_offset < payload.len() {
        let chunk_len = (payload.len() - payload_offset).min(MAX_IE_BODY);
        let ie = &mut action[ie_offset..ie_offset + VENDOR_IE_HEADER_LEN + chunk_len];
        ie[0] = VENDOR_IE_ID;
        ie[1] = (5 + chunk_len) as u8;
        ie[2..5].copy_from_slice(&ACTION_PREFIX[1..4]);
        ie[5] = ACTION_TYPE;
        let has_next_ie = matches!(layout, ActionFrameLayout::V2Elements)
            && payload_offset + chunk_len < payload.len();
        ie[6] = ESPNOW_V2_VERSION | if has_next_ie { 0x10 } else { 0 };
        ie[VENDOR_IE_HEADER_LEN..]
            .copy_from_slice(&payload[payload_offset..payload_offset + chunk_len]);
        payload_offset += chunk_len;
        ie_offset += VENDOR_IE_HEADER_LEN + chunk_len;
        if matches!(layout, ActionFrameLayout::FirstIeThenTail) {
            action[ie_offset..ie_offset + payload.len() - payload_offset]
                .copy_from_slice(&payload[payload_offset..]);
            break;
        }
    }
    Ok(used)
}

/// Parse a raw-injected ESP-NOW-compatible action frame. The adapter owns
/// monitor metadata and optional FCS removal; this function only validates
/// the portable 802.11/action envelope and returns the complete L2 payload.
pub fn parse_action_frame(frame: &[u8]) -> Option<([u8; 6], &[u8])> {
    if frame.len() < IEEE80211_HEADER_LEN + ACTION_HEADER_LEN + VENDOR_IE_HEADER_LEN
        || frame[0] != 0xd0
    {
        return None;
    }
    let source = frame.get(10..16)?.try_into().ok()?;
    let action = frame.get(IEEE80211_HEADER_LEN..)?;
    if action.get(..4) != Some(&ACTION_PREFIX) {
        return None;
    }
    let ie = action.get(ACTION_HEADER_LEN..)?;
    if ie.first().copied() != Some(VENDOR_IE_ID)
        || ie.get(2..5) != Some(&ACTION_PREFIX[1..4])
        || ie.get(5).copied() != Some(ACTION_TYPE)
        || ie.get(6).copied().map(|value| value & 0x0f) != Some(ESPNOW_V2_VERSION)
        || ie.get(6).copied().is_some_and(|value| value & 0x10 != 0)
    {
        return None;
    }
    let payload_len = ie.get(1).copied()?.checked_sub(5)? as usize;
    let payload = ie.get(VENDOR_IE_HEADER_LEN..VENDOR_IE_HEADER_LEN + payload_len)?;
    Some((source, payload))
}

/// Parse a possibly multi-IE raw QUIC bearer frame into caller-owned storage.
/// This makes the v2 envelope host-testable without imposing an ESP-IDF
/// allocation or a socket-shaped API on either adapter.
pub fn parse_action_frame_into(frame: &[u8], output: &mut [u8]) -> Option<([u8; 6], usize)> {
    if frame.len() < IEEE80211_HEADER_LEN + ACTION_HEADER_LEN + VENDOR_IE_HEADER_LEN
        || frame[0] != 0xd0
    {
        return None;
    }
    if frame.get(IEEE80211_HEADER_LEN..IEEE80211_HEADER_LEN + 4)? != ACTION_PREFIX {
        return None;
    }
    let source = frame.get(10..16)?.try_into().ok()?;
    let mut ie_offset: usize = IEEE80211_HEADER_LEN + ACTION_HEADER_LEN;
    let mut written: usize = 0;
    loop {
        let ie = frame.get(ie_offset..)?;
        let element_len = ie.get(1).copied()? as usize;
        let end = 2usize.checked_add(element_len)?;
        let element = ie.get(..end)?;
        if element[0] != VENDOR_IE_ID
            || element_len < 5
            || element.get(2..5) != Some(&ACTION_PREFIX[1..4])
            || element[5] != ACTION_TYPE
            || element[6] & 0x0f != ESPNOW_V2_VERSION
        {
            return None;
        }
        let body = &element[VENDOR_IE_HEADER_LEN..];
        let next = written.checked_add(body.len())?;
        if next > output.len() {
            return None;
        }
        output[written..next].copy_from_slice(body);
        written = next;
        let more = element[6] & 0x10 != 0;
        ie_offset = ie_offset.checked_add(end)?;
        if !more {
            // The one-IE-plus-tail form is an RX-filter experiment. It is
            // still a single frame and lets both raw adapters validate the
            // same QUIC bytes without pretending to be ESP-IDF ESP-NOW.
            let tail = frame.get(ie_offset..).unwrap_or_default();
            // ESP promiscuous metadata may retain the 802.11 FCS. A complete
            // v2 IE sequence has no tail, except for that four-byte checksum;
            // do not turn it into four bogus QUIC bytes. Any other tail is
            // the explicit one-IE-plus-tail lab layout.
            if tail.len() == 4 {
                return Some((source, written));
            }
            let next = written.checked_add(tail.len())?;
            if next > output.len() {
                return None;
            }
            output[written..next].copy_from_slice(tail);
            return Some((source, next));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_frame_round_trip_preserves_addresses_and_payload() {
        let destination = [1, 2, 3, 4, 5, 6];
        let source = [6, 5, 4, 3, 2, 1];
        let payload = [0x40, 0x01, 0x02, 0x03];
        let frame = build_action_frame(destination, source, [0xff; 6], &payload).unwrap();

        assert_eq!(
            parse_action_frame(&frame),
            Some((source, payload.as_slice()))
        );
    }

    #[test]
    fn action_frame_rejects_foreign_and_oversize_data() {
        assert!(
            build_action_frame([0; 6], [1; 6], [0xff; 6], &[0; MAX_ACTION_PAYLOAD + 1]).is_err()
        );
        assert!(parse_action_frame(
            &[0xd0; IEEE80211_HEADER_LEN + ACTION_HEADER_LEN + VENDOR_IE_HEADER_LEN]
        )
        .is_none());
    }

    #[test]
    fn action_frame_encodes_in_caller_owned_storage() {
        let destination = [1, 2, 3, 4, 5, 6];
        let source = [6, 5, 4, 3, 2, 1];
        let payload = [0x40, 0x01, 0x02, 0x03];
        let mut frame = [0xa5; 64];
        let used =
            encode_action_frame(&mut frame, destination, source, [0xff; 6], &payload).unwrap();
        assert_eq!(
            parse_action_frame(&frame[..used]),
            Some((source, payload.as_slice()))
        );
        assert_eq!(
            encode_action_frame(
                &mut frame,
                destination,
                source,
                [0xff; 6],
                &[0; MAX_ACTION_PAYLOAD + 1]
            ),
            Err(ActionFrameError::PayloadTooLarge)
        );
    }

    #[test]
    fn v2_elements_reassemble_a_full_quic_datagram() {
        let destination = [1, 2, 3, 4, 5, 6];
        let source = [6, 5, 4, 3, 2, 1];
        let payload = [0x5a; 700];
        let frame = build_action_frame(destination, source, [0xff; 6], &payload).unwrap();
        assert!(parse_action_frame(&frame).is_none());
        let mut output = [0; 700];
        assert_eq!(
            parse_action_frame_into(&frame, &mut output),
            Some((source, 700))
        );
        assert_eq!(output, payload);
    }

    #[test]
    fn v2_elements_ignore_a_promiscuous_fcs_tail() {
        let destination = [1, 2, 3, 4, 5, 6];
        let source = [6, 5, 4, 3, 2, 1];
        let payload = [0x5a; 300];
        let mut frame = build_action_frame(destination, source, [0xff; 6], &payload).unwrap();
        frame.extend_from_slice(&[1, 2, 3, 4]);
        let mut output = [0; 300];
        assert_eq!(
            parse_action_frame_into(&frame, &mut output),
            Some((source, 300))
        );
        assert_eq!(output, payload);
    }

    #[test]
    fn one_ie_then_tail_reassembles_a_full_quic_datagram() {
        let destination = [1, 2, 3, 4, 5, 6];
        let source = [6, 5, 4, 3, 2, 1];
        let payload = [0xa5; 700];
        let mut frame = [0; 800];
        let used = encode_action_frame_with_layout(
            &mut frame,
            destination,
            source,
            [0xff; 6],
            &payload,
            ActionFrameLayout::FirstIeThenTail,
        )
        .unwrap();
        let mut output = [0; 700];
        assert_eq!(
            parse_action_frame_into(&frame[..used], &mut output),
            Some((source, 700))
        );
        assert_eq!(output, payload);
    }
}
