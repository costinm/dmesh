//! Bounded, bearer-neutral discovery observation vocabulary.
//!
//! Adapters own their radio callbacks and local retention, but Android, Linux,
//! and ESP project their discovered-device lists through these same facts. A
//! missing field is an explicit unavailable platform observation, never an
//! inferred success.

use alloc::string::String;

pub const OBSERVATION_PEER: u32 = 1 << 0;
pub const OBSERVATION_BSSID: u32 = 1 << 1;
pub const OBSERVATION_CHANNEL: u32 = 1 << 2;
pub const OBSERVATION_RSSI: u32 = 1 << 3;
pub const OBSERVATION_PAYLOAD_FINGERPRINT: u32 = 1 << 4;
pub const OBSERVATION_ALL_FIELDS: u32 = OBSERVATION_PEER
    | OBSERVATION_BSSID
    | OBSERVATION_CHANNEL
    | OBSERVATION_RSSI
    | OBSERVATION_PAYLOAD_FINGERPRINT;

pub fn payload_hash(payload: &[u8]) -> u32 {
    payload.iter().fold(0x811c_9dc5u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryPacketKind {
    ActivePublish,
    ActiveSubscribe,
    Followup,
    Other,
}

impl DiscoveryPacketKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActivePublish => "active_publish",
            Self::ActiveSubscribe => "active_subscribe",
            Self::Followup => "followup",
            Self::Other => "other",
        }
    }
}

/// Receiver-side facts for one bearer and one discovered peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryObservation {
    /// Bitset of fields this adapter can report. A UI must render unavailable
    /// fields as unavailable, not as an RF failure or a zero-value fact.
    pub available_fields: u32,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub packets: u32,
    pub active_publish_rx: u32,
    pub active_subscribe_rx: u32,
    pub followup_rx: u32,
    pub last_kind: DiscoveryPacketKind,
    pub last_peer: String,
    pub last_bssid: Option<[u8; 6]>,
    pub last_channel: Option<u8>,
    pub last_rssi_dbm: Option<i16>,
    pub last_payload_len: u16,
    pub last_payload_hash: u32,
}

impl DiscoveryObservation {
    pub fn new(now_ms: i64, available_fields: u32) -> Self {
        Self {
            available_fields,
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
            packets: 0,
            active_publish_rx: 0,
            active_subscribe_rx: 0,
            followup_rx: 0,
            last_kind: DiscoveryPacketKind::Other,
            last_peer: String::new(),
            last_bssid: None,
            last_channel: None,
            last_rssi_dbm: None,
            last_payload_len: 0,
            last_payload_hash: 0,
        }
    }

    pub fn observe(
        &mut self,
        now_ms: i64,
        kind: DiscoveryPacketKind,
        peer: &str,
        bssid: Option<[u8; 6]>,
        channel: Option<u8>,
        rssi_dbm: Option<i16>,
        payload: &[u8],
    ) {
        self.last_seen_ms = now_ms;
        self.packets = self.packets.saturating_add(1);
        match kind {
            DiscoveryPacketKind::ActivePublish => {
                self.active_publish_rx = self.active_publish_rx.saturating_add(1)
            }
            DiscoveryPacketKind::ActiveSubscribe => {
                self.active_subscribe_rx = self.active_subscribe_rx.saturating_add(1)
            }
            DiscoveryPacketKind::Followup => self.followup_rx = self.followup_rx.saturating_add(1),
            DiscoveryPacketKind::Other => {}
        }
        self.last_kind = kind;
        self.last_peer.clear();
        self.last_peer.push_str(peer);
        self.last_bssid = bssid;
        self.last_channel = channel;
        self.last_rssi_dbm = rssi_dbm;
        self.last_payload_len = payload.len().min(u16::MAX as usize) as u16;
        self.last_payload_hash = payload_hash(payload);
    }

    /// Facts which the producing adapter cannot provide for this observation.
    /// Consumers render these explicitly as unavailable rather than treating a
    /// missing RSSI/channel/BSSID as a received zero value.
    pub const fn unavailable_fields(&self) -> u32 {
        OBSERVATION_ALL_FIELDS & !self.available_fields
    }
}

#[cfg(test)]
mod tests {
    use super::{DiscoveryObservation, DiscoveryPacketKind, OBSERVATION_ALL_FIELDS};

    #[test]
    fn observation_distinguishes_nan_packet_kinds() {
        let mut observation = DiscoveryObservation::new(10, OBSERVATION_ALL_FIELDS);
        observation.observe(
            11,
            DiscoveryPacketKind::ActivePublish,
            "peer",
            None,
            None,
            None,
            b"a",
        );
        observation.observe(
            12,
            DiscoveryPacketKind::ActiveSubscribe,
            "peer",
            None,
            None,
            None,
            b"b",
        );
        observation.observe(
            13,
            DiscoveryPacketKind::Followup,
            "peer",
            None,
            None,
            Some(-42),
            b"c",
        );
        assert_eq!(observation.first_seen_ms, 10);
        assert_eq!(observation.last_seen_ms, 13);
        assert_eq!(observation.packets, 3);
        assert_eq!(observation.active_publish_rx, 1);
        assert_eq!(observation.active_subscribe_rx, 1);
        assert_eq!(observation.followup_rx, 1);
        assert_eq!(observation.last_rssi_dbm, Some(-42));
        assert_eq!(observation.unavailable_fields(), 0);
    }
}
