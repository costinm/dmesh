//! Meshtastic packet framing owned by the LoRa module.
//!
//! Main deliberately treats radio payloads as opaque bytes.  Keeping this
//! codec beside the radio policy prevents the ESP application from growing a
//! second, subtly different Meshtastic implementation.

pub const MESHTASTIC_HEADER_LEN: usize = 16;
pub const MESHTASTIC_MAX_FRAME_LEN: usize = 255;
pub const MESHTASTIC_BROADCAST: u32 = u32::MAX;
pub const MESHTASTIC_DEFAULT_CHANNEL_HASH: u8 = 0x1d;
pub const MESHTASTIC_DEFAULT_HOP_LIMIT: u8 = 0;
pub const MESHTASTIC_DEFAULT_PORTNUM: u32 = 256;
const MESHTASTIC_DATA_PAYLOAD_MAX: usize = 233;

const PACKET_FLAGS_HOP_LIMIT_MASK: u8 = 0x07;
const PACKET_FLAGS_HOP_START_MASK: u8 = 0xe0;
const PACKET_FLAGS_HOP_START_SHIFT: u8 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameKind {
    Meshtastic,
    Raw,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameError {
    UnsupportedFormat,
    FrameTooLarge,
    PortOutOfRange,
    DataTooLarge,
}

pub type Result<T> = core::result::Result<T, FrameError>;

impl FrameKind {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "meshtastic" | "mt" => Ok(Self::Meshtastic),
            "raw" => Ok(Self::Raw),
            _ => Err(FrameError::UnsupportedFormat),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MeshtasticHeader {
    pub to: u32,
    pub from: u32,
    pub id: u32,
    pub flags: u8,
    pub channel: u8,
    pub next_hop: u8,
    pub relay_node: u8,
}

impl MeshtasticHeader {
    pub fn hop_limit(self) -> u8 { self.flags & PACKET_FLAGS_HOP_LIMIT_MASK }

    pub fn hop_start(self) -> u8 {
        (self.flags & PACKET_FLAGS_HOP_START_MASK) >> PACKET_FLAGS_HOP_START_SHIFT
    }

    pub fn is_for(self, node: u32) -> bool { self.to == node }

    pub fn is_broadcast(self) -> bool { self.to == MESHTASTIC_BROADCAST }

    fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < MESHTASTIC_HEADER_LEN { return None; }
        let header = Self {
            to: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            from: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            id: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            flags: bytes[12],
            channel: bytes[13],
            next_hop: bytes[14],
            relay_node: bytes[15],
        };
        (header.to != 0 || header.from != 0 || header.id != 0).then_some(header)
    }

    fn write(self, out: &mut [u8]) {
        out[0..4].copy_from_slice(&self.to.to_le_bytes());
        out[4..8].copy_from_slice(&self.from.to_le_bytes());
        out[8..12].copy_from_slice(&self.id.to_le_bytes());
        out[12..16].copy_from_slice(&[self.flags, self.channel, self.next_hop, self.relay_node]);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameBytes {
    pub bytes: [u8; MESHTASTIC_MAX_FRAME_LEN],
    pub len: usize,
}

pub struct DecodedFrame<'a> {
    pub kind: FrameKind,
    pub payload: &'a [u8],
    pub meshtastic: Option<MeshtasticHeader>,
}

pub fn encode_meshtastic_frame(
    payload: &[u8], sender: u32, packet_id: u32, channel: u8, hop_limit: u8,
) -> Result<FrameBytes> {
    if payload.len() + MESHTASTIC_HEADER_LEN > 255 {
        return Err(FrameError::FrameTooLarge);
    }
    let hop_limit = hop_limit & PACKET_FLAGS_HOP_LIMIT_MASK;
    let header = MeshtasticHeader {
        to: MESHTASTIC_BROADCAST,
        from: sender,
        id: packet_id,
        flags: hop_limit | ((hop_limit << PACKET_FLAGS_HOP_START_SHIFT) & PACKET_FLAGS_HOP_START_MASK),
        channel,
        next_hop: 0,
        relay_node: 0,
    };
    let len = MESHTASTIC_HEADER_LEN + payload.len();
    let mut out = [0u8; MESHTASTIC_MAX_FRAME_LEN];
    header.write(&mut out[..MESHTASTIC_HEADER_LEN]);
    out[MESHTASTIC_HEADER_LEN..len].copy_from_slice(payload);
    Ok(FrameBytes { bytes: out, len })
}

pub fn encode_meshtastic_data(portnum: u32, payload: &[u8]) -> Result<FrameBytes> {
    if portnum > 511 { return Err(FrameError::PortOutOfRange); }
    if payload.len() > MESHTASTIC_DATA_PAYLOAD_MAX { return Err(FrameError::DataTooLarge); }
    let mut out = [0u8; MESHTASTIC_MAX_FRAME_LEN];
    let mut len = 0;
    encode_varint((1 << 3) | 0, &mut out, &mut len);
    encode_varint(portnum, &mut out, &mut len);
    encode_varint((2 << 3) | 2, &mut out, &mut len);
    encode_varint(payload.len() as u32, &mut out, &mut len);
    out[len..len + payload.len()].copy_from_slice(payload);
    len += payload.len();
    Ok(FrameBytes { bytes: out, len })
}

fn encode_varint(mut value: u32, out: &mut [u8], len: &mut usize) {
    while value >= 0x80 {
        out[*len] = (value as u8 & 0x7f) | 0x80;
        *len += 1;
        value >>= 7;
    }
    out[*len] = value as u8;
    *len += 1;
}

pub fn decode_frame(bytes: &[u8]) -> DecodedFrame<'_> {
    if let Some(header) = MeshtasticHeader::parse(bytes) {
        return DecodedFrame {
            kind: FrameKind::Meshtastic,
            payload: &bytes[MESHTASTIC_HEADER_LEN..],
            meshtastic: Some(header),
        };
    }
    DecodedFrame { kind: FrameKind::Raw, payload: bytes, meshtastic: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meshtastic_frame_round_trips_header_and_payload() {
        let frame = encode_meshtastic_frame(b"hello", 0x0102_0304, 7, 0x1d, 2).unwrap();
        let decoded = decode_frame(&frame.bytes[..frame.len]);
        assert_eq!(decoded.kind, FrameKind::Meshtastic);
        assert_eq!(decoded.payload, b"hello");
        let header = decoded.meshtastic.unwrap();
        assert_eq!(header.to, MESHTASTIC_BROADCAST);
        assert_eq!(header.from, 0x0102_0304);
        assert_eq!(header.id, 7);
        assert_eq!(header.hop_limit(), 2);
        assert_eq!(header.hop_start(), 2);
    }

    #[test]
    fn raw_payload_is_not_misclassified() {
        let decoded = decode_frame(b"raw");
        assert_eq!(decoded.kind, FrameKind::Raw);
        assert!(decoded.meshtastic.is_none());
    }
}
