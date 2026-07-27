use anyhow::{anyhow, bail, Result};

pub const MESHTASTIC_HEADER_LEN: usize = 16;
pub const MESHTASTIC_BROADCAST: u32 = u32::MAX;

// xor("MediumFast") ^ xor(psk), 0 psk (unencrypted) -> 0x1D
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

impl FrameKind {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "meshtastic" | "mt" => Ok(Self::Meshtastic),
            "raw" => Ok(Self::Raw),
            _ => bail!("unsupported frame format {value}"),
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
    pub fn hop_limit(self) -> u8 {
        self.flags & PACKET_FLAGS_HOP_LIMIT_MASK
    }

    pub fn hop_start(self) -> u8 {
        (self.flags & PACKET_FLAGS_HOP_START_MASK) >> PACKET_FLAGS_HOP_START_SHIFT
    }

    pub fn is_for(self, node: u32) -> bool {
        self.to == node
    }

    pub fn is_broadcast(self) -> bool {
        self.to == MESHTASTIC_BROADCAST
    }

    fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < MESHTASTIC_HEADER_LEN {
            return None;
        }
        let header = Self {
            to: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            from: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            id: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            flags: bytes[12],
            channel: bytes[13],
            next_hop: bytes[14],
            relay_node: bytes[15],
        };
        if header.to == 0 && header.from == 0 && header.id == 0 {
            None
        } else {
            Some(header)
        }
    }

    fn write(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to.to_le_bytes());
        out.extend_from_slice(&self.from.to_le_bytes());
        out.extend_from_slice(&self.id.to_le_bytes());
        out.push(self.flags);
        out.push(self.channel);
        out.push(self.next_hop);
        out.push(self.relay_node);
    }
}

pub struct DecodedFrame<'a> {
    pub kind: FrameKind,
    pub payload: &'a [u8],
    pub meshtastic: Option<MeshtasticHeader>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameAddress {
    pub kind: FrameKind,
    pub destination: Option<String>,
    pub local_match: bool,
    pub broadcast: bool,
}

pub fn encode_meshtastic_frame(
    payload: &[u8],
    sender: u32,
    packet_id: u32,
    channel: u8,
    hop_limit: u8,
) -> Result<Vec<u8>> {
    if payload.len() + MESHTASTIC_HEADER_LEN > 255 {
        bail!(
            "meshtastic LoRa payload too large: {} > {}",
            payload.len(),
            255 - MESHTASTIC_HEADER_LEN
        );
    }
    let hop_limit = hop_limit & PACKET_FLAGS_HOP_LIMIT_MASK;
    let header = MeshtasticHeader {
        to: MESHTASTIC_BROADCAST,
        from: sender,
        id: packet_id,
        flags: hop_limit
            | ((hop_limit << PACKET_FLAGS_HOP_START_SHIFT) & PACKET_FLAGS_HOP_START_MASK),
        channel,
        next_hop: 0,
        relay_node: 0,
    };
    let mut out = Vec::with_capacity(MESHTASTIC_HEADER_LEN + payload.len());
    header.write(&mut out);
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn encode_meshtastic_data(portnum: u32, payload: &[u8]) -> Result<Vec<u8>> {
    if portnum > 511 {
        bail!("Meshtastic portnum out of private/reserved range: {portnum}");
    }
    if payload.len() > MESHTASTIC_DATA_PAYLOAD_MAX {
        bail!(
            "Meshtastic Data payload too large: {} > {}",
            payload.len(),
            MESHTASTIC_DATA_PAYLOAD_MAX
        );
    }
    let mut out = Vec::with_capacity(5 + payload.len());
    encode_varint((1 << 3) | 0, &mut out);
    encode_varint(portnum, &mut out);
    encode_varint((2 << 3) | 2, &mut out);
    encode_varint(payload.len() as u32, &mut out);
    out.extend_from_slice(payload);
    Ok(out)
}

fn encode_varint(mut value: u32, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

pub fn decode_frame(bytes: &[u8]) -> Result<DecodedFrame<'_>> {
    if let Some(header) = MeshtasticHeader::parse(bytes) {
        return Ok(DecodedFrame {
            kind: FrameKind::Meshtastic,
            payload: &bytes[MESHTASTIC_HEADER_LEN..],
            meshtastic: Some(header),
        });
    }

    Ok(DecodedFrame {
        kind: FrameKind::Raw,
        payload: bytes,
        meshtastic: None,
    })
}

pub fn address_metadata(
    bytes: &[u8],
    settings: &super::settings::SharedSettings,
) -> Result<FrameAddress> {
    let decoded = decode_frame(bytes)?;
    let Some(header) = decoded.meshtastic else {
        return Ok(FrameAddress {
            kind: decoded.kind,
            destination: None,
            local_match: false,
            broadcast: false,
        });
    };
    let destination = format_meshtastic_node(header.to);
    let local_match = settings
        .borrow()
        .get_str("identity.meshtastic")?
        .or_else(|| settings.borrow().get_str("identity.node").ok().flatten())
        .map(|value| normalize_node(&value) == Some(header.to))
        .unwrap_or(false);
    Ok(FrameAddress {
        kind: decoded.kind,
        destination: Some(destination),
        local_match,
        broadcast: header.is_broadcast(),
    })
}

pub fn format_meshtastic_node(node: u32) -> String {
    format!("{node:08x}")
}

fn normalize_node(value: &str) -> Option<u32> {
    let value = value.trim();
    let value = value.strip_prefix('!').unwrap_or(value);
    let value = value.strip_prefix("0x").unwrap_or(value);
    u32::from_str_radix(value, 16)
        .ok()
        .or_else(|| value.parse::<u32>().ok())
}

pub fn parse_bytes(value: &str) -> Result<Vec<u8>> {
    let value = value.strip_prefix("hex:").unwrap_or(value);
    if value.contains(',') {
        return value
            .split(',')
            .map(|v| Ok(parse_i32(v.trim())? as u8))
            .collect();
    }
    if value.len() % 2 != 0 {
        bail!("hex byte string must have even length");
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(Into::into))
        .collect()
}

pub fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn parse_i32(value: &str) -> Result<i32> {
    if let Some(hex) = value.strip_prefix("0x") {
        i32::from_str_radix(hex, 16).map_err(|err| anyhow!("invalid hex integer {value}: {err}"))
    } else {
        value
            .parse::<i32>()
            .map_err(|err| anyhow!("invalid integer {value}: {err}"))
    }
}
