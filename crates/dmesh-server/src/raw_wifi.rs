//! CBOR schema for bounded raw 802.11 hardware experiments.
//!
//! This is deliberately host- and ESP-independent. Adapters apply the typed
//! request to their radio APIs; the request never implies a socket API.

use crate::cbor::Decoder;

pub const RAW_WIFI_OP_TX: u64 = 1;
pub const RAW_WIFI_MAX_FRAME: usize = 1500;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawWifiInterface {
    Auto,
    Sta,
    Ap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawWifiRate {
    Auto,
    Mbps6,
    Mbps9,
    Mbps12,
    Mbps18,
    Mbps24,
    Mbps36,
    Mbps48,
    Mbps54,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawWifiTxRequest<'a> {
    pub channel: u8,
    pub interface: RawWifiInterface,
    pub system_sequence: bool,
    pub rate: RawWifiRate,
    pub disable_11b: bool,
    pub frame: &'a [u8],
}

/// Decode canonical CBOR map keys: 0=operation, 1=frame bytes, 2=channel,
/// 3=interface (0 auto, 1 sta, 2 ap), 4=system sequence, 5=rate, 6=disable
/// 11b. Unknown keys are skipped so host tooling can add observation-only
/// fields without changing firmware parsers.
pub fn decode_raw_wifi_tx(data: &[u8]) -> Result<RawWifiTxRequest<'_>, &'static str> {
    let mut decoder = Decoder::new(data);
    let (major, entries) = decoder.head().ok_or("raw wifi CBOR")?;
    if major != 5 {
        return Err("raw wifi map");
    }
    let mut operation = None;
    let mut frame = None;
    let mut channel = 6u8;
    let mut interface = RawWifiInterface::Auto;
    let mut system_sequence = true;
    let mut rate = RawWifiRate::Auto;
    let mut disable_11b = true;
    for _ in 0..entries {
        let key = decoder.uint().ok_or("raw wifi key")?;
        match key {
            0 => operation = Some(decoder.uint().ok_or("raw wifi operation")?),
            1 => frame = Some(decoder.bytes_ref().ok_or("raw wifi frame")?),
            2 => {
                channel = u8::try_from(decoder.uint().ok_or("raw wifi channel")?)
                    .map_err(|_| "raw wifi channel")?
            }
            3 => {
                interface = match decoder.uint().ok_or("raw wifi interface")? {
                    0 => RawWifiInterface::Auto,
                    1 => RawWifiInterface::Sta,
                    2 => RawWifiInterface::Ap,
                    _ => return Err("raw wifi interface"),
                }
            }
            4 => system_sequence = decoder.boolean().ok_or("raw wifi system sequence")?,
            5 => {
                rate = match decoder.uint().ok_or("raw wifi rate")? {
                    0 => RawWifiRate::Auto,
                    6 => RawWifiRate::Mbps6,
                    9 => RawWifiRate::Mbps9,
                    12 => RawWifiRate::Mbps12,
                    18 => RawWifiRate::Mbps18,
                    24 => RawWifiRate::Mbps24,
                    36 => RawWifiRate::Mbps36,
                    48 => RawWifiRate::Mbps48,
                    54 => RawWifiRate::Mbps54,
                    _ => return Err("raw wifi rate"),
                }
            }
            6 => disable_11b = decoder.boolean().ok_or("raw wifi disable 11b")?,
            _ => decoder.skip().ok_or("raw wifi value")?,
        }
    }
    if !decoder.is_finished() || operation != Some(RAW_WIFI_OP_TX) {
        return Err("raw wifi operation");
    }
    let frame = frame.ok_or("raw wifi frame")?;
    if !(24..=RAW_WIFI_MAX_FRAME).contains(&frame.len()) || !(1..=13).contains(&channel) {
        return Err("raw wifi bounds");
    }
    Ok(RawWifiTxRequest {
        channel,
        interface,
        system_sequence,
        rate,
        disable_11b,
        frame,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::Encoder;

    #[test]
    fn raw_tx_schema_decodes_all_radio_controls() {
        let frame = [0xd0; 24];
        let mut wire = [0; 80];
        let mut e = Encoder::new(&mut wire);
        e.map(7).unwrap();
        e.uint(0).unwrap();
        e.uint(RAW_WIFI_OP_TX).unwrap();
        e.uint(1).unwrap();
        e.bytes_value(&frame).unwrap();
        e.uint(2).unwrap();
        e.uint(6).unwrap();
        e.uint(3).unwrap();
        e.uint(2).unwrap();
        e.uint(4).unwrap();
        e.boolean(false).unwrap();
        e.uint(5).unwrap();
        e.uint(24).unwrap();
        e.uint(6).unwrap();
        e.boolean(false).unwrap();
        let used = e.len();
        drop(e);
        let request = decode_raw_wifi_tx(&wire[..used]).unwrap();
        assert_eq!(request.interface, RawWifiInterface::Ap);
        assert_eq!(request.rate, RawWifiRate::Mbps24);
        assert!(!request.system_sequence && !request.disable_11b);
        assert_eq!(request.frame, frame);
    }
}
