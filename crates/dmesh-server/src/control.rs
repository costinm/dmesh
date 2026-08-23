//! Core DMesh control-plane schema.
//!
//! These methods use the canonical tagged envelope and deliberately fit in a
//! single bearer message.  UART, UDP6, NAN service discovery/follow-ups,
//! ESP-NOW actions, LoRa, and a QUIC stream can therefore invoke the same
//! operation.  Reliability and ordering are properties of the selected
//! bearer, not of this schema.

use crate::{
    cbor::{Decoder, Encoder},
    tagged::{Name, Record, decode},
};

/// Component for device-local settings and transport lifecycle.  Board modules
/// receive their own component IDs rather than adding methods here.
pub const CONTROL_COMPONENT: u64 = 1;
pub const SETTINGS_GET: u64 = 1;
pub const SETTINGS_SET: u64 = 2;
pub const SETTINGS_LIST: u64 = 3;
pub const TRANSPORT_START: u64 = 4;
pub const TRANSPORT_STOP: u64 = 5;

const FIELD_KEY: u64 = 1;
const FIELD_VALUE: u64 = 2;
const FIELD_MODE: u64 = 1;
/// Volatile STA target for `transport.start`. It is intentionally not a
/// setting: UART and future NAN Service Info use the same association command.
const FIELD_STA_SSID: u64 = 2;
/// Optional AP identity/channel learned from `lmesh-wifi` or future NAN SD.
/// They are part of the immutable association target, not radio-lab state.
const FIELD_STA_BSSID: u64 = 3;
const FIELD_STA_CHANNEL: u64 = 4;
const FIELD_RAW_TX_RATE: u64 = 5;
const FIELD_STA_DRIVER_TX: u64 = 6;
const FIELD_STA_BSSID_CHECK_DISABLED: u64 = 7;
const FIELD_STA_AMPDU_ENABLED: u64 = 8;
const FIELD_STA_11B_RATES_DISABLED: u64 = 9;
const FIELD_STA_RAW_RX_ENABLED: u64 = 10;
const FIELD_ESPNOW_CAPTURE: u64 = 13;
/// NAN discovery-window cadence, in 512 ms discovery windows. `0` disables
/// promiscuous NAN capture; `1` captures every DW; `8` and `16` select the
/// four- and eight-second cadences.
const FIELD_NAN_DW_INTERVAL: u64 = 14;
/// Associated NOW action policy. `0` is the default/on, `1` is explicit on,
/// and `2` is explicit off. Future controls such as `udp6` remain independent
/// rather than minting another transport-start name.
const FIELD_NOW: u64 = 15;
/// Start a local AP alongside either physical mode. `0` is off and `1` is on.
const FIELD_AP: u64 = 16;
/// Optional WPA2 passphrase for an ephemeral STA target, for example an
/// Android P2P Group Owner. It is transport-start session data, never a
/// setting or persisted credential.
const FIELD_STA_PASSPHRASE: u64 = 17;
/// UART ownership/speed selector for the applied profile. Tag 18 preserves the
/// existing passphrase field while keeping this addition backward-compatible.
/// `0` disables UART, `1` means 115200 baud, and `2..=7` select the other
/// common baud rates. USB packet mode ignores the numeric speed.
const FIELD_UART: u64 = 18;
/// Enable the NAN Data Path (NDP) bearer for this immutable radio epoch.
/// NDP is meaningful only to adapters that implement it today (Android), but
/// it belongs in the common start record so peers can negotiate it without an
/// Android-only control schema.
const FIELD_NDP: u64 = 19;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportKind {
    /// Associate with an infrastructure AP.
    Sta,
    /// Do not associate with an infrastructure AP.
    Nan,
    Uart,
}

/// Volatile physical-bearer parameters captured atomically by
/// `transport.start`. They are immutable for that Wi-Fi radio epoch; changing
/// any one requires a new `transport.start`, which replaces the old epoch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransportConfig<'a> {
    pub ssid: Option<&'a [u8]>,
    pub passphrase: Option<&'a [u8]>,
    pub bssid: Option<[u8; 6]>,
    pub channel: Option<u8>,
    pub raw_tx_rate: Option<u8>,
    pub sta_driver_tx: Option<bool>,
    pub sta_bssid_check_disabled: Option<bool>,
    pub sta_ampdu_enabled: Option<bool>,
    pub sta_11b_rates_disabled: Option<bool>,
    pub sta_raw_rx_enabled: Option<bool>,
    pub espnow_capture: Option<bool>,
    pub nan_dw_interval: Option<u8>,
    pub now: Option<u8>,
    /// `0` disables and `1` enables NAN Data Path where the adapter supports
    /// it. Unsupported adapters retain the requested profile and report their
    /// capability separately rather than reinterpreting the field.
    pub ndp: Option<u8>,
    pub ap: Option<u8>,
    pub uart: Option<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request<'a> {
    SettingsGet {
        key: &'a [u8],
    },
    SettingsSet {
        key: &'a [u8],
        value: &'a [u8],
    },
    SettingsList,
    TransportStart {
        kind: TransportKind,
        config: TransportConfig<'a>,
    },
    TransportStop {
        kind: TransportKind,
    },
}

/// Platform adapter for the common control component. The trait deliberately
/// receives typed operations rather than CBOR: host configuration, ESP NVS,
/// and radio owners share the same routing and validation below.
pub trait Handler {
    type Error;

    fn settings_get(&mut self, key: &[u8]) -> Result<(), Self::Error>;
    fn settings_set(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error>;
    fn settings_list(&mut self) -> Result<(), Self::Error>;
    fn transport_start(
        &mut self,
        kind: TransportKind,
        config: TransportConfig<'_>,
    ) -> Result<(), Self::Error>;
    fn transport_stop(&mut self, kind: TransportKind) -> Result<(), Self::Error>;
}

/// Error returned by the shared tagged-control dispatcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchError<E> {
    MalformedOrDirected,
    Handler(E),
}

/// Decode and apply one local control record. Directed records are rejected
/// before an adapter runs: a mesh ingress must first route `to` via
/// `raw_dispatch::route_tagged`.
pub fn dispatch<H: Handler>(packet: &[u8], handler: &mut H) -> Result<(), DispatchError<H::Error>> {
    let request = decode_request(packet).ok_or(DispatchError::MalformedOrDirected)?;
    dispatch_request(request, handler).map_err(DispatchError::Handler)
}

/// Apply an already-decoded request. This is useful after a mesh-aware ingress
/// has selected a local destination without re-parsing or copying CBOR.
pub fn dispatch_request<H: Handler>(request: Request<'_>, handler: &mut H) -> Result<(), H::Error> {
    match request {
        Request::SettingsGet { key } => handler.settings_get(key),
        Request::SettingsSet { key, value } => handler.settings_set(key, value),
        Request::SettingsList => handler.settings_list(),
        Request::TransportStart { kind, config } => handler.transport_start(kind, config),
        Request::TransportStop { kind } => handler.transport_stop(kind),
    }
}

/// Decode one local tagged direct-control request. Directed records are
/// rejected here: a mesh-aware bearer must use `raw_dispatch::route_tagged`,
/// choose a next hop, and only then invoke `decode_record` after removing the
/// routing metadata. A Recovery device must never execute a `to` request as
/// though it were addressed locally.
pub fn decode_request(packet: &[u8]) -> Option<Request<'_>> {
    let record = decode(packet)?;
    if record.to.is_some() {
        return None;
    }
    decode_record(record)
}

pub fn decode_record(record: Record<'_>) -> Option<Request<'_>> {
    if record.component != Some(Name::Tag(CONTROL_COMPONENT)) {
        return None;
    }
    let fields = record.fields?;
    match record.method? {
        Name::Tag(SETTINGS_GET) => Some(Request::SettingsGet {
            key: field_bytes(fields, FIELD_KEY)?,
        }),
        Name::Tag(SETTINGS_SET) => Some(Request::SettingsSet {
            key: field_bytes(fields, FIELD_KEY)?,
            value: field_bytes(fields, FIELD_VALUE)?,
        }),
        Name::Tag(SETTINGS_LIST) => map_is_empty(fields).then_some(Request::SettingsList),
        Name::Tag(TRANSPORT_START) => Some(Request::TransportStart {
            kind: transport_kind(field_uint(fields, FIELD_MODE)?)?,
            config: decode_transport_config(fields)?,
        }),
        Name::Tag(TRANSPORT_STOP) => Some(Request::TransportStop {
            kind: transport_kind(field_uint(fields, FIELD_MODE)?)?,
        }),
        _ => None,
    }
}

fn transport_kind(value: u64) -> Option<TransportKind> {
    Some(match value {
        1 => TransportKind::Sta,
        5 => TransportKind::Uart,
        // Appended after retiring the old combined modes. Values 2, 3, and 4
        // are deliberately rejected rather than reinterpreted.
        6 => TransportKind::Nan,
        _ => return None,
    })
}

fn decode_transport_config(encoded: &[u8]) -> Option<TransportConfig<'_>> {
    let mut d = Decoder::new(encoded);
    let (major, count) = d.head()?;
    if major != 5 || count == u64::MAX {
        return None;
    }
    let mut config = TransportConfig::default();
    for _ in 0..count {
        match d.uint()? {
            FIELD_STA_SSID => {
                let ssid = d.text_ref().or_else(|| d.bytes_ref())?;
                if ssid.is_empty() || ssid.len() > 32 || ssid.contains(&0) {
                    return None;
                }
                config.ssid = Some(ssid);
            }
            FIELD_STA_BSSID => {
                let bytes = d.bytes_ref()?;
                config.bssid = (bytes.len() == 6).then(|| bytes.try_into().ok()).flatten();
            }
            FIELD_STA_CHANNEL => {
                let channel = u8::try_from(d.uint()?).ok()?;
                if !(1..=14).contains(&channel) {
                    return None;
                }
                config.channel = Some(channel);
            }
            FIELD_STA_PASSPHRASE => {
                let passphrase = d.text_ref().or_else(|| d.bytes_ref())?;
                if !(8..=63).contains(&passphrase.len()) || passphrase.contains(&0) {
                    return None;
                }
                config.passphrase = Some(passphrase);
            }
            FIELD_RAW_TX_RATE => {
                let rate = d.uint()? as u8;
                if !matches!(rate, 0 | 6 | 9 | 12 | 18 | 24 | 36 | 48 | 54) {
                    return None;
                }
                config.raw_tx_rate = Some(rate);
            }
            FIELD_STA_DRIVER_TX => config.sta_driver_tx = Some(d.boolean()?),
            FIELD_STA_BSSID_CHECK_DISABLED => config.sta_bssid_check_disabled = Some(d.boolean()?),
            FIELD_STA_AMPDU_ENABLED => config.sta_ampdu_enabled = Some(d.boolean()?),
            FIELD_STA_11B_RATES_DISABLED => config.sta_11b_rates_disabled = Some(d.boolean()?),
            FIELD_STA_RAW_RX_ENABLED => config.sta_raw_rx_enabled = Some(d.boolean()?),
            FIELD_ESPNOW_CAPTURE => config.espnow_capture = Some(d.boolean()?),
            FIELD_NAN_DW_INTERVAL => {
                let interval = d.uint()? as u8;
                if !matches!(interval, 0 | 1 | 8 | 16) {
                    return None;
                }
                config.nan_dw_interval = Some(interval);
            }
            FIELD_NOW => {
                let enabled = d.uint()? as u8;
                if enabled > 2 {
                    return None;
                }
                config.now = Some(enabled);
            }
            FIELD_NDP => {
                let enabled = d.uint()? as u8;
                if enabled > 1 {
                    return None;
                }
                config.ndp = Some(enabled);
            }
            FIELD_AP => {
                let enabled = d.uint()? as u8;
                if enabled > 1 {
                    return None;
                }
                config.ap = Some(enabled);
            }
            FIELD_UART => {
                let speed = u8::try_from(d.uint()?).ok()?;
                if speed > 7 {
                    return None;
                }
                config.uart = Some(speed);
            }
            _ => d.skip()?,
        }
    }
    d.is_finished().then_some(config)
}

fn map_is_empty(encoded: &[u8]) -> bool {
    let mut d = Decoder::new(encoded);
    matches!(d.head(), Some((5, 0))) && d.is_finished()
}

fn field_bytes<'a>(encoded: &'a [u8], wanted: u64) -> Option<&'a [u8]> {
    let mut d = Decoder::new(encoded);
    let (major, count) = d.head()?;
    if major != 5 || count == u64::MAX {
        return None;
    }
    let mut result = None;
    for _ in 0..count {
        let key = d.uint()?;
        if key == wanted {
            result = Some(d.text_ref().or_else(|| d.bytes_ref())?);
        } else {
            d.skip()?;
        }
    }
    d.is_finished()
        .then_some(result?)
        .filter(|value| !value.is_empty())
}

fn field_uint(encoded: &[u8], wanted: u64) -> Option<u64> {
    let mut d = Decoder::new(encoded);
    let (major, count) = d.head()?;
    if major != 5 || count == u64::MAX {
        return None;
    }
    let mut result = None;
    for _ in 0..count {
        let key = d.uint()?;
        if key == wanted {
            result = Some(d.uint()?);
        } else {
            d.skip()?;
        }
    }
    d.is_finished().then_some(result?)
}

/// Fixed-buffer request encoder shared by device tests and host adapters.
pub fn encode_request(request: Request<'_>, id: Option<u64>, out: &mut [u8]) -> Option<usize> {
    let field_count = match request {
        Request::SettingsSet { .. } => 2,
        Request::SettingsList => 0,
        Request::TransportStart { config, .. } => 1 + transport_config_count(config),
        _ => 1,
    };
    let mut e = Encoder::new(out);
    e.map(if id.is_some() { 4 } else { 3 })?;
    e.uint(1)?;
    e.uint(CONTROL_COMPONENT)?;
    e.uint(2)?;
    e.uint(match request {
        Request::SettingsGet { .. } => SETTINGS_GET,
        Request::SettingsSet { .. } => SETTINGS_SET,
        Request::SettingsList => SETTINGS_LIST,
        Request::TransportStart { .. } => TRANSPORT_START,
        Request::TransportStop { .. } => TRANSPORT_STOP,
    })?;
    if let Some(id) = id {
        e.uint(3)?;
        e.uint(id)?;
    }
    e.uint(5)?;
    e.map(field_count)?;
    match request {
        Request::SettingsGet { key } => {
            e.uint(FIELD_KEY)?;
            e.text_value(key)?;
        }
        Request::SettingsSet { key, value } => {
            e.uint(FIELD_KEY)?;
            e.text_value(key)?;
            e.uint(FIELD_VALUE)?;
            e.text_value(value)?;
        }
        Request::SettingsList => {}
        Request::TransportStart { kind, config } => {
            e.uint(FIELD_MODE)?;
            e.uint(match kind {
                TransportKind::Sta => 1,
                TransportKind::Uart => 5,
                TransportKind::Nan => 6,
            })?;
            encode_config(config, &mut e)?;
        }
        Request::TransportStop { kind } => {
            e.uint(FIELD_MODE)?;
            e.uint(match kind {
                TransportKind::Sta => 1,
                TransportKind::Uart => 5,
                TransportKind::Nan => 6,
            })?;
        }
    }
    Some(e.len())
}

fn transport_config_count(config: TransportConfig<'_>) -> u64 {
    [
        config.ssid.is_some(),
        config.passphrase.is_some(),
        config.bssid.is_some(),
        config.channel.is_some(),
        config.raw_tx_rate.is_some(),
        config.sta_driver_tx.is_some(),
        config.sta_bssid_check_disabled.is_some(),
        config.sta_ampdu_enabled.is_some(),
        config.sta_11b_rates_disabled.is_some(),
        config.sta_raw_rx_enabled.is_some(),
        config.espnow_capture.is_some(),
        config.nan_dw_interval.is_some(),
        config.now.is_some(),
        config.ndp.is_some(),
        config.ap.is_some(),
        config.uart.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count() as u64
}

fn encode_config(config: TransportConfig<'_>, e: &mut Encoder<'_>) -> Option<()> {
    if let Some(ssid) = config.ssid {
        if ssid.is_empty() || ssid.len() > 32 || ssid.contains(&0) {
            return None;
        }
        e.uint(FIELD_STA_SSID)?;
        e.text_value(ssid)?;
    }
    if let Some(passphrase) = config.passphrase {
        if !(8..=63).contains(&passphrase.len()) || passphrase.contains(&0) {
            return None;
        }
        e.uint(FIELD_STA_PASSPHRASE)?;
        e.text_value(passphrase)?;
    }
    if let Some(bssid) = config.bssid {
        e.uint(FIELD_STA_BSSID)?;
        e.bytes_value(&bssid)?;
    }
    if let Some(channel) = config.channel {
        if !(1..=14).contains(&channel) {
            return None;
        }
        e.uint(FIELD_STA_CHANNEL)?;
        e.uint(u64::from(channel))?;
    }
    for (field, value) in [(FIELD_RAW_TX_RATE, config.raw_tx_rate)] {
        if let Some(value) = value {
            e.uint(field)?;
            e.uint(value as u64)?;
        }
    }
    if let Some(value) = config.nan_dw_interval {
        e.uint(FIELD_NAN_DW_INTERVAL)?;
        e.uint(value as u64)?;
    }
    if let Some(value) = config.now {
        e.uint(FIELD_NOW)?;
        e.uint(value as u64)?;
    }
    if let Some(value) = config.ndp {
        if value > 1 {
            return None;
        }
        e.uint(FIELD_NDP)?;
        e.uint(value as u64)?;
    }
    if let Some(value) = config.ap {
        e.uint(FIELD_AP)?;
        e.uint(value as u64)?;
    }
    if let Some(value) = config.uart {
        e.uint(FIELD_UART)?;
        e.uint(u64::from(value))?;
    }
    for (field, value) in [
        (FIELD_STA_DRIVER_TX, config.sta_driver_tx),
        (
            FIELD_STA_BSSID_CHECK_DISABLED,
            config.sta_bssid_check_disabled,
        ),
        (FIELD_STA_AMPDU_ENABLED, config.sta_ampdu_enabled),
        (FIELD_STA_11B_RATES_DISABLED, config.sta_11b_rates_disabled),
        (FIELD_STA_RAW_RX_ENABLED, config.sta_raw_rx_enabled),
        (FIELD_ESPNOW_CAPTURE, config.espnow_capture),
    ] {
        if let Some(value) = value {
            e.uint(field)?;
            e.boolean(value)?;
        }
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn settings_and_transport_requests_use_one_canonical_record() {
        let mut wire = [0; 96];
        let used = encode_request(
            Request::SettingsSet {
                key: b"ssid",
                value: b"DIRECT-test",
            },
            Some(7),
            &mut wire,
        )
        .unwrap();
        assert_eq!(
            decode_request(&wire[..used]),
            Some(Request::SettingsSet {
                key: b"ssid",
                value: b"DIRECT-test"
            })
        );
        let used = encode_request(
            Request::TransportStart {
                kind: TransportKind::Nan,
                config: TransportConfig::default(),
            },
            None,
            &mut wire,
        )
        .unwrap();
        assert_eq!(
            decode_request(&wire[..used]),
            Some(Request::TransportStart {
                kind: TransportKind::Nan,
                config: TransportConfig::default(),
            })
        );
    }

    #[test]
    fn transport_start_captures_one_complete_radio_profile() {
        let mut wire = [0; 96];
        let config = TransportConfig {
            ssid: Some(b"Direct-test"),
            raw_tx_rate: Some(54),
            sta_driver_tx: Some(true),
            now: Some(1),
            nan_dw_interval: Some(8),
            ndp: Some(1),
            ap: Some(1),
            ..TransportConfig::default()
        };
        let used = encode_request(
            Request::TransportStart {
                kind: TransportKind::Sta,
                config,
            },
            Some(8),
            &mut wire,
        )
        .unwrap();
        assert_eq!(
            decode_request(&wire[..used]),
            Some(Request::TransportStart {
                kind: TransportKind::Sta,
                config,
            })
        );
    }

    #[test]
    fn directed_control_is_not_executed_locally() {
        // {component: 1, method: settings.list, fields: {}, to: "e7"}
        let wire = [0xa4, 1, 1, 2, 3, 5, 0xa0, 9, 0x62, b'e', b'7'];
        assert_eq!(decode_request(&wire), None);
    }

    #[derive(Default)]
    struct RecordingHandler {
        transport: Option<TransportKind>,
    }

    impl Handler for RecordingHandler {
        type Error = ();

        fn settings_get(&mut self, _: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }
        fn settings_set(&mut self, _: &[u8], _: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }
        fn settings_list(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
        fn transport_start(
            &mut self,
            kind: TransportKind,
            config: TransportConfig<'_>,
        ) -> Result<(), Self::Error> {
            assert_eq!(config.raw_tx_rate, Some(54));
            self.transport = Some(kind);
            Ok(())
        }
        fn transport_stop(&mut self, _: TransportKind) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn shared_dispatcher_reaches_the_start_owner_once() {
        let mut wire = [0; 96];
        let physical = TransportConfig {
            raw_tx_rate: Some(54),
            ..TransportConfig::default()
        };
        let used = encode_request(
            Request::TransportStart {
                kind: TransportKind::Sta,
                config: physical,
            },
            None,
            &mut wire,
        )
        .unwrap();
        let mut handler = RecordingHandler::default();
        dispatch(&wire[..used], &mut handler).unwrap();
        assert_eq!(handler.transport, Some(TransportKind::Sta));
    }
}
