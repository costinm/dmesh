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
/// Complete declarative volatile transport profile. An all-off profile is the
/// sole stop representation; callers must not model lifecycle as imperative
/// start/stop commands.
pub const TRANSPORT_SET: u64 = 4;

const FIELD_KEY: u64 = 1;
const FIELD_VALUE: u64 = 2;
const FIELD_MODE: u64 = 1;
// Shared transport declaration for DMesh firmware, Android and host. It has
// the same fields and tagged-CBOR representation as esp-xip-modules' profile
// (src/transport_profile/mod.rs); keep both sides in sync via docs/transport-cbor.md.
// Android/host's generated platform_api::TransportSetRequest uses that schema too.
pub use crate::transport_profile::{TransportConfig, TransportKind};
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
    TransportSet {
        kind: TransportKind,
        config: TransportConfig<'a>,
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
    fn transport_set(
        &mut self,
        kind: TransportKind,
        config: TransportConfig<'_>,
    ) -> Result<(), Self::Error>;
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
        Request::TransportSet { kind, config } => handler.transport_set(kind, config),
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
    match record.method? {
        Name::Tag(SETTINGS_GET) => {
            let fields = record.fields?;
            Some(Request::SettingsGet {
                key: field_bytes(fields, FIELD_KEY)?,
            })
        }
        Name::Tag(SETTINGS_SET) => {
            let fields = record.fields?;
            Some(Request::SettingsSet {
                key: field_bytes(fields, FIELD_KEY)?,
                value: field_bytes(fields, FIELD_VALUE)?,
            })
        }
        // Schema adapters are allowed to omit an empty map.  Treat that as
        // equivalent to the compact CBOR encoder's `{}` so `settings.list`
        // is a normal tagged stream handler on every bearer.
        Name::Tag(SETTINGS_LIST) => record.fields.map_or(Some(Request::SettingsList), |fields| {
            map_is_empty(fields).then_some(Request::SettingsList)
        }),
        Name::Tag(TRANSPORT_SET) => {
            let fields = record.fields?;
            Some(Request::TransportSet {
                kind: transport_kind(field_uint(fields, FIELD_MODE)?)?,
                config: decode_transport_config(fields)?,
            })
        }
        _ => None,
    }
}

use crate::transport_profile::transport_kind;
fn decode_transport_config(encoded: &[u8]) -> Option<TransportConfig<'_>> {
    crate::transport_profile::decode_config(encoded)
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
            // `text_ref` consumes the CBOR head before discovering a byte
            // string, so rewind before trying the binary form. Settings keys
            // remain text while settings values may now be arbitrary bytes.
            let saved = d.position();
            result = Some(d.text_ref().or_else(|| {
                d.set_position(saved);
                d.bytes_ref()
            })?);
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
        Request::TransportSet { config, .. } => 1 + transport_config_count(config),
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
        Request::TransportSet { .. } => TRANSPORT_SET,
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
            // Settings values are opaque bytes. Text settings retain their
            // UTF-8 validation in the receiving store, while NVS blobs such
            // as the control-plane key need no base64 transport workaround.
            e.bytes_value(value)?;
        }
        Request::SettingsList => {}
        Request::TransportSet { kind, config } => {
            e.uint(FIELD_MODE)?;
            e.uint(u64::from(crate::transport_profile::mode(Some(kind))))?;
            encode_config(config, &mut e)?;
        }
    }
    Some(e.len())
}

fn transport_config_count(config: TransportConfig<'_>) -> u64 { crate::transport_profile::field_count(config) }
fn encode_config(config: TransportConfig<'_>, e: &mut Encoder<'_>) -> Option<()> {
    crate::transport_profile::encode_config_into(config, e)
}

#[cfg(test)]
mod tests {
    #[test]
    fn transport_bssid_accepts_catalog_text_and_binary() {
        // Tagged request-field maps, matching the generated catalog wire type.
        let text = b"\xa1\x03\x71aa:BB:02:03:04:05";
        let binary = b"\xa1\x03\x46\xaa\xbb\x02\x03\x04\x05";
        for encoded in [text.as_slice(), binary.as_slice()] {
            assert_eq!(super::decode_transport_config(encoded).unwrap().bssid,
                Some([0xaa, 0xbb, 2, 3, 4, 5]));
        }
        assert!(crate::transport_profile::parse_bssid_text(b"aa-bb-02-03-04-05").is_none());
        assert!(crate::transport_profile::parse_bssid_text(b"aa:gg:02:03:04:05").is_none());
        assert!(super::decode_transport_config(b"\xa1\x03\x45abcde").is_none());
        assert!(super::decode_transport_config(b"\xa1\x03\x66abcdef").is_none());
    }
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
            Request::TransportSet {
                kind: TransportKind::Nan,
                config: TransportConfig::default(),
            },
            None,
            &mut wire,
        )
        .unwrap();
        assert_eq!(
            decode_request(&wire[..used]),
            Some(Request::TransportSet {
                kind: TransportKind::Nan,
                config: TransportConfig::default(),
            })
        );
    }

    #[test]
    fn settings_set_encodes_binary_value_as_cbor_bytes() {
        let mut wire = [0u8; 96];
        let used = encode_request(
            Request::SettingsSet {
                key: b"cp",
                value: &[0, 0xff, 1],
            },
            None,
            &mut wire,
        )
        .unwrap();
        // The raw 0x43 bytes header makes this unambiguously a CBOR byte
        // string, not a text string which would reject the 0xff byte.
        assert!(
            wire[..used]
                .windows(4)
                .any(|window| window == [0x43, 0, 0xff, 1])
        );
        assert_eq!(
            decode_request(&wire[..used]),
            Some(Request::SettingsSet {
                key: b"cp",
                value: &[0, 0xff, 1]
            })
        );
    }

    #[test]
    fn transport_set_captures_one_complete_radio_profile() {
        let mut wire = [0; 96];
        let config = TransportConfig {
            ssid: Some(b"Direct-test"),
            raw_tx_rate: Some(54),
            sta_driver_tx: Some(true),
            now: Some(1),
            nan_dw_interval: Some(8),
            ndp: Some(1),
            ap: Some(1),
            ble: Some(1),
            ..TransportConfig::default()
        };
        let used = encode_request(
            Request::TransportSet {
                kind: TransportKind::Sta,
                config,
            },
            Some(8),
            &mut wire,
        )
        .unwrap();
        assert_eq!(
            decode_request(&wire[..used]),
            Some(Request::TransportSet {
                kind: TransportKind::Sta,
                config,
            })
        );
    }

    #[test]
    fn settings_list_allows_schema_omitted_empty_fields() {
        // The JSON/schema bridge does not need to materialize an empty
        // fields map.  This must decode identically to `encode_request` so
        // the stream handler is not formatter- or bearer-dependent.
        let wire = [
            0xa3,
            1,
            CONTROL_COMPONENT as u8,
            2,
            SETTINGS_LIST as u8,
            3,
            7,
        ];
        assert_eq!(decode_request(&wire), Some(Request::SettingsList));
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
        fn transport_set(
            &mut self,
            kind: TransportKind,
            config: TransportConfig<'_>,
        ) -> Result<(), Self::Error> {
            assert_eq!(config.raw_tx_rate, Some(54));
            self.transport = Some(kind);
            Ok(())
        }
    }

    #[test]
    fn shared_dispatcher_reaches_the_set_owner_once() {
        let mut wire = [0; 96];
        let physical = TransportConfig {
            raw_tx_rate: Some(54),
            ..TransportConfig::default()
        };
        let used = encode_request(
            Request::TransportSet {
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

    #[test]
    fn transport_set_round_trips_explicit_open_mode() {
        let mut wire = [0; 96];
        let request = Request::TransportSet {
            kind: TransportKind::Sta,
            config: TransportConfig {
                ssid: Some(b"DIRECT-dmesh"),
                open: Some(true),
                ..TransportConfig::default()
            },
        };
        let used = encode_request(request, Some(10), &mut wire).unwrap();
        assert_eq!(decode_request(&wire[..used]), Some(request));
    }

    #[test]
    fn transport_set_round_trips_921600_uart_selector() {
        let request = Request::TransportSet {
            kind: TransportKind::Uart,
            config: TransportConfig { uart: Some(9), ..Default::default() },
        };
        let mut wire = [0; 96];
        let used = encode_request(request, Some(10), &mut wire).unwrap();
        assert_eq!(decode_request(&wire[..used]), Some(request));
        let invalid = Request::TransportSet {
            kind: TransportKind::Uart,
            config: TransportConfig { uart: Some(10), ..Default::default() },
        };
        assert!(encode_request(invalid, None, &mut wire).is_none());
    }
}
