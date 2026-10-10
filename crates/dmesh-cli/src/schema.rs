use anyhow::{Context, Result};
use mesh::tagged::{NameOrTag, TaggedSchema};
use serde_json::{Map, Value};
use std::sync::Arc;

const CATALOG_SERVICE: &str = "lmesh";

/// The catalog tag of a field named `to` that is the envelope's destination.
/// Other methods use tag 15 for unrelated fields (`transport.set`'s `now`).

/// The installed service catalog is the source for named and tagged requests.
pub fn load_tagged_schema() -> Arc<TaggedSchema> {
    mesh::catalog::service_catalog_resolver()
        .require(CATALOG_SERVICE)
        .unwrap_or_else(|error| panic!("load {CATALOG_SERVICE} tools.json: {error}"))
        .catalog
        .clone()
}

/// Only device-advertised methods are sent across the device bearer.
pub fn is_stream_command_name(name: &str) -> bool {
    let resolved = mesh::catalog::service_catalog_resolver()
        .require(CATALOG_SERVICE)
        .unwrap_or_else(|error| panic!("load {CATALOG_SERVICE} tools.json: {error}"));
    resolved.catalog.method(name).is_some()
        && resolved
            .tools
            .get("tools")
            .and_then(Value::as_array)
            .or_else(|| resolved.tools.as_array())
            .is_some_and(|tools| {
                tools
                    .iter()
                    .any(|tool| tool["name"] == name && tool["x-dmesh-device"] == true)
            })
}

fn decode_tagged_reply(schema: &TaggedSchema, payload: &[u8]) -> Result<Value> {
    let wire = dmesh_server::tagged::decode(payload).context("not a tagged record")?;
    let mut record = mesh::cbor::decode_record(payload)?;
    if let Some(component) = wire.component {
        record.component = device_name(component)?;
    }
    if let Some(method) = wire.method {
        record.method = device_name(method)?;
    }
    // The device-directed probe result uses a response-specific field map;
    // its numeric tags intentionally do not mirror the request tags. The
    // shared presentation catalog currently describes only input fields, so
    // project these five stable result fields before generic rendering can
    // mislabel (for example) `status` as `bytes`.
    if wire.component == Some(dmesh_server::tagged::Name::Tag(
        dmesh_server::probe::PROBE_COMPONENT,
    )) && wire.method == Some(dmesh_server::tagged::Name::Tag(dmesh_server::probe::PROBE_START))
    {
        if let Some(result) = record.result.as_mut().and_then(Value::as_object_mut) {
            for (tag, name) in [
                ("1", "status"),
                ("2", "peer"),
                ("3", "requested_bytes"),
                ("4", "received_bytes"),
                ("5", "elapsed_us"),
            ] {
                if let Some(value) = result.remove(tag) {
                    result.insert(name.to_owned(), value);
                }
            }
        }
    }
    Ok(schema.to_jsonl(&record))
}

fn device_name(name: dmesh_server::tagged::Name<'_>) -> Result<NameOrTag> {
    match name {
        dmesh_server::tagged::Name::Tag(tag) => Ok(NameOrTag::Tag(u32::try_from(tag)?)),
        dmesh_server::tagged::Name::Text(text) => {
            Ok(NameOrTag::Name(String::from_utf8(text.to_vec())?))
        }
        dmesh_server::tagged::Name::Bytes(_) => {
            anyhow::bail!("binary method identity is unsupported")
        }
    }
}

/// Render text diagnostics and tagged service records from a device bearer.
/// Unknown packet formats remain visible as hex.
pub fn render_device_record(schema: &TaggedSchema, payload: &[u8]) -> String {
    if payload.is_empty() {
        return "kind=empty".to_owned();
    }
    match decode_tagged_reply(schema, payload) {
        Ok(decoded) if decoded.get("error").is_none() => cbor_log_fields(&decoded),
        Ok(decoded) => format!("kind=cbor_error value={decoded}"),
        Err(_) if bytes_are_text(payload) => format!(
            "kind=text text={}",
            serde_json::to_string(&text_preview(payload)).expect("string JSON")
        ),
        Err(_) => format!(
            "kind=raw bytes={} hex={}",
            payload.len(),
            hex_encode(payload)
        ),
    }
}

/// Encode a schema command for a normal tagged QUIC stream: every catalog method is a stream
/// handler, there is no separate connectionless "direct" form.
pub fn encode_stream_command_with_id(command: &str, id: u64) -> Result<Vec<u8>> {
    let schema = load_tagged_schema();
    let record = schema.parse_text(command)?;
    let method = schema
        .method_name(&record)
        .context("command method")?
        .to_owned();
    finish_record(&schema, &method, record, id)
}

/// Encode a shell-split service invocation without splitting quoted field values.
pub fn encode_stream_argv_with_id(arguments: &[String], id: u64) -> Result<Vec<u8>> {
    let schema = load_tagged_schema();
    let method = arguments.first().context("missing device method")?;
    let record = schema.parse_argv(method, &arguments[1..])?;
    finish_record(&schema, method, record, id)
}

/// Turn a parsed request into its wire record. The field rules (kinds, `timeout`, `to`) are
/// `mesh::tagged`'s and are the same for `key=value` and JSON input; what is left here is DMesh's:
/// nothing else: every handler decodes the common encoding.
fn finish_record(
    schema: &TaggedSchema,
    method: &str,
    mut record: mesh::tagged::TaggedRecord,
    id: u64,
) -> Result<Vec<u8>> {
    let entry = schema
        .method(method)
        .with_context(|| format!("unknown device method {method}"))?;
    let named = schema.to_jsonl(&record);
    let fields: Map<String, Value> = named
        .as_object()
        .context("command fields")?
        .iter()
        .filter(|(key, _)| !matches!(key.as_str(), "method" | "to" | "timeout"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    schema.validate_fields(method, &fields)?;
    // Devices dispatch by number: a method without numeric identities cannot be sent.
    if !matches!(entry.component, NameOrTag::Tag(_)) || !matches!(entry.method, NameOrTag::Tag(_)) {
        anyhow::bail!("device command {method} has no numeric component and method");
    }
    // A destination has one canonical spelling (`mesh://` for a bare node): `mesh::resolve`'s.
    if let Some(Value::String(raw)) = record.to.clone() {
        record.to = Some(Value::String(mesh::resolve::canonical_target(&raw).unwrap_or(raw)));
    }
    record.id = Some(Value::from(id));
    schema.encode_request(&record)
}

/// Render diagnostic fields, hiding the routine successful status marker.
pub fn cbor_log_fields(value: &Value) -> String {
    let mut value = value.clone();
    if let Some(object) = value.as_object_mut() {
        if object.get("status").and_then(Value::as_str) == Some("ok") {
            object.remove("status");
        }
    }
    mesh::logfmt::flatten_json(&value)
}

fn bytes_are_text(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .filter(|byte| matches!(**byte, b'\t' | b'\r' | b'\n' | 0x20..=0x7e))
        .count()
        * 100
        >= bytes.len().saturating_mul(90)
}

fn text_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .filter_map(|byte| match *byte {
            b'\r' | b'\n' => None,
            b'\t' | 0x20..=0x7e => Some((*byte as char).to_string()),
            value => Some(format!("\\x{value:02x}")),
        })
        .collect()
}

fn hex_encode(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn diagnostic_rendering_hides_only_top_level_success() {
        assert_eq!(
            super::cbor_log_fields(
                &serde_json::json!({"status":"ok", "radio":{"status":"ok", "count":2}})
            ),
            "radio.count=2 radio.status=ok"
        );
    }

    #[test]
    fn mostly_ascii_diagnostic_cbor_is_decoded_before_text_fallback() {
        let schema = load_tagged_schema();
        let mut result = [0u8; 320];
        let mut encoder = dmesh_server::cbor::Encoder::new(&mut result);
        encoder.map(2).unwrap();
        encoder.text_value(b"cursor").unwrap();
        encoder.uint(8).unwrap();
        encoder.text_value(b"records").unwrap();
        encoder.array(1).unwrap();
        encoder.map(2).unwrap();
        encoder.text_value(b"sequence").unwrap();
        encoder.uint(8).unwrap();
        encoder.text_value(b"line").unwrap();
        encoder
            .text_value(b"wifi: remote diagnostic line with mostly printable ASCII")
            .unwrap();
        let result_len = encoder.len();
        drop(encoder);

        let mut wire = [0u8; 400];
        let used = dmesh_server::tagged::encode_numeric_response(
            208,
            2,
            8,
            &result[..result_len],
            &mut wire,
        )
        .unwrap();
        let rendered = render_device_record(&schema, &wire[..used]);
        assert!(!rendered.contains("kind=text"), "{rendered}");
        assert!(rendered.contains("log.watch"), "{rendered}");
        assert!(rendered.contains("remote diagnostic line"), "{rendered}");
    }
    use super::{
        encode_stream_argv_with_id,
        encode_stream_command_with_id, load_tagged_schema, render_device_record,
    };
    use mesh::tagged::NameOrTag;
    use serde_json::Value;

    #[test]
    fn session_renderer_keeps_text_and_schema_labels() {
        let schema = load_tagged_schema();
        assert_eq!(
            render_device_record(&schema, b"boot ready\n"),
            "kind=text text=\"boot ready\""
        );
    }

    #[test]
    fn direct_transport_control_uses_the_common_tagged_envelope() {
        let mut command = [0u8; 96];
        let config = dmesh_server::control::TransportConfig {
            ssid: Some(b"Direct-test"),
            raw_tx_rate: Some(24),
            sta_driver_tx: Some(true),
            ..dmesh_server::control::TransportConfig::default()
        };
        let used = dmesh_server::control::encode_request(
            dmesh_server::control::Request::TransportSet {
                kind: dmesh_server::control::TransportKind::Sta,
                config,
            },
            Some(9),
            &mut command,
        )
        .unwrap();
        assert_eq!(
            dmesh_server::control::decode_request(&command[..used]),
            Some(dmesh_server::control::Request::TransportSet {
                kind: dmesh_server::control::TransportKind::Sta,
                config,
            })
        );
    }

    #[test]
    fn discovery_nodes_uses_the_correlated_empty_stream_request() {
        let wire = encode_stream_command_with_id("discovery.nodes", 22).unwrap();
        assert!(dmesh_server::announce::is_devices_observed_request(&wire));
        let record = dmesh_server::tagged::decode(&wire).unwrap();
        assert_eq!(record.id, Some(22));
        assert!(record.fields.is_none());
        // The generic encoder produces exactly the bytes of the dedicated constructor it replaced.
        let mut dedicated = [0u8; 32];
        let used = dmesh_server::tagged::encode_numeric_empty_request(
            dmesh_server::announce::ANNOUNCE_COMPONENT,
            dmesh_server::announce::ANNOUNCE_DEVICES_OBSERVED,
            22,
            &mut dedicated,
        )
        .unwrap();
        assert_eq!(wire, dedicated[..used]);
    }

    #[test]
    fn discovery_active_uses_the_common_correlated_action() {
        let wire = encode_stream_command_with_id("discovery.active", 23).unwrap();
        let record = dmesh_server::tagged::decode(&wire).unwrap();
        assert_eq!(record.component, Some(dmesh_server::tagged::Name::Tag(6)));
        assert_eq!(record.method, Some(dmesh_server::tagged::Name::Tag(10)));
        assert_eq!(record.id, Some(23));
        assert!(record.fields.is_none());
    }

    #[test]
    fn nan_wakeup_encodes_the_targeted_controller_action() {
        let wire = encode_stream_command_with_id("nan.wakeup to=84:0d:8e:07:41:70", 9).unwrap();
        let record = dmesh_server::tagged::decode(&wire).unwrap();
        assert_eq!(record.id, Some(9));
        assert_eq!(
            dmesh_server::announce::decode_nan_wakeup_request(record),
            Some([0x84, 0x0d, 0x8e, 0x07, 0x41, 0x70])
        );
    }

    #[test]
    fn the_catalog_encodes_log_watch_and_the_firmware_telemetry_snapshots() {
        let command =
            encode_stream_command_with_id("log.watch since_seq=5 limit=2 level=2 source=nan", 3).unwrap();
        let request = dmesh_server::log_watch::WatchRequest::decode(
            dmesh_server::tagged::decode(&command).unwrap().fields,
        )
        .unwrap_or_else(|| panic!("log.watch fields: {command:02x?}"));
        assert_eq!(
            (request.since_seq, request.limit, request.level, request.source.as_deref()),
            (5, 2, 2, Some("nan"))
        );
        for (name, method) in [
            ("telemetry.memory", 10),
            ("telemetry.power", 11),
            ("telemetry.runtime", 12),
            ("telemetry.bearers", 9),
        ] {
            let command = encode_stream_command_with_id(name, 4).unwrap();
            let envelope = dmesh_server::tagged::decode(&command).unwrap();
            assert_eq!(envelope.component, Some(dmesh_server::tagged::Name::Tag(7)), "{name}");
            assert_eq!(envelope.method, Some(dmesh_server::tagged::Name::Tag(method)), "{name}");
        }
    }

    #[test]
    fn timeout_is_the_envelope_allowance_not_a_method_field() {
        let command = encode_stream_command_with_id("probe.start bytes=4096 timeout=2500", 5).unwrap();
        let envelope = dmesh_server::tagged::decode(&command).expect("envelope");
        assert_eq!(envelope.timeout, Some(2500));
        assert_eq!(envelope.id, Some(5));
        let without = encode_stream_command_with_id("probe.start bytes=4096", 5).unwrap();
        assert_eq!(dmesh_server::tagged::decode(&without).unwrap().timeout, None);
    }

    #[test]
    fn transport_set_uses_the_cli_catalog_and_common_envelope() {
        let command = encode_stream_command_with_id("transport.set mode=nan now=1", 0).unwrap();
        let envelope = dmesh_server::tagged::decode(&command).expect("tagged envelope");
        assert_eq!(envelope.component, Some(dmesh_server::tagged::Name::Tag(1)));
        assert_eq!(envelope.method, Some(dmesh_server::tagged::Name::Tag(4)));
        assert_eq!(envelope.id, Some(0));
        assert_eq!(
            dmesh_server::control::decode_request(&command),
            Some(dmesh_server::control::Request::TransportSet {
                kind: dmesh_server::control::TransportKind::Nan,
                config: dmesh_server::control::TransportConfig {
                    now: Some(1),
                    ..dmesh_server::control::TransportConfig::default()
                },
            })
        );
    }

    #[test]
    fn transport_set_preserves_the_explicit_sleepy_dw_fields() {
        let command = encode_stream_command_with_id(
            "transport.set mode=nan nan_dw_interval=1 now=2 ap=0 ble=1",
            24,
        )
        .unwrap();
        assert_eq!(
            dmesh_server::control::decode_request(&command),
            Some(dmesh_server::control::Request::TransportSet {
                kind: dmesh_server::control::TransportKind::Nan,
                config: dmesh_server::control::TransportConfig {
                    nan_dw_interval: Some(1),
                    now: Some(2),
                    ap: Some(0),
                    ble: Some(1),
                    ..dmesh_server::control::TransportConfig::default()
                },
            })
        );
    }

    #[test]
    fn settings_set_is_stream_only() {
        let command = encode_stream_command_with_id("settings.set key=sta_ssid value=costin", 41)
            .expect("stream settings command");
        let record = dmesh_server::tagged::decode(&command).expect("tagged stream command");
        assert_eq!(record.component, Some(dmesh_server::tagged::Name::Tag(1)));
        assert_eq!(record.method, Some(dmesh_server::tagged::Name::Tag(2)));
        assert_eq!(record.id, Some(41));
    }

    #[test]
    fn numeric_looking_settings_values_remain_cbor_text() {
        let wire = encode_stream_command_with_id("settings.set key=nan_dw_interval value=1", 42).unwrap();
        assert_eq!(dmesh_server::control::decode_request(&wire),
            Some(dmesh_server::control::Request::SettingsSet { key: b"nan_dw_interval", value: b"1" }));
    }

    #[test]
    fn probe_is_a_schema_driven_bearer_neutral_stream() {
        let named = encode_stream_command_with_id("settings.set key=name value=demo", 77)
            .expect("named fields");
        let numeric = encode_stream_command_with_id("settings.set 1=name 2=demo", 77)
            .expect("numeric field tags");
        let options = encode_stream_command_with_id("settings.set --key=name --value=demo", 77)
            .expect("mesh-style field options");
        let numeric_options = encode_stream_command_with_id("settings.set --1=name --2=demo", 77)
            .expect("numeric mesh-style field options");
        assert_eq!(numeric, named);
        assert_eq!(options, named);
        assert_eq!(numeric_options, named);
        let spaced = encode_stream_argv_with_id(
            &[
                "settings.set".to_owned(),
                "--key=name".to_owned(),
                "--value=two words".to_owned(),
            ],
            78,
        )
        .expect("quoted field value remains one argument");
        let spaced_record = mesh::cbor::decode_record(&spaced).unwrap();
        assert_eq!(
            spaced_record.env.get(&NameOrTag::Tag(2)),
            Some(&Value::String("two words".to_owned()))
        );
        assert!(encode_stream_command_with_id("settings.set 99=demo", 77).is_err());
        let command = encode_stream_command_with_id("probe.start bytes=4096 packet_size=512", 44)
            .expect("stream probe command");
        let record = dmesh_server::tagged::decode(&command).expect("tagged probe request");
        assert_eq!(
            dmesh_server::probe::decode_probe_start_record(record),
            Some((44, dmesh_server::probe::ProbeServiceRequest::new(4096, 512)))
        );
        let directed = encode_stream_command_with_id(
            "probe.start to=mesh://fc00::a4 bytes=256 packet_size=128 peer=espnow://02:11:22:33:44:55",
            45,
        )
        .expect("device-directed probe remains the probe method");
        let record = dmesh_server::tagged::decode(&directed).expect("tagged probe request");
        assert_eq!(
            record.to,
            Some(dmesh_server::tagged::Name::Text(b"mesh://fc00::a4")),
            "wire={directed:02x?}"
        );
        let (id, request) =
            dmesh_server::probe::decode_probe_start_record(record).expect("directed probe fields");
        assert_eq!(id, 45);
        assert_eq!(
            request
                .peer
                .and_then(|destination| destination.espnow_mac()),
            Some([0x02, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
    }

    #[test]
    fn directed_probe_result_uses_response_field_names() {
        let mut request = dmesh_server::probe::ProbeServiceRequest::new(128, 128);
        request.peer = Some(
            dmesh_server::probe::ProbeDestination::parse("espnow://02:11:22:33:44:55")
                .unwrap(),
        );
        let mut response = [0u8; 256];
        let used = dmesh_server::probe::encode_probe_result_response(
            46,
            request,
            true,
            128,
            9_876,
            &mut response,
        )
        .unwrap();
        let rendered = render_device_record(&load_tagged_schema(), &response[..used]);
        assert!(rendered.contains("result.status=ok"), "{rendered}");
        assert!(
            rendered.contains("result.peer=espnow://02:11:22:33:44:55"),
            "{rendered}"
        );
        assert!(rendered.contains("result.requested_bytes=128"), "{rendered}");
        assert!(rendered.contains("result.received_bytes=128"), "{rendered}");
        assert!(rendered.contains("result.elapsed_us=9876"), "{rendered}");
    }

        #[test]
    fn module_stop_is_a_schema_driven_empty_stream_request() {
        let command =
            encode_stream_command_with_id("module.stop", 48).expect("module stop stream request");
        let record = dmesh_server::tagged::decode(&command).expect("tagged module stop");
        assert_eq!(
            record.component,
            Some(dmesh_server::tagged::Name::Tag(1000))
        );
        assert_eq!(record.method, Some(dmesh_server::tagged::Name::Tag(3)));
        assert_eq!(record.id, Some(48));
    }

    #[test]
    fn module_inventory_and_init_are_advertised_device_stream_methods() {
        for (name, method) in [("module.status", 1), ("module.init", 2)] {
            assert!(super::is_stream_command_name(name));
            let command = encode_stream_command_with_id(name, 48).unwrap();
            let record = dmesh_server::tagged::decode(&command).unwrap();
            assert_eq!(record.component, Some(dmesh_server::tagged::Name::Tag(1000)));
            assert_eq!(record.method, Some(dmesh_server::tagged::Name::Tag(method)));
            assert_eq!(record.id, Some(48));
        }
    }

    #[test]
    fn boot_recovery_is_an_empty_tagged_stream_request() {
        let command =
            encode_stream_command_with_id("boot.recovery", 46).expect("stream boot request");
        let record = dmesh_server::tagged::decode(&command).expect("tagged boot request");
        assert_eq!(
            record.component,
            Some(dmesh_server::tagged::Name::Tag(
                dmesh_server::services::BOOT_COMPONENT,
            ))
        );
        assert_eq!(
            record.method,
            Some(dmesh_server::tagged::Name::Tag(
                dmesh_server::services::BOOT_RECOVERY_METHOD,
            ))
        );
        assert_eq!(record.id, Some(46));
        assert!(record.to.is_none());
        assert!(record.params.is_none());
        assert!(record.data.is_none());
        assert!(record.fields.is_none());
        assert!(record.result.is_none());
        assert!(record.error.is_none());
    }

    #[test]
    fn device_telemetry_is_a_read_only_tagged_stream_request() {
        let command = encode_stream_command_with_id("telemetry.device", 47)
            .expect("stream device telemetry request");
        let record = dmesh_server::tagged::decode(&command).expect("tagged identity request");
        assert_eq!(
            record.component,
            Some(dmesh_server::tagged::Name::Tag(
                dmesh_server::telemetry::TELEMETRY_COMPONENT,
            ))
        );
        assert_eq!(
            record.method,
            Some(dmesh_server::tagged::Name::Tag(
                dmesh_server::telemetry::DEVICE_METHOD,
            ))
        );
        assert_eq!(record.id, Some(47));
        assert!(record.fields.is_none());
    }

    #[test]
    fn ble_control_is_a_schema_driven_tagged_stream() {
        let command =
            encode_stream_command_with_id("ble.start", 48).expect("stream BLE start request");
        let record = dmesh_server::tagged::decode(&command).expect("tagged BLE start request");
        assert_eq!(record.component, Some(dmesh_server::tagged::Name::Tag(104)));
        assert_eq!(record.method, Some(dmesh_server::tagged::Name::Tag(80)));
        assert_eq!(record.id, Some(48));
        assert!(record.fields.is_none());

        let command = encode_stream_command_with_id("ble.scan duration_ms=2500", 49)
            .expect("stream BLE scan request");
        let record = dmesh_server::tagged::decode(&command).expect("tagged BLE scan request");
        assert_eq!(record.component, Some(dmesh_server::tagged::Name::Tag(104)));
        assert_eq!(record.method, Some(dmesh_server::tagged::Name::Tag(82)));
        let mut decoder =
            dmesh_server::cbor::Decoder::new(record.fields.expect("scan duration field"));
        let (major, count) = decoder.head().expect("CBOR map");
        assert_eq!(major, 5);
        assert_eq!(count, 1);
        assert_eq!(decoder.uint(), Some(2));
        assert_eq!(decoder.uint_or_text(), Some(2500));

        let command =
            encode_stream_command_with_id("ble.connect addr=88664b020b6d addr_type=1 psm=129", 51)
                .expect("stream BLE connect request");
        let record = dmesh_server::tagged::decode(&command).expect("tagged BLE connect request");
        assert_eq!(record.component, Some(dmesh_server::tagged::Name::Tag(104)));
        assert_eq!(record.method, Some(dmesh_server::tagged::Name::Tag(85)));
        let mut decoder =
            dmesh_server::cbor::Decoder::new(record.fields.expect("BLE connect field"));
        let (major, count) = decoder.head().expect("CBOR map");
        assert_eq!(major, 5);
        assert_eq!(count, 3);
        let mut seen = [false; 5];
        for _ in 0..count {
            let key = decoder.uint().expect("BLE connect key");
            seen[key as usize] = true;
            match key {
                2 => {
                    assert_eq!(
                        decoder.bytes_ref(),
                        Some([0x88, 0x66, 0x4b, 0x02, 0x0b, 0x6d].as_slice())
                    );
                }
                3 => assert_eq!(decoder.uint(), Some(1)),
                4 => assert_eq!(decoder.uint(), Some(129)),
                _ => unreachable!(),
            }
        }
        assert!(seen[2] && seen[3] && seen[4]);

        let command = encode_stream_command_with_id(
            "ble.connect addr=88:66:4b:02:0b:6d addr_type=1 psm=129",
            53,
        )
        .expect("stream BLE colon address connect request");
        let record = dmesh_server::tagged::decode(&command)
            .expect("tagged BLE colon address connect request");
        assert_eq!(record.component, Some(dmesh_server::tagged::Name::Tag(104)));
        assert_eq!(record.method, Some(dmesh_server::tagged::Name::Tag(85)));
        let mut decoder =
            dmesh_server::cbor::Decoder::new(record.fields.expect("BLE colon connect field"));
        let (major, count) = decoder.head().expect("CBOR map");
        assert_eq!(major, 5);
        assert_eq!(count, 3);
        let mut seen = [false; 5];
        for _ in 0..count {
            let key = decoder.uint().expect("BLE colon connect key");
            seen[key as usize] = true;
            match key {
                2 => {
                    assert_eq!(
                        decoder.bytes_ref(),
                        Some([0x88, 0x66, 0x4b, 0x02, 0x0b, 0x6d].as_slice())
                    );
                }
                3 => assert_eq!(decoder.uint(), Some(1)),
                4 => assert_eq!(decoder.uint(), Some(129)),
                _ => unreachable!(),
            }
        }
        assert!(seen[2] && seen[3] && seen[4]);

        let command = encode_stream_command_with_id("ble.coc.send data=deadbeef", 52)
            .expect("stream BLE CoC send request");
        let record = dmesh_server::tagged::decode(&command).expect("tagged BLE CoC send request");
        assert_eq!(record.component, Some(dmesh_server::tagged::Name::Tag(104)));
        assert_eq!(record.method, Some(dmesh_server::tagged::Name::Tag(86)));
        let mut decoder =
            dmesh_server::cbor::Decoder::new(record.fields.expect("BLE CoC send field"));
        let (major, count) = decoder.head().expect("CBOR map");
        assert_eq!(major, 5);
        assert_eq!(count, 1);
        assert_eq!(decoder.uint(), Some(2));
        assert_eq!(
            decoder.bytes_ref(),
            Some([0xde, 0xad, 0xbe, 0xef].as_slice())
        );
    }

    #[test]
    fn ble_status_response_uses_the_schema_field_names() {
        let schema = load_tagged_schema();
        let mut result = [0u8; 16];
        let mut encoder = dmesh_server::cbor::Encoder::new(&mut result);
        encoder.map(2).unwrap();
        encoder.uint(1).unwrap();
        encoder.boolean(true).unwrap();
        encoder.uint(9).unwrap();
        encoder.boolean(false).unwrap();
        let result_len = encoder.len();
        let mut wire = [0u8; 64];
        let used = dmesh_server::tagged::encode_numeric_response(
            104,
            83,
            50,
            &result[..result_len],
            &mut wire,
        )
        .expect("bounded BLE status response");
        let rendered = render_device_record(&schema, &wire[..used]);
        assert!(rendered.contains("method=ble.status"), "{rendered}");
        assert!(rendered.contains("result.ready=true"), "{rendered}");
        assert!(rendered.contains("result.scanning=false"), "{rendered}");
    }

    #[test]
    fn connection_diagnostics_are_schema_driven_tagged_streams() {
        for (name, method) in [
            ("status", 1),
            ("services", 2),
        ] {
            let wire = encode_stream_command_with_id(name, 91).unwrap();
            let record = dmesh_server::tagged::decode(&wire).unwrap();
            assert_eq!(
                record.component,
                Some(dmesh_server::tagged::Name::Tag(
                    dmesh_server::services::DIAGNOSTIC_COMPONENT,
                ))
            );
            assert_eq!(record.method, Some(dmesh_server::tagged::Name::Tag(method)));
            assert_eq!(record.id, Some(91));
        }
    }

    #[test]
    fn radio_control_is_stream_only() {
        let telemetry = encode_stream_command_with_id("telemetry.nan", 43)
            .expect("stream telemetry command");
        assert_eq!(
            dmesh_server::telemetry::decode_request(&telemetry),
            Some((dmesh_server::telemetry::NAN_METRICS_METHOD, 43))
        );
    }

    #[test]
    fn radio_snapshot_has_a_stream_handler_but_no_direct_encoding() {
        let stream =
            encode_stream_command_with_id("radio.snapshot", 42).expect("stream radio snapshot");
        assert!(dmesh_server::raw_wifi::decode_raw_wifi_handler(&stream).is_ok());
        let mut expected = [0u8; 16];
        let used = dmesh_server::raw_wifi::encode_raw_wifi_snapshot_request_with_id(
            dmesh_server::raw_wifi::RAW_WIFI_METHOD_SNAPSHOT,
            0,
            &mut expected,
        )
        .unwrap();
        assert_eq!(
            dmesh_server::raw_wifi::decode_raw_wifi_handler(&expected[..used]),
            Ok(dmesh_server::raw_wifi::RawWifiLabRequest::Snapshot)
        );
    }

    #[test]
    fn radio_tx_hex_is_a_correlated_stream_byte_request() {
        let stream = encode_stream_command_with_id(
            "radio.tx frame=d000ffffffff00112233445566778899aabbccddeeff00112233445566 channel=6 interface=sta rate=6",
            43,
        )
        .expect("stream radio TX");
        let record = dmesh_server::tagged::decode(&stream).expect("tagged radio TX");
        assert_eq!(record.id, Some(43));
        let request =
            dmesh_server::raw_wifi::decode_raw_wifi_tx_record(record).expect("raw TX bytes");
        assert_eq!(request.channel, 6);
        assert_eq!(
            request.interface,
            dmesh_server::raw_wifi::RawWifiInterface::Sta
        );
        assert_eq!(request.rate, dmesh_server::raw_wifi::RawWifiRate::Mbps6);
        assert_eq!(request.frame[0], 0xd0);
    }

    #[test]
    fn tagged_wifi_scan_result_uses_the_common_control_renderer() {
        let schema = load_tagged_schema();
        let result = [0xa5, 1, 0x80, 2, 4, 3, 0, 4, 0, 5, 0xf5];
        let mut wire = [0u8; 64];
        let used = dmesh_server::tagged::encode_numeric_response(4, 77, 91, &result, &mut wire)
            .expect("bounded scan response");
        let rendered = render_device_record(&schema, &wire[..used]);
        assert!(rendered.contains("method=wifi.scan"), "{rendered}");
        assert!(rendered.contains("id=91"), "{rendered}");
        assert!(rendered.contains("result.2=4"), "{rendered}");
    }

    #[test]
    fn tagged_transport_error_keeps_its_method_and_request_id() {
        let schema = load_tagged_schema();
        let mut wire = [0u8; 64];
        let used =
            dmesh_server::tagged::encode_numeric_error(1, 4, 92, b"invalid_setting", &mut wire)
                .expect("bounded transport error");
        let rendered = render_device_record(&schema, &wire[..used]);
        assert!(
            rendered.contains("\"method\":\"transport.set\""),
            "{rendered}"
        );
        assert!(rendered.contains("\"id\":92"), "{rendered}");
        assert!(rendered.contains("invalid_setting"), "{rendered}");
    }
}
