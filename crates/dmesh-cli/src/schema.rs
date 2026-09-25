use anyhow::{Context, Result};
use mesh::tagged::{NameOrTag, TaggedSchema};
use serde_json::{Map, Value};
use std::sync::Arc;

const CATALOG_SERVICE: &str = "lmesh";

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
    if bytes_are_text(payload) {
        return format!(
            "kind=text text={}",
            serde_json::to_string(&text_preview(payload)).expect("string JSON")
        );
    }
    match decode_tagged_reply(schema, payload) {
        Ok(decoded) if decoded.get("error").is_none() => cbor_log_fields(&decoded),
        Ok(decoded) => format!("kind=cbor_error value={decoded}"),
        Err(_) => format!(
            "kind=raw bytes={} hex={}",
            payload.len(),
            hex_encode(payload)
        ),
    }
}

/// Encode a schema-guided direct command as one canonical tagged-CBOR record.
///
/// Direct records require reviewed numeric component and method tags.
pub fn encode_direct_command(command: &str) -> Result<Vec<u8>> {
    encode_direct_command_with_id(command, 0)
}

/// Encode one correlated direct command. Callers that cross a bearer must
/// supply a fresh nonzero ID so request and result use the common envelope.
pub fn encode_direct_command_with_id(command: &str, id: u64) -> Result<Vec<u8>> {
    encode_schema_command_with_id(command, id, true)
}

/// Encode a schema command for a normal tagged QUIC stream.  This is the
/// operator-facing counterpart of the direct encoder: every schema method is
/// available here, while the direct path remains restricted to transport.set.
pub fn encode_stream_command_with_id(command: &str, id: u64) -> Result<Vec<u8>> {
    encode_schema_command_with_id(command, id, false)
}

/// Encode a shell-split service invocation without splitting quoted field values.
pub fn encode_stream_argv_with_id(arguments: &[String], id: u64) -> Result<Vec<u8>> {
    let schema = load_tagged_schema();
    let method = arguments.first().context("missing device method")?;
    let record = schema.parse_argv(method, &arguments[1..])?;
    let fields = schema.to_jsonl(&record);
    let fields = fields.as_object().context("command fields")?;
    let fields = fields
        .iter()
        .filter(|(key, _)| *key != "method")
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    encode_schema_fields_with_id(&schema, method, &fields, id, false)
}

fn encode_schema_command_with_id(command: &str, id: u64, direct: bool) -> Result<Vec<u8>> {
    let schema = load_tagged_schema();
    let record = schema.parse_text(command)?;
    let value = schema.to_jsonl(&record);
    let method = value
        .get("method")
        .and_then(Value::as_str)
        .context("command method")?;
    let fields = value
        .as_object()
        .context("command fields")?
        .iter()
        .filter(|(key, _)| key.as_str() != "method")
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    encode_schema_fields_with_id(&schema, method, &fields, id, direct)
}

/// Encode a JSON request from the local session/HTTP-style surface with the
/// same schema used by shell `field=value` commands.
pub fn encode_stream_fields_with_id(
    method: &str,
    fields: &Map<String, Value>,
    id: u64,
) -> Result<Vec<u8>> {
    encode_schema_fields_with_id(&load_tagged_schema(), method, fields, id, false)
}

fn encode_schema_fields_with_id(
    schema: &TaggedSchema,
    method: &str,
    fields: &Map<String, Value>,
    id: u64,
    direct: bool,
) -> Result<Vec<u8>> {
    let entry = schema.validate_fields(method, fields)?;
    if direct && (method != "transport.set" || entry.component != NameOrTag::Tag(1)) {
        anyhow::bail!("{method} is stream-only; only transport.set has a direct encoding");
    }
    // Firmware handlers with an explicit wire constructor still need the
    // numeric identity here; ordinary requests use the shared mesh catalog.
    let component = match entry.component {
        NameOrTag::Tag(tag) => tag,
        _ => anyhow::bail!("device command {method} has no numeric component"),
    };
    let method_tag = match entry.method {
        NameOrTag::Tag(tag) => tag,
        _ => anyhow::bail!("device command {method} has no numeric method"),
    };
    // The inventory uses the shared correlated *empty* request constructor.
    // It must carry an id for a normal QUIC stream, unlike the older
    // connectionless observation form.
    if component == dmesh_server::announce::ANNOUNCE_COMPONENT as u32
        && u64::from(method_tag) == dmesh_server::announce::ANNOUNCE_DEVICES_OBSERVED
        && fields.is_empty()
    {
        let mut wire = [0u8; 32];
        let used = dmesh_server::tagged::encode_numeric_empty_request(
            dmesh_server::announce::ANNOUNCE_COMPONENT,
            dmesh_server::announce::ANNOUNCE_DEVICES_OBSERVED,
            id,
            &mut wire,
        )
        .context("discovery.nodes request")?;
        return Ok(wire[..used].to_vec());
    }
    // Raw-radio snapshot/reset use a registered empty *fields map*, not an
    // omitted payload. `mesh::cbor::encode_record` correctly omits an empty
    // generic environment, but that would make the embedded raw handler
    // distinguish this request from its documented `{5:{}}` envelope. Keep
    // CLI, direct UART, and E2E on the one shared constructor.
    if component == dmesh_server::raw_wifi::RAW_WIFI_COMPONENT as u32
        && fields.is_empty()
        && (u64::from(method_tag) == dmesh_server::raw_wifi::RAW_WIFI_METHOD_SNAPSHOT
            || u64::from(method_tag) == dmesh_server::raw_wifi::RAW_WIFI_METHOD_RESET_COUNTERS
            || u64::from(method_tag) == dmesh_server::raw_wifi::RAW_WIFI_METHOD_SCAN)
    {
        let mut wire = [0u8; 24];
        let used = dmesh_server::raw_wifi::encode_raw_wifi_snapshot_request_with_id(
            u64::from(method_tag),
            id,
            &mut wire,
        )
        .context("raw radio snapshot request")?;
        return Ok(wire[..used].to_vec());
    }
    if component == dmesh_server::raw_wifi::RAW_WIFI_COMPONENT as u32
        && u64::from(method_tag) == dmesh_server::raw_wifi::RAW_WIFI_METHOD_TX
    {
        let mut wire = [0u8; dmesh_server::raw_wifi::RAW_WIFI_MAX_FRAME + 64];
        let used = dmesh_server::raw_wifi::encode_raw_wifi_tx_json_request(fields, id, &mut wire)
            .context("radio.tx request")?;
        return Ok(wire[..used].to_vec());
    }
    let mut record = schema.record_from_value(method, &Value::Object(fields.clone()))?;
    record.id = Some(Value::from(id));
    mesh::cbor::encode_record(&record)
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
    use super::{
        encode_direct_command, encode_direct_command_with_id, encode_stream_argv_with_id,
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
    fn relay_apply_is_stream_only() {
        assert!(encode_direct_command_with_id("relay.apply allocation=7", 19).is_err());
    }

    #[test]
    fn discovery_nodes_uses_the_correlated_empty_stream_request() {
        let wire = encode_stream_command_with_id("discovery.nodes", 22).unwrap();
        assert!(dmesh_server::announce::is_devices_observed_request(&wire));
        let record = dmesh_server::tagged::decode(&wire).unwrap();
        assert_eq!(record.id, Some(22));
        assert!(record.fields.is_none());
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
    fn relay_pair_is_stream_only() {
        assert!(encode_direct_command_with_id("relay.pair forward_allocation=7", 20).is_err());
    }

    #[test]
    fn relay_list_is_a_catalogued_stream_command() {
        let record = encode_stream_command_with_id("relay.list", 21).unwrap();
        let record = dmesh_server::tagged::decode(&record).unwrap();
        assert_eq!(record.component, Some(dmesh_server::tagged::Name::Tag(5)));
        assert_eq!(record.method, Some(dmesh_server::tagged::Name::Tag(3)));
        assert_eq!(record.id, Some(21));
    }

    #[test]
    fn direct_transport_set_uses_the_cli_catalog_and_common_envelope() {
        let command = encode_direct_command("transport.set mode=nan now=1").unwrap();
        let envelope = dmesh_server::tagged::decode(&command).expect("tagged direct envelope");
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
        assert!(encode_direct_command("settings.set key=sta_ssid value=costin").is_err());
        let command = encode_stream_command_with_id("settings.set key=sta_ssid value=costin", 41)
            .expect("stream settings command");
        let record = dmesh_server::tagged::decode(&command).expect("tagged stream command");
        assert_eq!(record.component, Some(dmesh_server::tagged::Name::Tag(1)));
        assert_eq!(record.method, Some(dmesh_server::tagged::Name::Tag(2)));
        assert_eq!(record.id, Some(41));
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
        assert!(encode_direct_command("probe bytes=4096 packet_size=512").is_err());
        let command = encode_stream_command_with_id("probe bytes=4096 packet_size=512", 44)
            .expect("stream probe command");
        let record = dmesh_server::tagged::decode(&command).expect("tagged probe request");
        assert_eq!(
            dmesh_server::probe::decode_probe_run_record(record),
            Some((44, dmesh_server::probe::ProbeServiceRequest::new(4096, 512)))
        );
    }

    #[test]
    fn object_flash_is_a_schema_driven_stream_request() {
        assert!(
            encode_direct_command("object.flash cpu=13 target=3 transport=0 dry_run=true").is_err()
        );
        let command = encode_stream_command_with_id(
            "object.flash cpu=13 target=3 transport=0 dry_run=true",
            45,
        )
        .expect("stream flash request");
        let (id, request) = dmesh_server::verified_object::decode_flash_handler_request(&command)
            .expect("canonical flash request");
        assert_eq!(id, 45);
        assert_eq!(request.object.cpu, 13);
        assert_eq!(request.object.target, 3);
        assert_eq!(request.transport, 0);
        assert!(request.dry_run);

        let command = encode_stream_command_with_id("object.flash cpu=13 target=3", 46)
            .expect("flash request with defaults");
        let (id, request) = dmesh_server::verified_object::decode_flash_handler_request(&command)
            .expect("canonical flash request with defaults");
        assert_eq!(id, 46);
        assert_eq!(request.object.cpu, 13);
        assert_eq!(request.object.target, 3);
        assert_eq!(request.transport, 0);
        assert!(!request.dry_run);

        let command =
            encode_stream_command_with_id("object.flash name=lora cpu=0 target=7 address=0", 47)
                .expect("named module flash request");
        let (_, request) = dmesh_server::verified_object::decode_flash_handler_request(&command)
            .expect("canonical named flash request");
        assert_eq!(request.object.name, Some(&b"lora"[..]));
        assert_eq!(request.address, Some(0));
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
    fn boot_recovery_is_an_empty_tagged_stream_request() {
        assert!(encode_direct_command("boot.recovery").is_err());
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
    fn firmware_identity_is_a_read_only_tagged_stream_request() {
        assert!(encode_direct_command("firmware.identity").is_err());
        let command = encode_stream_command_with_id("firmware.identity", 47)
            .expect("stream firmware identity request");
        let record = dmesh_server::tagged::decode(&command).expect("tagged identity request");
        assert_eq!(
            record.component,
            Some(dmesh_server::tagged::Name::Tag(
                dmesh_server::services::FIRMWARE_COMPONENT,
            ))
        );
        assert_eq!(
            record.method,
            Some(dmesh_server::tagged::Name::Tag(
                dmesh_server::services::FIRMWARE_IDENTITY_METHOD,
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
                        decoder.bytes_or_text_ref(),
                        Some(b"hex:88664b020b6d".as_slice())
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
                        decoder.bytes_or_text_ref(),
                        Some(b"hex:88664b020b6d".as_slice())
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
            decoder.bytes_or_text_ref(),
            Some(b"hex:deadbeef".as_slice())
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
            ("metrics", 3),
            ("events since=4", 4),
            ("log-watch since=4 records=8", 5),
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
        assert!(encode_direct_command("radio.control channel=6").is_err());
        let telemetry = encode_stream_command_with_id("telemetry.nan_metrics", 43)
            .expect("stream telemetry command");
        assert_eq!(
            dmesh_server::telemetry::decode_request(&telemetry),
            Some((dmesh_server::telemetry::NAN_METRICS_METHOD, 43))
        );
    }

    #[test]
    fn radio_snapshot_has_a_stream_handler_but_no_direct_encoding() {
        assert!(encode_direct_command("radio.snapshot").is_err());
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
        assert!(
            encode_direct_command("radio.tx frame=d000000000000000000000000000000000000000000000")
                .is_err()
        );
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
