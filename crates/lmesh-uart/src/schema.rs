use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

// The canonical schema is compiled in. `SCHEMA_DIR` supplies every
// optional schema that lmesh-uart should translate at runtime.
const CORE_SCHEMA: &str = include_str!("../../lmesh/resources/firmware-schema.json");
const SCHEMA_DIRECTORY_RELATIVE_PATH: &str = "schemas";

#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct FirmwareSchemaFile {
    #[serde(default)]
    pub methods: Vec<SchemaMethod>,
    #[serde(default)]
    pub messages: Vec<SchemaMessage>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct SchemaMethod {
    pub id: u16,
    pub name: String,
    #[serde(default)]
    pub direct_control: bool,
    #[serde(default)]
    pub fields: Vec<SchemaField>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct SchemaMessage {
    pub name: String,
    #[serde(default)]
    pub format: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    pub fields: Vec<SchemaField>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct SchemaField {
    #[serde(default)]
    pub id: Option<u16>,
    pub name: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub kind: Option<String>,
    /// Textual enum spelling accepted by `dmesh-cli --command`, mapped to
    /// the canonical numeric CBOR value.  This keeps command formatting in
    /// the generated schema instead of hard-coding radio lab vocabulary in
    /// the UART bearer client.
    #[serde(default)]
    pub values: BTreeMap<String, u64>,
}

/// Host-side vocabulary for compact firmware CBOR. It is independent of a
/// particular bearer: device sessions use the same schema over UART, UDP, or
/// any later QUIC-lite path.
#[derive(Clone, Debug, Default)]
pub struct FirmwareSchema {
    methods: BTreeMap<u16, SchemaMethod>,
    fields: BTreeMap<u16, BTreeMap<u16, String>>,
    messages: BTreeMap<String, SchemaMessage>,
    catalog: mesh::cbor::Catalog,
}

impl FirmwareSchema {
    pub fn load() -> Self {
        let mut schema = Self::default();
        if let Ok(core) = serde_json::from_str::<FirmwareSchemaFile>(CORE_SCHEMA) {
            schema.merge(core);
        }

        for path in configured_schema_files() {
            match fs::read_to_string(&path)
                .with_context(|| format!("read schema {}", path.display()))
                .and_then(|contents| {
                    serde_json::from_str::<FirmwareSchemaFile>(&contents)
                        .with_context(|| format!("parse schema {}", path.display()))
                }) {
                Ok(file) => schema.merge(file),
                Err(error) => {
                    tracing::warn!(path = %path.display(), error = %error, "schema_load_failed")
                }
            }
        }
        schema.refresh_catalog();
        schema
    }

    fn refresh_catalog(&mut self) {
        let tools = self.methods.values().map(|method| {
            let properties = method.fields.iter().map(|field| {
                (field.name.clone(), json!({"x-mesh-cbor": {"id": field.id}}))
            }).collect::<Map<String, Value>>();
            json!({
                "name": method.name,
                "x-mesh-cbor": {"id": method.id},
                "inputSchema": {"type": "object", "properties": properties},
            })
        }).collect::<Vec<_>>();
        self.catalog = mesh::cbor::Catalog::from_tools_json(&Value::Array(tools))
            .expect("firmware JSON schema has valid u16 CBOR tags");
    }

    fn merge(&mut self, file: FirmwareSchemaFile) {
        for method in file.methods {
            self.fields.insert(
                method.id,
                method
                    .fields
                    .iter()
                    .filter_map(|field| field.id.map(|id| (id, field.name.clone())))
                    .collect(),
            );
            self.methods.insert(method.id, method);
        }
        for message in file.messages {
            self.messages.insert(message.name.clone(), message);
        }
    }

    pub fn rename_decoded(&self, mut value: Value) -> Value {
        let Some(object) = value.as_object_mut() else {
            return value;
        };
        let method_id = object
            .get("method")
            .and_then(Value::as_u64)
            .and_then(|id| u16::try_from(id).ok())
            // `mesh::cbor::decode_json` may already have replaced the
            // numeric method tag with its catalog name.  Keep the field and
            // message schema lookup working in that normal decoded form.
            .or_else(|| {
                object.get("method").and_then(Value::as_str).and_then(|name| {
                    self.methods
                        .iter()
                        .find_map(|(id, method)| (method.name == name).then_some(*id))
                })
            });
        let method_name =
            method_id.and_then(|id| self.methods.get(&id).map(|method| method.name.clone()));
        if let Some(name) = method_name {
            object.insert("method".to_owned(), Value::String(name));
        }
        let Some(payload) = object.get_mut("payload").and_then(Value::as_object_mut) else {
            return value;
        };
        let Some(method_id) = method_id else {
            return value;
        };
        let Some(fields) = self.fields.get(&method_id) else {
            return value;
        };
        let mut renamed = Map::new();
        for (key, item) in std::mem::take(payload) {
            let name = key
                .parse::<u16>()
                .ok()
                .and_then(|id| fields.get(&id).cloned())
                .unwrap_or(key);
            renamed.insert(name, item);
        }
        *payload = renamed;
        if method_id == 0 {
            if let Some(message) = payload
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_owned)
            {
                if let Some(data) = self.decode_message(&message) {
                    payload.insert("data".to_owned(), Value::Object(data));
                }
            }
        }
        value
    }

    /// Decode a firmware compact-CBOR payload into a schema-labelled value.
    /// Unknown method and field IDs remain numeric, so diagnostics stay
    /// structured and lossless when a host has not yet installed a schema.
    pub fn decode_packet(&self, payload: &[u8]) -> Result<Value> {
        let value = mesh::cbor::decode_json(payload, &self.catalog)?;
        Ok(self.rename_decoded(value))
    }

    fn decode_message(&self, message: &str) -> Option<Map<String, Value>> {
        let mut fields = message.split_whitespace();
        let _kind = fields.next()?;
        let message_type = fields.find_map(|field| field.strip_prefix("type="))?;
        let schema = self.messages.get(&format!("event.{message_type}"))?;
        if schema.format.as_deref() != Some("kv") {
            return None;
        }
        let field_types = schema
            .fields
            .iter()
            .map(|field| {
                (
                    field.name.as_str(),
                    field.kind.as_deref().unwrap_or("string"),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut data = Map::new();
        data.insert("type".to_owned(), Value::String(message_type.to_owned()));
        for field in message.split_whitespace().skip(1) {
            let Some((key, raw)) = field.split_once('=') else {
                continue;
            };
            let kind = field_types.get(key).copied().unwrap_or("string");
            let value = match kind {
                "bool" => raw.parse::<bool>().map(Value::Bool).ok(),
                "u64" => raw.parse::<u64>().ok().map(|value| Value::from(value)),
                "i64" => raw.parse::<i64>().ok().map(|value| Value::from(value)),
                _ => Some(Value::String(raw.to_owned())),
            }?;
            data.insert(key.to_owned(), value);
        }
        Some(data)
    }
}

/// Render a direct device record for a human-facing shell/session. Printable
/// boot and platform output remains text; compact CBOR is decoded and labelled
/// by the local schema. Unknown data is retained as hex instead of discarded.
pub fn render_device_record(schema: &FirmwareSchema, payload: &[u8]) -> String {
    if payload.is_empty() {
        return "kind=empty".to_owned();
    }
    if bytes_are_text(payload) {
        return format!(
            "kind=text text={}",
            serde_json::to_string(&text_preview(payload)).expect("string JSON")
        );
    }
    match schema.decode_packet(payload) {
        Ok(decoded) if decoded.get("error").is_none() => cbor_log_fields(&decoded),
        Ok(decoded) => format!("kind=cbor_error value={decoded}"),
        Err(_) => format!(
            "kind=raw bytes={} hex={}",
            payload.len(),
            hex_encode(payload)
        ),
    }
}

/// Convert a shell-style command to the compact stream frame used only by the
/// explicitly selected direct-CBOR exception plane. New application operations
/// should use QUIC-lite service streams, where normal flow control applies.
fn command_json(command: &str, schema: &FirmwareSchema) -> Result<Value> {
    let mut words = command.split_ascii_whitespace();
    let method = words.next().context("empty firmware command")?;
    let mut fields = Map::new();
    for word in words {
        let (key, value) = word.split_once('=').unwrap_or((word, "true"));
        if key == "payload" {
            let hex = value.strip_prefix("hex:").unwrap_or(value);
            fields.insert("data".to_owned(), Value::Array(decode_hex(hex)?.into_iter().map(Value::from).collect()));
        } else {
            fields.insert(
                key.to_owned(),
                schema.command_value(method, key, value)?,
            );
        }
    }
    fields.insert("method".to_owned(), Value::String(method.to_owned()));
    Ok(Value::Object(fields))
}

impl FirmwareSchema {
    fn command_value(&self, method: &str, name: &str, value: &str) -> Result<Value> {
        let field = self
            .methods
            .values()
            .find(|entry| entry.name == method)
            .and_then(|entry| entry.fields.iter().find(|field| field.name == name));
        let Some(field) = field else {
            // Existing firmware commands deliberately retain their text
            // values for forward compatibility. Typed conversion is enabled
            // only where the installed JSON schema declares it.
            return Ok(Value::String(value.to_owned()));
        };
        match field.kind.as_deref() {
            Some("bool") => value
                .parse::<bool>()
                .map(Value::Bool)
                .with_context(|| format!("{method} {name} must be bool")),
            Some("u8") | Some("u16") | Some("u32") | Some("u64") => value
                .parse::<u64>()
                .map(Value::from)
                .with_context(|| format!("{method} {name} must be integer")),
            Some("enum") => {
                if let Some(value) = field.values.get(value) {
                    Ok(Value::from(*value))
                } else {
                    value
                        .parse::<u64>()
                        .map(Value::from)
                        .with_context(|| format!("unknown {method} {name} value={value}"))
                }
            }
            // MAC stays a canonical text spelling on the command line.  The
            // host-owned radio schema validates and converts it at its CBOR
            // handler boundary, avoiding a UART-only byte convention.
            Some("mac") => Ok(Value::String(value.to_ascii_lowercase())),
            _ => Ok(Value::String(value.to_owned())),
        }
    }
}

#[cfg(test)]
pub fn encode_text_command(command: &str) -> Result<Vec<u8>> {
    let schema = FirmwareSchema::load();
    Ok(mesh::cbor::encode_stream_frame(&mesh::cbor::encode_json(&command_json(command, &schema)?, &schema.catalog)?)?)
}

/// Encode the explicit Recovery direct-control exception without a generic
/// stream-frame wrapper. Recovery accepts the canonical `{0: "recovery",
/// 6: {...}}` CBOR envelope before a QUIC-lite connection exists; wrapping it
/// turns the command into unrelated stream data and is correctly rejected.
pub fn encode_direct_command(command: &str) -> Result<Vec<u8>> {
    let schema = FirmwareSchema::load();
    let value = command_json(command, &schema)?;
    let method = value.get("method").and_then(Value::as_str).context("command method")?;
    let cbor = mesh::cbor::encode_json(&value, &schema.catalog)?;
    let direct = schema.methods.values().any(|entry| entry.name == method && entry.direct_control);
    if direct { Ok(cbor) } else { Ok(mesh::cbor::encode_stream_frame(&cbor)?) }
}

/// Compact logfmt renderer shared by the session CLI and the remaining
/// diagnostics code. `status=ok` is omitted because it is not delivery proof.
pub fn cbor_log_fields(value: &Value) -> String {
    let mut fields = Vec::new();
    flatten_cbor_log_value(&mut fields, None, value, true);
    fields.join(" ")
}

fn flatten_cbor_log_value(
    fields: &mut Vec<String>,
    prefix: Option<&str>,
    value: &Value,
    top_level: bool,
) {
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                if top_level && key == "status" && value.as_str() == Some("ok") {
                    continue;
                }
                let key = prefix
                    .map(|prefix| format!("{prefix}.{key}"))
                    .unwrap_or_else(|| key.clone());
                flatten_cbor_log_value(fields, Some(&key), value, false);
            }
        }
        Value::Array(_) => {
            if let Some(key) = prefix {
                fields.push(format!("{key}={}", logfmt_json_value(value)));
            }
        }
        _ => {
            if let Some(key) = prefix {
                fields.push(format!("{key}={}", logfmt_json_value(value)));
            }
        }
    }
}

fn logfmt_json_value(value: &Value) -> String {
    match value {
        Value::String(value)
            if !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'=' | b'"')) =>
        {
            value.clone()
        }
        _ => value.to_string(),
    }
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

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        anyhow::bail!("hex payload must have an even number of characters");
    }
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).map_err(Into::into))
        .collect()
}

fn hex_encode(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[allow(dead_code)]
fn firmware_arg_tag(name: &str) -> Option<u16> {
    Some(match name {
        "op" => 87,
        "name" => 409,
        "server" => 246,
        "port" => 191,
        "target" => 346,
        "object_action_stats" => 272,
        _ => return None,
    })
}

fn configured_schema_files() -> Vec<PathBuf> {
    let Some(dir) = std::env::var_os("SCHEMA_DIR")
        .map(PathBuf::from)
        .and_then(resolve_schema_directory)
        .or_else(default_schema_directory)
    else {
        return Vec::new();
    };
    if let Ok(entries) = fs::read_dir(dir) {
        return entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
            .collect();
    }
    Vec::new()
}

fn default_schema_directory() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(SCHEMA_DIRECTORY_RELATIVE_PATH))
}

fn resolve_schema_directory(path: PathBuf) -> Option<PathBuf> {
    if path.is_absolute() {
        Some(path)
    } else {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join(path))
    }
}

#[cfg(test)]
mod tests {
    use super::{FirmwareSchema, encode_direct_command, encode_text_command, render_device_record};
    use minicbor::Encoder;
    use serde_json::json;

    #[test]
    fn core_schema_names_event_and_message_tag() {
        let schema = FirmwareSchema::load();
        let decoded = schema.rename_decoded(json!({
            "method": 0,
            "payload": {"32": "event type=mode.state active=infra infra_active=false"},
            "status": "event"
        }));
        assert_eq!(decoded["method"], "event");
        assert_eq!(
            decoded["payload"]["message"],
            "event type=mode.state active=infra infra_active=false"
        );
        assert_eq!(decoded["payload"]["data"]["type"], "mode.state");
        assert_eq!(decoded["payload"]["data"]["infra_active"], false);
    }

    #[test]
    fn compact_cbor_is_rendered_with_schema_names() {
        let mut packet = Vec::new();
        let mut encoder = Encoder::new(&mut packet);
        encoder.map(2).unwrap();
        encoder.u16(0).unwrap().u16(0).unwrap();
        encoder.u16(6).unwrap().map(1).unwrap();
        encoder
            .u16(32)
            .unwrap()
            .str("event type=mode.state active=infra infra_active=true")
            .unwrap();

        let decoded = FirmwareSchema::load().decode_packet(&packet).unwrap();
        assert_eq!(decoded["method"], "event");
        assert_eq!(
            decoded["payload"]["message"],
            "event type=mode.state active=infra infra_active=true"
        );
        assert_eq!(decoded["payload"]["data"]["infra_active"], true);
    }

    #[test]
    fn unknown_method_and_tags_remain_structured() {
        let decoded = FirmwareSchema::load().rename_decoded(json!({
            "method": 65535,
            "payload": {"999": true}
        }));
        assert_eq!(decoded["method"], 65535);
        assert_eq!(decoded["payload"]["999"], true);
    }

    #[test]
    fn session_renderer_keeps_text_and_schema_labels() {
        let schema = FirmwareSchema::load();
        assert_eq!(
            render_device_record(&schema, b"boot ready\n"),
            "kind=text text=\"boot ready\""
        );
        let command = encode_text_command("mode active_ms=1000").unwrap();
        let payload = mesh::cbor::decode_stream_frame(&command).unwrap();
        assert!(schema.decode_packet(payload).is_ok());
    }

    #[test]
    fn recovery_direct_command_is_not_stream_wrapped() {
        let command = encode_direct_command("recovery raw_tx_rate=24").unwrap();
        let decoded = dmesh_server::recovery::decode_recovery_command(&command);
        assert!(decoded.is_some(), "command={command:02x?}");
        assert_eq!(decoded.unwrap().raw_tx_rate, Some(24));
    }

    #[test]
    fn recovery_direct_command_selects_sta_egress_runtime() {
        let command = encode_direct_command("recovery sta_driver_tx=true").unwrap();
        let decoded = dmesh_server::recovery::decode_recovery_command(&command).unwrap();
        assert_eq!(decoded.sta_driver_tx, Some(true));
    }

    #[test]
    fn radio_control_command_uses_schema_types_and_direct_handler_envelope() {
        let command = encode_direct_command(
            "radio.control channel=6 sta_state=disconnect_hold comparator_bssid=50:6f:9a:01:34:4a comparator_enabled=true promiscuous=false dw_policy=disabled",
        )
        .unwrap();
        let dmesh_server::raw_wifi::RawWifiLabRequest::Control(control) =
            dmesh_server::raw_wifi::decode_raw_wifi_handler(&command).unwrap()
        else {
            panic!("radio control request")
        };
        assert_eq!(control.channel, Some(6));
        assert_eq!(
            control.sta_state,
            Some(dmesh_server::raw_wifi::RawWifiStaState::DisconnectHold)
        );
        assert_eq!(control.comparator_bssid, Some([0x50, 0x6f, 0x9a, 0x01, 0x34, 0x4a]));
        assert_eq!(control.comparator_enabled, Some(true));
        assert_eq!(control.promiscuous, Some(false));
        assert_eq!(
            control.dw_policy,
            Some(dmesh_server::raw_wifi::RawWifiDwPolicy::Disabled)
        );
    }
}
