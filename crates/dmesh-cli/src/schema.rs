use anyhow::{Context, Result};
use mesh::tagged::{NameOrTag, TaggedCatalog, TaggedRecord};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

// TODO: move common (device free) to ssh-mesh, evaluate the rest.

// The canonical schema is compiled in. `SCHEMA_DIR` supplies every
// optional schema that dmesh-cli should translate at runtime.
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
    /// Optional common tagged component used by stream dispatch and rendering.
    #[serde(default)]
    pub component: Option<u16>,
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
    /// Textual enum spelling accepted by `dmesh-cli --msg`, mapped to
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
    methods: BTreeMap<String, SchemaMethod>,
    fields: BTreeMap<String, BTreeMap<u16, String>>,
    messages: BTreeMap<String, SchemaMessage>,
    catalog: mesh::cbor::Catalog,
    /// Numeric tagged-CBOR catalog for the direct-record boundary.  It is
    /// built from the installed schema artifact, so the CLI never needs to
    /// manufacture the retired compact `{0,6}` map and translate it again.
    tagged_catalog: TaggedCatalog,
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

    /// True when a command name is handled through the normal tagged stream
    /// plane. This lets the CLI grammar come from the schema rather than a
    /// second hard-coded subcommand list.
    pub fn is_stream_command_name(&self, name: &str) -> bool {
        self.methods
            .values()
            .any(|method| method.name == name && method.component.is_some())
    }

    fn refresh_catalog(&mut self) {
        let tools = self
            .methods
            .values()
            .map(|method| {
                let properties = method
                    .fields
                    .iter()
                    .map(|field| (field.name.clone(), json!({"x-mesh-cbor": {"id": field.id}})))
                    .collect::<Map<String, Value>>();
                json!({
                    "name": method.name,
                    "x-mesh-cbor": {"id": method.id},
                    "inputSchema": {"type": "object", "properties": properties},
                })
            })
            .collect::<Vec<_>>();
        self.catalog = mesh::cbor::Catalog::from_tools_json(&Value::Array(tools))
            .expect("firmware JSON schema has valid u16 CBOR tags");
        // `TaggedCatalog` is the canonical command encoder. Keep the older
        // compact catalog above only for rendering historical diagnostic
        // records until every producer has moved to tagged CBOR.
        self.tagged_catalog = TaggedCatalog::from_tools_json(&Value::Array(
            self.methods
                .values()
                .map(|method| {
                    let properties = method
                        .fields
                        .iter()
                        .filter_map(|field| {
                            field
                                .id
                                .map(|id| (field.name.clone(), json!({"x-protobuf-index": id})))
                        })
                        .collect::<Map<String, Value>>();
                    json!({
                        "name": method.name,
                        "x-component-index": method.component,
                        "x-method-index": method.id,
                        "inputSchema": {"type": "object", "properties": properties},
                    })
                })
                .collect(),
        ))
        .expect("firmware JSON schema has valid tagged-CBOR metadata");
    }

    fn merge(&mut self, file: FirmwareSchemaFile) {
        for method in file.methods {
            let name = method.name.clone();
            self.fields.insert(
                name.clone(),
                method
                    .fields
                    .iter()
                    .filter_map(|field| field.id.map(|id| (id, field.name.clone())))
                    .collect(),
            );
            self.methods.insert(name, method);
        }
        for message in file.messages {
            self.messages.insert(message.name.clone(), message);
        }
    }

    pub fn rename_decoded(&self, value: Value) -> Value {
        self.rename_decoded_for_component(value, None)
    }

    fn rename_decoded_for_component(&self, mut value: Value, component: Option<u16>) -> Value {
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
                object
                    .get("method")
                    .and_then(Value::as_str)
                    .and_then(|name| {
                        self.methods
                            .values()
                            .find_map(|method| (method.name == name).then_some(method.id))
                    })
            });
        let method_name = method_id.and_then(|id| {
            self.methods
                .values()
                .find(|method| {
                    method.id == id && component.is_none_or(|c| method.component == Some(c))
                })
                .map(|method| method.name.clone())
        });
        if let Some(name) = method_name {
            object.insert("method".to_owned(), Value::String(name));
        }
        let Some(payload) = object.get_mut("payload").and_then(Value::as_object_mut) else {
            return value;
        };
        let Some(method_id) = method_id else {
            return value;
        };
        let Some(method_name) = self
            .methods
            .values()
            .find(|method| {
                method.id == method_id && component.is_none_or(|c| method.component == Some(c))
            })
            .map(|method| method.name.as_str())
        else {
            return value;
        };
        let Some(fields) = self.fields.get(method_name) else {
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
    ///
    /// Direct firmware controls use the common tagged record envelope
    /// (`component`, `method`, `id`, `fields`/`result`), not the older compact
    /// `{0: method, 6: payload}` diagnostic map.  Project that canonical form
    /// into the compact renderer's input shape first, so `wifi.scan` renders
    /// exactly like `transport.set`.
    pub fn decode_packet(&self, payload: &[u8]) -> Result<Value> {
        if let Some(record) = dmesh_server::tagged::decode(payload) {
            if let (
                Some(dmesh_server::tagged::Name::Tag(component)),
                Some(dmesh_server::tagged::Name::Tag(method)),
                Some(id),
                Some(body),
            ) = (
                record.component,
                record.method,
                record.id,
                record.result.or(record.error),
            ) {
                let mut compact = Vec::with_capacity(payload.len());
                dmesh_server::cbor::encode::map(3, &mut compact);
                dmesh_server::cbor::encode::uint(0, &mut compact);
                dmesh_server::cbor::encode::uint(method, &mut compact);
                dmesh_server::cbor::encode::uint(1, &mut compact);
                dmesh_server::cbor::encode::uint(id, &mut compact);
                dmesh_server::cbor::encode::uint(
                    if record.result.is_some() { 6 } else { 5 },
                    &mut compact,
                );
                compact.extend_from_slice(body);
                let mut value = mesh::cbor::decode_json(&compact, &self.catalog)?;
                if let Some(object) = value.as_object_mut() {
                    // The legacy compact catalog is keyed only by method ID.
                    // Restore the wire ID before the component-aware lookup so
                    // equal method numbers in different tagged components do
                    // not borrow each other's names or field schemas.
                    object.insert("method".to_owned(), Value::from(method));
                }
                return Ok(self.rename_decoded_for_component(value, u16::try_from(component).ok()));
            }
        }
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
            fields.insert(
                "data".to_owned(),
                Value::Array(decode_hex(hex)?.into_iter().map(Value::from).collect()),
            );
        } else {
            fields.insert(key.to_owned(), schema.command_value(method, key, value)?);
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
            // Text has no byte-string type. Keep the representation marker
            // local to the JSON/text adapter; the shared CBOR encoder turns
            // it into a byte string for every client surface.
            Some("hex") => Ok(Value::String(format!("hex:{value}"))),
            _ => Ok(Value::String(value.to_owned())),
        }
    }
}

/// Encode a schema-guided direct command as one canonical tagged-CBOR record.
///
/// The installed schema remains the temporary catalog artifact during the
/// generator migration, but this function no longer creates the retired
/// compact `{0: method, 6: payload}` map and decodes it again.  Direct records
/// require numeric component and method tags; an unreviewed schema entry must
/// use the explicit JSON-RPC compatibility path instead of unnamed CBOR.
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

fn encode_schema_command_with_id(command: &str, id: u64, direct: bool) -> Result<Vec<u8>> {
    let schema = FirmwareSchema::load();
    let mut value = command_json(command, &schema)?;
    let method = value
        .get("method")
        .and_then(Value::as_str)
        .context("command method")?
        .to_owned();
    value
        .as_object_mut()
        .context("command object")?
        .remove("method");
    encode_schema_fields_with_id(
        &schema,
        &method,
        value.as_object().context("command fields")?,
        id,
        direct,
    )
}

/// Encode a JSON request from the local session/HTTP-style surface with the
/// same schema used by shell `field=value` commands.
pub fn encode_stream_fields_with_id(
    method: &str,
    fields: &Map<String, Value>,
    id: u64,
) -> Result<Vec<u8>> {
    encode_schema_fields_with_id(&FirmwareSchema::load(), method, fields, id, false)
}

fn encode_schema_fields_with_id(
    schema: &FirmwareSchema,
    method: &str,
    fields: &Map<String, Value>,
    id: u64,
    direct: bool,
) -> Result<Vec<u8>> {
    let entry = schema
        .methods
        .values()
        .find(|entry| entry.name == *method)
        .context("unknown firmware command")?;
    if direct && (entry.name != "transport.set" || entry.component != Some(1)) {
        anyhow::bail!("{method} is stream-only; only transport.set has a direct encoding");
    }
    // The pinned mesh catalog translates text and JSONL but does not expose
    // the newer `record_from_value` helper. Direct firmware commands already
    // carry reviewed numeric component/method/field IDs in `FirmwareSchema`,
    // so construct that tagged record here without a text round trip.
    let component = entry
        .component
        .context("direct firmware command has no component")?;
    // The inventory uses the shared correlated *empty* request constructor.
    // It must carry an id for a normal QUIC stream, unlike the older
    // connectionless observation form.
    if component == dmesh_server::announce::ANNOUNCE_COMPONENT as u16
        && u64::from(entry.id) == dmesh_server::announce::ANNOUNCE_DEVICES_OBSERVED
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
    if component == dmesh_server::raw_wifi::RAW_WIFI_COMPONENT as u16
        && fields.is_empty()
        && (u64::from(entry.id) == dmesh_server::raw_wifi::RAW_WIFI_METHOD_SNAPSHOT
            || u64::from(entry.id) == dmesh_server::raw_wifi::RAW_WIFI_METHOD_RESET_COUNTERS
            || u64::from(entry.id) == dmesh_server::raw_wifi::RAW_WIFI_METHOD_SCAN)
    {
        let mut wire = [0u8; 24];
        let used = dmesh_server::raw_wifi::encode_raw_wifi_snapshot_request_with_id(
            u64::from(entry.id),
            id,
            &mut wire,
        )
        .context("raw radio snapshot request")?;
        return Ok(wire[..used].to_vec());
    }
    if component == dmesh_server::raw_wifi::RAW_WIFI_COMPONENT as u16
        && u64::from(entry.id) == dmesh_server::raw_wifi::RAW_WIFI_METHOD_TX
    {
        let mut wire = [0u8; dmesh_server::raw_wifi::RAW_WIFI_MAX_FRAME + 64];
        let used = dmesh_server::raw_wifi::encode_raw_wifi_tx_json_request(fields, id, &mut wire)
            .context("radio.tx request")?;
        return Ok(wire[..used].to_vec());
    }
    let mut record = TaggedRecord {
        component: NameOrTag::Tag(u32::from(component)),
        method: NameOrTag::Tag(u32::from(entry.id)),
        id: Some(Value::from(id)),
        ..TaggedRecord::default()
    };
    for (name, field_value) in fields {
        let field = entry
            .fields
            .iter()
            .find(|field| field.name == *name)
            .with_context(|| format!("unknown command field {method}.{name}"))?;
        let id = field
            .id
            .with_context(|| format!("command field {method}.{name} has no numeric ID"))?;
        record
            .env
            .insert(NameOrTag::Tag(u32::from(id)), field_value.clone());
    }
    mesh::cbor::encode_record(&record)
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
    use super::{
        FirmwareSchema, encode_direct_command, encode_direct_command_with_id,
        encode_stream_command_with_id, render_device_record,
    };
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
        let schema = FirmwareSchema::load();
        let result = [0xa5, 1, 0x80, 2, 4, 3, 0, 4, 0, 5, 0xf5];
        let mut wire = [0u8; 64];
        let used = dmesh_server::tagged::encode_numeric_response(4, 77, 91, &result, &mut wire)
            .expect("bounded scan response");
        let rendered = render_device_record(&schema, &wire[..used]);
        assert!(rendered.contains("method=wifi.scan"), "{rendered}");
        assert!(rendered.contains("id=91"), "{rendered}");
        assert!(rendered.contains("payload.2=4"), "{rendered}");
    }

    #[test]
    fn tagged_transport_error_keeps_its_method_and_request_id() {
        let schema = FirmwareSchema::load();
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
