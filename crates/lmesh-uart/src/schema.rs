use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{Map, Value};
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
}

#[derive(Clone, Debug, Default)]
pub(crate) struct FirmwareSchema {
    methods: BTreeMap<u16, SchemaMethod>,
    fields: BTreeMap<u16, BTreeMap<u16, String>>,
    messages: BTreeMap<String, SchemaMessage>,
}

impl FirmwareSchema {
    pub(crate) fn load() -> Self {
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
        schema
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

    pub(crate) fn rename_decoded(&self, mut value: Value) -> Value {
        let Some(object) = value.as_object_mut() else {
            return value;
        };
        let method_id = object
            .get("method")
            .and_then(Value::as_u64)
            .and_then(|id| u16::try_from(id).ok());
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
    pub(crate) fn decode_packet(&self, payload: &[u8]) -> Result<Value> {
        let value = mesh::cbor::decode_json(payload, &mesh::cbor::Catalog::default())?;
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
    use super::FirmwareSchema;
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
}
