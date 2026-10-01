//! Shared schema loading for mesh services.
//!
//! Service-specific catalogs can be embedded by callers and extended with
//! files from `MESH_SCHEMA_FILES` or `MESH_SCHEMA_DIR`.

use anyhow::{Context, Result};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, fs, path::PathBuf};

/// A generated component resource schema. Consumers embed their generated
/// resource and use this shared parser for shell, JSONL, and JNI ingress.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ResourceSchemaFile {
    #[serde(default)]
    pub methods: Vec<ResourceMethod>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ResourceMethod {
    pub name: String,
    #[serde(default)]
    pub fields: Vec<ResourceField>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ResourceField {
    pub name: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub values: BTreeMap<String, u64>,
}

/// Schema-backed human command parser shared by every mesh ingress.
#[derive(Clone, Debug, Default)]
pub struct ResourceSchema {
    methods: BTreeMap<String, ResourceMethod>,
}

impl ResourceSchema {
    pub fn from_embedded(embedded: &str) -> Result<Self> {
        let mut result = Self::default();
        for file in load_json::<ResourceSchemaFile>(Some(embedded))? {
            for method in file.methods {
                result.methods.insert(method.name.clone(), method);
            }
        }
        Ok(result)
    }

    /// Parse `method key=value flag` into the canonical JSONL request shape.
    pub fn parse_shell(&self, line: &str) -> Result<Value> {
        let mut words = line.split_ascii_whitespace();
        let method = words.next().context("empty command")?.to_owned();
        // Resource catalogs are additive. Unknown methods remain a structured
        // text request so a newer endpoint can extend the command surface
        // without requiring a client upgrade; known fields are still typed.
        let schema = self.methods.get(&method);
        let mut fields = Map::new();
        for word in words {
            let (name, raw) = word.split_once('=').unwrap_or((word, "true"));
            let field =
                schema.and_then(|schema| schema.fields.iter().find(|field| field.name == name));
            let value = match field.and_then(|field| field.kind.as_deref()) {
                Some("bool") => raw
                    .parse::<bool>()
                    .map(Value::Bool)
                    .with_context(|| format!("{method}.{name} must be bool"))?,
                Some("u8") | Some("u16") | Some("u32") | Some("u64") => raw
                    .parse::<u64>()
                    .map(Value::from)
                    .with_context(|| format!("{method}.{name} must be integer"))?,
                Some("enum") => Value::from(match field.expect("enum field").values.get(raw) {
                    Some(value) => *value,
                    None => raw
                        .parse::<u64>()
                        .with_context(|| format!("unknown {method}.{name}={raw}"))?,
                }),
                _ => Value::String(raw.to_owned()),
            };
            fields.insert(name.to_owned(), value);
        }
        Ok(serde_json::json!({"method": method, "params": fields}))
    }
}

pub fn load_json<T: DeserializeOwned>(embedded: Option<&str>) -> Result<Vec<T>> {
    let mut values = Vec::new();
    if let Some(contents) = embedded {
        values.push(serde_json::from_str(contents).context("parse embedded schema")?);
    }
    for path in configured_files() {
        let contents =
            fs::read_to_string(&path).with_context(|| format!("read schema {}", path.display()))?;
        values.push(
            serde_json::from_str(&contents)
                .with_context(|| format!("parse schema {}", path.display()))?,
        );
    }
    Ok(values)
}

pub fn configured_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    let value = std::env::var("MESH_SCHEMA_FILES");
    if let Ok(value) = value {
        files.extend(
            value
                .split(':')
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
        );
    }
    let dir = std::env::var("MESH_SCHEMA_DIR")
        .unwrap_or_else(|_| "/etc/mesh/schemas".to_owned());
    if let Ok(entries) = fs::read_dir(dir) {
        files.extend(
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json")),
        );
    }
    files
}
