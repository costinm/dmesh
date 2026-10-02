//! Schema-optional records shared by text, JSON, CBOR, and future binary codecs.
//!
//! Numeric tags are an encoding-independent identity. A catalog is optional:
//! unknown numeric tags are represented in text/JSON as `@<decimal>`.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value};

/// A name which may have a compact numeric representation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NameOrTag {
    Name(String),
    Tag(u32),
}

impl NameOrTag {
    /// Parse `@<decimal>` as a tag; all other names remain text.
    pub fn parse(value: &str) -> Self {
        value
            .strip_prefix('@')
            .and_then(|id| id.parse().ok())
            .map(Self::Tag)
            .unwrap_or_else(|| Self::Name(value.to_owned()))
    }

    /// Render a schema-independent, shell-safe spelling.
    pub fn text(&self) -> String {
        match self {
            Self::Name(value) => value.clone(),
            Self::Tag(id) => format!("@{id}"),
        }
    }
}

/// The common representation used by generic gateways.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TaggedRecord {
    pub component: NameOrTag,
    pub method: NameOrTag,
    pub id: Option<Value>,
    pub params: Vec<Value>,
    pub env: BTreeMap<NameOrTag, Value>,
    /// Present only on a successful response; requests leave it unset.
    pub result: Option<Value>,
    /// Present only on a failed response. Keeping it in the common envelope
    /// lets JSON-RPC gateways translate failures mechanically.
    pub error: Option<Value>,
    /// Optional mesh destination. When present, a mesh-capable dispatcher
    /// forwards the request to this destination instead of executing the
    /// method locally. It is envelope routing metadata, not a handler field.
    pub to: Option<Value>,
    /// Opaque binary payload outside `env`. Keeping this borrowed/owned byte
    /// lane distinct from normal typed fields lets proxy stubs forward large
    /// records without base64 or an intermediate JSON value.
    pub data: Option<Vec<u8>>,
}

/// The envelope kind is derived from field presence; there is intentionally no
/// extra discriminator on the wire. This keeps requests small while making a
/// malformed response impossible to mistake for a command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    Request,
    Message,
    Response,
    Error,
}

impl TaggedRecord {
    /// Validate and classify the common command envelope.
    ///
    /// * `method` + `id` is a request expecting a reply.
    /// * `method` without `id` is a one-way message or event.
    /// * `id` + `result` or `id` + `error` is a reply.
    pub fn kind(&self) -> Result<RecordKind> {
        let has_method = !matches!(&self.method, NameOrTag::Name(value) if value.is_empty());
        match (
            has_method,
            self.id.is_some(),
            self.result.is_some(),
            self.error.is_some(),
        ) {
            (true, true, false, false) => Ok(RecordKind::Request),
            (true, false, false, false) => Ok(RecordKind::Message),
            (false, true, true, false) => Ok(RecordKind::Response),
            (false, true, false, true) => Ok(RecordKind::Error),
            _ => bail!("invalid tagged record envelope"),
        }
    }
}

impl Default for NameOrTag {
    fn default() -> Self {
        Self::Name(String::new())
    }
}

/// Per-method dictionary data extracted from the API catalog.
#[derive(Clone, Debug, Default)]
pub struct MethodSchema {
    pub component: NameOrTag,
    pub method: NameOrTag,
    pub fields: BTreeMap<String, FieldSchema>,
}

#[derive(Clone, Debug)]
pub struct FieldSchema {
    pub tag: u32,
    pub kind: Option<String>,
    pub values: BTreeMap<String, u64>,
}

/// Catalog used for format translation. It intentionally permits unknown values.
#[derive(Clone, Debug, Default)]
pub struct TaggedSchema {
    methods: BTreeMap<String, MethodSchema>,
}

/// Previous name for the format-neutral tagged schema.
pub type TaggedCatalog = TaggedSchema;

impl TaggedSchema {
    /// Reject a command outside the catalog or fields without reviewed tags.
    /// Clients using a strictly schema-driven API can call this before a
    /// format-specific encoder, including CBOR or a future protobuf codec.
    pub fn validate_fields(
        &self,
        method: &str,
        fields: &Map<String, Value>,
    ) -> Result<&MethodSchema> {
        let schema = self
            .methods
            .get(method)
            .ok_or_else(|| anyhow!("unknown schema method {method}"))?;
        for name in fields.keys() {
            if field_schema(Some(schema), name).is_none() {
                bail!("unknown schema field {method}.{name}");
            }
        }
        Ok(schema)
    }
    /// Read the generated numeric metadata from `tools.json`.
    ///
    /// New API.md-derived artifacts use `x-component-index`,
    /// `x-method-index`, and `x-protobuf-index`. The older mesh/DMesh
    /// annotations remain accepted here so every host adapter can migrate to
    /// the one catalog without a wire-format flag day.
    pub fn from_tools_json(value: &Value) -> Result<Self> {
        let tools = value
            .as_array()
            .or_else(|| value.get("tools").and_then(Value::as_array))
            .ok_or_else(|| anyhow!("tools catalog must be an array"))?;
        let mut catalog = Self::default();
        for tool in tools {
            let Some(name) = tool.get("name").and_then(Value::as_str) else {
                continue;
            };
            let wire = tool.get("x-mesh-wire");
            let (default_component, default_method) = name.split_once('.').unwrap_or(("", name));
            let component = name_or_index(
                tool.get("x-component-index")
                    .or_else(|| wire.and_then(|wire| wire.get("component"))),
                default_component,
            );
            let method = name_or_index(
                tool.get("x-method-index")
                    .or_else(|| wire.and_then(|wire| wire.get("method")))
                    .or_else(|| wire.and_then(|wire| wire.get("method_id"))),
                default_method,
            );
            let mut schema = MethodSchema {
                component,
                method,
                fields: BTreeMap::new(),
            };
            if let Some(properties) = tool
                .pointer("/inputSchema/properties")
                .and_then(Value::as_object)
            {
                for (field, property) in properties {
                    let annotation = property.get("x-mesh-wire");
                    if let Some(tag) = property
                        .get("x-protobuf-index")
                        .and_then(Value::as_u64)
                        .or_else(|| {
                            property
                                .get("x-mesh-cbor")
                                .and_then(|value| value.get("id"))
                                .and_then(Value::as_u64)
                        })
                        .or_else(|| {
                            annotation
                                .and_then(|value| value.get("tag"))
                                .and_then(Value::as_u64)
                        })
                    {
                        schema.fields.insert(
                            field.clone(),
                            FieldSchema {
                                tag: tag as u32,
                                kind: property
                                    .get("x-mesh-cbor-type")
                                    .or_else(|| property.get("x-dmesh-kind"))
                                    .and_then(Value::as_str)
                                    .map(str::to_owned),
                                values: property
                                    .get("x-mesh-values")
                                    .or_else(|| property.get("x-dmesh-values"))
                                    .and_then(Value::as_object)
                                    .map(|values| {
                                        values
                                            .iter()
                                            .filter_map(|(name, value)| {
                                                value.as_u64().map(|value| (name.clone(), value))
                                            })
                                            .collect()
                                    })
                                    .unwrap_or_default(),
                            },
                        );
                    }
                }
            }
            catalog.methods.insert(name.to_owned(), schema);
        }
        Ok(catalog)
    }

    pub fn method(&self, name: &str) -> Option<&MethodSchema> {
        self.methods.get(name)
    }

    /// Resolve a numeric or textual record identity to its documented method
    /// name. A catalog's compact numeric IDs and its public names are
    /// interchangeable identities at this boundary: host callers may retain
    /// self-describing names while constrained links use tags.
    ///
    /// Service dispatchers use this when an inbound tagged-CBOR request needs
    /// to enter an existing typed serde handler.
    pub fn method_name(&self, record: &TaggedRecord) -> Option<&str> {
        self.methods
            .iter()
            .find(|(name, schema)| {
                let (component_name, method_name) =
                    name.split_once('.').unwrap_or(("", name.as_str()));
                identity_matches(&record.component, &schema.component, component_name)
                    && identity_matches(&record.method, &schema.method, method_name)
            })
            .map(|(name, _)| name.as_str())
    }

    /// Translate a documented request to the JSON object expected by a typed
    /// service handler. Unlike [`Self::to_jsonl`], this rejects unknown
    /// methods, so a service can use its generated catalog as its public API
    /// boundary without duplicating identity checks.
    pub fn documented_request(&self, record: &TaggedRecord) -> Result<Value> {
        if self.method_name(record).is_none() {
            bail!("tagged-CBOR method is outside the public catalog");
        }
        Ok(self.to_jsonl(record))
    }

    /// Parse `component.method name=value ...` into a tagged record.
    pub fn parse_text(&self, line: &str) -> Result<TaggedRecord> {
        let tokens = text_tokens(line)?;
        self.parse_tokens(&tokens)
    }

    /// Parse a method name and already shell-split arguments into a tagged record.
    ///
    /// Command-line clients must use this rather than joining argv back into a
    /// text line: a field value such as `command=ble stats=true` is one argv
    /// token and must remain one value when a generated tools catalog supplies
    /// its wire tags.
    pub fn parse_argv(&self, method_name: &str, arguments: &[String]) -> Result<TaggedRecord> {
        let mut tokens = Vec::with_capacity(arguments.len() + 1);
        tokens.push(method_name);
        tokens.extend(arguments.iter().map(String::as_str));
        self.parse_tokens(&tokens)
    }

    /// Build a record from a structured Rust/JSON request value.
    ///
    /// This is the non-text counterpart to [`Self::parse_argv`]. Rust clients
    /// serialize their typed request struct once, then this catalog applies
    /// the reviewed field tags without inventing a `key=value` intermediate.
    /// Unknown methods or fields remain named so callers can deliberately use
    /// the JSON-RPC compatibility path until they have reviewed API IDs.
    pub fn record_from_value(&self, method_name: &str, value: &Value) -> Result<TaggedRecord> {
        let schema = self.methods.get(method_name);
        let (component, method) = schema
            .map(|schema| (schema.component.clone(), schema.method.clone()))
            .unwrap_or_else(|| {
                let (component, method) = method_name.split_once('.').unwrap_or(("", method_name));
                (
                    NameOrTag::Name(component.to_owned()),
                    NameOrTag::Name(method.to_owned()),
                )
            });
        let object = value
            .as_object()
            .ok_or_else(|| anyhow!("structured request for {method_name:?} must be an object"))?;
        let mut record = TaggedRecord {
            component,
            method,
            ..Default::default()
        };
        for (name, value) in object {
            match name.as_str() {
                "id" => record.id = Some(value.clone()),
                "to" if !schema.is_some_and(|schema| schema.fields.contains_key("to")) => {
                    record.to = Some(value.clone())
                }
                // `data` is deliberately a CBOR byte field in the envelope.
                // The Rust wire adapter accepts an array of octets here so
                // binary data does not cross a base64/text conversion.
                "data" if !schema.is_some_and(|schema| schema.fields.contains_key("data")) => {
                    let bytes = value
                        .as_array()
                        .ok_or_else(|| anyhow!("structured request data must be an octet array"))?
                        .iter()
                        .map(|value| {
                            value
                                .as_u64()
                                .and_then(|value| u8::try_from(value).ok())
                                .ok_or_else(|| {
                                    anyhow!("structured request data contains a non-octet")
                                })
                        })
                        .collect::<Result<Vec<_>>>()?;
                    record.data = Some(bytes);
                }
                _ => {
                    let key = field_key(schema, name);
                    record.env.insert(key, value.clone());
                }
            }
        }
        Ok(record)
    }

    fn parse_tokens(&self, tokens: &[&str]) -> Result<TaggedRecord> {
        let (method_name, rest) = tokens
            .split_first()
            .ok_or_else(|| anyhow!("missing method"))?;
        let schema = self.methods.get(*method_name);
        let (component, method) = schema
            .map(|schema| (schema.component.clone(), schema.method.clone()))
            .unwrap_or_else(|| {
                let (component, method) = method_name.split_once('.').unwrap_or(("", method_name));
                (
                    NameOrTag::Name(component.to_owned()),
                    NameOrTag::Name(method.to_owned()),
                )
            });
        let mut record = TaggedRecord {
            component,
            method,
            ..Default::default()
        };
        for &token in rest {
            if token.starts_with('-') {
                let option = token.trim_start_matches('-');
                let (name, value) = option
                    .split_once('=')
                    .ok_or_else(|| anyhow!("option {token} requires =value"))?;
                if name == "to" && !schema.is_some_and(|schema| schema.fields.contains_key("to")) {
                    record.to = Some(text_value(value));
                    continue;
                }
                let key = field_key(schema, name);
                record
                    .env
                    .insert(key, field_text_value(schema, name, value)?);
            } else if let Some((name, value)) = token.split_once('=')
                && !name.is_empty()
            {
                if name == "to" && !schema.is_some_and(|schema| schema.fields.contains_key("to")) {
                    record.to = Some(text_value(value));
                    continue;
                }
                let key = field_key(schema, name);
                record
                    .env
                    .insert(key, field_text_value(schema, name, value)?);
            } else {
                bail!("argument {token:?} must be name=value");
            }
        }
        Ok(record)
    }

    /// Produce the method-and-fields JSON object used for local dispatch.
    pub fn to_jsonl(&self, record: &TaggedRecord) -> Value {
        let mut value = Map::new();
        let documented_name = self.method_name(record);
        let component = record.component.text();
        let method = record.method.text();
        value.insert(
            "method".to_owned(),
            Value::String(documented_name.map(str::to_owned).unwrap_or_else(|| {
                if component.is_empty() {
                    method.clone()
                } else {
                    format!("{component}.{method}")
                }
            })),
        );
        if let Some(id) = &record.id {
            value.insert("id".to_owned(), id.clone());
        }
        let schema = documented_name.and_then(|name| self.methods.get(name));
        for (key, item) in &record.env {
            let name = match key {
                NameOrTag::Name(name) => name.clone(),
                NameOrTag::Tag(tag) => schema
                    .and_then(|schema| {
                        schema
                            .fields
                            .iter()
                            .find(|(_, field)| field.tag == *tag)
                            .map(|(name, _)| name.clone())
                    })
                    .unwrap_or_else(|| format!("@{tag}")),
            };
            value.insert(name, item.clone());
        }
        if !record.params.is_empty() {
            value.insert("params".to_owned(), Value::Array(record.params.clone()));
        }
        if let Some(result) = &record.result {
            value.insert("result".to_owned(), project_fields(result, schema));
        }
        if let Some(error) = &record.error {
            value.insert("error".to_owned(), error.clone());
        }
        if let Some(to) = &record.to {
            value.insert("to".to_owned(), to.clone());
        }
        if let Some(data) = &record.data {
            value.insert(
                "data".to_owned(),
                Value::String(format!("base64:{}", crate::cbor::base64(data))),
            );
        }
        Value::Object(value)
    }
}

fn project_fields(value: &Value, schema: Option<&MethodSchema>) -> Value {
    let Some(object) = value.as_object() else {
        return value.clone();
    };
    let Some(schema) = schema else {
        return value.clone();
    };
    let mut projected = Map::new();
    for (key, value) in object {
        let name = key
            .parse::<u32>()
            .ok()
            .and_then(|tag| {
                schema
                    .fields
                    .iter()
                    .find(|(_, field)| field.tag == tag)
                    .map(|(name, _)| name.clone())
            })
            .unwrap_or_else(|| key.clone());
        projected.insert(name, value.clone());
    }
    Value::Object(projected)
}

/// Match either spelling of a catalog identity. `wire` is normally a tag for
/// an embedded-capable API, while `name` is retained by the catalog key for
/// host-native callers.
fn identity_matches(actual: &NameOrTag, wire: &NameOrTag, name: &str) -> bool {
    actual == wire || matches!(actual, NameOrTag::Name(actual_name) if actual_name == name)
}

fn field_schema<'a>(schema: Option<&'a MethodSchema>, name: &str) -> Option<&'a FieldSchema> {
    schema.and_then(|schema| {
        schema.fields.get(name).or_else(|| {
            name.trim_start_matches('@')
                .parse::<u32>()
                .ok()
                .and_then(|tag| schema.fields.values().find(|field| field.tag == tag))
        })
    })
}

fn field_key(schema: Option<&MethodSchema>, name: &str) -> NameOrTag {
    field_schema(schema, name)
        .map(|field| NameOrTag::Tag(field.tag))
        .unwrap_or_else(|| NameOrTag::parse(name))
}

fn field_text_value(schema: Option<&MethodSchema>, name: &str, value: &str) -> Result<Value> {
    let Some(field) = field_schema(schema, name) else {
        return Ok(text_value(value));
    };
    match field.kind.as_deref() {
        Some("bool") => Ok(Value::Bool(value.parse()?)),
        Some("u8" | "u16" | "u32" | "u64") => Ok(Value::from(value.parse::<u64>()?)),
        Some("enum") => Ok(Value::from(
            field
                .values
                .get(value)
                .copied()
                .map(Ok)
                .unwrap_or_else(|| value.parse::<u64>())?,
        )),
        Some("mac") => Ok(Value::String(value.to_ascii_lowercase())),
        Some("hex") => Ok(Value::String(format!(
            "hex:{}",
            value.trim_start_matches("hex:").replace(':', "")
        ))),
        _ => Ok(text_value(value)),
    }
}

fn name_or_index(value: Option<&Value>, fallback: &str) -> NameOrTag {
    match value {
        Some(Value::Number(value)) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .map(NameOrTag::Tag)
            .unwrap_or_else(|| NameOrTag::Name(fallback.to_owned())),
        Some(Value::String(value)) => NameOrTag::parse(value),
        _ => NameOrTag::Name(fallback.to_owned()),
    }
}

/// Compatibility wrapper around the shared lazy schema resolver.
///
/// New callers that also need documentation or source provenance should use
/// [`crate::catalog::CatalogResolver`] directly. Successful parses are retained
/// by the process-wide resolver.
pub fn load_service_catalog(component: &str) -> Option<Result<TaggedCatalog>> {
    crate::catalog::service_catalog_resolver()
        .resolve(component)
        .map(|result| result.map(|resolved| (*resolved.catalog).clone()))
}

/// Build a [`TaggedRecord`] from one typed request value, preferring the
/// generated catalog's numeric encoding but keeping the self-describing
/// textual encoding when no catalog is discoverable.
///
/// Client-owned translation helper (`mesh-init.start_terminal` style callers in
/// ssh-mesh bridges, JSONL/seqpacket callers): the client owns the wire for its
/// single encoding, loading the component's `tools.json` on demand and never
/// embedding or manufacturing a schema. With a catalog the record carries
/// numeric identity from `x-component-index` / `x-method-index` plus field
/// keys; without one `component`/`method` stay textual per the documented
/// name-based fallback. A service can still reject either representation;
/// the catalog simply makes the compact form available when installed.
pub fn record_from_value_translated(
    component: &str,
    method: &str,
    value: &Value,
    catalog: Option<&TaggedCatalog>,
) -> Result<TaggedRecord> {
    let Some(catalog) = catalog else {
        let record = TaggedRecord {
            component: NameOrTag::Name(component.to_string()),
            method: NameOrTag::Name(method.to_string()),
            ..Default::default()
        };
        let mut env = BTreeMap::new();
        let object = value
            .as_object()
            .ok_or_else(|| anyhow!("request must be a JSON object"))?;
        for (key, field) in object {
            if key == "method" {
                continue;
            }
            env.insert(NameOrTag::Name(key.clone()), field.clone());
        }
        return Ok(TaggedRecord { env, ..record });
    };
    let qualified = format!("{component}.{method}");
    catalog.record_from_value(&qualified, value)
}

/// Convert CLI `COMPONENT METHOD key=value` arguments into a common record.
/// With a catalog this produces numeric identifiers; without one the record is
/// still self-describing and can be forwarded as tagged CBOR.
pub fn record_from_argv(
    arguments: &[String],
    catalog: Option<&TaggedCatalog>,
) -> Result<TaggedRecord> {
    let component = arguments
        .first()
        .ok_or_else(|| anyhow!("RPC endpoints require COMPONENT METHOD [options/parameters]"))?;
    let (method_name, invocation_args) = if component.contains('.') {
        (component.clone(), arguments[1..].to_vec())
    } else if let Some(method) = arguments.get(1) {
        (format!("{component}.{method}"), arguments[2..].to_vec())
    } else {
        // A single bare token is a component-less documented method such as
        // `status`; the installed catalog decides whether it is real. The
        // no-catalog fallback below keeps the previous requirement.
        (component.clone(), Vec::new())
    };
    if let Some(catalog) = catalog {
        return catalog.parse_argv(&method_name, &invocation_args);
    }
    let (component, method) = if component.contains('.') {
        component
            .split_once('.')
            .ok_or_else(|| anyhow!("dotted RPC method must contain a component and method"))?
    } else {
        (
            component.as_str(),
            arguments
                .get(1)
                .ok_or_else(|| {
                    anyhow!("RPC endpoints require COMPONENT METHOD [options/parameters]")
                })?
                .as_str(),
        )
    };
    let mut record = TaggedRecord {
        component: NameOrTag::parse(component),
        method: NameOrTag::parse(method),
        ..Default::default()
    };
    for value in invocation_args {
        if value.starts_with('-') {
            let (key, value) = value
                .trim_start_matches('-')
                .split_once('=')
                .ok_or_else(|| anyhow!("option {value} requires =value"))?;
            record.env.insert(NameOrTag::parse(key), text_value(value));
        } else if let Some((key, value)) = value.split_once('=')
            && !key.is_empty()
        {
            record.env.insert(NameOrTag::parse(key), text_value(value));
        } else {
            bail!("argument {value:?} must be name=value");
        }
    }
    Ok(record)
}

/// Convert a tagged record to a method-and-fields JSON object without
/// duplicating client-specific translation logic. Catalog names are preferred;
/// unknown numeric keys use the stable `@N` spelling.
pub fn to_json(record: &TaggedRecord, catalog: Option<&TaggedCatalog>) -> Value {
    if let Some(catalog) = catalog {
        return catalog.to_jsonl(record);
    }
    let mut value = Map::new();
    let component = record.component.text();
    let method = record.method.text();
    value.insert(
        "method".to_owned(),
        Value::String(if component.is_empty() {
            method
        } else {
            format!("{component}.{method}")
        }),
    );
    if let Some(id) = &record.id {
        value.insert("id".to_owned(), id.clone());
    }
    for (key, item) in &record.env {
        value.insert(key.text(), item.clone());
    }
    if !record.params.is_empty() {
        value.insert("params".to_owned(), Value::Array(record.params.clone()));
    }
    if let Some(result) = &record.result {
        value.insert("result".to_owned(), result.clone());
    }
    if let Some(error) = &record.error {
        value.insert("error".to_owned(), error.clone());
    }
    if let Some(to) = &record.to {
        value.insert("to".to_owned(), to.clone());
    }
    if let Some(data) = &record.data {
        value.insert(
            "data".to_owned(),
            Value::Array(data.iter().copied().map(Value::from).collect()),
        );
    }
    Value::Object(value)
}

/// Decode the schema-free JSON projection used by generic HTTP gateways.
///
/// `component`, `method`, and `env` keys accept either names or decimal numeric
/// strings/numbers.  Numeric object keys are retained as [`NameOrTag::Tag`],
/// allowing a gateway to convert `{ "1": 4 }` to CBOR integer map key `1`
/// without loading a catalog.
pub fn record_from_json(value: &Value) -> Result<TaggedRecord> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("tagged JSON record must be an object"))?;
    let component = object
        .get("component")
        .ok_or_else(|| anyhow!("tagged JSON record lacks component"))
        .and_then(json_name_or_tag)?;
    let method = object
        .get("method")
        .ok_or_else(|| anyhow!("tagged JSON record lacks method"))
        .and_then(json_name_or_tag)?;
    let params = object
        .get("params")
        .map(|value| {
            value
                .as_array()
                .cloned()
                .ok_or_else(|| anyhow!("tagged JSON params must be an array"))
        })
        .transpose()?
        .unwrap_or_default();
    let mut env = BTreeMap::new();
    if let Some(values) = object.get("env") {
        for (key, value) in values
            .as_object()
            .ok_or_else(|| anyhow!("tagged JSON env must be an object"))?
        {
            let key = key
                .parse::<u32>()
                .map(NameOrTag::Tag)
                .unwrap_or_else(|_| NameOrTag::Name(key.clone()));
            env.insert(key, value.clone());
        }
    }
    let data = object
        .get("data")
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| anyhow!("tagged JSON data must be an octet array"))?
                .iter()
                .map(|value| {
                    value
                        .as_u64()
                        .and_then(|value| u8::try_from(value).ok())
                        .ok_or_else(|| anyhow!("tagged JSON data contains a non-octet"))
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?;
    let record = TaggedRecord {
        component,
        method,
        id: object.get("id").cloned(),
        params,
        env,
        result: object.get("result").cloned(),
        error: object.get("error").cloned(),
        to: object.get("to").cloned(),
        data,
    };
    record.kind()?;
    Ok(record)
}

fn json_name_or_tag(value: &Value) -> Result<NameOrTag> {
    match value {
        Value::String(value) => Ok(NameOrTag::parse(value)),
        Value::Number(value) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .map(NameOrTag::Tag)
            .ok_or_else(|| anyhow!("numeric tag must fit u32")),
        _ => bail!("name/tag must be a string or unsigned integer"),
    }
}

/// Render a tagged record as a structured-text command for operator and
/// gateway compatibility. Rust callers should select the CBOR codec.
pub fn to_text(record: &TaggedRecord) -> String {
    let mut values = vec![format!(
        "{}.{}",
        record.component.text(),
        record.method.text()
    )];
    values.extend(
        record
            .env
            .iter()
            .map(|(key, value)| format!("{}={}", key.text(), render_text_value(value))),
    );
    values.extend(record.params.iter().map(render_text_value));
    format!("{}\n", values.join(" "))
}

fn text_value(value: &str) -> Value {
    if let Ok(value) = value.parse::<i64>() {
        Value::from(value)
    } else if let Ok(value) = value.parse::<f64>() {
        Value::from(value)
    } else if matches!(value, "true" | "false") {
        Value::Bool(value == "true")
    } else {
        Value::String(value.to_owned())
    }
}

fn render_text_value(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

fn text_tokens(line: &str) -> Result<Vec<&str>> {
    // Shell quoting is intentionally delegated to the invoking shell. This is
    // a record grammar, not a shell interpreter.
    let tokens: Vec<_> = line.split_whitespace().collect();
    if tokens
        .iter()
        .any(|token| token.contains('"') || token.contains('\''))
    {
        bail!("quote values in the shell before passing a mesh invocation");
    }
    Ok(tokens)
}

/// A request or response type whose serde fields carry the numeric tags of
/// its `API.md`. `mesh-api-gen --rust-tags` implements this for every
/// generated struct, so the same serde type serves JSON/HTML callers and the
/// tag-keyed CBOR that crosses a socket, JNI or Binder boundary; no catalog is
/// consulted at runtime.
pub trait TaggedFields: serde::Serialize + serde::de::DeserializeOwned {
    /// `(serde field name, API.md tag)`.
    const FIELDS: &'static [(&'static str, u32)];
}

/// The in-memory form of a tag-keyed map: an object whose keys are decimal
/// tags. The CBOR encoder writes such a key as an unsigned integer.
pub fn to_tagged_value<T: TaggedFields>(value: &T) -> Result<Value> {
    let Value::Object(fields) = serde_json::to_value(value)? else {
        // A unit struct (no fields) is an empty map.
        return Ok(Value::Object(Map::new()));
    };
    let mut tagged = Map::with_capacity(fields.len());
    for (name, value) in fields {
        let tag = T::FIELDS
            .iter()
            .find(|(field, _)| *field == name)
            .map(|(_, tag)| *tag)
            .ok_or_else(|| anyhow!("field {name} has no API tag"))?;
        tagged.insert(tag.to_string(), value);
    }
    Ok(Value::Object(tagged))
}

/// Decode a tag-keyed map (keys are decimal tags or field names) into `T`.
/// Unknown tags are ignored, so a newer peer's extra fields do not break an
/// older one.
pub fn from_tagged_value<T: TaggedFields>(value: &Value) -> Result<T> {
    let Value::Object(fields) = value else {
        bail!("tagged fields must be a map");
    };
    // A type with no fields is a unit struct, which serde reads from null.
    if T::FIELDS.is_empty() {
        return Ok(serde_json::from_value(Value::Null)?);
    }
    let mut named = Map::with_capacity(fields.len());
    for (key, value) in fields {
        let name = key
            .parse::<u32>()
            .ok()
            .and_then(|tag| T::FIELDS.iter().find(|(_, t)| *t == tag).map(|(n, _)| *n))
            .map(str::to_owned)
            .unwrap_or_else(|| key.clone());
        if T::FIELDS.iter().any(|(field, _)| *field == name) {
            named.insert(name, value.clone());
        }
    }
    Ok(serde_json::from_value(Value::Object(named))?)
}

/// Decode a request record's fields (`env`, tag or name keyed) into `T`.
pub fn request_fields<T: TaggedFields>(record: &TaggedRecord) -> Result<T> {
    let mut fields = Map::new();
    for (key, value) in &record.env {
        let key = match key {
            NameOrTag::Tag(tag) => tag.to_string(),
            NameOrTag::Name(name) => name.clone(),
        };
        fields.insert(key, value.clone());
    }
    from_tagged_value(&Value::Object(fields))
}

/// A correlated success response carrying `value` as its tag-keyed result.
pub fn response_record<T: TaggedFields>(id: Value, value: &T) -> Result<TaggedRecord> {
    Ok(TaggedRecord {
        id: Some(id),
        result: Some(to_tagged_value(value)?),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_fields_accept_names_and_numeric_keys_with_declared_types() {
        let catalog = TaggedCatalog::from_tools_json(&serde_json::json!([{
            "name": "nan.wakeup", "x-component-index": 2, "x-method-index": 3,
            "inputSchema": {"properties": {
                "to": {"x-protobuf-index": 1, "x-mesh-cbor-type": "mac"},
                "mode": {"x-protobuf-index": 2, "x-mesh-cbor-type": "enum", "x-mesh-values": {"sta": 5}}
            }}
        }])).unwrap();
        let record = catalog
            .parse_argv("nan.wakeup", &["--1=AA:BB".into(), "--mode=sta".into()])
            .unwrap();
        assert_eq!(
            record.env.get(&NameOrTag::Tag(1)),
            Some(&Value::String("aa:bb".into()))
        );
        assert_eq!(record.env.get(&NameOrTag::Tag(2)), Some(&Value::from(5)));
        assert!(record.to.is_none());
        let structured = catalog
            .record_from_value("nan.wakeup", &serde_json::json!({"to":"AA:BB"}))
            .unwrap();
        assert!(
            catalog
                .validate_fields(
                    "nan.wakeup",
                    serde_json::json!({"1":"aa:bb"}).as_object().unwrap()
                )
                .is_ok()
        );
        assert!(
            catalog
                .validate_fields(
                    "nan.wakeup",
                    serde_json::json!({"99":"bad"}).as_object().unwrap()
                )
                .is_err()
        );
        assert_eq!(
            structured.env.get(&NameOrTag::Tag(1)),
            Some(&Value::String("AA:BB".into()))
        );
        let result = TaggedRecord {
            component: NameOrTag::Tag(2),
            method: NameOrTag::Tag(3),
            id: Some(Value::from(9)),
            result: Some(serde_json::json!({"1":"aa:bb", "99":true})),
            ..Default::default()
        };
        let rendered = catalog.to_jsonl(&result);
        assert_eq!(rendered["method"], "nan.wakeup");
        assert_eq!(rendered["result"]["to"], "aa:bb");
        assert_eq!(rendered["result"]["99"], true);
    }
    use serde_json::json;

    #[test]
    fn text_arguments_require_named_fields() {
        let catalog = TaggedCatalog::from_tools_json(&json!([{
            "name":"wifi.listen", "x-mesh-wire":{"component":"wifi","method":"listen"},
            "inputSchema":{"properties":{"iface":{"x-mesh-wire":{"tag":1}},"listen_sec":{"x-mesh-wire":{"tag":2}}}}
        }])).unwrap();
        let record = catalog
            .parse_text("wifi.listen -listen_sec=1 iface=wlan0")
            .unwrap();
        assert!(record.params.is_empty());
        assert_eq!(record.env.get(&NameOrTag::Tag(1)), Some(&json!("wlan0")));
        assert_eq!(record.env.get(&NameOrTag::Tag(2)), Some(&json!(1)));
        assert!(catalog.parse_text("wifi.listen wlan0").is_err());
    }

    #[test]
    fn text_bare_named_values_are_fields() {
        let catalog = TaggedCatalog::default();
        let record = catalog.parse_text("service.stop name=lmesh").unwrap();
        assert!(record.params.is_empty());
        assert_eq!(
            record.env.get(&NameOrTag::Name("name".to_owned())),
            Some(&json!("lmesh"))
        );
    }

    #[test]
    fn argv_preserves_space_containing_field_value() {
        let catalog = TaggedCatalog::from_tools_json(&json!([{
            "name":"esp.serial.command",
            "x-mesh-wire":{"component":"esp","method":"serial.command"},
            "inputSchema":{"properties":{"command":{"x-mesh-wire":{"tag":1}}}}
        }]))
        .unwrap();
        let record = catalog
            .parse_argv("esp.serial.command", &["command=ble stats=true".to_owned()])
            .unwrap();
        assert_eq!(
            record.env.get(&NameOrTag::Tag(1)),
            Some(&json!("ble stats=true"))
        );
    }

    #[test]
    fn structured_request_uses_catalog_tags_without_text_round_trip() {
        let catalog = TaggedCatalog::from_tools_json(&json!([{
            "name":"wifi.status",
            "x-component-index":5,
            "x-method-index":1,
            "inputSchema":{"properties":{"iface":{"x-protobuf-index":1}}}
        }]))
        .unwrap();
        let record = catalog
            .record_from_value("wifi.status", &json!({"iface": "wlan0"}))
            .unwrap();
        assert_eq!(record.component, NameOrTag::Tag(5));
        assert_eq!(record.method, NameOrTag::Tag(1));
        assert_eq!(record.env.get(&NameOrTag::Tag(1)), Some(&json!("wlan0")));
    }

    #[test]
    fn catalog_accepts_names_for_numeric_method_identity() {
        let catalog = TaggedCatalog::from_tools_json(&json!([{
            "name":"mesh-init.start_terminal",
            "x-component-index":3,
            "x-method-index":16,
            "inputSchema":{"properties":{"name":{"x-protobuf-index":1}}}
        }]))
        .unwrap();
        let record = TaggedRecord {
            component: NameOrTag::Name("mesh-init".to_owned()),
            method: NameOrTag::Name("start_terminal".to_owned()),
            env: [(NameOrTag::Name("name".to_owned()), json!("alice"))]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        assert_eq!(
            catalog.method_name(&record),
            Some("mesh-init.start_terminal")
        );
        assert_eq!(
            catalog.documented_request(&record).unwrap(),
            json!({"method":"mesh-init.start_terminal", "name":"alice"})
        );
    }

    #[test]
    fn common_helpers_keep_schema_less_calls_and_responses_structured() {
        let arguments = vec!["core.status".to_owned(), "verbose=true".to_owned()];
        let mut record = record_from_argv(&arguments, None).unwrap();
        record.id = Some(json!(9));
        assert_eq!(record.component.text(), "core");
        assert_eq!(record.method.text(), "status");
        assert_eq!(
            to_json(&record, None),
            json!({"method":"core.status", "id":9, "verbose":true})
        );
    }

    #[test]
    fn envelope_kind_is_unambiguous() {
        let request = TaggedRecord {
            component: NameOrTag::Name("core".to_owned()),
            method: NameOrTag::Name("status".to_owned()),
            id: Some(json!(1)),
            ..Default::default()
        };
        assert_eq!(request.kind().unwrap(), RecordKind::Request);

        let response = TaggedRecord {
            id: Some(json!(1)),
            result: Some(json!({"ready": true})),
            ..Default::default()
        };
        assert_eq!(response.kind().unwrap(), RecordKind::Response);

        let malformed = TaggedRecord {
            id: Some(json!(1)),
            result: Some(json!(true)),
            error: Some(json!("no")),
            ..Default::default()
        };
        assert!(malformed.kind().is_err());
    }

    #[test]
    fn schema_free_json_envelope_keeps_numeric_fields_and_destination() {
        let record = record_from_json(&json!({
            "component": 4,
            "method": 7,
            "id": 9,
            "to": "peer-a",
            "env": {"1": 4, "label": "ok"}
        }))
        .unwrap();
        assert_eq!(record.component, NameOrTag::Tag(4));
        assert_eq!(record.method, NameOrTag::Tag(7));
        assert_eq!(record.env.get(&NameOrTag::Tag(1)), Some(&json!(4)));
        assert_eq!(
            record.env.get(&NameOrTag::Name("label".to_owned())),
            Some(&json!("ok"))
        );
        assert_eq!(record.to, Some(json!("peer-a")));
    }

    #[test]
    fn generated_protobuf_indices_produce_compact_tagged_records() {
        let catalog = TaggedCatalog::from_tools_json(&json!([{
            "name": "radio.control",
            "x-component-index": 0,
            "x-method-index": 72,
            "inputSchema": {"properties": {
                "channel": {"x-protobuf-index": 2},
                "promiscuous": {"x-protobuf-index": 10}
            }}
        }]))
        .unwrap();
        let record = catalog
            .parse_argv(
                "radio.control",
                &["channel=6".to_owned(), "promiscuous=true".to_owned()],
            )
            .unwrap();
        assert_eq!(record.component, NameOrTag::Tag(0));
        assert_eq!(record.method, NameOrTag::Tag(72));
        assert_eq!(record.env.get(&NameOrTag::Tag(2)), Some(&json!(6)));
        assert_eq!(record.env.get(&NameOrTag::Tag(10)), Some(&json!(true)));
        assert_eq!(
            catalog.to_jsonl(&record),
            json!({
                "method": "radio.control",
                "channel": 6,
                "promiscuous": true
            })
        );
        assert!(
            catalog
                .parse_argv("radio.control", &["true".to_owned()])
                .is_err()
        );
    }
    #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
    struct Sample {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u64>,
        label: String,
        r#type: Option<String>,
    }

    impl TaggedFields for Sample {
        const FIELDS: &'static [(&'static str, u32)] = &[("limit", 1), ("label", 2), ("type", 3)];
    }

    #[test]
    fn serde_structs_round_trip_as_tag_keyed_cbor() {
        let value = Sample {
            limit: Some(5),
            label: "x".to_owned(),
            r#type: None,
        };
        let record = response_record(json!(7), &value).unwrap();
        // Keys are tags, not names, on the wire.
        let bytes = crate::cbor::encode_record(&record).unwrap();
        let decoded = crate::cbor::decode_record(&bytes).unwrap();
        let result = decoded.result.unwrap();
        assert_eq!(result["1"], 5);
        assert_eq!(result["2"], "x");
        assert!(result.get("limit").is_none());
        assert_eq!(from_tagged_value::<Sample>(&result).unwrap(), value);
    }

    #[test]
    fn request_fields_accept_tags_and_names_and_ignore_unknown_tags() {
        let record = TaggedRecord {
            env: [
                (NameOrTag::Tag(1), json!(3)),
                (NameOrTag::Name("label".to_owned()), json!("y")),
                (NameOrTag::Tag(99), json!("future")),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };
        let sample = request_fields::<Sample>(&record).unwrap();
        assert_eq!(sample.limit, Some(3));
        assert_eq!(sample.label, "y");
    }

    #[derive(Debug, PartialEq, serde::Deserialize, serde::Serialize)]
    struct Nothing;

    impl TaggedFields for Nothing {
        const FIELDS: &'static [(&'static str, u32)] = &[];
    }

    #[test]
    fn a_unit_struct_is_an_empty_map() {
        let value = to_tagged_value(&Nothing).unwrap();
        assert_eq!(value, json!({}));
        assert_eq!(from_tagged_value::<Nothing>(&value).unwrap(), Nothing);
        assert_eq!(
            request_fields::<Nothing>(&TaggedRecord::default()).unwrap(),
            Nothing
        );
    }

}
