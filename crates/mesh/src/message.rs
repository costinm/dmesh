use std::collections::BTreeMap;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const STREAM_OPEN_METHOD: &str = "mesh.stream.open";
pub const STREAM_OPENED_METHOD: &str = "mesh.stream.opened";

pub const KIND_RESPONSE: u16 = 1;
pub const KIND_ERROR: u16 = 2;
pub const KIND_EVENT: u16 = 10;
pub const KIND_MESSAGE: u16 = 11;
pub const KIND_STATS: u16 = 12;
pub const KIND_DM_PING: u16 = 20;
pub const KIND_DM_PONG: u16 = 21;
pub const KIND_LORA_TX: u16 = 30;
pub const KIND_LORA_RX: u16 = 31;
pub const KIND_NAN_START: u16 = 40;
pub const KIND_NAN_PUBLISH: u16 = 41;
pub const KIND_NAN_SUBSCRIBE: u16 = 42;
pub const KIND_NAN_FOLLOWUP: u16 = 43;
pub const KIND_BLE_SCAN: u16 = 50;
pub const KIND_BLE_ADV: u16 = 51;

pub const FIELD_ID: u16 = 1;
pub const FIELD_NODE: u16 = 2;
pub const FIELD_PEER: u16 = 3;
pub const FIELD_MEDIUM: u16 = 4;
pub const FIELD_NETWORK: u16 = 5;
pub const FIELD_RADIO_ID: u16 = 6;
pub const FIELD_TS_MS: u16 = 7;
pub const FIELD_PAYLOAD: u16 = 8;
pub const FIELD_PAYLOAD_HASH: u16 = 9;
pub const FIELD_LEN: u16 = 10;
pub const FIELD_RSSI: u16 = 11;
pub const FIELD_SNR: u16 = 12;
pub const FIELD_SEQ: u16 = 13;
pub const FIELD_STATUS: u16 = 14;
pub const FIELD_ERROR: u16 = 15;
pub const FIELD_PATH: u16 = 16;
pub const FIELD_IFACE: u16 = 17;
pub const FIELD_CTRL_DIR: u16 = 18;
pub const FIELD_CHANNEL: u16 = 19;
pub const FIELD_ROLE: u16 = 20;

// Keep service-side text stream conventions in sync with
// `fw/esp32/rust/src/commands/protocol.rs`: one newline-terminated record,
// record kind as the first token, and structured fields as logfmt-style
// `key=value` pairs. Use quoted values when strings contain whitespace or
// shell-sensitive separators.

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TextRecord {
    pub kind: String,
    pub args: Vec<String>,
    pub fields: BTreeMap<String, String>,
}

/// Codec used to receive or emit a normalized mesh message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshMessageCodec {
    Text,
    FirmwareText,
    Json,
    JsonRpc,
    WpaText,
    Cbor,
}

/// Normalized radio/control message shared by host, firmware, and UDS adapters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshMessage {
    /// Numeric kind tag from the shared registry.
    pub kind_tag: u16,
    /// Numeric field tags from the shared registry.
    pub fields: BTreeMap<u16, String>,
    /// Optional binary payload when a text record carries `payload=hex:...`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Vec<u8>>,
    /// Source codec used to parse or format this message.
    pub codec: MeshMessageCodec,
    /// Wall-clock timestamp in milliseconds since Unix epoch.
    pub timestamp_ms: u64,
}

impl MeshMessage {
    /// Create a normalized message with the current timestamp.
    pub fn new(kind_tag: u16, codec: MeshMessageCodec) -> Self {
        Self {
            kind_tag,
            fields: BTreeMap::new(),
            payload: None,
            codec,
            timestamp_ms: now_millis(),
        }
    }

    /// Add or replace a normalized field.
    pub fn field(mut self, tag: u16, value: impl ToString) -> Self {
        self.fields.insert(tag, value.to_string());
        self
    }

    /// Attach a binary payload.
    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Return a field by numeric tag.
    pub fn field_value(&self, tag: u16) -> Option<&str> {
        self.fields.get(&tag).map(String::as_str)
    }

    /// Return the canonical kind name, or `unknown` for unregistered tags.
    pub fn kind_name(&self) -> &'static str {
        kind_name(self.kind_tag).unwrap_or("unknown")
    }

    /// Convert the normalized message back to the shared mesh text record format.
    pub fn to_text_record(&self) -> TextRecord {
        let mut record = TextRecord::new(self.kind_name());
        for (tag, value) in &self.fields {
            let key = field_name(*tag).unwrap_or("field");
            let key = if key == "field" {
                format!("field_{tag}")
            } else {
                key.to_string()
            };
            record.fields.insert(key, value.clone());
        }
        if let Some(payload) = &self.payload {
            record.fields.insert(
                "payload".to_string(),
                format!("hex:{}", hex_encode(payload)),
            );
        }
        record
    }
}

impl TextRecord {
    pub fn new(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            args: Vec::new(),
            fields: BTreeMap::new(),
        }
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn field(mut self, key: impl Into<String>, value: impl ToString) -> Self {
        self.fields.insert(key.into(), value.to_string());
        self
    }

    pub fn from_json_object(kind: impl Into<String>, value: &Value) -> Self {
        let mut record = Self::new(kind);
        if let Some(object) = value.as_object() {
            for (key, value) in object {
                record
                    .fields
                    .insert(key.clone(), text_value_from_json(value));
            }
        } else {
            record
                .fields
                .insert("value".to_string(), text_value_from_json(value));
        }
        record
    }

    pub fn parse(line: &str) -> Result<Self> {
        let tokens = split_text_tokens(line)?;
        let mut iter = tokens.into_iter();
        let kind = iter
            .next()
            .ok_or_else(|| anyhow!("text record requires a kind"))?;
        let mut record = Self::new(kind);
        for token in iter {
            if let Some((key, value)) = token.split_once('=') {
                if key.is_empty() {
                    return Err(anyhow!("text record field key cannot be empty"));
                }
                record.fields.insert(key.to_string(), value.to_string());
            } else {
                record.args.push(token);
            }
        }
        Ok(record)
    }

    pub fn format(&self) -> String {
        let mut out = quote_text_value(&self.kind);
        for arg in &self.args {
            out.push(' ');
            out.push_str(&quote_text_value(arg));
        }
        for (key, value) in &self.fields {
            out.push(' ');
            out.push_str(key);
            out.push('=');
            out.push_str(&quote_text_value(value));
        }
        out
    }
}

pub fn format_text_response(success: bool, error: Option<&str>, data: Option<&Value>) -> String {
    if success {
        match data {
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| TextRecord::from_json_object("response", item).format())
                .collect::<Vec<_>>()
                .join("\n"),
            Some(value) => TextRecord::from_json_object("response", value)
                .field("success", "true")
                .format(),
            None => TextRecord::new("response")
                .field("success", "true")
                .format(),
        }
    } else {
        TextRecord::new("error")
            .field("message", error.unwrap_or("unknown error"))
            .format()
    }
}

#[derive(Clone, Debug)]
pub enum LineProtocolFormat {
    Json(crate::jsonl::ProtocolFormat),
    Text,
    BinaryMux,
}

#[derive(Clone, Debug, Default)]
pub struct LineProtocolSession {
    format: Option<LineProtocolFormat>,
}

impl LineProtocolSession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn format(&self) -> Option<&LineProtocolFormat> {
        self.format.as_ref()
    }

    pub fn parse_request_line(
        &mut self,
        line: &str,
    ) -> (LineProtocolFormat, Result<crate::protocol::Request, String>) {
        if self.format.is_none() {
            let selected = match line.as_bytes().first().copied() {
                Some(byte) => LineProtocolFormat::from_first_byte(byte),
                None => Err(anyhow!("empty protocol line")),
            };
            match selected {
                Ok(format) => self.format = Some(format),
                Err(err) => {
                    self.format = Some(LineProtocolFormat::Text);
                    return (LineProtocolFormat::Text, Err(err.to_string()));
                }
            }
        }

        let format = match self.format.as_mut().expect("protocol selected") {
            LineProtocolFormat::Json(json_format) => {
                if line.starts_with('{') {
                    let (new_format, _) =
                        crate::jsonl::parse_request::<crate::protocol::Request>(line);
                    *json_format = new_format;
                }
                LineProtocolFormat::Json(json_format.clone())
            }
            selected => selected.clone(),
        };
        let parsed = parse_request_line_with_format(line, &format);
        (format, parsed)
    }

    pub fn format_response(&self, response: crate::protocol::Response) -> Result<String> {
        let format = self
            .format
            .as_ref()
            .ok_or_else(|| anyhow!("protocol not selected"))?;
        format_protocol_response(response, format)
    }
}

impl LineProtocolFormat {
    pub fn from_first_byte(byte: u8) -> Result<Self> {
        match byte {
            0x00 => Ok(Self::BinaryMux),
            b'{' => Ok(Self::Json(crate::jsonl::ProtocolFormat::JsonRpc {
                id: None,
            })),
            byte if byte.is_ascii() => Ok(Self::Text),
            _ => Err(anyhow!("unsupported protocol first byte 0x{byte:02x}")),
        }
    }
}

pub fn parse_request_line_with_format(
    line: &str,
    format: &LineProtocolFormat,
) -> Result<crate::protocol::Request, String> {
    match format {
        LineProtocolFormat::Json(_) => {
            let (_, parsed) = crate::jsonl::parse_request::<crate::protocol::Request>(line);
            parsed
        }
        LineProtocolFormat::Text => parse_text_request(line).map_err(|err| err.to_string()),
        LineProtocolFormat::BinaryMux => {
            Err("binary mux protocol is not implemented yet".to_string())
        }
    }
}

pub fn parse_request_line(
    line: &str,
) -> (LineProtocolFormat, Result<crate::protocol::Request, String>) {
    LineProtocolSession::new().parse_request_line(line)
}

pub fn format_protocol_response(
    response: crate::protocol::Response,
    format: &LineProtocolFormat,
) -> Result<String> {
    match format {
        LineProtocolFormat::Json(format) => crate::jsonl::format_response(response, format),
        LineProtocolFormat::Text => Ok(format_text_response(
            response.success,
            response.error.as_deref(),
            response.data.as_ref(),
        )),
        LineProtocolFormat::BinaryMux => Err(anyhow!("binary mux protocol is not implemented yet")),
    }
}

pub fn text_record_to_request(record: TextRecord) -> Result<crate::protocol::Request> {
    use crate::protocol::Request;

    match record.kind.as_str() {
        "status" => Ok(Request::Status {
            name: record.fields.get("name").cloned(),
        }),
        "start" => Ok(Request::Start {
            name: required_field(&record, "name")?,
            args: split_list_field(record.fields.get("args")),
            env: BTreeMap::new().into_iter().collect(),
            context: None,
        }),
        "stop" => Ok(Request::Stop {
            name: required_field(&record, "name")?,
            signal: record
                .fields
                .get("signal")
                .map(|value| value.parse())
                .transpose()?,
        }),
        "freeze" => Ok(Request::Freeze {
            name: required_field(&record, "name")?,
            reason: record.fields.get("reason").cloned(),
        }),
        "unfreeze" => Ok(Request::Unfreeze {
            name: required_field(&record, "name")?,
        }),
        "reconcile" => Ok(Request::Reconcile),
        "reload" => Ok(Request::Reload),
        "shutdown" => Ok(Request::Shutdown),
        command => Err(anyhow!("unsupported text command {command}")),
    }
}

pub fn parse_text_request(line: &str) -> Result<crate::protocol::Request> {
    text_record_to_request(TextRecord::parse(line)?)
}

/// Return the numeric registry tag for a canonical kind name or alias.
pub fn kind_tag(name: &str) -> Option<u16> {
    match name {
        "response" => Some(KIND_RESPONSE),
        "error" => Some(KIND_ERROR),
        "event" => Some(KIND_EVENT),
        "message" | "messages" => Some(KIND_MESSAGE),
        "stats" => Some(KIND_STATS),
        "dm.ping" | "ping" => Some(KIND_DM_PING),
        "dm.pong" | "pong" => Some(KIND_DM_PONG),
        "lora.tx" => Some(KIND_LORA_TX),
        "lora.rx" => Some(KIND_LORA_RX),
        "nan.start" | "wifi.nan.start" => Some(KIND_NAN_START),
        "nan.publish" | "wifi.nan.adv" => Some(KIND_NAN_PUBLISH),
        "nan.subscribe" | "wifi.nan.sub" => Some(KIND_NAN_SUBSCRIBE),
        "nan.followup" | "wifi.nan.ping" => Some(KIND_NAN_FOLLOWUP),
        "ble.scan" => Some(KIND_BLE_SCAN),
        "ble.adv" => Some(KIND_BLE_ADV),
        _ => None,
    }
}

/// Return the canonical kind name for a numeric registry tag.
pub fn kind_name(tag: u16) -> Option<&'static str> {
    match tag {
        KIND_RESPONSE => Some("response"),
        KIND_ERROR => Some("error"),
        KIND_EVENT => Some("event"),
        KIND_MESSAGE => Some("message"),
        KIND_STATS => Some("stats"),
        KIND_DM_PING => Some("dm.ping"),
        KIND_DM_PONG => Some("dm.pong"),
        KIND_LORA_TX => Some("lora.tx"),
        KIND_LORA_RX => Some("lora.rx"),
        KIND_NAN_START => Some("nan.start"),
        KIND_NAN_PUBLISH => Some("nan.publish"),
        KIND_NAN_SUBSCRIBE => Some("nan.subscribe"),
        KIND_NAN_FOLLOWUP => Some("nan.followup"),
        KIND_BLE_SCAN => Some("ble.scan"),
        KIND_BLE_ADV => Some("ble.adv"),
        _ => None,
    }
}

/// Return the numeric registry tag for a canonical field name or alias.
pub fn field_tag(name: &str) -> Option<u16> {
    match name {
        "id" => Some(FIELD_ID),
        "node" | "src" | "source" | "device_id" => Some(FIELD_NODE),
        "peer" | "target" | "target_id" => Some(FIELD_PEER),
        "medium" => Some(FIELD_MEDIUM),
        "network" => Some(FIELD_NETWORK),
        "radio_id" | "radio" | "dev_id" => Some(FIELD_RADIO_ID),
        "ts_ms" | "timestamp_ms" => Some(FIELD_TS_MS),
        "payload" | "payload_text" => Some(FIELD_PAYLOAD),
        "payload_hash" | "hash" => Some(FIELD_PAYLOAD_HASH),
        "len" | "payload_len" => Some(FIELD_LEN),
        "rssi" | "scan_rssi" => Some(FIELD_RSSI),
        "snr" | "snr_q4" => Some(FIELD_SNR),
        "seq" => Some(FIELD_SEQ),
        "status" => Some(FIELD_STATUS),
        "error" | "message" => Some(FIELD_ERROR),
        "path" => Some(FIELD_PATH),
        "iface" => Some(FIELD_IFACE),
        "ctrl_dir" => Some(FIELD_CTRL_DIR),
        "channel" => Some(FIELD_CHANNEL),
        "role" => Some(FIELD_ROLE),
        _ => None,
    }
}

/// Return the canonical field name for a numeric registry tag.
pub fn field_name(tag: u16) -> Option<&'static str> {
    match tag {
        FIELD_ID => Some("id"),
        FIELD_NODE => Some("node"),
        FIELD_PEER => Some("peer"),
        FIELD_MEDIUM => Some("medium"),
        FIELD_NETWORK => Some("network"),
        FIELD_RADIO_ID => Some("radio_id"),
        FIELD_TS_MS => Some("ts_ms"),
        FIELD_PAYLOAD => Some("payload"),
        FIELD_PAYLOAD_HASH => Some("payload_hash"),
        FIELD_LEN => Some("len"),
        FIELD_RSSI => Some("rssi"),
        FIELD_SNR => Some("snr"),
        FIELD_SEQ => Some("seq"),
        FIELD_STATUS => Some("status"),
        FIELD_ERROR => Some("error"),
        FIELD_PATH => Some("path"),
        FIELD_IFACE => Some("iface"),
        FIELD_CTRL_DIR => Some("ctrl_dir"),
        FIELD_CHANNEL => Some("channel"),
        FIELD_ROLE => Some("role"),
        _ => None,
    }
}

/// Parse one shared mesh text, JSON, JSON-RPC, or WPA line into a normalized message.
pub fn parse_mesh_message_line(line: &str) -> Result<MeshMessage> {
    let trimmed = line.trim();
    if trimmed.starts_with('{') {
        return parse_json_message(trimmed);
    }
    if trimmed.starts_with('<') || matches!(trimmed, "OK" | "FAIL" | "UNKNOWN COMMAND") {
        return Ok(parse_wpa_message(trimmed));
    }
    let record = TextRecord::parse(trimmed)?;
    Ok(text_record_to_mesh_message(record, MeshMessageCodec::Text))
}

/// Parse one ESP firmware text reply or log line into a normalized message.
pub fn parse_firmware_message_line(line: &str) -> Result<MeshMessage> {
    let record = TextRecord::parse(line)?;
    Ok(text_record_to_mesh_message(
        normalize_firmware_record(record),
        MeshMessageCodec::FirmwareText,
    ))
}

/// Parse one WPA control response or async event into a normalized message.
pub fn parse_wpa_message(line: &str) -> MeshMessage {
    let trimmed = line.trim();
    let mut message = MeshMessage::new(KIND_EVENT, MeshMessageCodec::WpaText);
    if trimmed.starts_with('<') {
        if let Some((level, event)) = trimmed.split_once('>') {
            message = message.field(FIELD_STATUS, level.trim_start_matches('<'));
            message = message.field(FIELD_PAYLOAD, event);
            if event.starts_with("CTRL-EVENT-") {
                message = message.field(FIELD_MEDIUM, "nan");
            }
        } else {
            message = message.field(FIELD_PAYLOAD, trimmed);
        }
    } else if trimmed == "OK" {
        message = message.field(FIELD_STATUS, "ok");
    } else if trimmed.starts_with("FAIL") || trimmed.starts_with("UNKNOWN COMMAND") {
        message.kind_tag = KIND_ERROR;
        message = message
            .field(FIELD_STATUS, "fail")
            .field(FIELD_ERROR, trimmed);
    } else {
        for line in trimmed.lines() {
            if let Some((key, value)) = line.split_once('=') {
                if let Some(tag) = field_tag(key.trim()) {
                    message.fields.insert(tag, value.trim().to_string());
                }
            }
        }
        message = message.field(FIELD_PAYLOAD, trimmed);
    }
    message
}

/// Format a normalized message as the shared mesh text record format.
pub fn mesh_message_to_text(message: &MeshMessage) -> String {
    message.to_text_record().format()
}

/// Convert a parsed text record into a normalized message using the supplied source codec.
pub fn text_record_to_mesh_message(record: TextRecord, codec: MeshMessageCodec) -> MeshMessage {
    let mut selected_kind_tag = kind_tag(&record.kind).unwrap_or(KIND_EVENT);
    let mut message = MeshMessage::new(selected_kind_tag, codec);
    if record.kind == "event" {
        if let Some(event_type) = record
            .fields
            .get("type")
            .or_else(|| record.fields.get("ev"))
        {
            selected_kind_tag = kind_tag(event_type).unwrap_or(KIND_EVENT);
            message.kind_tag = selected_kind_tag;
        }
    }
    for arg in record.args {
        if !arg.is_empty() {
            let value = message.fields.entry(FIELD_PAYLOAD).or_default();
            if !value.is_empty() {
                value.push(' ');
            }
            value.push_str(&arg);
        }
    }
    for (key, value) in record.fields {
        if key == "payload" {
            if let Some(hex) = value.strip_prefix("hex:") {
                if let Ok(payload) = decode_hex(hex) {
                    message.payload = Some(payload);
                    continue;
                }
            }
        }
        if key == "type" || key == "ev" {
            message.fields.insert(FIELD_STATUS, value);
            continue;
        }
        if let Some(tag) = field_tag(&key) {
            message.fields.insert(tag, value);
        }
    }
    message
}

fn normalize_firmware_record(record: TextRecord) -> TextRecord {
    match record.kind.as_str() {
        "stats" | "messages" => record,
        "ev" => {
            let mut normalized = TextRecord::new("event");
            normalized.fields = record.fields;
            if let Some(first) = record.args.first() {
                normalized.fields.insert("type".to_string(), first.clone());
            }
            normalized
        }
        "event" => record,
        _ => record,
    }
}

fn parse_json_message(line: &str) -> Result<MeshMessage> {
    let value: Value = serde_json::from_str(line)?;
    let codec = if value.get("jsonrpc").is_some() {
        MeshMessageCodec::JsonRpc
    } else {
        MeshMessageCodec::Json
    };
    let method = value
        .get("method")
        .and_then(Value::as_str)
        .or_else(|| value.get("type").and_then(Value::as_str))
        .unwrap_or("message");
    let mut message = MeshMessage::new(kind_tag(method).unwrap_or(KIND_MESSAGE), codec);
    if let Some(id) = value.get("id") {
        message.fields.insert(FIELD_ID, text_value_from_json(id));
    }
    let fields = value
        .get("params")
        .or_else(|| value.get("data"))
        .unwrap_or(&value);
    if let Some(object) = fields.as_object() {
        for (key, value) in object {
            if matches!(key.as_str(), "jsonrpc" | "method" | "params" | "data") {
                continue;
            }
            if let Some(tag) = field_tag(key) {
                message.fields.insert(tag, text_value_from_json(value));
            }
        }
    }
    Ok(message)
}

fn required_field(record: &TextRecord, key: &str) -> Result<String> {
    record
        .fields
        .get(key)
        .cloned()
        .ok_or_else(|| anyhow!("text command {} requires {key}=...", record.kind))
}

fn split_list_field(value: Option<&String>) -> Vec<String> {
    value
        .map(|value| {
            value
                .split(',')
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub fn quote_text_value(value: &str) -> String {
    if is_bare_text_value(value) {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn is_bare_text_value(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\'' | b'\\' | b'='))
}

fn split_text_tokens(line: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();
    let mut quoted = false;
    while let Some(ch) = chars.next() {
        match ch {
            '"' if quoted => quoted = false,
            '"' if current.is_empty() || current.ends_with('=') => quoted = true,
            '\\' if quoted => {
                let Some(escaped) = chars.next() else {
                    return Err(anyhow!("unterminated text escape"));
                };
                current.push(match escaped {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    other => other,
                });
            }
            ch if ch.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            ch => current.push(ch),
        }
    }
    if quoted {
        return Err(anyhow!("unterminated quoted text value"));
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

pub fn text_value_from_json(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamOpenRequest {
    pub id: Option<String>,
    pub session: String,
    pub stream: String,
    pub mode: String,
    pub kind: String,
}

impl StreamOpenRequest {
    pub fn parse(value: &Value, default_session: impl Into<String>) -> Option<Self> {
        let obj = value.as_object()?;
        if obj.get("method").and_then(Value::as_str)? != STREAM_OPEN_METHOD {
            return None;
        }

        let data = obj.get("data").and_then(Value::as_object);
        let mode = data
            .and_then(|data| data.get("mode"))
            .or_else(|| obj.get("mode"))
            .and_then(Value::as_str)?;
        if !matches!(mode, "binary" | "raw") {
            return None;
        }

        let default_session = default_session.into();
        let id = obj.get("id").map(json_value_to_string);
        let session = obj
            .get("session")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or(default_session);
        let stream = obj
            .get("stream")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("{session}:binary"));
        let kind = data
            .and_then(|data| data.get("kind"))
            .or_else(|| obj.get("kind"))
            .and_then(Value::as_str)
            .unwrap_or("shell")
            .to_string();

        Some(Self {
            id,
            session,
            stream,
            mode: mode.to_string(),
            kind,
        })
    }

    pub fn opened_response(&self) -> Value {
        json!({
            "id": self.id.clone(),
            "replyTo": self.id.clone(),
            "session": self.session.clone(),
            "stream": self.stream.clone(),
            "type": "response",
            "method": STREAM_OPENED_METHOD,
            "data": {
                "mode": self.mode.clone(),
                "kind": self.kind.clone(),
            }
        })
    }
}

pub fn canonical_method_name(name: &str) -> String {
    name.to_string()
}

fn json_value_to_string(v: &Value) -> String {
    v.as_str()
        .map(str::to_string)
        .unwrap_or_else(|| v.to_string())
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(anyhow!("hex payload length must be even"));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    for idx in (0..bytes.len()).step_by(2) {
        let hi = hex_digit(bytes[idx])?;
        let lo = hex_digit(bytes[idx + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_digit(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(anyhow!("invalid hex digit 0x{byte:02x}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_record_formats_and_parses_logfmt_style_fields() {
        let line = TextRecord::new("event")
            .field("type", "lora.rx")
            .field("message", "hello world")
            .field("count", 2)
            .format();

        assert_eq!(line, r#"event count=2 message="hello world" type=lora.rx"#);
        let parsed = TextRecord::parse(&line).unwrap();
        assert_eq!(parsed.kind, "event");
        assert_eq!(parsed.fields["type"], "lora.rx");
        assert_eq!(parsed.fields["message"], "hello world");
        assert_eq!(parsed.fields["count"], "2");
    }

    #[test]
    fn text_response_formats_objects_and_errors() {
        let response =
            format_text_response(true, None, Some(&json!({"state": "running", "pid": 42})));
        assert_eq!(response, "response pid=42 state=running success=true");

        let error = format_text_response(false, Some("bad service"), None);
        assert_eq!(error, r#"error message="bad service""#);
    }

    #[test]
    fn line_protocol_session_selects_once_from_first_byte() {
        let mut session = LineProtocolSession::new();
        let (format, parsed) = session.parse_request_line("status name=alpha");
        assert!(matches!(format, LineProtocolFormat::Text));
        assert!(matches!(
            parsed.unwrap(),
            crate::protocol::Request::Status { name } if name.as_deref() == Some("alpha")
        ));

        let (format, parsed) = session.parse_request_line(r#"{"method":"status","name":"json"}"#);
        assert!(matches!(format, LineProtocolFormat::Text));
        assert!(
            parsed.is_err(),
            "JSON-looking line stays text after text selection"
        );
    }

    #[test]
    fn line_protocol_session_detects_json_text_and_binary() {
        let mut json_session = LineProtocolSession::new();
        let (format, parsed) = json_session.parse_request_line(
            r#"{"jsonrpc":"2.0","id":1,"method":"status","params":{"name":"x"}}"#,
        );
        assert!(matches!(
            format,
            LineProtocolFormat::Json(crate::jsonl::ProtocolFormat::JsonRpc {
                id: Some(serde_json::Value::Number(ref id)),
            }) if id.as_i64() == Some(1)
        ));
        assert!(matches!(
            parsed.unwrap(),
            crate::protocol::Request::Status { name } if name.as_deref() == Some("x")
        ));

        let mut binary_session = LineProtocolSession::new();
        let (format, parsed) = binary_session.parse_request_line("\0ignored");
        assert!(matches!(format, LineProtocolFormat::BinaryMux));
        assert!(parsed.unwrap_err().contains("binary mux"));
    }

    #[test]
    fn parses_nested_binary_stream_open() {
        let request = StreamOpenRequest::parse(
            &json!({
                "id": "stream-upgrade-1",
                "method": STREAM_OPEN_METHOD,
                "data": {
                    "mode": "binary",
                    "kind": "shell"
                }
            }),
            "ssh:7",
        )
        .expect("stream open");

        assert_eq!(request.id.as_deref(), Some("stream-upgrade-1"));
        assert_eq!(request.session, "ssh:7");
        assert_eq!(request.stream, "ssh:7:binary");
        assert_eq!(request.mode, "binary");
        assert_eq!(request.kind, "shell");

        assert_eq!(
            request.opened_response(),
            json!({
                "id": "stream-upgrade-1",
                "replyTo": "stream-upgrade-1",
                "session": "ssh:7",
                "stream": "ssh:7:binary",
                "type": "response",
                "method": STREAM_OPENED_METHOD,
                "data": {
                    "mode": "binary",
                    "kind": "shell"
                }
            })
        );
    }

    #[test]
    fn parses_flat_raw_stream_open_with_session_fields() {
        let request = StreamOpenRequest::parse(
            &json!({
                "method": STREAM_OPEN_METHOD,
                "mode": "raw",
                "kind": "binder",
                "session": "session-1",
                "stream": "stream-1"
            }),
            "ssh:7",
        )
        .expect("stream open");

        assert_eq!(request.id, None);
        assert_eq!(request.session, "session-1");
        assert_eq!(request.stream, "stream-1");
        assert_eq!(request.mode, "raw");
        assert_eq!(request.kind, "binder");
    }

    #[test]
    fn rejects_non_stream_open_method() {
        assert!(StreamOpenRequest::parse(&json!({"method": "mesh.message"}), "ssh:7").is_none());
    }

    #[test]
    fn rejects_text_mode() {
        assert!(
            StreamOpenRequest::parse(
                &json!({"method": STREAM_OPEN_METHOD, "mode": "text"}),
                "ssh:7"
            )
            .is_none()
        );
    }

    #[test]
    fn parses_method_name() {
        let request = StreamOpenRequest::parse(
            &json!({
                "id": "stream-upgrade-1",
                "method": STREAM_OPEN_METHOD,
                "data": {
                    "mode": "binary"
                }
            }),
            "ssh:7",
        )
        .expect("stream open");

        assert_eq!(request.stream, "ssh:7:binary");
    }

    #[test]
    fn normalizes_mesh_text_message_with_hex_payload() {
        let message =
            parse_mesh_message_line("lora.rx node=abc medium=lora rssi=-72 payload=hex:6869")
                .unwrap();
        assert_eq!(message.kind_tag, KIND_LORA_RX);
        assert_eq!(message.field_value(FIELD_NODE), Some("abc"));
        assert_eq!(message.field_value(FIELD_MEDIUM), Some("lora"));
        assert_eq!(message.field_value(FIELD_RSSI), Some("-72"));
        assert_eq!(message.payload.as_deref(), Some(&b"hi"[..]));
        assert_eq!(
            mesh_message_to_text(&message),
            "lora.rx medium=lora node=abc payload=hex:6869 rssi=-72"
        );
    }

    #[test]
    fn normalizes_firmware_reply_lines() {
        let stats = parse_firmware_message_line("stats node=esp1 medium=lora rssi=-80").unwrap();
        assert_eq!(stats.kind_tag, KIND_STATS);
        assert_eq!(stats.codec, MeshMessageCodec::FirmwareText);
        assert_eq!(stats.field_value(FIELD_NODE), Some("esp1"));

        let event = parse_firmware_message_line("event type=lora.rx node=esp2 len=4").unwrap();
        assert_eq!(event.kind_tag, KIND_LORA_RX);
        assert_eq!(event.field_value(FIELD_LEN), Some("4"));
    }

    #[test]
    fn normalizes_json_and_wpa_messages() {
        let json = parse_mesh_message_line(
            r#"{"jsonrpc":"2.0","id":7,"method":"discovery.ping","params":{"medium":"all","node":"n1"}}"#,
        )
        .unwrap();
        assert_eq!(json.codec, MeshMessageCodec::JsonRpc);
        assert_eq!(json.field_value(FIELD_ID), Some("7"));
        assert_eq!(json.field_value(FIELD_MEDIUM), Some("all"));

        let wpa = parse_wpa_message("<3>CTRL-EVENT-NAN-DISCOVERY-RESULT peer=aa");
        assert_eq!(wpa.codec, MeshMessageCodec::WpaText);
        assert_eq!(wpa.field_value(FIELD_MEDIUM), Some("nan"));
        assert_eq!(wpa.field_value(FIELD_STATUS), Some("3"));
    }
}
