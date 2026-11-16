use std::sync::Arc;

use anyhow::{Context, bail};
use async_trait::async_trait;
use mesh::tagged::{NameOrTag, RecordKind, TaggedRecord};
use mesh::wire::{TaggedRecordHandler, response_error, response_ok};
use serde_json::{Map, Value, json};

pub const SERVICE_NAME: &str = "transport";
pub const COMPONENT_ID: u32 = 1;
pub const METHOD_SET: u32 = 4;

const TRANSPORT_SET_FIELDS: &[(&str, u32)] = &[
    ("mode", 1),
    ("ssid", 2),
    ("bssid", 3),
    ("channel", 4),
    ("raw_tx_rate", 5),
    ("sta_driver_tx", 6),
    ("sta_bssid_check_disabled", 7),
    ("sta_ampdu_enabled", 8),
    ("sta_11b_rates_disabled", 9),
    ("sta_raw_rx_enabled", 10),
    ("espnow_capture", 13),
    ("nan_dw_interval", 14),
    ("now", 15),
    ("ap", 16),
    ("passphrase", 17),
    ("uart", 18),
    ("ndp", 19),
    ("open", 24),
    ("wake_target", 25),
    ("ble", 26),
    ("iface", 27),
    ("uart_mode", 28),
    ("uart_baud", 29),
    ("uart_port", 30),
    ("radio_mode", 31),
    ("radio_frequency", 32),
    ("radio_bandwidth", 33),
    ("radio_bitrate", 34),
    ("radio_tx_power", 35),
    ("radio_spreading_factor", 36),
    ("radio_coding_rate", 37),
    ("ap_ssid", 38),
    ("ap_passphrase", 39),
];

#[async_trait]
pub trait TransportBackend: Send + Sync {
    async fn set(&self, params: Value) -> anyhow::Result<Value>;
}

pub struct TransportService {
    backend: Arc<dyn TransportBackend>,
}

impl TransportService {
    pub fn new(backend: Arc<dyn TransportBackend>) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl TaggedRecordHandler for TransportService {
    async fn handle_record(&self, record: TaggedRecord) -> anyhow::Result<Option<TaggedRecord>> {
        let kind = record.kind()?;
        let output = self.execute(&record).await;
        match kind {
            RecordKind::Request => {
                let id = record.id.context("transport service request missing id")?;
                Ok(Some(match output {
                    Ok(value) => response_ok(id, value),
                    Err(error) => response_error(id, json!({"error": error.to_string()})),
                }))
            }
            _ => {
                output?;
                Ok(None)
            }
        }
    }
}

impl TransportService {
    async fn execute(&self, record: &TaggedRecord) -> anyhow::Result<Value> {
        let is_transport = matches!(
            &record.component,
            NameOrTag::Name(name) if name == SERVICE_NAME
        ) || record.component == NameOrTag::Tag(COMPONENT_ID);
        let is_set = matches!(
            &record.method,
            NameOrTag::Name(m) if m == "set" || m == "transport.set"
        ) || record.method == NameOrTag::Tag(METHOD_SET);
        if !is_transport || !is_set {
            bail!(
                "unsupported transport service request {:?}.{:?}",
                record.component,
                record.method
            );
        }

        let mut params = Map::new();
        let resolved_jsonl = mesh::catalog::service_catalog_resolver()
            .resolve(SERVICE_NAME)
            .and_then(|res| res.ok())
            .filter(|resolved| resolved.catalog.method_name(record).is_some())
            .and_then(|resolved| match resolved.catalog.to_jsonl(record) {
                Value::Object(map) => Some(map),
                _ => None,
            });
        if let Some(mut map) = resolved_jsonl {
            for envelope_key in ["method", "id", "params", "result", "error", "to"] {
                map.remove(envelope_key);
            }
            for (key, value) in map {
                if let Some(digits) = key.strip_prefix('@')
                    && let Ok(tag) = digits.parse::<u32>()
                {
                    let field_name = TRANSPORT_SET_FIELDS
                        .iter()
                        .find(|&&(_, field_tag)| field_tag == tag)
                        .map(|&(name, _)| name.to_owned())
                        .unwrap_or_else(|| tag.to_string());
                    params.insert(field_name, value);
                } else {
                    params.insert(key, value);
                }
            }
        } else {
            for (key, value) in &record.env {
                match key {
                    NameOrTag::Name(name) => {
                        params.insert(name.clone(), value.clone());
                    }
                    NameOrTag::Tag(tag) => {
                        let field_name = TRANSPORT_SET_FIELDS
                            .iter()
                            .find(|&&(_, field_tag)| field_tag == *tag)
                            .map(|&(name, _)| name.to_owned())
                            .unwrap_or_else(|| tag.to_string());
                        params.insert(field_name, value.clone());
                    }
                }
            }
        }
        if !params.contains_key("mode") {
            bail!("transport.set requires mode");
        }
        self.backend.set(Value::Object(params)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBackend;

    #[async_trait]
    impl TransportBackend for MockBackend {
        async fn set(&self, params: Value) -> anyhow::Result<Value> {
            Ok(json!({"operation": "set", "params": params}))
        }
    }

    #[tokio::test]
    async fn transport_service_dispatches_named_and_tagged_requests() {
        let service = TransportService::new(Arc::new(MockBackend));
        let response = service
            .handle_record(TaggedRecord {
                component: NameOrTag::Name("transport".to_owned()),
                method: NameOrTag::Name("set".to_owned()),
                id: Some(json!(8)),
                env: [(NameOrTag::Name("mode".to_owned()), json!(6))]
                    .into_iter()
                    .collect(),
                ..Default::default()
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            response.result,
            Some(json!({"operation": "set", "params": {"mode": 6}}))
        );

        let response = service
            .handle_record(TaggedRecord {
                component: NameOrTag::Tag(COMPONENT_ID),
                method: NameOrTag::Tag(METHOD_SET),
                id: Some(json!(9)),
                env: [
                    (NameOrTag::Tag(1), json!(6)),
                    (NameOrTag::Tag(16), json!(1)),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            response.result,
            Some(json!({"operation": "set", "params": {"mode": 6, "ap": 1}}))
        );
    }
}
