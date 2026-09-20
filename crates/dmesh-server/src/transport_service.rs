use std::sync::Arc;

use anyhow::{Context, bail};
use async_trait::async_trait;
use mesh::tagged::{TaggedCatalog, TaggedRecord};
use mesh::wire::{TaggedRecordHandler, response_error, response_ok};
use serde_json::{Value, json};
use ssh_mesh::mesh_rest::{MeshService, MeshServiceBackend};

pub const SERVICE_NAME: &str = "transport";

#[async_trait]
pub trait TransportBackend: Send + Sync {
    async fn status(&self) -> anyhow::Result<Value>;
    async fn set(&self, params: Value) -> anyhow::Result<Value>;
    async fn start(&self, params: Value) -> anyhow::Result<Value>;
}

pub fn tools_json() -> Value {
    json!([
        {
            "name": "transport.status",
            "description": "Report the local radio transport snapshot.",
            "inputSchema": {"type": "object"},
            "outputSchema": {"type": "object"},
            "x-ui-visibility": "default"
        },
        {
            "name": "transport.set",
            "description": "Change the local radio transport mode.",
            "inputSchema": {
                "type": "object",
                "required": ["mode"],
                "properties": {
                    "mode": {"type": "string", "enum": ["sta", "uart", "nan", "aware"]},
                    "ssid": {"type": "string"},
                    "passphrase": {"type": "string"},
                    "bssid": {"type": "string"},
                    "bssid_hex": {"type": "string"},
                    "channel": {"type": "integer", "minimum": 0, "maximum": 255},
                    "ap": {"type": "integer", "minimum": 0, "maximum": 1},
                    "p2p_go": {"type": "integer", "minimum": 0, "maximum": 1},
                    "now": {"type": "integer", "minimum": 0, "maximum": 2},
                    "ble": {"type": "integer", "minimum": 0, "maximum": 2},
                    "uart": {"type": "integer", "minimum": 0, "maximum": 1},
                    "nan_dw_interval": {"type": "integer", "minimum": 0, "maximum": 16},
                    "wake_target": {"type": "string"}
                },
                "additionalProperties": false
            },
            "outputSchema": {"type": "object"},
            "x-ui-visibility": "default"
        },
        {
            "name": "transport.start",
            "description": "Send a parameterized NAN wake/activation record to one sleepy device.",
            "inputSchema": {
                "type": "object",
                "required": ["target_mac"],
                "properties": {
                    "target_mac": {"type": "string"},
                    "kind": {"type": "integer", "minimum": 1, "maximum": 6},
                    "ap": {"type": "integer", "minimum": 0, "maximum": 1},
                    "now": {"type": "integer", "minimum": 0, "maximum": 2},
                    "ble": {"type": "integer", "minimum": 0, "maximum": 2},
                    "nan_dw_interval": {"type": "integer", "minimum": 0, "maximum": 16}
                },
                "additionalProperties": false
            },
            "outputSchema": {"type": "object"},
            "x-ui-visibility": "default"
        }
    ])
}

pub struct TransportService {
    backend: Arc<dyn TransportBackend>,
    catalog: TaggedCatalog,
}

impl TransportService {
    pub fn new(backend: Arc<dyn TransportBackend>) -> anyhow::Result<Self> {
        let catalog = TaggedCatalog::from_tools_json(&tools_json())
            .context("transport service catalog must be valid")?;
        Ok(Self { backend, catalog })
    }

    pub fn mesh_service(backend: Arc<dyn TransportBackend>) -> anyhow::Result<MeshService> {
        Ok(MeshService {
            backend: MeshServiceBackend::Direct(Arc::new(Self::new(backend)?)),
            catalog: Some(tools_json()),
        })
    }
}

#[async_trait]
impl TaggedRecordHandler for TransportService {
    async fn handle_record(&self, record: TaggedRecord) -> anyhow::Result<Option<TaggedRecord>> {
        let kind = record.kind()?;
        let projected = self.catalog.to_jsonl(&record);
        let method = projected
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let output = self.execute(method, &projected).await;
        match kind {
            mesh::tagged::RecordKind::Request => {
                let id = record.id.context("transport service request missing id")?;
                Ok(Some(match output {
                    Ok(value) => response_ok(id, value),
                    Err(error) => response_error(
                        id,
                        json!({"error": error.to_string()}),
                    ),
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
    async fn execute(&self, method: &str, fields: &Value) -> anyhow::Result<Value> {
        match method {
            "transport.status" => self.backend.status().await,
            "transport.set" => {
                let mut params = fields.clone();
                if let Some(object) = params.as_object_mut() {
                    object.remove("method");
                    object.remove("id");
                }
                if params.get("mode").is_none() {
                    bail!("transport.set requires mode");
                }
                self.backend.set(params).await
            }
            "transport.start" => {
                let target = fields
                    .get("target_mac")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .context("transport.start requires target_mac")?;
                let mut params = json!({"target_mac": target});
                for key in ["kind", "ap", "now", "ble", "nan_dw_interval"] {
                    if let Some(value) = fields.get(key) {
                        params[key] = value.clone();
                    }
                }
                self.backend.start(params).await
            }
            other => bail!("unsupported transport service method {other}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh::tagged::NameOrTag;

    struct MockBackend;

    #[async_trait]
    impl TransportBackend for MockBackend {
        async fn status(&self) -> anyhow::Result<Value> {
            Ok(json!({"operation": "status"}))
        }
        async fn set(&self, params: Value) -> anyhow::Result<Value> {
            Ok(json!({"operation": "set", "params": params}))
        }
        async fn start(&self, params: Value) -> anyhow::Result<Value> {
            Ok(json!({"operation": "start", "params": params}))
        }
    }

    #[tokio::test]
    async fn transport_service_dispatches_wake_requests() {
        let service = TransportService::new(Arc::new(MockBackend)).unwrap();
        let response = service.handle_record(TaggedRecord {
            component: NameOrTag::Name("transport".to_owned()),
            method: NameOrTag::Name("start".to_owned()),
            id: Some(json!(9)),
            env: [
                (NameOrTag::Name("target_mac".to_owned()), json!("aa:bb:cc:dd:ee:ff")),
                (NameOrTag::Name("now".to_owned()), json!(1)),
            ].into_iter().collect(),
            ..Default::default()
        }).await.unwrap().unwrap();
        assert_eq!(response.result, Some(json!({
            "operation": "start",
            "params": {"target_mac": "aa:bb:cc:dd:ee:ff", "now": 1}
        })));
    }

    #[tokio::test]
    async fn transport_service_catalog_dispatches_named_requests() {
        let service = TransportService::new(Arc::new(MockBackend)).unwrap();
        let response = service
            .handle_record(TaggedRecord {
                component: NameOrTag::Name("transport".to_owned()),
                method: NameOrTag::Name("set".to_owned()),
                id: Some(json!(8)),
                env: [(NameOrTag::Name("mode".to_owned()), json!("nan"))]
                    .into_iter()
                    .collect(),
                ..Default::default()
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            response.result,
            Some(json!({"operation": "set", "params": {"mode": "nan"}}))
        );
    }
}
