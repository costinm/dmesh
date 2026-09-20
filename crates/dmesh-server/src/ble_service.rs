use std::sync::Arc;

use anyhow::{Context, bail};
use async_trait::async_trait;
use mesh::tagged::{TaggedCatalog, TaggedRecord};
use mesh::wire::{TaggedRecordHandler, response_error, response_ok};
use serde_json::{Value, json};
use ssh_mesh::mesh_rest::{MeshService, MeshServiceBackend};

pub const SERVICE_NAME: &str = "ble";

#[async_trait]
pub trait BleBackend: Send + Sync {
    async fn status(&self) -> anyhow::Result<Value>;
    async fn scan(&self) -> anyhow::Result<Value>;
    async fn scan_stop(&self) -> anyhow::Result<Value>;
    async fn scan_results(&self, limit: Option<u64>) -> anyhow::Result<Value>;
    async fn scan_clear(&self) -> anyhow::Result<Value>;
    async fn connect(&self, address: String, psm: u16) -> anyhow::Result<Value>;
    async fn disconnect(&self) -> anyhow::Result<Value>;
}

pub fn tools_json() -> Value {
    json!([
        {
            "name": "ble.status",
            "description": "Report the local BLE adapter, CoC, and bearer state.",
            "inputSchema": {"type": "object"},
            "outputSchema": {"type": "object"},
            "x-ui-visibility": "default"
        },
        {
            "name": "ble.scan",
            "description": "Start a bounded local BLE scan for DMesh companion advertisements.",
            "inputSchema": {"type": "object"},
            "outputSchema": {"type": "object"},
            "x-ui-visibility": "default"
        },
        {
            "name": "ble.scan_stop",
            "description": "Stop the local BLE scan without clearing retained results.",
            "inputSchema": {"type": "object"},
            "outputSchema": {"type": "object"},
            "x-ui-visibility": "default"
        },
        {
            "name": "ble.scan_results",
            "description": "List retained BLE scan results for multi-device selection.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 64}
                }
            },
            "outputSchema": {"type": "object"},
            "x-ui-visibility": "default"
        },
        {
            "name": "ble.scan_clear",
            "description": "Clear retained BLE scan results.",
            "inputSchema": {"type": "object"},
            "outputSchema": {"type": "object"},
            "x-ui-visibility": "default"
        },
        {
            "name": "ble.connect",
            "description": "Connect to one scanned BLE device over L2CAP CoC.",
            "inputSchema": {
                "type": "object",
                "required": ["address"],
                "properties": {
                    "address": {"type": "string"},
                    "psm": {"type": "integer", "minimum": 1, "maximum": 65535}
                }
            },
            "outputSchema": {"type": "object"},
            "x-ui-visibility": "default"
        },
        {
            "name": "ble.disconnect",
            "description": "Disconnect the local BLE CoC bearer.",
            "inputSchema": {"type": "object"},
            "outputSchema": {"type": "object"},
            "x-ui-visibility": "default"
        },
    ])
}

pub struct BleService {
    backend: Arc<dyn BleBackend>,
    catalog: TaggedCatalog,
}

impl BleService {
    pub fn new(backend: Arc<dyn BleBackend>) -> anyhow::Result<Self> {
        let catalog = TaggedCatalog::from_tools_json(&tools_json())
            .context("ble service catalog must be valid")?;
        Ok(Self { backend, catalog })
    }

    pub fn mesh_service(backend: Arc<dyn BleBackend>) -> anyhow::Result<MeshService> {
        Ok(MeshService {
            backend: MeshServiceBackend::Direct(Arc::new(Self::new(backend)?)),
            catalog: Some(tools_json()),
        })
    }
}

#[async_trait]
impl TaggedRecordHandler for BleService {
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
                let id = record.id.context("ble service request missing id")?;
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

impl BleService {
    async fn execute(&self, method: &str, fields: &Value) -> anyhow::Result<Value> {
        match method {
            "ble.status" => self.backend.status().await,
            "ble.scan" => self.backend.scan().await,
            "ble.scan_stop" => self.backend.scan_stop().await,
            "ble.scan_results" => {
                let limit = fields
                    .get("limit")
                    .and_then(Value::as_u64)
                    .map(|value| value.min(64));
                self.backend.scan_results(limit).await
            }
            "ble.scan_clear" => self.backend.scan_clear().await,
            "ble.connect" => {
                let address = fields
                    .get("address")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .context("ble.connect requires address")?
                    .to_owned();
                let psm = fields
                    .get("psm")
                    .and_then(Value::as_u64)
                    .unwrap_or(128)
                    .try_into()
                    .context("ble.connect psm must fit u16")?;
                self.backend.connect(address, psm).await
            }
            "ble.disconnect" => self.backend.disconnect().await,
            other => bail!("unsupported ble service method {other}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh::tagged::NameOrTag;

    struct MockBackend;

    #[async_trait]
    impl BleBackend for MockBackend {
        async fn status(&self) -> anyhow::Result<Value> {
            Ok(json!({"operation": "status"}))
        }
        async fn scan(&self) -> anyhow::Result<Value> {
            Ok(json!({"operation": "scan"}))
        }
        async fn scan_stop(&self) -> anyhow::Result<Value> {
            Ok(json!({"operation": "scan_stop"}))
        }
        async fn scan_results(&self, limit: Option<u64>) -> anyhow::Result<Value> {
            Ok(json!({"operation": "scan_results", "limit": limit}))
        }
        async fn scan_clear(&self) -> anyhow::Result<Value> {
            Ok(json!({"operation": "scan_clear"}))
        }
        async fn connect(&self, address: String, psm: u16) -> anyhow::Result<Value> {
            Ok(json!({"operation": "connect", "address": address, "psm": psm}))
        }
        async fn disconnect(&self) -> anyhow::Result<Value> {
            Ok(json!({"operation": "disconnect"}))
        }
    }

    #[tokio::test]
    async fn ble_service_catalog_dispatches_named_requests() {
        let service = BleService::new(Arc::new(MockBackend)).unwrap();
        let response = service
            .handle_record(TaggedRecord {
                component: NameOrTag::Name("ble".to_owned()),
                method: NameOrTag::Name("status".to_owned()),
                id: Some(json!(7)),
                ..Default::default()
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.id, Some(json!(7)));
        assert_eq!(
            response.result,
            Some(json!({"operation": "status"}))
        );
    }


    #[test]
    fn ble_service_mesh_registration_uses_the_shared_catalog() {
        let service = BleService::mesh_service(Arc::new(MockBackend)).unwrap();
        assert!(service.catalog.is_some());
        let names = TaggedCatalog::from_tools_json(service.catalog.as_ref().unwrap())
            .unwrap()
            .method("ble.scan_results")
            .is_some();
        assert!(names);
    }
}
