use std::sync::Arc;

use anyhow::{Context, bail};
use async_trait::async_trait;
use mesh::tagged::{TaggedCatalog, TaggedRecord};
use mesh::wire::{TaggedRecordHandler, response_error, response_ok};
use serde_json::{Value, json};
use ssh_mesh::mesh_rest::{MeshService, MeshServiceBackend};

pub const SERVICE_NAME: &str = "wifi";

#[async_trait]
pub trait WifiBackend: Send + Sync {
    async fn status(&self) -> anyhow::Result<Value>;
    async fn scan(&self) -> anyhow::Result<Value>;
}

pub fn tools_json() -> Value {
    json!([
        {
            "name": "wifi.status",
            "description": "Report the local Wi-Fi controller, station, and NAN snapshot.",
            "inputSchema": {"type": "object"},
            "outputSchema": {"type": "object"},
            "x-ui-visibility": "default"
        },
        {
            "name": "wifi.scan",
            "description": "Request a bounded platform Wi-Fi scan.",
            "inputSchema": {"type": "object"},
            "outputSchema": {"type": "object"},
            "x-ui-visibility": "default"
        }
    ])
}

pub struct WifiService {
    backend: Arc<dyn WifiBackend>,
    catalog: TaggedCatalog,
}

impl WifiService {
    pub fn new(backend: Arc<dyn WifiBackend>) -> anyhow::Result<Self> {
        let catalog = TaggedCatalog::from_tools_json(&tools_json())
            .context("wifi service catalog must be valid")?;
        Ok(Self { backend, catalog })
    }

    pub fn mesh_service(backend: Arc<dyn WifiBackend>) -> anyhow::Result<MeshService> {
        Ok(MeshService {
            backend: MeshServiceBackend::Direct(Arc::new(Self::new(backend)?)),
            catalog: Some(tools_json()),
        })
    }
}

#[async_trait]
impl TaggedRecordHandler for WifiService {
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
                let id = record.id.context("wifi service request missing id")?;
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

impl WifiService {
    async fn execute(&self, method: &str, _fields: &Value) -> anyhow::Result<Value> {
        match method {
            "wifi.status" => self.backend.status().await,
            "wifi.scan" => self.backend.scan().await,
            other => bail!("unsupported wifi service method {other}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh::tagged::NameOrTag;

    struct MockBackend;

    #[async_trait]
    impl WifiBackend for MockBackend {
        async fn status(&self) -> anyhow::Result<Value> {
            Ok(json!({"operation": "status"}))
        }
        async fn scan(&self) -> anyhow::Result<Value> {
            Ok(json!({"operation": "scan"}))
        }
    }

    #[tokio::test]
    async fn wifi_service_catalog_dispatches_named_requests() {
        let service = WifiService::new(Arc::new(MockBackend)).unwrap();
        let response = service
            .handle_record(TaggedRecord {
                component: NameOrTag::Name("wifi".to_owned()),
                method: NameOrTag::Name("scan".to_owned()),
                id: Some(json!(7)),
                ..Default::default()
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.id, Some(json!(7)));
        assert_eq!(response.result, Some(json!({"operation": "scan"})));
    }
}
