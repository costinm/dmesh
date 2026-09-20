use std::sync::Arc;

use anyhow::{Context, bail};
use async_trait::async_trait;
use mesh::tagged::{TaggedCatalog, TaggedRecord};
use mesh::wire::{TaggedRecordHandler, response_error, response_ok};
use serde_json::{Value, json};
use ssh_mesh::mesh_rest::{MeshService, MeshServiceBackend};

pub const SERVICE_NAME: &str = "history";

#[async_trait]
pub trait HistoryBackend: Send + Sync {
    async fn radio_history(
        &self,
        limit: Option<u64>,
        since_ms: Option<u64>,
        keys: Option<String>,
    ) -> anyhow::Result<Value>;
}

pub fn tools_json() -> Value {
    json!([
        {
            "name": "radio.history",
            "description": "Read the bounded local radio event history.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 256},
                    "since_ms": {"type": "integer", "minimum": 0},
                    "keys": {"type": "string"}
                }
            },
            "outputSchema": {"type": "object"},
            "x-ui-visibility": "default"
        }
    ])
}

pub struct HistoryService {
    backend: Arc<dyn HistoryBackend>,
    catalog: TaggedCatalog,
}

impl HistoryService {
    pub fn new(backend: Arc<dyn HistoryBackend>) -> anyhow::Result<Self> {
        let catalog = TaggedCatalog::from_tools_json(&tools_json())
            .context("history service catalog must be valid")?;
        Ok(Self { backend, catalog })
    }

    pub fn mesh_service(backend: Arc<dyn HistoryBackend>) -> anyhow::Result<MeshService> {
        Ok(MeshService {
            backend: MeshServiceBackend::Direct(Arc::new(Self::new(backend)?)),
            catalog: Some(tools_json()),
        })
    }
}

#[async_trait]
impl TaggedRecordHandler for HistoryService {
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
                let id = record.id.context("history service request missing id")?;
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

impl HistoryService {
    async fn execute(&self, method: &str, fields: &Value) -> anyhow::Result<Value> {
        if method != "radio.history" {
            bail!("unsupported history service method {method}");
        }
        let limit = fields
            .get("limit")
            .and_then(Value::as_u64)
            .map(|value| value.min(256));
        let since_ms = fields.get("since_ms").and_then(Value::as_u64);
        let keys = fields
            .get("keys")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        self.backend
            .radio_history(limit, since_ms, keys)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh::tagged::NameOrTag;

    struct MockBackend;

    #[async_trait]
    impl HistoryBackend for MockBackend {
        async fn radio_history(
            &self,
            limit: Option<u64>,
            since_ms: Option<u64>,
            keys: Option<String>,
        ) -> anyhow::Result<Value> {
            Ok(json!({
                "operation": "history",
                "limit": limit,
                "since_ms": since_ms,
                "keys": keys
            }))
        }
    }

    #[tokio::test]
    async fn history_service_catalog_dispatches_named_requests() {
        let service = HistoryService::new(Arc::new(MockBackend)).unwrap();
        let response = service
            .handle_record(TaggedRecord {
                component: NameOrTag::Name("radio".to_owned()),
                method: NameOrTag::Name("history".to_owned()),
                id: Some(json!(9)),
                env: [(NameOrTag::Name("limit".to_owned()), json!(64))]
                    .into_iter()
                    .collect(),
                ..Default::default()
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            response.result,
            Some(json!({
                "operation": "history",
                "limit": 64,
                "since_ms": null,
                "keys": null
            }))
        );
    }
}
