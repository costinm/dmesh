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
    async fn set(&self, params: Value) -> anyhow::Result<Value>;
}

pub fn tools_json() -> Value {
    let catalog: Value = serde_json::from_str(include_str!("../../lmesh/resources/tools.json"))
        .expect("lmesh tools catalog must be valid JSON");
    Value::Array(
        catalog["tools"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|tool| tool["name"] == "transport.set")
            .cloned()
            .collect(),
    )
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
            encoding: ssh_mesh::mesh_rest::MeshServiceEncoding::TaggedCbor,
            component: "transport".to_owned(),
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
    async fn execute(&self, method: &str, fields: &Value) -> anyhow::Result<Value> {
        match method {
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
        async fn set(&self, params: Value) -> anyhow::Result<Value> {
            Ok(json!({"operation": "set", "params": params}))
        }
    }

    #[tokio::test]
    async fn transport_service_catalog_dispatches_named_requests() {
        let service = TransportService::new(Arc::new(MockBackend)).unwrap();
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
    }

    #[test]
    fn transport_service_uses_common_component_and_method_tags() {
        let catalog = TaggedCatalog::from_tools_json(&tools_json()).unwrap();
        let tool = catalog.method("transport.set").unwrap();
        assert_eq!(tool.component, NameOrTag::Tag(1));
        assert_eq!(tool.method, NameOrTag::Tag(4));
    }
}
