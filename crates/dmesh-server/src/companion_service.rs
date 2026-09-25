//! Platform-neutral companion pairing API; adapters own physical bearers.

use std::sync::Arc;
use anyhow::{Context, bail};
use async_trait::async_trait;
use mesh::tagged::{TaggedCatalog, TaggedRecord};
use mesh::wire::{TaggedRecordHandler, response_error, response_ok};
use serde_json::{Value, json};
use ssh_mesh::mesh_rest::{MeshService, MeshServiceBackend};

pub const SERVICE_NAME: &str = "companion";

#[async_trait]
pub trait CompanionBackend: Send + Sync {
    async fn pair(&self, kind: String, id: String, vip6: Option<String>, baud: Option<u32>, psm: Option<u16>) -> anyhow::Result<Value>;
    async fn unpair(&self, kind: String, id: String) -> anyhow::Result<Value>;
}

pub fn tools_json() -> Value {
    crate::platform_catalog::tools_for("companion.")
}

pub struct CompanionService {
    backend: Arc<dyn CompanionBackend>,
    catalog: TaggedCatalog,
}

impl CompanionService {
    pub fn new(backend: Arc<dyn CompanionBackend>) -> anyhow::Result<Self> {
        Ok(Self { backend, catalog: TaggedCatalog::from_tools_json(&tools_json())? })
    }

    pub fn mesh_service(backend: Arc<dyn CompanionBackend>) -> anyhow::Result<MeshService> {
        Ok(MeshService {
            backend: MeshServiceBackend::Direct(Arc::new(Self::new(backend)?)),
            encoding: ssh_mesh::mesh_rest::MeshServiceEncoding::TaggedCbor,
            component: SERVICE_NAME.to_owned(),
        })
    }

    async fn execute(&self, method: &str, fields: &Value) -> anyhow::Result<Value> {
        let kind = fields.get("kind").and_then(Value::as_str).filter(|value| !value.is_empty())
            .context("companion request requires kind")?.to_owned();
        let id = fields.get("id").and_then(Value::as_str).filter(|value| !value.is_empty())
            .context("companion request requires id")?.to_owned();
        match method {
            "companion.pair" => {
                if fields.get("name").is_some() || fields.get("root_public_key_b64").is_some() {
                    bail!("pairing name and root-key provisioning are not implemented");
                }
                self.backend.pair(
                kind, id,
                fields.get("vip6").and_then(Value::as_str).map(str::to_owned),
                fields.get("baud").and_then(Value::as_u64).map(u32::try_from).transpose()?,
                fields.get("psm").and_then(Value::as_u64).map(u16::try_from).transpose()?,
                ).await
            },
            "companion.unpair" => self.backend.unpair(kind, id).await,
            other => bail!("unsupported companion method {other}"),
        }
    }
}

#[async_trait]
impl TaggedRecordHandler for CompanionService {
    async fn handle_record(&self, record: TaggedRecord) -> anyhow::Result<Option<TaggedRecord>> {
        let kind = record.kind()?;
        let fields = self.catalog.to_jsonl(&record);
        let method = fields.get("method").and_then(Value::as_str).unwrap_or_default();
        let output = self.execute(method, &fields).await;
        match kind {
            mesh::tagged::RecordKind::Request => {
                let id = record.id.context("companion request missing id")?;
                Ok(Some(match output {
                    Ok(value) => response_ok(id, value),
                    Err(error) => response_error(id, json!({"error": error.to_string()})),
                }))
            }
            _ => { output?; Ok(None) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh::tagged::NameOrTag;

    struct MockBackend;

    #[async_trait]
    impl CompanionBackend for MockBackend {
        async fn pair(&self, kind: String, id: String, _vip6: Option<String>, _baud: Option<u32>, psm: Option<u16>) -> anyhow::Result<Value> {
            Ok(json!({"kind": kind, "id": id, "psm": psm}))
        }
        async fn unpair(&self, kind: String, id: String) -> anyhow::Result<Value> {
            Ok(json!({"kind": kind, "released": id}))
        }
    }

    #[tokio::test]
    async fn numeric_pair_uses_the_shared_kind_and_id_fields() {
        let service = CompanionService::new(Arc::new(MockBackend)).unwrap();
        let request = TaggedRecord {
            component: NameOrTag::Tag(209),
            method: NameOrTag::Tag(1),
            id: Some(json!(7)),
            env: [
                (NameOrTag::Tag(1), json!("ble")),
                (NameOrTag::Tag(2), json!("AA:BB:CC:DD:EE:FF")),
                (NameOrTag::Tag(5), json!(128)),
            ].into_iter().collect(),
            ..Default::default()
        };
        let response = service.handle_record(request).await.unwrap().unwrap();
        assert_eq!(response.result, Some(json!({"kind": "ble", "id": "AA:BB:CC:DD:EE:FF", "psm": 128})));
    }
}
