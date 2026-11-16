use std::sync::Arc;

use anyhow::{Context, bail};
use async_trait::async_trait;
use mesh::tagged::{NameOrTag, RecordKind, TaggedRecord};
use mesh::wire::{TaggedRecordHandler, response_error, response_ok};
use serde_json::{Value, json};

pub const SERVICE_NAME: &str = "wifi";
pub const COMPONENT_ID: u32 = 205;

#[async_trait]
pub trait WifiBackend: Send + Sync {
    async fn status(&self) -> anyhow::Result<Value>;
    async fn scan(&self) -> anyhow::Result<Value>;
}

pub struct WifiService {
    backend: Arc<dyn WifiBackend>,
}

impl WifiService {
    pub fn new(backend: Arc<dyn WifiBackend>) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl TaggedRecordHandler for WifiService {
    async fn handle_record(&self, record: TaggedRecord) -> anyhow::Result<Option<TaggedRecord>> {
        let kind = record.kind()?;
        let output = self.execute(&record).await;
        match kind {
            RecordKind::Request => {
                let id = record.id.context("wifi service request missing id")?;
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

impl WifiService {
    async fn execute(&self, record: &TaggedRecord) -> anyhow::Result<Value> {
        let is_wifi = matches!(
            &record.component,
            NameOrTag::Name(name) if name == SERVICE_NAME
        ) || record.component == NameOrTag::Tag(COMPONENT_ID);
        if !is_wifi {
            bail!("unsupported wifi service component {:?}", record.component);
        }
        match &record.method {
            NameOrTag::Name(m) if m == "status" || m == "wifi.status" => {
                self.backend.status().await
            }
            NameOrTag::Tag(1) => self.backend.status().await,
            NameOrTag::Name(m) if m == "scan" || m == "wifi.scan" => self.backend.scan().await,
            NameOrTag::Tag(2) => self.backend.scan().await,
            other => bail!("unsupported wifi service method {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    async fn wifi_service_dispatches_named_and_tagged_requests() {
        let service = WifiService::new(Arc::new(MockBackend));
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

        let response = service
            .handle_record(TaggedRecord {
                component: NameOrTag::Tag(205),
                method: NameOrTag::Tag(1),
                id: Some(json!(8)),
                ..Default::default()
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.id, Some(json!(8)));
        assert_eq!(response.result, Some(json!({"operation": "status"})));
    }
}
