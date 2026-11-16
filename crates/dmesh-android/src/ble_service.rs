use std::sync::Arc;

use anyhow::{Context, bail};
use async_trait::async_trait;
use mesh::tagged::{NameOrTag, RecordKind, TaggedFields, TaggedRecord, request_fields};
use mesh::wire::{TaggedRecordHandler, response_error, response_ok};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const SERVICE_NAME: &str = "ble";
pub const COMPONENT_ID: u32 = 201;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct BleScanResultsRequest {
    #[serde(default)]
    limit: Option<u64>,
}

impl TaggedFields for BleScanResultsRequest {
    const FIELDS: &'static [(&'static str, u32)] = &[("limit", 1)];
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct BleConnectRequest {
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    psm: Option<u16>,
}

impl TaggedFields for BleConnectRequest {
    const FIELDS: &'static [(&'static str, u32)] = &[("address", 1), ("psm", 2)];
}

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

pub struct BleService {
    backend: Arc<dyn BleBackend>,
}

impl BleService {
    pub fn new(backend: Arc<dyn BleBackend>) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl TaggedRecordHandler for BleService {
    async fn handle_record(&self, record: TaggedRecord) -> anyhow::Result<Option<TaggedRecord>> {
        let kind = record.kind()?;
        let output = self.execute(&record).await;
        match kind {
            RecordKind::Request => {
                let id = record.id.context("ble service request missing id")?;
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

impl BleService {
    async fn execute(&self, record: &TaggedRecord) -> anyhow::Result<Value> {
        let is_ble = matches!(
            &record.component,
            NameOrTag::Name(name) if name == SERVICE_NAME
        ) || record.component == NameOrTag::Tag(COMPONENT_ID);
        if !is_ble {
            bail!("unsupported ble service component {:?}", record.component);
        }
        match &record.method {
            NameOrTag::Name(m) if m == "status" || m == "ble.status" => self.backend.status().await,
            NameOrTag::Tag(1) => self.backend.status().await,
            NameOrTag::Name(m) if m == "scan" || m == "ble.scan" => self.backend.scan().await,
            NameOrTag::Tag(2) => self.backend.scan().await,
            NameOrTag::Name(m) if m == "scan_stop" || m == "ble.scan_stop" => {
                self.backend.scan_stop().await
            }
            NameOrTag::Tag(3) => self.backend.scan_stop().await,
            NameOrTag::Name(m) if m == "scan_results" || m == "ble.scan_results" => {
                let req: BleScanResultsRequest = request_fields(record)?;
                self.backend.scan_results(req.limit.map(|v| v.min(64))).await
            }
            NameOrTag::Tag(4) => {
                let req: BleScanResultsRequest = request_fields(record)?;
                self.backend.scan_results(req.limit.map(|v| v.min(64))).await
            }
            NameOrTag::Name(m) if m == "scan_clear" || m == "ble.scan_clear" => {
                self.backend.scan_clear().await
            }
            NameOrTag::Tag(5) => self.backend.scan_clear().await,
            NameOrTag::Name(m) if m == "connect" || m == "ble.connect" => {
                self.connect_with(record).await
            }
            NameOrTag::Tag(6) => self.connect_with(record).await,
            NameOrTag::Name(m) if m == "disconnect" || m == "ble.disconnect" => {
                self.backend.disconnect().await
            }
            NameOrTag::Tag(7) => self.backend.disconnect().await,
            other => bail!("unsupported ble service method {other:?}"),
        }
    }

    async fn connect_with(&self, record: &TaggedRecord) -> anyhow::Result<Value> {
        let req: BleConnectRequest = request_fields(record)?;
        let address = req
            .address
            .filter(|value| !value.is_empty())
            .context("ble.connect requires address")?;
        let psm = req.psm.unwrap_or(128);
        self.backend.connect(address, psm).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    async fn ble_service_dispatches_named_and_tagged_requests() {
        let service = BleService::new(Arc::new(MockBackend));
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
        assert_eq!(response.result, Some(json!({"operation": "status"})));

        let response = service
            .handle_record(TaggedRecord {
                component: NameOrTag::Tag(201),
                method: NameOrTag::Tag(4),
                id: Some(json!(8)),
                env: [(NameOrTag::Tag(1), json!(5))].into_iter().collect(),
                ..Default::default()
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.id, Some(json!(8)));
        assert_eq!(
            response.result,
            Some(json!({"operation": "scan_results", "limit": 5}))
        );
    }
}
