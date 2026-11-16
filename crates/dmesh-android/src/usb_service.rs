use std::sync::Arc;

use anyhow::{Context, bail};
use async_trait::async_trait;
use mesh::tagged::{NameOrTag, RecordKind, TaggedFields, TaggedRecord, request_fields};
use mesh::wire::{TaggedRecordHandler, response_error, response_ok};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const SERVICE_NAME: &str = "usb";
pub const COMPONENT_ID: u32 = 204;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct UsbOpenRequest {
    #[serde(default)]
    vendor_id: Option<u16>,
    #[serde(default)]
    product_id: Option<u16>,
    #[serde(default)]
    auto: Option<bool>,
}

impl TaggedFields for UsbOpenRequest {
    const FIELDS: &'static [(&'static str, u32)] =
        &[("vendor_id", 1), ("product_id", 2), ("auto", 3)];
}

#[async_trait]
pub trait UsbBackend: Send + Sync {
    async fn status(&self) -> anyhow::Result<Value>;
    async fn devices(&self) -> anyhow::Result<Value>;
    async fn open(&self, params: Value) -> anyhow::Result<Value>;
    async fn close(&self) -> anyhow::Result<Value>;
    async fn discover(&self) -> anyhow::Result<Value>;
}

pub struct UsbService {
    backend: Arc<dyn UsbBackend>,
}

impl UsbService {
    pub fn new(backend: Arc<dyn UsbBackend>) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl TaggedRecordHandler for UsbService {
    async fn handle_record(&self, record: TaggedRecord) -> anyhow::Result<Option<TaggedRecord>> {
        let kind = record.kind()?;
        let output = self.execute(&record).await;
        match kind {
            RecordKind::Request => {
                let id = record.id.context("usb service request missing id")?;
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

impl UsbService {
    async fn execute(&self, record: &TaggedRecord) -> anyhow::Result<Value> {
        let is_usb = matches!(
            &record.component,
            NameOrTag::Name(name) if name == SERVICE_NAME
        ) || record.component == NameOrTag::Tag(COMPONENT_ID);
        if !is_usb {
            bail!("unsupported usb service component {:?}", record.component);
        }
        match &record.method {
            NameOrTag::Name(m) if m == "status" || m == "usb.status" => self.backend.status().await,
            NameOrTag::Tag(1) => self.backend.status().await,
            NameOrTag::Name(m) if m == "devices" || m == "usb.devices" => {
                self.backend.devices().await
            }
            NameOrTag::Tag(2) => self.backend.devices().await,
            NameOrTag::Name(m) if m == "open" || m == "usb.open" => self.open_with(record).await,
            NameOrTag::Tag(3) => self.open_with(record).await,
            NameOrTag::Name(m) if m == "close" || m == "usb.close" => self.backend.close().await,
            NameOrTag::Tag(4) => self.backend.close().await,
            NameOrTag::Name(m) if m == "discover" || m == "usb.discover" => {
                self.backend.discover().await
            }
            NameOrTag::Tag(5) => self.backend.discover().await,
            other => bail!("unsupported usb service method {other:?}"),
        }
    }

    async fn open_with(&self, record: &TaggedRecord) -> anyhow::Result<Value> {
        let req: UsbOpenRequest = request_fields(record)?;
        if req.vendor_id.is_some() != req.product_id.is_some() {
            bail!("usb.open requires vendor_id and product_id together");
        }
        let params = if let (Some(vendor_id), Some(product_id)) = (req.vendor_id, req.product_id) {
            if vendor_id == 0 || product_id == 0 {
                bail!("vendor_id/product_id must fit in USB IDs");
            }
            json!({
                "vendor_id": vendor_id,
                "product_id": product_id
            })
        } else {
            let mut params = json!({});
            if let Some(auto) = req.auto {
                params["auto"] = json!(auto);
            }
            params
        };
        self.backend.open(params).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBackend;

    #[async_trait]
    impl UsbBackend for MockBackend {
        async fn status(&self) -> anyhow::Result<Value> {
            Ok(json!({"operation": "status"}))
        }
        async fn devices(&self) -> anyhow::Result<Value> {
            Ok(json!({"operation": "devices"}))
        }
        async fn open(&self, params: Value) -> anyhow::Result<Value> {
            Ok(json!({"operation": "open", "params": params}))
        }
        async fn close(&self) -> anyhow::Result<Value> {
            Ok(json!({"operation": "close"}))
        }
        async fn discover(&self) -> anyhow::Result<Value> {
            Ok(json!({"operation": "discover"}))
        }
    }

    #[tokio::test]
    async fn usb_service_dispatches_named_requests() {
        let service = UsbService::new(Arc::new(MockBackend));
        let response = service
            .handle_record(TaggedRecord {
                component: NameOrTag::Name("usb".to_owned()),
                method: NameOrTag::Name("status".to_owned()),
                id: Some(json!(7)),
                ..Default::default()
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.id, Some(json!(7)));
        assert_eq!(response.result, Some(json!({"operation": "status"})));
    }

    #[tokio::test]
    async fn usb_service_open_validates_vendor_and_product() {
        let service = UsbService::new(Arc::new(MockBackend));
        let response = service
            .handle_record(TaggedRecord {
                component: NameOrTag::Tag(204),
                method: NameOrTag::Tag(3),
                id: Some(json!(8)),
                env: [
                    (NameOrTag::Tag(1), json!(0x303a)),
                    (NameOrTag::Tag(2), json!(0x1001)),
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
            Some(json!({
                "operation": "open",
                "params": {
                    "vendor_id": 0x303a,
                    "product_id": 0x1001
                }
            }))
        );
    }

    #[tokio::test]
    async fn usb_service_open_defaults_to_auto_discovery() {
        let service = UsbService::new(Arc::new(MockBackend));
        let response = service
            .handle_record(TaggedRecord {
                component: NameOrTag::Name("usb".to_owned()),
                method: NameOrTag::Name("open".to_owned()),
                id: Some(json!(9)),
                ..Default::default()
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            response.result,
            Some(json!({"operation": "open", "params": {}}))
        );
    }
}
