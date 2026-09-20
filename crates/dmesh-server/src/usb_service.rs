use std::sync::Arc;

use anyhow::{Context, bail};
use async_trait::async_trait;
use mesh::tagged::{TaggedCatalog, TaggedRecord};
use mesh::wire::{TaggedRecordHandler, response_error, response_ok};
use serde_json::{Value, json};
use ssh_mesh::mesh_rest::{MeshService, MeshServiceBackend};

pub const SERVICE_NAME: &str = "usb";

#[async_trait]
pub trait UsbBackend: Send + Sync {
    async fn status(&self) -> anyhow::Result<Value>;
    async fn devices(&self) -> anyhow::Result<Value>;
    async fn open(&self, params: Value) -> anyhow::Result<Value>;
    async fn close(&self) -> anyhow::Result<Value>;
}

pub fn tools_json() -> Value {
    json!([
        {
            "name": "usb.status",
            "description": "Report the local USB serial adapter, interface, and bearer state.",
            "inputSchema": {"type": "object"},
            "outputSchema": {"type": "object"},
            "x-ui-visibility": "default"
        },
        {
            "name": "usb.devices",
            "description": "List USB devices visible to the Android host.",
            "inputSchema": {"type": "object"},
            "outputSchema": {"type": "object"},
            "x-ui-visibility": "default"
        },
        {
            "name": "usb.open",
            "description": "Open a USB serial device and attach it to the Rust mesh bearer.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vendor_id": {"type": "integer", "minimum": 1, "maximum": 65535},
                    "product_id": {"type": "integer", "minimum": 1, "maximum": 65535},
                    "auto": {"type": "boolean"}
                },
                "additionalProperties": false
            },
            "outputSchema": {"type": "object"},
            "x-ui-visibility": "default"
        },
        {
            "name": "usb.close",
            "description": "Close the active USB serial bearer.",
            "inputSchema": {"type": "object"},
            "outputSchema": {"type": "object"},
            "x-ui-visibility": "default"
        }
    ])
}

pub struct UsbService {
    backend: Arc<dyn UsbBackend>,
    catalog: TaggedCatalog,
}

impl UsbService {
    pub fn new(backend: Arc<dyn UsbBackend>) -> anyhow::Result<Self> {
        let catalog = TaggedCatalog::from_tools_json(&tools_json())
            .context("usb service catalog must be valid")?;
        Ok(Self { backend, catalog })
    }

    pub fn mesh_service(backend: Arc<dyn UsbBackend>) -> anyhow::Result<MeshService> {
        Ok(MeshService {
            backend: MeshServiceBackend::Direct(Arc::new(Self::new(backend)?)),
            catalog: Some(tools_json()),
        })
    }
}

#[async_trait]
impl TaggedRecordHandler for UsbService {
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
                let id = record.id.context("usb service request missing id")?;
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

impl UsbService {
    async fn execute(&self, method: &str, fields: &Value) -> anyhow::Result<Value> {
        match method {
            "usb.status" => self.backend.status().await,
            "usb.devices" => self.backend.devices().await,
            "usb.open" => {
                let has_vendor = fields.get("vendor_id").is_some();
                let has_product = fields.get("product_id").is_some();
                if has_vendor != has_product {
                    bail!("usb.open requires vendor_id and product_id together");
                }
                let params = if has_vendor {
                    let vendor_id = fields
                        .get("vendor_id")
                        .and_then(Value::as_u64)
                        .context("vendor_id must be an integer")?;
                    let product_id = fields
                        .get("product_id")
                        .and_then(Value::as_u64)
                        .context("product_id must be an integer")?;
                    if !(1..=0xffff).contains(&vendor_id) || !(1..=0xffff).contains(&product_id) {
                        bail!("vendor_id/product_id must fit in USB IDs");
                    }
                    json!({
                        "vendor_id": vendor_id,
                        "product_id": product_id
                    })
                } else {
                    let mut params = json!({});
                    if let Some(auto) = fields.get("auto").and_then(Value::as_bool) {
                        params["auto"] = json!(auto);
                    }
                    params
                };
                self.backend.open(params).await
            }
            "usb.close" => self.backend.close().await,
            other => bail!("unsupported usb service method {other}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh::tagged::NameOrTag;

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
    }

    #[tokio::test]
    async fn usb_service_catalog_dispatches_named_requests() {
        let service = UsbService::new(Arc::new(MockBackend)).unwrap();
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
        assert_eq!(
            response.result,
            Some(json!({"operation": "status"}))
        );
    }

    #[tokio::test]
    async fn usb_service_open_validates_vendor_and_product() {
        let service = UsbService::new(Arc::new(MockBackend)).unwrap();
        let response = service
            .handle_record(TaggedRecord {
                component: NameOrTag::Name("usb".to_owned()),
                method: NameOrTag::Name("open".to_owned()),
                id: Some(json!(8)),
                env: [
                    (NameOrTag::Name("vendor_id".to_owned()), json!(0x303a)),
                    (NameOrTag::Name("product_id".to_owned()), json!(0x1001)),
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
        let service = UsbService::new(Arc::new(MockBackend)).unwrap();
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
