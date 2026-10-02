//! Host-side bridges between the tagged-CBOR registry and ssh-mesh's
//! `TaggedRecordHandler` (the type its HTTP gateway, SSH and control-socket
//! sessions speak). Both directions carry tagged CBOR bytes, so a request
//! takes the same path whether it arrives from a QUIC peer, the local socket
//! or the HTTP translator.

use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use mesh::tagged::{TaggedFields, TaggedRecord};
use mesh::wire::TaggedRecordHandler;
use serde_json::{Value, json};

use crate::registry::{self, Call, CallContext, Handler, Method, Registry, Reply};

/// Registry handler that runs an existing `TaggedRecordHandler`.
#[derive(Clone)]
pub struct RecordHandlerAdapter(pub Arc<dyn TaggedRecordHandler>);

impl Handler for RecordHandlerAdapter {
    fn call<'a>(&'a self, call: Call<'a>) -> Reply<'a> {
        Box::pin(async move {
            let record = mesh::cbor::decode_record(call.data).ok()?;
            let response = self.0.handle_record(record).await.ok()??;
            mesh::cbor::encode_record(&response).ok()
        })
    }
}

/// `TaggedRecordHandler` that dispatches through a registry, as local
/// ingress. With no registry it uses the process-wide one.
#[derive(Clone, Default)]
pub struct RegistryRecordHandler {
    registry: Option<Arc<Registry>>,
}

impl RegistryRecordHandler {
    pub fn global() -> Self {
        Self::default()
    }

    pub fn new(registry: Arc<Registry>) -> Self {
        Self {
            registry: Some(registry),
        }
    }
}

#[async_trait]
impl TaggedRecordHandler for RegistryRecordHandler {
    async fn handle_record(&self, record: TaggedRecord) -> Result<Option<TaggedRecord>> {
        let request = mesh::cbor::encode_record(&record)?;
        let response = match &self.registry {
            Some(registry) => registry.dispatch(&request, true, CallContext::local()).await,
            None => registry::dispatch(&request, true, CallContext::local()).await,
        };
        match response {
            Some(bytes) => Ok(Some(mesh::cbor::decode_record(&bytes)?)),
            None => Ok(None),
        }
    }
}

/// A registry handler written against the typed request and response structs
/// that `mesh-api-gen --rust-tags` generates from `API.md`. The request is
/// decoded from the record's numeric tags and the response is encoded back to
/// tags, so the handler body sees no JSON and no catalog. An `Err` becomes the
/// method's correlated tagged error.
pub struct TypedHandler<Req, Resp, F> {
    handler: F,
    _types: PhantomData<fn(Req) -> Resp>,
}

impl<Req, Resp, F> TypedHandler<Req, Resp, F> {
    pub fn new(handler: F) -> Self {
        Self {
            handler,
            _types: PhantomData,
        }
    }
}

impl<Req, Resp, F: Clone> Clone for TypedHandler<Req, Resp, F> {
    fn clone(&self) -> Self {
        Self::new(self.handler.clone())
    }
}

impl<Req, Resp, F, Fut> Handler for TypedHandler<Req, Resp, F>
where
    Req: TaggedFields + Send + 'static,
    Resp: TaggedFields + Send + 'static,
    F: Fn(Req, CallContext) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = std::result::Result<Resp, String>> + Send + 'static,
{
    fn call<'a>(&'a self, call: Call<'a>) -> Reply<'a> {
        Box::pin(async move {
            let record = mesh::cbor::decode_record(call.data).ok()?;
            let id = record.id.clone()?;
            let outcome = match mesh::tagged::request_fields::<Req>(&record) {
                Ok(request) => (self.handler)(request, call.context).await,
                Err(error) => Err(format!("invalid request: {error}")),
            };
            // A response carries its correlation id and the result or error;
            // the envelope has no component/method on a response.
            let response = match outcome {
                Ok(value) => mesh::wire::response_ok(id, mesh::tagged::to_tagged_value(&value).ok()?),
                Err(message) => mesh::wire::response_error(id, json!(message)),
            };
            mesh::cbor::encode_record(&response).ok()
        })
    }
}

/// Encode a typed `value` as the correlated response to a raw request, for
/// handlers that are not written against [`TypedHandler`].
pub fn typed_response<T: TaggedFields>(request: &[u8], value: &T) -> Option<Vec<u8>> {
    let record = mesh::cbor::decode_record(request).ok()?;
    let response = mesh::wire::response_ok(record.id?, mesh::tagged::to_tagged_value(value).ok()?);
    mesh::cbor::encode_record(&response).ok()
}

/// The registrable methods of a generated tool catalog: every tool carrying a
/// component and method index, named `component.method`. Names are leaked
/// once; a registration lives for the process.
pub fn methods_from_tools(tools: &Value) -> Vec<Method> {
    let tools = tools
        .as_array()
        .or_else(|| tools.get("tools").and_then(Value::as_array));
    tools
        .into_iter()
        .flatten()
        .filter_map(|tool| {
            let name = tool.get("name")?.as_str()?;
            let component = tool.get("x-component-index")?.as_u64()?;
            let method = tool.get("x-method-index")?.as_u64()?;
            let (component_name, method_name) = name.split_once('.').unwrap_or(("", name));
            Some(Method::new(
                component,
                Box::leak(component_name.to_owned().into_boxed_str()),
                method,
                Box::leak(method_name.to_owned().into_boxed_str()),
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh::tagged::NameOrTag;

    #[test]
    fn tools_become_numbered_and_named_methods() {
        let tools = serde_json::json!([
            {"name": "usb.open", "x-component-index": 204, "x-method-index": 3},
            {"name": "status", "x-component-index": 9, "x-method-index": 1},
            {"name": "unnumbered"},
        ]);
        let methods = methods_from_tools(&tools);
        assert_eq!(methods.len(), 2);
        assert_eq!(methods[0].wire_name(), "usb.open");
        assert_eq!((methods[0].component, methods[0].method), (204, 3));
        assert_eq!(methods[1].wire_name(), "status");
        assert_eq!(methods[1].component_name, "");
    }

    #[test]
    fn each_platform_service_reports_its_catalogued_methods() {
        let names = |methods: Vec<Method>| {
            methods.iter().map(Method::wire_name).collect::<Vec<_>>()
        };
        assert_eq!(
            names(crate::usb_service::methods()),
            ["usb.status", "usb.devices", "usb.open", "usb.close", "usb.discover"]
        );
        assert_eq!(
            names(crate::wifi_service::methods()),
            ["wifi.status", "wifi.scan"]
        );
        assert_eq!(
            names(crate::companion_service::methods()),
            ["companion.pair", "companion.unpair"]
        );
        assert_eq!(names(crate::transport_service::methods()), ["transport.set"]);
        assert_eq!(crate::ble_service::methods().len(), 5);
    }
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    struct EchoRequest {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        text: Option<String>,
    }
    impl TaggedFields for EchoRequest {
        const FIELDS: &'static [(&'static str, u32)] = &[("text", 1)];
    }
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    struct EchoResponse {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        echoed: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        local: Option<bool>,
    }
    impl TaggedFields for EchoResponse {
        const FIELDS: &'static [(&'static str, u32)] = &[("echoed", 1), ("local", 2)];
    }

    #[tokio::test]
    async fn typed_handler_decodes_tags_and_encodes_tags() {
        let registry = Registry::new();
        let method = Method::new(0x7ffd, "demo", 1, "echo");
        assert!(registry.register(
            method,
            TypedHandler::new(|request: EchoRequest, context: CallContext| async move {
                match request.text.as_deref() {
                    Some("boom") => Err("boom".to_owned()),
                    text => Ok(EchoResponse {
                        echoed: text.map(str::to_owned),
                        local: Some(context.local),
                    }),
                }
            }),
        ));
        let request = |text: &str| {
            mesh::cbor::encode_record(&TaggedRecord {
                component: NameOrTag::Tag(0x7ffd),
                method: NameOrTag::Tag(1),
                id: Some(json!(3)),
                env: [(NameOrTag::Tag(1), json!(text))].into_iter().collect(),
                ..Default::default()
            })
            .unwrap()
        };
        let bytes = request("hi");
        let response = registry
            .dispatch(&bytes, true, CallContext::local())
            .await
            .unwrap();
        let record = mesh::cbor::decode_record(&response).unwrap();
        let result = record.result.unwrap();
        assert_eq!(result["1"], "hi");
        assert_eq!(result["2"], true);
        assert_eq!(record.id, Some(json!(3)));

        let failure = registry
            .dispatch(&request("boom"), true, CallContext::default())
            .await
            .unwrap();
        assert_eq!(
            mesh::cbor::decode_record(&failure).unwrap().error,
            Some(json!("boom"))
        );
    }

}
