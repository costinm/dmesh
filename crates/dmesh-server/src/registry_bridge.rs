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
use mesh::tagged::TaggedRecord;
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

/// A generated request or response struct that marshals itself to and from the
/// tag-keyed CBOR map of `API.md` (`mesh-api-gen --rust-tags` implements this
/// for every type in `platform_api`). No JSON is involved in either direction.
pub trait TaggedCbor: Sized {
    fn encode_cbor(&self) -> Vec<u8>;
    fn decode_cbor(input: &[u8]) -> std::result::Result<Self, String>;
}

/// The correlated success response for a request to `component`/`method`:
/// `{1: component, 2: method, 3: id, 6: result}`, where `result` is one encoded
/// CBOR item. Gateways that decode responses with `mesh::cbor::decode_record`
/// need the numeric names, as every other registered handler's response has.
pub fn response_with_result(
    component: u64,
    method: u64,
    id: u64,
    result: &[u8],
) -> Option<Vec<u8>> {
    let mut out = vec![0u8; result.len() + 48];
    let used = crate::tagged::encode_numeric_response(component, method, id, result, &mut out)?;
    out.truncate(used);
    Some(out)
}

fn numeric_names(record: &crate::tagged::Record<'_>) -> Option<(u64, u64)> {
    match (record.component?, record.method?) {
        (crate::tagged::Name::Tag(component), crate::tagged::Name::Tag(method)) => {
            Some((component, method))
        }
        _ => None,
    }
}

/// A registry handler written against the typed request and response structs
/// that `mesh-api-gen --rust-tags` generates from `API.md`. The request fields
/// are decoded from the record's numeric tags and the response is encoded back
/// to tags by the structs' generated marshalling, so the handler body sees no
/// JSON and no catalog. An `Err` becomes the method's correlated tagged error.
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
    Req: TaggedCbor + Send + 'static,
    Resp: TaggedCbor + Send + 'static,
    F: Fn(Req, CallContext) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = std::result::Result<Resp, String>> + Send + 'static,
{
    fn call<'a>(&'a self, call: Call<'a>) -> Reply<'a> {
        Box::pin(async move {
            let id = call.record.id?;
            let (component, method) = numeric_names(&call.record)?;
            // An omitted fields map is the same as an empty one.
            let outcome = match Req::decode_cbor(call.record.fields.unwrap_or(&[0xa0])) {
                Ok(request) => (self.handler)(request, call.context).await,
                Err(error) => Err(format!("invalid request: {error}")),
            };
            // A response carries its correlation id and the result or error;
            // the envelope has no component/method on a response.
            match outcome {
                Ok(value) => response_with_result(component, method, id, &value.encode_cbor()),
                Err(message) => {
                    let mut out = vec![0u8; message.len() + 48];
                    crate::tagged::encode_numeric_error(
                        component,
                        method,
                        id,
                        message.as_bytes(),
                        &mut out,
                    )
                    .map(|used| {
                        out.truncate(used);
                        out
                    })
                }
            }
        })
    }
}

/// Encode a typed `value` as the correlated response to a raw request, for
/// handlers that are not written against [`TypedHandler`].
pub fn typed_response<T: TaggedCbor>(request: &[u8], value: &T) -> Option<Vec<u8>> {
    let record = crate::tagged::decode(request)?;
    let (component, method) = numeric_names(&record)?;
    response_with_result(component, method, record.id?, &value.encode_cbor())
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
            names(crate::companion::methods()),
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
    impl TaggedCbor for EchoRequest {
        fn encode_cbor(&self) -> Vec<u8> {
            unreachable!("requests are only decoded")
        }
        fn decode_cbor(input: &[u8]) -> std::result::Result<Self, String> {
            let mut d = crate::cbor::Decoder::new(input);
            let (_, count) = d.head().ok_or("not a map")?;
            let mut text = None;
            for _ in 0..count {
                match d.uint().ok_or("tag")? {
                    1 => text = Some(String::from_utf8(d.text_ref().ok_or("text")?.to_vec()).map_err(|_| "utf8")?),
                    _ => d.skip().ok_or("value")?,
                }
            }
            Ok(Self { text })
        }
    }
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    struct EchoResponse {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        echoed: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        local: Option<bool>,
    }
    impl TaggedCbor for EchoResponse {
        fn encode_cbor(&self) -> Vec<u8> {
            let mut out = vec![0u8; 64];
            let mut e = crate::cbor::Encoder::new(&mut out);
            e.map(u64::from(self.echoed.is_some()) + u64::from(self.local.is_some())).unwrap();
            if let Some(text) = &self.echoed {
                e.uint(1).unwrap();
                e.text_value(text.as_bytes()).unwrap();
            }
            if let Some(local) = self.local {
                e.uint(2).unwrap();
                e.bool(local).unwrap();
            }
            let used = e.len();
            out.truncate(used);
            out
        }
        fn decode_cbor(_: &[u8]) -> std::result::Result<Self, String> {
            unreachable!("responses are only encoded")
        }
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
        let failure = mesh::cbor::decode_record(&failure).unwrap();
        assert_eq!(failure.id, Some(json!(3)));
        assert!(failure.error.is_some());
    }

}
