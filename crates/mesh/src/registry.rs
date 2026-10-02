//! Protocol-neutral service identity, common handlers, and resource metadata.
//!
//! A worker can ship generated metadata without linking a gateway protocol.
//! JSON/text, tagged-CBOR, HTTP, CLI, or the optional `mesh-mcp` adapter may
//! all consume the same registry.

use serde_json::{Value, json};

use crate::protocol::Response;
use crate::tagged::NameOrTag;

pub use crate::jsonl::{JsonSource, ResourceSpec, ServiceRegistry};

/// Numeric identity and name of every common method, from `API.md`
/// (`mesh` 2000, `trace` 2001). Numbers dispatch the CBOR form; names are the
/// JSON/JSONL form. A service registers these beside its own numbered methods.
pub const COMMON_METHODS: &[(u64, u64, &str)] = &[
    (
        crate::generated_api_ids::COMPONENT_MESH as u64,
        crate::generated_api_ids::METHOD_MESH_INITIALIZE as u64,
        "mesh.initialize",
    ),
    (
        crate::generated_api_ids::COMPONENT_MESH as u64,
        crate::generated_api_ids::METHOD_MESH_TOOLS as u64,
        "mesh.tools",
    ),
    (
        crate::generated_api_ids::COMPONENT_MESH as u64,
        crate::generated_api_ids::METHOD_MESH_LIFECYCLE as u64,
        "mesh.lifecycle",
    ),
    (
        crate::generated_api_ids::COMPONENT_TRACE as u64,
        crate::generated_api_ids::METHOD_TRACE_SUBSCRIBE as u64,
        "trace.subscribe",
    ),
    (
        crate::generated_api_ids::COMPONENT_TRACE as u64,
        crate::generated_api_ids::METHOD_TRACE_SET_LEVEL as u64,
        "trace.set_level",
    ),
    (
        crate::generated_api_ids::COMPONENT_TRACE as u64,
        crate::generated_api_ids::METHOD_TRACE_GET_LEVEL as u64,
        "trace.get_level",
    ),
];

/// The canonical name of a common method number, if it is one.
pub fn common_method_name(component: u64, method: u64) -> Option<&'static str> {
    COMMON_METHODS
        .iter()
        .find(|(c, m, _)| *c == component && *m == method)
        .map(|(_, _, name)| *name)
}

/// The number of a common method name (canonical or the short alias), for
/// gateways that translate names to numbers at the edge.
pub fn common_method_identity(name: &str) -> Option<(u64, u64)> {
    COMMON_METHODS
        .iter()
        .find(|(_, _, canonical)| *canonical == name)
        .map(|(c, m, _)| (*c, *m))
}

/// Result of offering one decoded method and field map to the common registry.
/// Transport adapters retain ownership of framing, correlation, and encoding.
pub enum CommonDispatch {
    Response(Response),
    NotHandled,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::tagged::{NameOrTag, TaggedRecord};

    #[tokio::test]
    async fn registry_dispatches_named_tagged_common_methods() {
        let registry = ServiceRegistry::new("demo");
        let request = TaggedRecord {
            component: NameOrTag::Name("mesh".to_string()),
            method: NameOrTag::Name("initialize".to_string()),
            id: Some(json!(7)),
            ..Default::default()
        };
        let response = registry.dispatch_tagged(&request).await.unwrap().unwrap();
        assert_eq!(response.id, Some(json!(7)));
        assert_eq!(response.result.unwrap()["1"], "demo");
    }

    #[tokio::test]
    async fn registry_dispatches_numbered_common_methods() {
        let registry = ServiceRegistry::new("demo");
        let request = TaggedRecord {
            component: NameOrTag::Tag(2000),
            method: NameOrTag::Tag(1),
            id: Some(json!(5)),
            ..Default::default()
        };
        let response = registry.dispatch_tagged(&request).await.unwrap().unwrap();
        assert_eq!(response.id, Some(json!(5)));
        assert_eq!(response.result.unwrap()["1"], "demo");

        // A number outside the common components is the service's own.
        let own = TaggedRecord {
            component: NameOrTag::Tag(1),
            method: NameOrTag::Tag(1),
            id: Some(json!(6)),
            ..Default::default()
        };
        assert!(registry.dispatch_tagged(&own).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn registry_dispatches_common_methods_as_cbor() {
        let registry = ServiceRegistry::new("demo");
        let request = TaggedRecord {
            component: NameOrTag::Tag(2001),
            method: NameOrTag::Tag(3),
            id: Some(json!(8)),
            ..Default::default()
        };
        let bytes = crate::cbor::encode_record(&request).unwrap();
        let response = registry.dispatch_cbor(&bytes).await.unwrap().unwrap();
        let response = crate::cbor::decode_record(&response).unwrap();
        assert_eq!(response.id, Some(json!(8)));
        assert!(response.result.unwrap().get("1").is_some());

        let unknown = TaggedRecord {
            component: NameOrTag::Tag(7),
            method: NameOrTag::Tag(7),
            id: Some(json!(9)),
            ..Default::default()
        };
        let bytes = crate::cbor::encode_record(&unknown).unwrap();
        assert!(registry.dispatch_cbor(&bytes).await.unwrap().is_none());
    }

    #[test]
    fn common_methods_have_unique_numbers_and_resolve_both_ways() {
        for (component, method, name) in COMMON_METHODS {
            assert_eq!(common_method_name(*component, *method), Some(*name));
            assert_eq!(common_method_identity(name), Some((*component, *method)));
        }
        assert_eq!(common_method_identity("mesh.initialize"), Some((2000, 1)));
        assert_eq!(common_method_name(1, 1), None);
    }
}

impl ServiceRegistry {
    /// Offer a tagged request to the built-in mesh handlers and preserve its
    /// correlation ID in the tagged response. `None` means the request belongs
    /// to an application handler.
    pub async fn dispatch_tagged(
        &self,
        request: &crate::tagged::TaggedRecord,
    ) -> anyhow::Result<Option<crate::tagged::TaggedRecord>> {
        use anyhow::Context;

        let mut decoded = crate::tagged::to_json(request, None);
        let fields = decoded
            .as_object_mut()
            .context("tagged request must decode to an object")?;
        // A numbered request is resolved by number; one that is not a common
        // method belongs to the service's own handlers.
        let method = match (&request.component, &request.method) {
            (NameOrTag::Tag(component), NameOrTag::Tag(method)) => {
                match common_method_name(u64::from(*component), u64::from(*method)) {
                    Some(name) => name.to_string(),
                    None => return Ok(None),
                }
            }
            _ => fields
                .get("method")
                .and_then(Value::as_str)
                .context("tagged request is missing its method")?
                .to_string(),
        };
        let tagged_fields: &[(&str, u32)] = match method.as_str() {
            "mesh.lifecycle" => &[("action", 1), ("cause", 2), ("observed", 3)],
            "trace.set_level" => &[("level", 1)],
            _ => &[],
        };
        for (name, tag) in tagged_fields {
            if let Some(value) = fields.remove(&format!("@{tag}")) {
                fields.entry((*name).to_string()).or_insert(value);
            }
        }
        let CommonDispatch::Response(response) = self.dispatch(&method, fields).await else {
            return Ok(None);
        };
        let id = request
            .id
            .clone()
            .context("common method requires a correlation id")?;
        let response_fields: &[(&str, u32)] = match method.as_str() {
            "mesh.initialize" => &[
                ("name", 1),
                ("version", 2),
                ("title", 3),
                ("instructions", 4),
            ],
            "mesh.tools" => &[("tools", 1)],
            "mesh.lifecycle" => &[("subscribers", 1)],
            "trace.set_level" | "trace.get_level" => &[("level", 1), ("message", 2)],
            "trace.subscribe" => &[("subscribed", 1), ("service", 2)],
            _ => &[],
        };
        Ok(Some(if response.success {
            let mut data = response.data.unwrap_or_default();
            if let Some(fields) = data.as_object_mut() {
                for (name, tag) in response_fields {
                    if let Some(value) = fields.remove(*name) {
                        fields.insert(tag.to_string(), value);
                    }
                }
            }
            crate::wire::response_ok(id, data)
        } else {
            crate::wire::response_error(id, response.error.unwrap_or_default().into())
        }))
    }

    /// Dispatch one tagged-CBOR request by number (or by name when the record
    /// carries text names) and return the encoded response. `None` means the
    /// request is not a common method. This is the form a numbered registry
    /// (for example `dmesh_server::registry`) registers for the common
    /// components; the name-keyed JSON entry points remain for gateways.
    pub async fn dispatch_cbor(&self, request: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        let record = crate::cbor::decode_record(request)?;
        match self.dispatch_tagged(&record).await? {
            Some(response) => Ok(Some(crate::cbor::encode_record(&response)?)),
            None => Ok(None),
        }
    }

    /// Dispatch the handlers installed by every mesh service registry after an
    /// adapter has decoded its wire representation. These currently cover
    /// service discovery, supervisor lifecycle, and trace configuration.
    pub async fn dispatch(
        &self,
        method: &str,
        fields: &serde_json::Map<String, Value>,
    ) -> CommonDispatch {
        let response = match method {
            "mesh.lifecycle" | "lifecycle" => {
                match serde_json::from_value::<crate::lifecycle::LifecycleEvent>(Value::Object(
                    fields.clone(),
                )) {
                    Ok(event) => Response::ok_with_data(json!({
                        "subscribers": crate::lifecycle::publish(event),
                    })),
                    Err(error) => Response::err(format!("invalid mesh.lifecycle event: {error}")),
                }
            }
            "mesh.initialize" | "initialize" => self.initialize(),
            "mesh.tools" | "tools" => self.tools().await,
            "trace.set_level" | "set_level" | "set_trace_level" | "set_source_level" => {
                let level = fields
                    .get("level")
                    .and_then(Value::as_str)
                    .unwrap_or("info");
                let request = crate::local_trace::TraceLevelRequest {
                    level: level.to_string(),
                };
                match crate::local_trace::set_trace_level(&request) {
                    Ok(response) => {
                        Response::ok_with_data(serde_json::to_value(response).unwrap_or_default())
                    }
                    Err(response) => Response::err(
                        response
                            .message
                            .unwrap_or_else(|| "Failed to set trace level".to_string()),
                    ),
                }
            }
            "trace.get_level" | "get_level" | "get_trace_level" => Response::ok_with_data(
                serde_json::to_value(crate::local_trace::get_trace_level()).unwrap_or_default(),
            ),
            "trace.subscribe" | "subscribe" => Response::ok_with_data(json!({
                "subscribed": true,
                "service": self.name(),
            })),
            _ => return CommonDispatch::NotHandled,
        };
        CommonDispatch::Response(response)
    }
}
