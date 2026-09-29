//! Destination registry and directed-record forwarding.
//!
//! Directed tagged-CBOR records carry a `to` destination, and the common
//! session loop already hands them to [`crate::wire::TaggedRecordHandler::
//! forward_record`]. This module supplies the missing generic implementation:
//! a registry that resolves a destination to a transport-neutral
//! [`MeshClient`], plus built-in TCP and Unix-socket routes. QUIC, SSH, or
//! other bearers register their own [`Route`] implementations without this
//! crate depending on them.
//!
//! `forward_record` opens one stream to the destination, writes the framed
//! record, and reads the correlated response. The router therefore works for
//! any stream peer that runs the common CBOR session loop, and composes with
//! the gateway translation: name-based JSON in, tagged-CBOR frame out, `to`
//! chosen by route policy, response translated back.

use std::sync::{Arc, RwLock};

use anyhow::{Context, Result, bail};
use serde_json::Value;
use tokio::net::{TcpStream, UnixStream};

use crate::client::{MeshClient, MeshStream, call_record};
use crate::tagged::{RecordKind, TaggedRecord};
use crate::wire::TaggedRecordHandler;

/// One routing entry: a predicate over `to` values plus the client that
/// serves matching destinations.
pub trait Route: Send + Sync {
    /// Return whether this route can serve the given destination value.
    fn accepts(&self, to: &Value) -> bool;
    /// Return the client used for accepted destinations.
    fn client(&self) -> Arc<dyn MeshClient>;
}

/// Order-preserving destination registry.
///
/// The first accepting route wins, so specific routes may be registered
/// before general ones. Successful resolution returns a client; the registry
/// holds no connection state.
#[derive(Default)]
pub struct MeshRouter {
    routes: RwLock<Vec<Arc<dyn Route>>>,
}

impl MeshRouter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a route. Later calls append; the first accepting route wins.
    pub fn register(&self, route: Arc<dyn Route>) {
        self.routes
            .write()
            .expect("mesh router lock poisoned")
            .push(route);
    }

    /// Resolve one destination to the first accepting route's client.
    pub fn resolve(&self, to: &Value) -> Option<Arc<dyn MeshClient>> {
        self.routes
            .read()
            .expect("mesh router lock poisoned")
            .iter()
            .find(|route| route.accepts(to))
            .map(|route| route.client())
    }

    /// Forward one directed request through the registry.
    ///
    /// Validates the request shape before any network work, resolves `to`,
    /// and delegates stream framing and response correlation to
    /// [`call_record`].
    pub async fn forward_record(&self, record: TaggedRecord) -> Result<TaggedRecord> {
        if record.kind()? != RecordKind::Request {
            bail!("forwarding requires a correlated request record");
        }
        if record.id.is_none() {
            bail!("forwarded request is missing an id");
        }
        let to = record
            .to
            .clone()
            .context("forwarded record is missing a `to` destination")?;
        let client = self.resolve(&to).ok_or_else(|| {
            anyhow::anyhow!("no route for destination {to}; register one or use a built-in form")
        })?;
        call_record(client.as_ref(), record).await
    }
}

/// Extract a TCP `host:port` destination from a `to` value.
///
/// Accepts `host:port` and `tcp://host:port`. Absolute paths and unknown
/// forms return `None` so other routes may claim them.
pub fn tcp_destination(to: &Value) -> Option<String> {
    let raw = to.as_str()?.trim();
    let candidate = raw.strip_prefix("tcp://").unwrap_or(raw);
    if candidate.starts_with('/') {
        return None;
    }
    let (_host, port) = candidate.rsplit_once(':')?;
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(candidate.to_owned())
}

/// Extract a Unix-socket destination from a `to` value.
///
/// Accepts `/absolute/path` and `uds:///absolute/path`; the path must be
/// absolute so relative names are never silently redirected.
pub fn uds_destination(to: &Value) -> Option<String> {
    let raw = to.as_str()?.trim();
    let path = raw.strip_prefix("uds://").unwrap_or(raw);
    if path.starts_with('/') {
        Some(path.to_owned())
    } else {
        None
    }
}

/// Route TCP destinations to a plain TCP connection.
pub struct TcpRoute;

impl Route for TcpRoute {
    fn accepts(&self, to: &Value) -> bool {
        tcp_destination(to).is_some()
    }

    fn client(&self) -> Arc<dyn MeshClient> {
        Arc::new(TcpClient)
    }
}

/// [`MeshClient`] over plain TCP. The target node or path is a `host:port`
/// destination selected by [`tcp_destination`].
pub struct TcpClient;

#[async_trait::async_trait]
impl MeshClient for TcpClient {
    async fn open_stream(&self, target: &crate::client::MeshTarget) -> Result<Box<dyn MeshStream>> {
        let destination = target.path.clone().unwrap_or_else(|| target.node.clone());
        let address = tcp_destination(&Value::String(destination))
            .context("TCP route requires a host:port destination")?;
        let stream = TcpStream::connect(&address)
            .await
            .with_context(|| format!("connect TCP destination {address}"))?;
        Ok(Box::new(stream))
    }
}

/// Route Unix-socket destinations to a stream connection.
pub struct UdsRoute;

impl Route for UdsRoute {
    fn accepts(&self, to: &Value) -> bool {
        uds_destination(to).is_some()
    }

    fn client(&self) -> Arc<dyn MeshClient> {
        Arc::new(UdsClient)
    }
}

/// [`MeshClient`] over a Unix stream socket. The target node or path is an
/// absolute socket path selected by [`uds_destination`].
#[cfg(unix)]
pub struct UdsClient;

#[cfg(unix)]
#[async_trait::async_trait]
impl MeshClient for UdsClient {
    async fn open_stream(&self, target: &crate::client::MeshTarget) -> Result<Box<dyn MeshStream>> {
        let destination = target.path.clone().unwrap_or_else(|| target.node.clone());
        let path = uds_destination(&Value::String(destination))
            .context("UDS route requires an absolute socket path")?;
        let stream = UnixStream::connect(&path)
            .await
            .with_context(|| format!("connect UDS destination {path}"))?;
        Ok(Box::new(stream))
    }
}

/// A service handler that serves local records itself and forwards directed
/// records through a router.
///
/// Wrap any [`TaggedRecordHandler`] with this to obtain the generic
/// forwarding behavior; the wrapped handler never sees records that name
/// another destination.
pub struct ForwardingHandler<H> {
    handler: H,
    router: Arc<MeshRouter>,
}

impl<H> ForwardingHandler<H> {
    pub fn new(handler: H, router: Arc<MeshRouter>) -> Self {
        Self { handler, router }
    }
}

#[async_trait::async_trait]
impl<H: TaggedRecordHandler> TaggedRecordHandler for ForwardingHandler<H> {
    async fn handle_record(&self, record: TaggedRecord) -> Result<Option<TaggedRecord>> {
        self.handler.handle_record(record).await
    }

    async fn forward_record(&self, record: TaggedRecord) -> Result<Option<TaggedRecord>> {
        self.router.forward_record(record).await.map(Some)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use anyhow::Result as AnyResult;
    use serde_json::json;
    use tokio::io::DuplexStream;

    use super::*;
    use crate::tagged::NameOrTag;
    use crate::wire::{read_cbor_record, response_ok, serve_cbor_session, write_cbor_record};

    struct EchoHandler;

    #[async_trait::async_trait]
    impl TaggedRecordHandler for EchoHandler {
        async fn handle_record(&self, record: TaggedRecord) -> Result<Option<TaggedRecord>> {
            let id = record.id.clone().context("echo request missing id")?;
            Ok(Some(response_ok(id, json!({"echo": "local"}))))
        }
    }

    async fn serve_echo_tcp(listener: tokio::net::TcpListener) {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut stream = stream;
                let _ = serve_cbor_session(&mut stream, &EchoHandler).await;
            });
        }
    }

    #[tokio::test]
    async fn tcp_route_forwards_to_a_local_echo_service() -> AnyResult<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?.to_string();
        tokio::spawn(serve_echo_tcp(listener));

        let router = MeshRouter::new();
        router.register(Arc::new(TcpRoute));
        let response = router
            .forward_record(TaggedRecord {
                component: NameOrTag::Name("telemetry".to_owned()),
                method: NameOrTag::Name("status".to_owned()),
                id: Some(json!(11)),
                to: Some(Value::String(address)),
                ..Default::default()
            })
            .await?;
        assert_eq!(response.result, Some(json!({"echo": "local"})));
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn uds_route_forwards_to_a_local_echo_service() -> AnyResult<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("echo.sock");
        let listener = tokio::net::UnixListener::bind(&path)?;
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut stream = stream;
                    let _ = serve_cbor_session(&mut stream, &EchoHandler).await;
                });
            }
        });

        let router = MeshRouter::new();
        router.register(Arc::new(UdsRoute));
        let response = router
            .forward_record(TaggedRecord {
                component: NameOrTag::Name("telemetry".to_owned()),
                method: NameOrTag::Name("status".to_owned()),
                id: Some(json!(12)),
                to: Some(Value::String(path.display().to_string())),
                ..Default::default()
            })
            .await?;
        assert_eq!(response.result, Some(json!({"echo": "local"})));
        Ok(())
    }

    /// Test double: serves one request over an in-memory duplex pair.
    struct DuplexRoute(Mutex<Option<DuplexStream>>);

    impl Route for DuplexRoute {
        fn accepts(&self, to: &Value) -> bool {
            to.as_str() == Some("e7")
        }

        fn client(&self) -> Arc<dyn MeshClient> {
            Arc::new(DuplexClient(Mutex::new(
                self.0.lock().expect("mutex").take(),
            )))
        }
    }

    struct DuplexClient(Mutex<Option<DuplexStream>>);

    #[async_trait::async_trait]
    impl MeshClient for DuplexClient {
        async fn open_stream(
            &self,
            _target: &crate::client::MeshTarget,
        ) -> Result<Box<dyn MeshStream>> {
            let stream = self
                .0
                .lock()
                .expect("mutex")
                .take()
                .context("test stream already opened")?;
            Ok(Box::new(stream))
        }
    }

    #[tokio::test]
    async fn router_uses_the_first_accepting_route_and_reports_missing() -> AnyResult<()> {
        let (client_stream, mut peer_stream) = tokio::io::duplex(2048);
        let peer = tokio::spawn(async move {
            let request = read_cbor_record(&mut peer_stream).await?.expect("request");
            assert_eq!(request.to, None, "destination is routing metadata");
            write_cbor_record(
                &mut peer_stream,
                &response_ok(request.id.expect("id"), json!({"echo": "e7"})),
            )
            .await
        });

        let router = MeshRouter::new();
        router.register(Arc::new(DuplexRoute(Mutex::new(Some(client_stream)))));

        let missing = router
            .forward_record(TaggedRecord {
                component: NameOrTag::Name("telemetry".to_owned()),
                method: NameOrTag::Name("status".to_owned()),
                id: Some(json!(1)),
                to: Some(json!("unknown")),
                ..Default::default()
            })
            .await
            .expect_err("missing route must fail");
        assert!(missing.to_string().contains("no route"));

        let response = router
            .forward_record(TaggedRecord {
                component: NameOrTag::Name("telemetry".to_owned()),
                method: NameOrTag::Name("status".to_owned()),
                id: Some(json!(2)),
                to: Some(json!("e7")),
                ..Default::default()
            })
            .await?;
        assert_eq!(response.result, Some(json!({"echo": "e7"})));
        peer.await.expect("peer task")?;
        Ok(())
    }

    #[tokio::test]
    async fn forwarding_handler_splits_local_and_directed_records() -> AnyResult<()> {
        let (client_stream, mut peer_stream) = tokio::io::duplex(2048);
        let peer = tokio::spawn(async move {
            let request = read_cbor_record(&mut peer_stream).await?.expect("request");
            write_cbor_record(
                &mut peer_stream,
                &response_ok(request.id.expect("id"), json!({"echo": "forwarded"})),
            )
            .await
        });

        let router = MeshRouter::new();
        router.register(Arc::new(DuplexRoute(Mutex::new(Some(client_stream)))));
        let handler = ForwardingHandler::new(EchoHandler, Arc::new(router));

        let local = handler
            .handle_record(TaggedRecord {
                component: NameOrTag::Name("telemetry".to_owned()),
                method: NameOrTag::Name("status".to_owned()),
                id: Some(json!(3)),
                ..Default::default()
            })
            .await?
            .expect("local response");
        assert_eq!(local.result, Some(json!({"echo": "local"})));

        let directed = handler
            .forward_record(TaggedRecord {
                component: NameOrTag::Name("telemetry".to_owned()),
                method: NameOrTag::Name("status".to_owned()),
                id: Some(json!(4)),
                to: Some(json!("e7")),
                ..Default::default()
            })
            .await?
            .expect("forwarded response");
        assert_eq!(directed.result, Some(json!({"echo": "forwarded"})));
        peer.await.expect("peer task")?;
        Ok(())
    }

    #[test]
    fn destination_predicates_accept_only_documented_forms() {
        assert_eq!(
            tcp_destination(&json!("127.0.0.1:18981")),
            Some("127.0.0.1:18981".to_owned())
        );
        assert_eq!(
            tcp_destination(&json!("tcp://[::1]:18981")),
            Some("[::1]:18981".to_owned())
        );
        assert_eq!(tcp_destination(&json!("/run/mesh/mesh.sock")), None);
        assert_eq!(tcp_destination(&json!("host:notaport")), None);
        assert_eq!(tcp_destination(&json!(5)), None);

        assert_eq!(
            uds_destination(&json!("/run/mesh/mesh.sock")),
            Some("/run/mesh/mesh.sock".to_owned())
        );
        assert_eq!(
            uds_destination(&json!("uds:///run/mesh/mesh.sock")),
            Some("/run/mesh/mesh.sock".to_owned())
        );
        assert_eq!(uds_destination(&json!("uds://relative.sock")), None);
        assert_eq!(uds_destination(&json!("e7")), None);
    }
}
