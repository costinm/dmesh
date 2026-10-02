//! Application handlers over accepted QUIC-lite byte streams.
//!
//! This module does not expose connection IDs, packet numbers, stream IDs, or
//! bearer addresses. A host adapter registers a bearer with `QuicNode`, then
//! passes each stream returned by `accept_stream` to a handler here.

use core::{future::Future, pin::Pin};
use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Object-safe asynchronous byte stream accepted by an application handler.
pub trait AcceptedStream: AsyncRead + AsyncWrite + Unpin {}

impl<T> AcceptedStream for T where T: AsyncRead + AsyncWrite + Unpin {}

/// A service owns request framing and application completion, but no QUIC
/// packet or association state.
pub trait StreamHandler: Send + Sync {
    fn accept<'a>(
        &'a self,
        stream: &'a mut dyn AcceptedStream,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + 'a>>;
}

/// Application callback for one complete size-limited request record.
pub trait RecordHandler: Send + Sync {
    fn handle<'a>(
        &'a self,
        request: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + 'a>>;
}

/// Adapts existing request/response handlers to the accepted-stream boundary.
///
/// EOF is the record delimiter. The configured limit is enforced while
/// reading, before invoking application code. A successful response is fully
/// written and the sending half is shut down before completion is reported.
pub struct RecordStreamHandler<H> {
    handler: H,
    max_request_bytes: usize,
}

/// Which registry a [`RegistryStreamHandler`] dispatches into.
#[derive(Clone)]
enum RegistrySource {
    Global,
    Owned(std::sync::Arc<crate::registry::Registry>),
}

/// Serves handler streams (a header, then an optional raw body, FIN after the
/// body) from the registry. This is the one host adapter: it reads until the
/// header is complete, opens the registered handler, streams the request body
/// to the handler's sink and the response body from its source, and ends each
/// direction with FIN. No method is dispatched anywhere else.
#[derive(Clone)]
pub struct RegistryStreamHandler {
    registry: RegistrySource,
    local: bool,
    rewrite: Option<fn(&[u8]) -> Option<Vec<u8>>>,
}

impl RegistryStreamHandler {
    /// Serve the process-wide registry to network callers.
    pub fn global() -> Self {
        Self {
            registry: RegistrySource::Global,
            local: false,
            rewrite: None,
        }
    }

    /// Serve a service-owned registry to network callers.
    pub fn new(registry: std::sync::Arc<crate::registry::Registry>) -> Self {
        Self {
            registry: RegistrySource::Owned(registry),
            local: false,
            rewrite: None,
        }
    }

    /// Mark the callers as local ingress (the device's own control surface).
    pub fn local(mut self) -> Self {
        self.local = true;
        self
    }

    /// Rewrite a complete header before dispatch, for an edge that translates
    /// names to numbers. `None` keeps the header unchanged.
    pub fn with_header_rewrite(mut self, rewrite: fn(&[u8]) -> Option<Vec<u8>>) -> Self {
        self.rewrite = Some(rewrite);
        self
    }

    fn registry(&self) -> &crate::registry::Registry {
        match &self.registry {
            RegistrySource::Global => &crate::registry::REGISTRY,
            RegistrySource::Owned(registry) => registry,
        }
    }
}

async fn write_error<S>(stream: &mut S, message: &[u8]) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    stream
        .write_all(&crate::stream::error_header(None, message))
        .await?;
    stream.shutdown().await
}

/// The request's `timeout` envelope field as a duration.
fn context_timeout(timeout_ms: Option<u64>) -> Option<std::time::Duration> {
    timeout_ms.map(std::time::Duration::from_millis)
}

/// Write a response (header, then body) and end the direction with FIN.
async fn write_response<S>(stream: &mut S, response: crate::stream::Response) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut reader = response.into_reader();
    let mut out = [0u8; 1200];
    loop {
        let (count, done) = reader.read(&mut out);
        if count != 0 {
            stream.write_all(&out[..count]).await?;
        }
        if done {
            break;
        }
        if count == 0 {
            // The body has nothing ready; ask again shortly.
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    }
    stream.shutdown().await
}

impl RegistryStreamHandler {
    /// Serve one stream. The future is `Send` when the stream is, so a runtime
    /// that spawns tasks (Android, lmesh) can run it.
    pub async fn serve<S>(&self, stream: &mut S) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        use crate::stream::{Header, Outcome, Request, scan_header};
            let mut buffer = Vec::with_capacity(512);
            let mut chunk = [0u8; 2048];
            let header_len = loop {
                match scan_header(&buffer) {
                    Header::Complete(length) => break length,
                    Header::Invalid => return write_error(stream, b"invalid request header").await,
                    Header::NeedMore => {
                        let count = stream.read(&mut chunk).await?;
                        if count == 0 {
                            return write_error(stream, b"request ended inside its header").await;
                        }
                        buffer.extend_from_slice(&chunk[..count]);
                    }
                }
            };
            let mut pending = buffer.split_off(header_len);
            let mut header = buffer;
            if let Some(rewritten) = self.rewrite.and_then(|rewrite| rewrite(&header)) {
                header = rewritten;
            }
            let Some(record) = crate::tagged::decode(&header) else {
                return write_error(stream, b"invalid request header").await;
            };
            let context = crate::registry::CallContext {
                local: self.local,
                ..Default::default()
            };
            let request = Request {
                record,
                header: &header,
                context,
            };
            let timeout = context_timeout(request.record.timeout);
            let id = request.record.id;
            let exchange = async {
            match self.registry().open(request).await {
                None => stream.shutdown().await,
                Some(Outcome::Respond(response)) => write_response(stream, response).await,
                Some(Outcome::Defer(mut deferred)) => {
                    let response = loop {
                        if let Some(response) = deferred.poll() {
                            break response;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    };
                    write_response(stream, response).await
                }
                Some(Outcome::Receive(mut sink)) => {
                    let mut ended = false;
                    loop {
                        if !pending.is_empty() || ended {
                            match sink.write(&pending, ended) {
                                Ok(accepted) => {
                                    pending.drain(..accepted);
                                }
                                Err(header) => {
                                    return write_response(
                                        stream,
                                        crate::stream::Response::header(header),
                                    )
                                    .await;
                                }
                            }
                            if pending.is_empty() && ended {
                                break;
                            }
                            if !pending.is_empty() {
                                // The sink is withholding bytes; give it time.
                                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                                continue;
                            }
                        }
                        let count = stream.read(&mut chunk).await?;
                        if count == 0 {
                            ended = true;
                        } else {
                            pending.extend_from_slice(&chunk[..count]);
                        }
                    }
                    write_response(stream, sink.finish()).await
                }
            }
            };
            match timeout {
                None => exchange.await,
                Some(limit) => match tokio::time::timeout(limit, exchange).await {
                    Ok(result) => result,
                    // The caller's time ran out: abandon the handler (dropping
                    // it releases a deferred job or sink) and say so.
                    Err(_) => {
                        stream
                            .write_all(&crate::stream::error_header(id, b"timeout"))
                            .await?;
                        stream.shutdown().await
                    }
                },
            }
    }
}

impl StreamHandler for RegistryStreamHandler {
    fn accept<'a>(
        &'a self,
        stream: &'a mut dyn AcceptedStream,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + 'a>> {
        Box::pin(self.serve(stream))
    }
}

impl<H> RecordStreamHandler<H> {
    pub const fn new(handler: H, max_request_bytes: usize) -> Self {
        Self {
            handler,
            max_request_bytes,
        }
    }

    pub const fn max_request_bytes(&self) -> usize {
        self.max_request_bytes
    }
}

impl<H: RecordHandler> StreamHandler for RecordStreamHandler<H> {
    fn accept<'a>(
        &'a self,
        stream: &'a mut dyn AcceptedStream,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + 'a>> {
        Box::pin(async move {
            let read_limit = self.max_request_bytes.saturating_add(1);
            let mut request = Vec::with_capacity(self.max_request_bytes.min(4096));
            stream
                .take(read_limit as u64)
                .read_to_end(&mut request)
                .await?;
            if request.len() > self.max_request_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "request record exceeds configured size limit",
                ));
            }
            let response = self.handler.handle(request).await?;
            stream.write_all(&response).await?;
            stream.shutdown().await
        })
    }
}

/// Accept and dispatch one stream from a Tokio-backed quic-lite node.
pub async fn accept_one(
    node: &quic_lite::tokio::TokioNode,
    handler: &dyn StreamHandler,
) -> io::Result<()> {
    let mut stream = node
        .accept_stream()
        .await
        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "QUIC node driver stopped"))?;
    handler.accept(&mut stream).await
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Echo;

    impl RecordHandler for Echo {
        fn handle<'a>(
            &'a self,
            mut request: Vec<u8>,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + 'a>> {
            Box::pin(async move {
                request.make_ascii_uppercase();
                Ok(request)
            })
        }
    }

    #[tokio::test]
    async fn handler_accepts_a_stream_and_completes_its_response() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let handler = RecordStreamHandler::new(Echo, 16);
        let server_task = async {
            handler.accept(&mut server).await.unwrap();
        };
        let client_task = async {
            client.write_all(b"status").await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            response
        };
        let (_, response) = tokio::join!(server_task, client_task);
        assert_eq!(response, b"STATUS");
    }

    #[tokio::test]
    async fn record_limit_is_enforced_before_dispatch() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let handler = RecordStreamHandler::new(Echo, 4);
        let server_task = async { handler.accept(&mut server).await };
        let client_task = async {
            client.write_all(b"oversize").await.unwrap();
            client.shutdown().await.unwrap();
        };
        let (result, ()) = tokio::join!(server_task, client_task);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn registered_handlers_are_served_with_a_header_and_a_raw_body() {
        use crate::registry::{Method, Registry, SyncFn};
        use crate::stream::{BodySink, OpenFuture, Outcome, Request, Response};

        fn short(record: crate::tagged::Record<'_>) -> Option<Vec<u8>> {
            let mut out = [0u8; 32];
            let used =
                crate::tagged::encode_numeric_response(0x7ffd, 1, record.id?, &[0xa0], &mut out)?;
            Some(out[..used].to_vec())
        }

        struct Total(u64, u64);
        impl BodySink for Total {
            fn write(&mut self, chunk: &[u8], _fin: bool) -> Result<usize, Vec<u8>> {
                self.1 += chunk.len() as u64;
                Ok(chunk.len())
            }
            fn finish(self: Box<Self>) -> Response {
                let mut out = [0u8; 48];
                let used = crate::tagged::encode_numeric_response(
                    0x7ffd,
                    2,
                    self.0,
                    &[0xa1, 1, 0x19, (self.1 >> 8) as u8, self.1 as u8],
                    &mut out,
                )
                .unwrap();
                Response::header(out[..used].to_vec())
            }
        }
        struct Upload;
        impl crate::stream::StreamHandler for Upload {
            fn open<'a>(&'a self, request: Request<'a>) -> OpenFuture<'a> {
                let id = request.record.id.unwrap_or(0);
                Box::pin(async move { Some(Outcome::Receive(Box::new(Total(id, 0)))) })
            }
        }

        let registry = std::sync::Arc::new(Registry::new());
        assert!(registry.register(Method::new(0x7ffd, "t", 1, "short"), SyncFn(short)));
        assert!(registry.register_stream(Method::new(0x7ffd, "t", 2, "upload"), Upload));
        let handler = RegistryStreamHandler::new(registry);

        for (method, body, expect_len) in [(1u64, 0usize, None), (2, 3000, Some(3000u64))] {
            let (mut client, mut server) = tokio::io::duplex(512);
            let server_task = async { handler.accept(&mut server).await.unwrap() };
            let client_task = async {
                let mut header = [0u8; 32];
                let used =
                    crate::tagged::encode_numeric_empty_request(0x7ffd, method, 77, &mut header)
                        .unwrap();
                client.write_all(&header[..used]).await.unwrap();
                // The body is raw bytes that are not CBOR.
                client.write_all(&vec![0xffu8; body]).await.unwrap();
                client.shutdown().await.unwrap();
                let mut response = Vec::new();
                client.read_to_end(&mut response).await.unwrap();
                response
            };
            let (_, response) = tokio::join!(server_task, client_task);
            let record = crate::tagged::decode(&response).unwrap();
            assert_eq!(record.id, Some(if method == 1 { 77 } else { 77 }));
            if let Some(expected) = expect_len {
                let mut result = crate::cbor::Decoder::new(record.result.unwrap());
                assert_eq!(result.head(), Some((5, 1)));
                assert_eq!(result.uint(), Some(1));
                assert_eq!(result.uint(), Some(expected));
            }
        }
    }

    #[tokio::test]
    async fn the_request_timeout_abandons_a_handler_that_never_answers() {
        use crate::registry::{Method, Registry};
        use crate::stream::{Deferred, OpenFuture, Outcome, Request, Response};

        struct Never;
        impl Deferred for Never {
            fn poll(&mut self) -> Option<Response> {
                None
            }
        }
        struct Slow;
        impl crate::stream::StreamHandler for Slow {
            fn open<'a>(&'a self, request: Request<'a>) -> OpenFuture<'a> {
                // The handler sees the caller's allowance.
                assert_eq!(request.context.timeout_ms, Some(50));
                Box::pin(async { Some(Outcome::Defer(Box::new(Never))) })
            }
        }
        let registry = std::sync::Arc::new(Registry::new());
        assert!(registry.register_stream(Method::new(0x7ffd, "t", 3, "slow"), Slow));
        let handler = RegistryStreamHandler::new(registry);
        let (mut client, mut server) = tokio::io::duplex(256);
        let server_task = async { handler.accept(&mut server).await.unwrap() };
        let client_task = async {
            let mut header = [0u8; 32];
            let mut encoder = crate::cbor::Encoder::new(&mut header);
            encoder.map(5).unwrap();
            for (key, value) in [(1, 0x7ffd), (2, 3), (3, 9)] {
                encoder.uint(key).unwrap();
                encoder.uint(value).unwrap();
            }
            encoder.uint(5).unwrap();
            encoder.map(0).unwrap();
            // Envelope key 8: the allowance, in milliseconds.
            encoder.uint(8).unwrap();
            encoder.uint(50).unwrap();
            let used = encoder.len();
            client.write_all(&header[..used]).await.unwrap();
            client.shutdown().await.unwrap();
            let started = std::time::Instant::now();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            (response, started.elapsed())
        };
        let (_, (response, elapsed)) = tokio::join!(server_task, client_task);
        // A response has no method, so read its envelope keys directly.
        let mut decoder = crate::cbor::Decoder::new(&response);
        let (_, count) = decoder.head().expect("map");
        let (mut id, mut error) = (None, false);
        for _ in 0..count {
            match decoder.uint().unwrap() {
                3 => id = decoder.uint(),
                7 => {
                    error = true;
                    decoder.skip().unwrap();
                }
                _ => decoder.skip().unwrap(),
            }
        }
        assert_eq!(id, Some(9));
        assert!(error);
        assert!(elapsed >= std::time::Duration::from_millis(50), "{elapsed:?}");
        assert!(elapsed < std::time::Duration::from_secs(2), "{elapsed:?}");
    }

    #[tokio::test]
    async fn a_request_that_is_not_a_header_gets_an_error_header() {
        let handler = RegistryStreamHandler::new(std::sync::Arc::new(crate::registry::Registry::new()));
        let (mut client, mut server) = tokio::io::duplex(64);
        let server_task = async { handler.accept(&mut server).await.unwrap() };
        let client_task = async {
            client.write_all(&[0xff, 0xff]).await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            response
        };
        let (_, response) = tokio::join!(server_task, client_task);
        assert!(!response.is_empty());
    }
}
