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

/// Canonical adapter for the fixed-capacity tagged component registry.
/// Unknown or malformed records fail the stream without falling back to any
/// packet-level or connectionless dispatcher.
#[derive(Clone, Copy, Debug, Default)]
pub struct RegisteredTaggedHandler;

impl RecordHandler for RegisteredTaggedHandler {
    fn handle<'a>(
        &'a self,
        request: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + 'a>> {
        Box::pin(async move {
            crate::services::dispatch_tagged_stream(&request).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "no tagged component accepted the request",
                )
            })
        })
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

    fn registered_handler(record: crate::tagged::Record<'_>) -> Option<Vec<u8>> {
        (record.component == Some(crate::tagged::Name::Tag(0x7ffe))).then(|| b"registered".to_vec())
    }

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
    async fn registered_tagged_handler_is_reached_through_the_stream() {
        assert!(crate::services::register_tagged_component(
            0x7ffe,
            registered_handler
        ));
        let (mut client, mut server) = tokio::io::duplex(128);
        let handler = RecordStreamHandler::new(RegisteredTaggedHandler, 64);
        let server_task = async { handler.accept(&mut server).await.unwrap() };
        let client_task = async {
            let request = [0xa3, 1, 0x19, 0x7f, 0xfe, 2, 1, 3, 1];
            client.write_all(&request).await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            response
        };
        let (_, response) = tokio::join!(server_task, client_task);
        assert_eq!(response, b"registered");
    }
}
