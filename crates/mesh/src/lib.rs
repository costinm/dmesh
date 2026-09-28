/// Generated API data types from the normative mesh API.md catalog.
#[doc(hidden)]
pub mod api;
pub mod auth;
pub mod catalog;
pub mod cbor;
/// Transport-neutral outgoing mesh stream client contract.
pub mod client;
pub mod config;
/// Generated numeric IDs from the normative mesh API.md catalog.
pub mod generated_api_ids;
pub mod jobs;
pub mod jsonl;
pub mod lifecycle;
pub mod local_trace;
pub mod logfmt;
pub mod message;
pub mod mux;
pub mod mux_client;
pub mod paths;
pub mod protocol;
pub mod registry;
pub mod route;
pub mod schema;
pub mod seqpacket;
pub mod server;
pub mod tagged;
pub mod tun;
pub mod wire;

pub use client::{MeshClient, MeshStream, MeshTarget};

use std::sync::Arc;

/// A handler trait or structure for incoming lines-based protocol.
/// Typically implemented by the user of the library.
#[async_trait::async_trait]
pub trait LineHandler: Send + Sync + 'static {
    async fn handle_line(&self, line: &str) -> Result<Option<String>, anyhow::Error>;
}

/// A handler for the shared mesh text-record protocol.
#[async_trait::async_trait]
pub trait TextRecordHandler: Send + Sync + 'static {
    async fn handle_text_record(
        &self,
        record: message::TextRecord,
    ) -> Result<Option<message::TextRecord>, anyhow::Error>;
}

/// Parse newline-delimited lines from stdin/stdout.
pub async fn run_stdin_loop<H: LineHandler>(handler: Arc<H>) -> Result<(), anyhow::Error> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = tokio::io::BufReader::new(stdin);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;
        if bytes_read == 0 {
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(response) = handler.handle_line(trimmed).await? {
            stdout.write_all(response.as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}

/// Parse shared text protocol records from stdin/stdout.
pub async fn run_text_stdin_loop<H: TextRecordHandler>(
    handler: Arc<H>,
) -> Result<(), anyhow::Error> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = tokio::io::BufReader::new(stdin);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;
        if bytes_read == 0 {
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let record = message::TextRecord::parse(trimmed)?;
        if let Some(response) = handler.handle_text_record(record).await? {
            stdout.write_all(response.format().as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}

/// Trait for handling an incoming generic stream (e.g. from a WebSocket).
#[async_trait::async_trait]
pub trait StreamHandler: Send + Sync + 'static {
    /// Handle the bridged stream.
    /// `dest` is the path/destination from the request.
    /// `headers` are key-value pairs from HTTP request headers.
    async fn handle(
        &self,
        dest: &str,
        headers: &std::collections::HashMap<String, String>,
        stream: tokio::io::DuplexStream,
    );
}

/// Trait to define the route for a handler.
pub trait Routable {
    fn route(&self) -> &str;
}

/// Generic config provider trait. Implementations load config
/// objects by kind (category/subdirectory) and name (identifier/filename).
#[async_trait::async_trait]
pub trait ConfigProvider: Send + Sync {
    /// Load a config value as a JSON Value by kind and name.
    /// Returns None if the config does not exist.
    async fn get(&self, kind: &str, name: &str) -> Option<serde_json::Value>;
}
