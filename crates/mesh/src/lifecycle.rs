//! Common supervisor lifecycle notifications for mesh services.
//!
//! mesh-init delivers freeze/thaw requests over the service's mesh Unix
//! socket. For the freeze handshake (phase 2c) the reply carries `ready` or
//! `busy`: the service pauses its accept loop, re-checks its counters and
//! either confirms the epoch or cancels the freeze when a request is in
//! flight.

use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::broadcast;
use tokio::time::{Duration, timeout};

/// One memory reclaim trim level, in the spirit of Android onTrimMemory.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrimLevel {
    /// Release caches that are cheap to rebuild.
    Background,
    /// Release larger caches, still inexpensive.
    Ui,
    /// Drop everything reclaimable, e.g. before a code stop.
    Complete,
}

/// Linux supervisor transition delivered to a managed mesh service.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleAction {
    Freeze,
    Unfreeze,
    /// Ask the application to prepare for an upcoming freeze of the given
    /// epoch; the reply must be `ready` or `busy`.
    PrepareFreeze {
        epoch: u64,
    },
    /// Ask the application to drop caches it can rebuild.
    Trim {
        level: TrimLevel,
    },
    /// Tell the application the supervisor is shutting it down cleanly.
    Stop,
}

/// Why a Linux supervisor reported a lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleCause {
    Requested,
    External,
    /// Idle policy drove the transition.
    Idle,
    /// Pressure policy drove the transition.
    Pressure,
    /// An incoming connection or request woke the service.
    Activity,
}

/// Linux supervisor lifecycle event delivered over the local mesh service API.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct LifecycleEvent {
    pub action: LifecycleAction,
    pub cause: LifecycleCause,
    pub observed: bool,
}

/// A service's answer to `PrepareFreeze`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FreezeRequestReply {
    /// The service paused accepting and confirms the freeze epoch.
    Ready,
    /// The service is active; the freeze is cancelled.
    Busy,
}

/// The parsed result of a lifecycle notification round trip.
#[derive(Debug, Clone, PartialEq)]
pub struct LifecycleReply {
    pub success: bool,
    pub error: Option<String>,
    /// Echoed freeze epoch, when present.
    pub epoch: Option<u64>,
    /// The service's verdict, when it replied to a freeze handshake.
    pub reply: Option<FreezeRequestReply>,
}

fn lifecycle_bus() -> &'static broadcast::Sender<LifecycleEvent> {
    static BUS: OnceLock<broadcast::Sender<LifecycleEvent>> = OnceLock::new();
    BUS.get_or_init(|| broadcast::channel(32).0)
}

/// Subscribe to lifecycle events accepted by this process's mesh service.
pub fn subscribe() -> broadcast::Receiver<LifecycleEvent> {
    lifecycle_bus().subscribe()
}

pub(crate) fn publish(event: LifecycleEvent) -> usize {
    lifecycle_bus().send(event).unwrap_or(0)
}

/// Deliver one correlated lifecycle request to a service's mesh Unix socket
/// and parse the service's reply.
///
/// A missing socket is reported as a delivery failure, not an error, because
/// services without mesh endpoints cannot participate in handshakes.
pub async fn notify(socket_path: &Path, event: &LifecycleEvent) -> Result<LifecycleReply> {
    let response = timeout(Duration::from_millis(500), async {
        let stream = tokio::net::UnixStream::connect(socket_path)
            .await
            .with_context(|| format!("connect {}", socket_path.display()))?;
        let (read, mut write) = stream.into_split();
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "mesh-init-lifecycle",
            "method": "mesh.lifecycle",
            "params": event,
        });
        write.write_all(request.to_string().as_bytes()).await?;
        write.write_all(b"\n").await?;
        write.flush().await?;

        let mut response = String::new();
        BufReader::new(read).read_line(&mut response).await?;
        Result::<_, anyhow::Error>::Ok(response)
    })
    .await
    .context("lifecycle notification timed out")??;
    let value: serde_json::Value = serde_json::from_str(response.trim())?;
    if value.get("id")
        != Some(&serde_json::Value::String(
            "mesh-init-lifecycle".to_string(),
        ))
    {
        anyhow::bail!("service returned an uncorrelated lifecycle response");
    }
    let result = value.get("result");
    if value.get("error").is_some() {
        let error = value
            .get("error")
            .map(|e| {
                if let Some(message) = e.get("message").and_then(|m| m.as_str()) {
                    message.to_string()
                } else {
                    e.to_string()
                }
            })
            .unwrap_or_else(|| "service rejected lifecycle notification".to_string());
        return Ok(LifecycleReply {
            success: false,
            error: Some(error),
            epoch: None,
            reply: None,
        });
    }
    if result.is_none() {
        anyhow::bail!("service lifecycle response has no result");
    }
    let pane = result.cloned().unwrap_or_default();
    let reply = match pane.get("freeze").and_then(|f| f.as_str()) {
        Some("ready") => Some(FreezeRequestReply::Ready),
        Some("busy") => Some(FreezeRequestReply::Busy),
        _ => None,
    };
    Ok(LifecycleReply {
        success: true,
        error: pane
            .get("error")
            .and_then(|e| e.as_str())
            .map(str::to_string),
        epoch: pane
            .get("epoch")
            .and_then(serde_json::Value::as_u64)
            .map(|e| e & (u32::MAX as u64)),
        reply,
    })
}

/// Convenience wrapper used by callers that only need delivery success.
pub async fn notified(socket_path: &Path, event: &LifecycleEvent) -> bool {
    matches!(notify(socket_path, event).await, Ok(reply) if reply.success)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn notify_sends_correlated_json_rpc_to_service_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("mesh.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut line = String::new();
            BufReader::new(read).read_line(&mut line).await.unwrap();
            let request: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
            assert_eq!(request["method"], "mesh.lifecycle");
            assert_eq!(request["params"]["action"], "unfreeze");
            write
                .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":\"mesh-init-lifecycle\",\"result\":{}}\n")
                .await
                .unwrap();
        });

        let reply = notify(
            &socket,
            &LifecycleEvent {
                action: LifecycleAction::Unfreeze,
                cause: LifecycleCause::External,
                observed: false,
            },
        )
        .await
        .unwrap();
        assert!(reply.success);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn prepare_freeze_reads_ready_and_busy_replies() {
        let bodies: &[(&[u8], Option<FreezeRequestReply>)] = &[
            (
                b"{\"jsonrpc\":\"2.0\",\"id\":\"mesh-init-lifecycle\",\"result\":{\"freeze\":\"ready\",\"epoch\":7}}\n",
                Some(FreezeRequestReply::Ready),
            ),
            (
                b"{\"jsonrpc\":\"2.0\",\"id\":\"mesh-init-lifecycle\",\"result\":{\"freeze\":\"busy\",\"epoch\":7}}\n",
                Some(FreezeRequestReply::Busy),
            ),
            (
                b"{\"jsonrpc\":\"2.0\",\"id\":\"mesh-init-lifecycle\",\"result\":{}}\n",
                None,
            ),
        ];
        for (body, expected) in bodies {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("mesh.sock");
            let listener = tokio::net::UnixListener::bind(&socket).unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let (read, mut write) = stream.into_split();
                let mut line = String::new();
                BufReader::new(read).read_line(&mut line).await.unwrap();
                let request: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
                assert_eq!(request["method"], "mesh.lifecycle");
                // Externally-tagged enum serializes data fields under the
                // variant key rather than as a string.
                assert_eq!(request["params"]["action"]["prepare_freeze"]["epoch"], 7);
                write.write_all(*body).await.unwrap();
            });
            let reply = notify(
                &socket,
                &LifecycleEvent {
                    action: LifecycleAction::PrepareFreeze { epoch: 7 },
                    cause: LifecycleCause::Idle,
                    observed: false,
                },
            )
            .await
            .unwrap();
            assert_eq!(reply.reply, *expected);
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn reject_pares_down_to_error_reply() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("mesh.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut line = String::new();
            BufReader::new(read).read_line(&mut line).await.unwrap();
            write
                .write_all(
                    b"{\"jsonrpc\":\"2.0\",\"id\":\"mesh-init-lifecycle\",\"error\":{\"message\":\"busy\"}}\n",
                )
                .await
                .unwrap();
        });
        let reply = notify(
            &socket,
            &LifecycleEvent {
                action: LifecycleAction::Freeze,
                cause: LifecycleCause::Requested,
                observed: false,
            },
        )
        .await
        .unwrap();
        assert!(!reply.success);
        assert_eq!(reply.error.as_deref(), Some("busy"));
        server.await.unwrap();
    }
}
