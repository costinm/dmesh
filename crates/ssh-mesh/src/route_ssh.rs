//! SSH route for the shared directed-record router.
//!
//! This adapts [`mesh::client::MeshClient`] to [`SshClientManager`]: a
//! directed record with an `ssh://` destination opens a direct-tcpip or
//! streamlocal channel over the SSH connection, and the remote node bridges
//! it to its local service. The common CBOR session loop then runs on the
//! remote peer exactly as over TCP or UDS.
//!
//! Destination forms accepted by [`ssh_destination`]:
//!
//! - `ssh://node:port` — direct-tcpip to `127.0.0.1:port` on the node.
//! - `ssh://node/host:port` — direct-tcpip to an explicit remote host.
//! - `ssh://node//absolute/path` — streamlocal to a remote Unix socket.
//!
//! `node` is resolved by reusing an existing manager connection with that
//! host, or by connecting through SSH config (`connect(node, 0, .., ..)`),
//! which also selects the SSH port, user, and discovery keys.

use std::sync::Arc;

use anyhow::{Context, Result};
use serde_json::Value;

use mesh::client::{MeshClient, MeshStream};
use mesh::route::Route;

use crate::sshc::SshClientManager;

/// One parsed SSH destination: the node to connect through and the remote
/// service to reach from there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshEndpoint {
    pub node: String,
    pub service: SshService,
}

/// The remote service a directed stream is bridged to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshService {
    /// A remote TCP endpoint reached through direct-tcpip.
    Tcp { host: String, port: u16 },
    /// A remote Unix socket reached through direct-streamlocal.
    Uds { path: String },
}

/// Parse an `ssh://` destination value. Returns `None` for other forms so
/// other routes can claim them.
pub fn ssh_destination(to: &Value) -> Option<SshEndpoint> {
    let raw = to.as_str()?.trim();
    let rest = raw.strip_prefix("ssh://")?;
    if rest.is_empty() {
        return None;
    }

    let (mut node, service) = match rest.split_once('/') {
        Some((node, service)) => (node, Some(service)),
        None => (rest, None),
    };

    let service = match service {
        // `ssh://node//abs/path`: remote Unix socket.
        Some(path) if path.starts_with('/') => SshService::Uds {
            path: path.to_owned(),
        },
        // `ssh://node/host:port`: explicit remote TCP target.
        Some(target) => {
            let (host, port) = target.rsplit_once(':')?;
            let port: u16 = port.parse().ok()?;
            SshService::Tcp {
                host: host.to_owned(),
                port,
            }
        }
        // `ssh://node:port`: remote loopback TCP target.
        None => {
            let (node_part, port) = node.rsplit_once(':')?;
            let port: u16 = port.parse().ok()?;
            node = node_part;
            SshService::Tcp {
                host: "127.0.0.1".to_owned(),
                port,
            }
        }
    };

    let node = node.trim();
    if node.is_empty() {
        return None;
    }
    Some(SshEndpoint {
        node: node.to_owned(),
        service,
    })
}

/// Route `ssh://` destinations through [`SshClientManager`].
pub struct SshRoute {
    manager: Arc<SshClientManager>,
}

impl SshRoute {
    pub fn new(manager: Arc<SshClientManager>) -> Self {
        Self { manager }
    }
}

impl Route for SshRoute {
    fn accepts(&self, to: &Value) -> bool {
        ssh_destination(to).is_some()
    }

    fn client(&self) -> Arc<dyn MeshClient> {
        Arc::new(SshClient {
            manager: self.manager.clone(),
        })
    }
}

/// [`MeshClient`] over SSH channels.
pub struct SshClient {
    manager: Arc<SshClientManager>,
}

impl SshClient {
    /// Reuse an existing connection to the node or open one through SSH
    /// config resolution.
    async fn resolve_connection(&self, node: &str) -> Result<u64> {
        for info in self.manager.list_connections().await {
            if info.host == node {
                return Ok(info.id);
            }
        }
        // Port 0 and empty user/server key defer to SSH config and the
        // manager's discovery directory.
        self.manager
            .connect(node, 0, "", "")
            .await
            .with_context(|| {
                format!("connect SSH node {node}; configure it in SSH config or connect first")
            })
    }
}

#[async_trait::async_trait]
impl MeshClient for SshClient {
    async fn open_stream(&self, target: &mesh_api::MeshTarget) -> Result<Box<dyn MeshStream>> {
        let destination = target.path.clone().unwrap_or_else(|| target.node.clone());
        let endpoint = ssh_destination_checked(&Value::String(destination))?;
        let id = self.resolve_connection(&endpoint.node).await?;
        match endpoint.service {
            SshService::Tcp { host, port } => {
                let stream = self.manager.open_stream(id, &host, port).await?;
                Ok(Box::new(stream))
            }
            SshService::Uds { path } => {
                let stream = self.manager.open_streamlocal(id, &path).await?;
                Ok(Box::new(stream))
            }
        }
    }
}

/// Parse with a caller-facing error instead of `None`, for routes that must
/// explain why a destination was rejected.
pub fn ssh_destination_checked(to: &Value) -> Result<SshEndpoint> {
    ssh_destination(to).ok_or_else(|| {
        anyhow::anyhow!(
            "invalid ssh:// destination {to}; expected ssh://node:port, \
             ssh://node/host:port, or ssh://node//absolute/path"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_destination_parses_documented_forms() {
        let parsed = ssh_destination(&Value::String("ssh://e7:18981".into())).expect("loopback");
        assert_eq!(parsed.node, "e7");
        assert_eq!(
            parsed.service,
            SshService::Tcp {
                host: "127.0.0.1".into(),
                port: 18981
            }
        );

        let parsed =
            ssh_destination(&Value::String("ssh://e7/10.0.0.1:18981".into())).expect("explicit");
        assert_eq!(
            parsed.service,
            SshService::Tcp {
                host: "10.0.0.1".into(),
                port: 18981
            }
        );

        let parsed = ssh_destination(&Value::String("ssh://e7//run/mesh/x.sock".into()))
            .expect("streamlocal");
        assert_eq!(
            parsed.service,
            SshService::Uds {
                path: "/run/mesh/x.sock".into()
            }
        );

        // Non-SSH and ambiguous forms belong to other routes or fail.
        assert!(ssh_destination(&Value::String("e7".into())).is_none());
        assert!(ssh_destination(&Value::String("ssh://e7".into())).is_none());
        assert!(ssh_destination(&Value::String("ssh://:18981".into())).is_none());
        assert!(ssh_destination(&Value::String("ssh://e7:notaport".into())).is_none());
        assert!(ssh_destination(&Value::String("tcp://e7:18981".into())).is_none());
        assert!(ssh_destination(&Value::from(5)).is_none());
    }
}
