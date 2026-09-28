//! End-to-end SSH route test: a directed tagged-CBOR record forwarded over a
//! real in-process SSH server reaches a remote CBOR echo service through a
//! direct-tcpip channel.

use std::sync::Arc;

use anyhow::{Context, Result};
use serde_json::{Value, json};

use mesh::route::{MeshRouter, Route};
use mesh::tagged::NameOrTag;
use mesh::wire::{TaggedRecordHandler, response_ok, serve_cbor_session};
use ssh_mesh::route_ssh::{SshRoute, ssh_destination};
use ssh_mesh::sshc::SshClientManager;
use ssh_mesh::test_utils::{find_free_port, setup_test_environment};

struct EchoHandler;

#[async_trait::async_trait]
impl TaggedRecordHandler for EchoHandler {
    async fn handle_record(
        &self,
        record: mesh::tagged::TaggedRecord,
    ) -> Result<Option<mesh::tagged::TaggedRecord>> {
        let id = record.id.clone().context("echo request missing id")?;
        Ok(Some(response_ok(id, json!({"echo": "ssh-remote"}))))
    }
}

fn manager_from_setup(setup: &ssh_mesh::test_utils::TestSetup) -> Arc<SshClientManager> {
    let key = ssh_mesh::auth::load_or_generate_key(&setup.base_dir);
    Arc::new(SshClientManager::new(key, Vec::new(), None, None))
}

#[tokio::test]
async fn ssh_route_forwards_record_over_direct_tcpip() -> Result<()> {
    let setup = setup_test_environment(None, false).await?;
    let ssh_port = setup.ssh_port;
    let manager = manager_from_setup(&setup);

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Remote CBOR echo service reachable from the SSH server host.
    let service_port = find_free_port()?;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", service_port)).await?;
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let _ = serve_cbor_session(&mut stream, &EchoHandler).await;
            });
        }
    });

    // Pre-connect: node "127.0.0.1" resolves by host match; the route must
    // reuse this connection instead of dialing config-resolved port 0.
    let id = manager
        .connect("127.0.0.1", ssh_port, "testuser", "")
        .await?;
    assert!(id > 0);

    let destination = format!("ssh://127.0.0.1:{service_port}");
    let endpoint = ssh_destination(&Value::String(destination.clone())).expect("ssh endpoint");
    assert_eq!(endpoint.node, "127.0.0.1");

    let router = MeshRouter::new();
    router.register(Arc::new(SshRoute::new(manager)));

    let response = router
        .forward_record(mesh::tagged::TaggedRecord {
            component: NameOrTag::Name("telemetry".to_owned()),
            method: NameOrTag::Name("status".to_owned()),
            id: Some(json!(21)),
            to: Some(Value::String(destination)),
            ..Default::default()
        })
        .await?;

    assert_eq!(response.id, Some(json!(21)));
    assert_eq!(response.result, Some(json!({"echo": "ssh-remote"})));
    Ok(())
}
