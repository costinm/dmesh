//! Minimal UDP-only object-store server for transport benchmarks.
//!
//! This deliberately does not start lmesh, NAN, an AP, or the TCP listener.
//! It serves the same real artifacts and DRS2 UDP session as the integrated
//! lmesh server, but leaves the radio/control-plane process untouched.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use dmesh_object_store::{ObjectServer, ServerConfig};
use tokio::net::UdpSocket;

fn value(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_owned()))
        .init();
    let bind = value("DMESH_UDP_SERVER_BIND", "0.0.0.0");
    let port = value("DMESH_UDP_SERVER_PORT", "3336").parse::<u16>()?;
    let udp_mtu = value("DMESH_UDP_MTU", "1200").parse::<usize>()?;
    let hello_delay = value("DMESH_UDP_HELLO_DUPLICATE_DELAY_MS", "20").parse::<u64>()?;
    let send_delay = value("DMESH_UDP_SEND_DELAY_MS", "0").parse::<u64>()?;
    let root = PathBuf::from(value("DMESH_OBJECT_STORE_ROOT", "target/flash"));
    let server = ObjectServer::new(ServerConfig {
        bind: bind.clone(),
        port,
        artifact_root: root.clone(),
        udp_mtu,
        udp_hello_duplicate_delay: Duration::from_millis(hello_delay),
        udp_send_delay: Duration::from_millis(send_delay),
        ..ServerConfig::default()
    });
    let socket = UdpSocket::bind((&*bind, port)).await?;
    println!("dmesh UDP object server bind={bind}:{port} root={}", root.display());
    server.run_udp(socket).await
}
