//! Fixed-port DMSU UDP status responder used to test both directions without
//! involving the object-store scheduler, TCP, lmesh, or NAN.

use anyhow::Result;
use std::time::Instant;
use tokio::net::UdpSocket;

const MAGIC: &[u8; 4] = b"DMSU";
const VERSION: u8 = 1;
const REQUEST: u8 = 1;
const RESPONSE: u8 = 2;

fn value(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

#[tokio::main]
async fn main() -> Result<()> {
    let bind = value("DMESH_UDP_STATUS_BIND", "0.0.0.0");
    let port = value("DMESH_UDP_STATUS_PORT", "3338").parse::<u16>()?;
    let socket = UdpSocket::bind((&*bind, port)).await?;
    let started = Instant::now();
    println!("dmesh UDP status server bind={bind}:{port}");
    let mut request = [0u8; 128];
    let mut responses = 0u64;
    loop {
        let (received, peer) = socket.recv_from(&mut request).await?;
        if received != 14
            || request[..4] != *MAGIC
            || request[4] != VERSION
            || request[5] != REQUEST
        {
            eprintln!("udp-status invalid request peer={peer} bytes={received}");
            continue;
        }
        let nonce = &request[6..14];
        let uptime_ms = started.elapsed().as_millis() as u64;
        let mut response = [0u8; 26];
        response[..4].copy_from_slice(MAGIC);
        response[4] = VERSION;
        response[5] = RESPONSE;
        response[6..14].copy_from_slice(nonce);
        response[14..22].copy_from_slice(&uptime_ms.to_be_bytes());
        response[22..26].copy_from_slice(&[0, 0, 0, 0]);
        let sent = socket.send_to(&response, peer).await?;
        responses += 1;
        println!("udp-status request peer={peer} bytes={received} response_bytes={sent} responses={responses} uptime_ms={uptime_ms}");
    }
}
