//! Two-process synthetic dmesh-transport benchmark over real UDP.
//!
//! This intentionally has no object-store, file, manifest, or DRS2 logic.
//! The small HELLO/DONE records only delimit the benchmark; stream packets,
//! ACKs, flow credit, and congestion state come from dmesh-transport.

use anyhow::{anyhow, Result, bail};
use dmesh_transport::{
    AckRangeSet, ConnectionId, ConnectionLimits, EndpointState, Frame, Role,
    ShortHeader, INITIAL_MAX_DATA, INITIAL_MAX_STREAM_DATA,
    decode_frame,
};
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tokio::net::{UdpSocket, UnixDatagram};
use tokio::time::{Duration, timeout};

const MAGIC: &[u8; 5] = b"DMTB1";
const DONE: &[u8; 5] = b"DONE!";
const MTU: usize = 1200;
const CHUNK: usize = MTU - 32;

struct Flight {
    packet_number: u32,
    wire: Vec<u8>,
    acked: bool,
    lost: bool,
}

enum BenchSocket {
    Udp(UdpSocket),
    Unix(UnixDatagram),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Peer {
    Udp(SocketAddr),
    Unix(PathBuf),
}

impl BenchSocket {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Peer)> {
        match self {
            Self::Udp(socket) => socket.recv_from(buf).await.map(|(n, peer)| (n, Peer::Udp(peer))),
            Self::Unix(socket) => {
                let (n, peer) = socket.recv_from(buf).await?;
                let path = peer.as_pathname().ok_or_else(|| io::Error::other("unnamed unix peer"))?;
                Ok((n, Peer::Unix(path.to_owned())))
            }
        }
    }

    async fn send_to(&self, buf: &[u8], peer: &Peer) -> io::Result<usize> {
        match (self, peer) {
            (Self::Udp(socket), Peer::Udp(peer)) => socket.send_to(buf, peer).await,
            (Self::Unix(socket), Peer::Unix(peer)) => socket.send_to(buf, peer).await,
            _ => Err(io::Error::other("incompatible benchmark peer")),
        }
    }

    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Udp(socket) => socket.send(buf).await,
            Self::Unix(socket) => socket.send(buf).await,
        }
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Udp(socket) => socket.recv(buf).await,
            Self::Unix(socket) => socket.recv(buf).await,
        }
    }
}

fn bytes_arg() -> u64 {
    std::env::var("DMESH_STREAM_BYTES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(64 * 1024 * 1024)
}

fn window_arg() -> usize {
    std::env::var("DMESH_UDP_BENCH_WINDOW")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(32)
        .max(1)
}

fn drop_arg() -> Option<u32> {
    std::env::var("DMESH_UDP_BENCH_DROP_PACKET")
        .ok()
        .and_then(|value| value.parse().ok())
}

fn hello(total: u64) -> [u8; 13] {
    let mut out = [0u8; 13];
    out[..5].copy_from_slice(MAGIC);
    out[5..13].copy_from_slice(&total.to_be_bytes());
    out
}

fn parse_hello(packet: &[u8]) -> Option<u64> {
    if packet.len() != 13 || &packet[..5] != MAGIC { return None; }
    Some(u64::from_be_bytes(packet[5..13].try_into().ok()?))
}

fn packet_ack(header: ShortHeader, stream_end: u64, connection_end: u64, out: &mut [u8]) -> Result<usize> {
    let mut p = header.encode(out).map_err(|e| anyhow!("encode header: {e:?}"))?;
    p += Frame::Ack { largest: header.packet_number, delay: 0 }.encode(&mut out[p..])
        .map_err(|e| anyhow!("encode ack: {e:?}"))?;
    p += Frame::MaxData(connection_end.saturating_add(INITIAL_MAX_DATA)).encode(&mut out[p..])
        .map_err(|e| anyhow!("encode max data: {e:?}"))?;
    p += Frame::MaxStreamData { id: 3, max: stream_end.saturating_add(INITIAL_MAX_STREAM_DATA) }
        .encode(&mut out[p..]).map_err(|e| anyhow!("encode max stream data: {e:?}"))?;
    Ok(p)
}

async fn run_server(socket: BenchSocket, ready: &str, cleanup: Option<&Path>) -> Result<()> {
    let total = bytes_arg();
    let window = window_arg();
    println!("{ready}");
    let mut input = [0u8; MTU];
    let (n, peer) = socket.recv_from(&mut input).await?;
    if parse_hello(&input[..n]) != Some(total) {
        bail!("invalid benchmark HELLO or total mismatch");
    }

    let dcid = ConnectionId::new(1).unwrap();
    let mut endpoint = EndpointState::<2>::new(Role::Server, ConnectionLimits::default(), MTU as u64);
    endpoint.open_send_stream(3, INITIAL_MAX_STREAM_DATA)
        .map_err(|e| anyhow!("open stream: {e:?}"))?;
    let mut flights = VecDeque::<Flight>::new();
    let mut next_offset = 0u64;
    let mut packets = 0u64;
    let mut retransmits = 0u64;
    let started = Instant::now();

    loop {
        while next_offset < total && flights.len() < window && endpoint.congestion.can_send(MTU as u64) {
            let len = (total - next_offset).min(CHUNK as u64) as usize;
            let data = vec![0xa5u8; len];
            let mut wire = vec![0u8; MTU];
            let (used, packet_number) = endpoint.encode_stream_packet(
                dcid, 3, next_offset, next_offset + len as u64 == total, &data, &mut wire,
            ).map_err(|e| anyhow!("encode stream packet: {e:?}"))?;
            wire.truncate(used);
            socket.send_to(&wire, &peer).await?;
            flights.push_back(Flight { packet_number, wire, acked: false, lost: false });
            next_offset += len as u64;
            packets += 1;
        }

        if next_offset == total && flights.is_empty() {
            socket.send_to(DONE, &peer).await?;
            println!("server bytes={} packets={} retransmits={} elapsed_ms={} bitrate_kbps={} window={}",
                total, packets, retransmits, started.elapsed().as_millis().max(1),
                (total as u128 * 8_000 / started.elapsed().as_millis().max(1)) as u64 / 1000, window);
            if let Some(path) = cleanup { let _ = std::fs::remove_file(path); }
            return Ok(());
        }

        match timeout(Duration::from_millis(100), socket.recv_from(&mut input)).await {
            Ok(Ok((n, from))) if from == peer && &input[..n] == DONE => return Ok(()),
            Ok(Ok((n, from))) if from == peer => {
                let (_header, header_len) = ShortHeader::decode(&input[..n])
                    .map_err(|e| anyhow!("decode header: {e:?}"))?;
                let mut ack = None;
                let mut max_data = None;
                let mut max_stream = None;
                let mut p = header_len;
                while p < n {
                    let (frame, used) = decode_frame(&input[p..n])
                        .map_err(|e| anyhow!("decode frame: {e:?}"))?;
                    p += used;
                    match frame {
                        Frame::Ack { largest, .. } => {
                            let mut ranges = AckRangeSet::new(); ranges.insert(largest); ack = Some(ranges);
                        }
                        Frame::AckRanges { ranges, .. } => ack = Some(ranges),
                        Frame::MaxData(value) => max_data = Some(value),
                        Frame::MaxStreamData { id, max } if id == 3 => max_stream = Some(max),
                        _ => {}
                    }
                }
                if let Some(value) = max_data { endpoint.send.extend_connection(value); }
                if let Some(value) = max_stream {
                    endpoint.send.extend_stream(3, value)
                        .map_err(|e| anyhow!("extend stream: {e:?}"))?;
                }
                if let Some(ranges) = ack {
                    for flight in flights.iter_mut().filter(|flight| !flight.acked) {
                        if ranges.contains(flight.packet_number) {
                            flight.acked = true;
                            endpoint.acked(flight.wire.len() as u64);
                        }
                    }
                    while flights.front().is_some_and(|flight| flight.acked) { flights.pop_front(); }

                    if flights.iter().any(|flight| flight.acked) {
                        let mut lost_bytes = 0u64;
                        for flight in flights.iter_mut().filter(|flight| !flight.acked && !flight.lost) {
                            socket.send_to(&flight.wire, &peer).await?;
                            flight.lost = true;
                            lost_bytes += flight.wire.len() as u64;
                            retransmits += 1;
                            // Only the missing prefix is retransmitted.
                            break;
                        }
                        if lost_bytes != 0 { endpoint.lost(lost_bytes); }
                    }
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => {
                let mut lost_bytes = 0u64;
                for flight in flights.iter_mut().filter(|flight| !flight.acked) {
                    socket.send_to(&flight.wire, &peer).await?;
                    if !flight.lost { flight.lost = true; lost_bytes += flight.wire.len() as u64; }
                    retransmits += 1;
                }
                if lost_bytes != 0 { endpoint.lost(lost_bytes); }
            }
        }
    }
}

async fn run_client(socket: BenchSocket, cleanup: Option<&Path>) -> Result<()> {
    let total = bytes_arg();
    let drop_packet = drop_arg();
    socket.send(&hello(total)).await?;
    let mut endpoint = EndpointState::<2>::new(Role::Client, ConnectionLimits::default(), MTU as u64);
    let mut segments = BTreeMap::<u64, usize>::new();
    let mut contiguous = 0u64;
    let mut packets = 0u64;
    let mut duplicates = 0u64;
    let mut dropped = false;
    let started = Instant::now();
    let mut input = [0u8; MTU];
    loop {
        let n = timeout(Duration::from_secs(30), socket.recv(&mut input)).await??;
        if &input[..n] == DONE {
            if contiguous != total { bail!("server completed before client received all bytes"); }
            socket.send(DONE).await?;
            println!("client bytes={} packets={} duplicates={} dropped_ack={} elapsed_ms={} bitrate_kbps={} chunk_bytes={}",
                total, packets, duplicates, dropped, started.elapsed().as_millis().max(1),
                (total as u128 * 8_000 / started.elapsed().as_millis().max(1)) as u64 / 1000, CHUNK);
            if let Some(path) = cleanup { let _ = std::fs::remove_file(path); }
            return Ok(());
        }
        let (header, header_len) = ShortHeader::decode(&input[..n])
            .map_err(|e| anyhow!("decode header: {e:?}"))?;
        let (Frame::Stream(stream), _) = decode_frame(&input[header_len..n])
            .map_err(|e| anyhow!("decode frame: {e:?}"))? else { continue; };
        packets += 1;
        endpoint.receive.accept(stream.id, stream.offset, stream.data.len(), stream.fin)
            .map_err(|e| anyhow!("accept stream data: {e:?}"))?;
        endpoint.observe_packet(header.packet_number);
        if stream.offset < contiguous { duplicates += 1; }
        segments.entry(stream.offset).or_insert(stream.data.len());
        while let Some(len) = segments.remove(&contiguous) {
            contiguous += len as u64;
            endpoint.receive.consume(stream.id, len as u64)
                .map_err(|e| anyhow!("consume stream data: {e:?}"))?;
        }
        endpoint.receive.extend_connection_credit(INITIAL_MAX_DATA);
        endpoint.receive.extend_stream_credit(stream.id, INITIAL_MAX_STREAM_DATA)
            .map_err(|e| anyhow!("extend receive stream: {e:?}"))?;
        let mut ack = [0u8; 256];
        let ack_len = packet_ack(header, contiguous, endpoint.receive.connection.consumed, &mut ack)?;
        if drop_packet == Some(header.packet_number) && !dropped {
            dropped = true;
        } else {
            socket.send(&ack[..ack_len]).await?;
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("server") => {
            let bind = args.next().unwrap_or_else(|| "127.0.0.1:3339".into()).parse::<SocketAddr>()?;
            run_server(BenchSocket::Udp(UdpSocket::bind(bind).await?), &format!("udp_server_ready bind={bind}"), None).await
        }
        Some("client") => {
            let server = args.next().unwrap_or_else(|| "127.0.0.1:3339".into()).parse::<SocketAddr>()?;
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            socket.connect(server).await?;
            run_client(BenchSocket::Udp(socket), None).await
        }
        Some("unix-server") => {
            let path = PathBuf::from(args.next().unwrap_or_else(|| "/tmp/dmesh-transport-bench.sock".into()));
            let _ = std::fs::remove_file(&path);
            let socket = UnixDatagram::bind(&path)?;
            run_server(BenchSocket::Unix(socket), &format!("unix_server_ready path={}", path.display()), Some(&path)).await
        }
        Some("unix-client") => {
            let server = PathBuf::from(args.next().unwrap_or_else(|| "/tmp/dmesh-transport-bench.sock".into()));
            let client = std::env::temp_dir().join(format!("dmesh-transport-bench-{}.sock", std::process::id()));
            let _ = std::fs::remove_file(&client);
            let socket = UnixDatagram::bind(&client)?;
            socket.connect(&server)?;
            run_client(BenchSocket::Unix(socket), Some(&client)).await
        }
        _ => bail!("usage: transport-udp-bench server|client [addr] | unix-server|unix-client [path]"),
    }
}
