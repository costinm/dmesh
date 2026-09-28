#![cfg(feature = "tokio")]
#![deny(deprecated)]

//! Reference byte-stream probe shared by transport integration tests.
//!
//! TCP is the standard-library reference: it needs no packet, offset, window,
//! or completion adapter. QUIC-lite passes the same `run_client_probe` and
//! `run_server_probe` functions its Tokio stream view, proving packet and flow
//! control details do not leak into an application workload.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use quic_lite::bearer_framed::TokioFramedBearer;
use quic_lite::bearer_udp::TokioUdpBearer;
use quic_lite::fake::FakePacketBearer;
use quic_lite::{BearerName, PacketMeta, PeerL2Address, QuicNode};

const PROBE_BYTES: usize = 128 * 1024;
const WRITE_CHUNK: usize = 997;
type ProbePool =
    quic_lite::packet_pool::PacketPool<32, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
type ProbeNode = QuicNode<(), 2, 2, ProbePool>;

fn probe_byte(offset: usize) -> u8 {
    let mixed = (offset as u64)
        .wrapping_mul(0x9e37_79b9)
        .rotate_left((offset & 31) as u32);
    (mixed ^ (mixed >> 17) ^ 0xa5) as u8
}

async fn write_probe<W>(stream: &mut W, bytes: usize) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut offset = 0usize;
    let mut chunk = [0u8; WRITE_CHUNK];
    while offset < bytes {
        let len = (bytes - offset).min(chunk.len());
        for (index, byte) in chunk[..len].iter_mut().enumerate() {
            *byte = probe_byte(offset + index);
        }
        stream.write_all(&chunk[..len]).await?;
        offset += len;
    }
    stream.shutdown().await
}

async fn read_probe<R>(stream: &mut R, expected: usize) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut offset = 0usize;
    let mut chunk = [0u8; 1531];
    loop {
        let len = stream.read(&mut chunk).await?;
        if len == 0 {
            break;
        }
        if offset.saturating_add(len) > expected
            || chunk[..len]
                .iter()
                .enumerate()
                .any(|(index, byte)| *byte != probe_byte(offset + index))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "probe stream returned different bytes",
            ));
        }
        offset += len;
    }
    if offset != expected {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("probe stream ended after {offset} of {expected} bytes"),
        ));
    }
    Ok(())
}

async fn run_client_probe<S>(stream: &mut S, bytes: usize) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_probe(stream, bytes).await?;
    read_probe(stream, bytes).await
}

async fn run_server_probe<S>(stream: &mut S, bytes: usize) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    read_probe(stream, bytes).await?;
    write_probe(stream, bytes).await
}

async fn run_quic_probe(
    mut client_node: ProbeNode,
    mut server_node: ProbeNode,
    address: PacketMeta,
) -> io::Result<()> {
    let association = client_node
        .associate(address, 0)
        .map_err(|error| io::Error::other(format!("{error:?}")))?;
    let exchange = async {
        let server = async {
            let accepted = server_node
                .accept_stream(quic_lite::ConnectionLimits::default())
                .await
                .map_err(|error| io::Error::other(format!("{error:?}")))?;
            let mut stream = server_node.accepted_stream(accepted);
            run_server_probe(&mut stream, PROBE_BYTES).await
        };
        let client = async {
            client_node
                .wait_established(association)
                .await
                .map_err(|error| io::Error::other(format!("{error:?}")))?;
            let stream = client_node
                .open_stream(association)
                .map_err(|error| io::Error::other(format!("{error:?}")))?;
            let mut stream = client_node.stream(stream);
            run_client_probe(&mut stream, PROBE_BYTES).await
        };
        let (server, client) = tokio::join!(server, client);
        server?;
        client
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), exchange)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "QUIC probe stalled"))?
}

#[tokio::test]
async fn tcp_is_the_reference_stream_api_for_the_probe() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    let server = async {
        let (mut stream, _) = listener.accept().await?;
        run_server_probe(&mut stream, PROBE_BYTES).await
    };
    let client = async {
        let mut stream = tokio::net::TcpStream::connect(address).await?;
        run_client_probe(&mut stream, PROBE_BYTES).await
    };

    let (server, client) = tokio::join!(server, client);
    server.unwrap();
    client.unwrap();
}

#[tokio::test]
async fn fake_bearer_uses_the_same_stream_probe_as_tcp() {
    static CLIENT_POOL: ProbePool = ProbePool::new();
    static SERVER_POOL: ProbePool = ProbePool::new();

    let (client_bearer, server_bearer) = FakePacketBearer::<ProbePool>::pair(
        BearerName::new("probe-client").unwrap(),
        BearerName::new("probe-server").unwrap(),
    );
    let mut client_node = ProbeNode::new(None, &CLIENT_POOL);
    let mut server_node = ProbeNode::new(None, &SERVER_POOL);
    let client_bearer = client_node.add_bearer(client_bearer).unwrap();
    server_node.add_bearer(server_bearer).unwrap();

    run_quic_probe(
        client_node,
        server_node,
        PacketMeta {
            bearer: client_bearer,
            peer_l2_address: PeerL2Address::new(1).unwrap(),
            received_at_us: 0,
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn framed_bearer_uses_the_same_stream_probe_as_tcp() {
    static CLIENT_POOL: ProbePool = ProbePool::new();
    static SERVER_POOL: ProbePool = ProbePool::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let connect = tokio::net::TcpStream::connect(listener.local_addr().unwrap());
    let accept = listener.accept();
    let (client, server) = tokio::join!(connect, accept);

    let mut client_node = ProbeNode::new(None, &CLIENT_POOL);
    let mut server_node = ProbeNode::new(None, &SERVER_POOL);
    let client_bearer = client_node
        .add_bearer(TokioFramedBearer::<ProbePool>::from_tcp(
            client.unwrap(),
            BearerName::new("frame-client").unwrap(),
        ))
        .unwrap();
    server_node
        .add_bearer(TokioFramedBearer::<ProbePool>::from_tcp(
            server.unwrap().0,
            BearerName::new("frame-server").unwrap(),
        ))
        .unwrap();

    run_quic_probe(
        client_node,
        server_node,
        PacketMeta {
            bearer: client_bearer,
            peer_l2_address: PeerL2Address::new(1).unwrap(),
            received_at_us: 0,
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn udp_bearer_uses_the_same_stream_probe_as_tcp() {
    static CLIENT_POOL: ProbePool = ProbePool::new();
    static SERVER_POOL: ProbePool = ProbePool::new();
    let mut client_bearer = TokioUdpBearer::<8>::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let mut server_bearer = TokioUdpBearer::<8>::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    client_bearer.set_name(BearerName::new("udp-probe-client").unwrap());
    server_bearer.set_name(BearerName::new("udp-probe-server").unwrap());
    let server_address = server_bearer.local_addr().unwrap();
    let client_address = client_bearer.local_addr().unwrap();
    let server_peer = client_bearer.register_peer(server_address).unwrap();
    server_bearer.register_peer(client_address).unwrap();

    let mut client_node = ProbeNode::new(None, &CLIENT_POOL);
    let mut server_node = ProbeNode::new(None, &SERVER_POOL);
    let client_bearer = client_node.add_bearer(client_bearer).unwrap();
    server_node.add_bearer(server_bearer).unwrap();

    run_quic_probe(
        client_node,
        server_node,
        PacketMeta {
            bearer: client_bearer,
            peer_l2_address: server_peer,
            received_at_us: 0,
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn direct_message_uses_the_same_tokio_stream_operations() {
    static CLIENT_POOL: ProbePool = ProbePool::new();
    static SERVER_POOL: ProbePool = ProbePool::new();
    let (client_bearer, server_bearer) = FakePacketBearer::<ProbePool>::pair(
        BearerName::new("message-client").unwrap(),
        BearerName::new("message-server").unwrap(),
    );
    let mut client_node = ProbeNode::new(None, &CLIENT_POOL);
    let mut server_node = ProbeNode::new(None, &SERVER_POOL);
    let client_bearer = client_node.add_bearer(client_bearer).unwrap();
    server_node.add_bearer(server_bearer).unwrap();
    let request = client_node.open_message(PacketMeta {
        bearer: client_bearer,
        peer_l2_address: PeerL2Address::new(1).unwrap(),
        received_at_us: 0,
    });

    let server = async {
        let accepted = server_node
            .accept_stream(quic_lite::ConnectionLimits::default())
            .await
            .unwrap();
        let mut stream = server_node.accepted_stream(accepted);
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"ping");
        stream.write_all(b"pong").await.unwrap();
        stream.shutdown().await.unwrap();
    };
    let client = async {
        let mut stream = client_node.stream(request);
        stream.write_all(b"ping").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"pong");
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        tokio::join!(server, client);
    })
    .await
    .expect("direct message stream stalled");
}

#[tokio::test]
async fn tokio_stream_retransmits_after_receiver_pool_drop() {
    static CLIENT_POOL: ProbePool = ProbePool::new();
    static SERVER_POOL: ProbePool = ProbePool::new();
    let (client_bearer, server_bearer) = FakePacketBearer::<ProbePool>::pair(
        BearerName::new("loss-client").unwrap(),
        BearerName::new("loss-server").unwrap(),
    );
    let mut client_node = ProbeNode::new(None, &CLIENT_POOL);
    let mut server_node = ProbeNode::new(None, &SERVER_POOL);
    let client_bearer = client_node.add_bearer(client_bearer).unwrap();
    server_node.add_bearer(server_bearer).unwrap();
    let association = client_node
        .associate(
            PacketMeta {
                bearer: client_bearer,
                peer_l2_address: PeerL2Address::new(1).unwrap(),
                received_at_us: 0,
            },
            0,
        )
        .unwrap();

    let setup_server = server_node.accept_stream(quic_lite::ConnectionLimits::default());
    let setup_client = async {
        client_node.wait_established(association).await.unwrap();
        let mut stream = client_node.open_stream(association).unwrap();
        client_node.write_stream(&mut stream, b"setup").unwrap();
        client_node.finish_stream(&mut stream).unwrap();
    };
    let (setup, ()) = tokio::join!(setup_server, setup_client);
    assert_eq!(setup.unwrap().bytes, b"setup");
    let setup_fin = server_node
        .accept_stream(quic_lite::ConnectionLimits::default())
        .await
        .unwrap();
    assert!(setup_fin.bytes.is_empty() && setup_fin.fin);

    let mut held = Vec::new();
    while let Some(packet) = SERVER_POOL.acquire_with(&[0]) {
        held.push(packet);
    }
    assert!(!held.is_empty());
    let stream = client_node.open_stream(association).unwrap();
    let server = async {
        let accepted = server_node
            .accept_stream(quic_lite::ConnectionLimits::default())
            .await
            .unwrap();
        assert_eq!(accepted.bytes, b"retry me");
        let mut stream = server_node.accepted_stream(accepted);
        stream.write_all(b"retried").await.unwrap();
        stream.shutdown().await.unwrap();
    };
    let client = async {
        let mut stream = client_node.stream(stream);
        stream.write_all(b"retry me").await.unwrap();
        stream.shutdown().await.unwrap();
        drop(held);
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"retried");
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        tokio::join!(server, client);
    })
    .await
    .expect("timer did not retransmit the dropped packet");
}
