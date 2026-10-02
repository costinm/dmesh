#![cfg(feature = "tokio")]

use quic_lite::{
    BearerName, ConnectionLimits, PacketMeta, PeerL2Address, QuicNode, fake::FakePacketBearer,
    packet_pool::PacketPool, tokio::TokioNodeDriver,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Pool = PacketPool<16, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
type Node = QuicNode<Pool>;

#[tokio::test]
async fn owned_handles_exchange_two_concurrent_streams() {
    static CLIENT_POOL: Pool = Pool::new();
    static SERVER_POOL: Pool = Pool::new();
    let (client_bearer, server_bearer) = FakePacketBearer::<Pool>::pair(
        BearerName::new("driver-client").unwrap(),
        BearerName::new("driver-server").unwrap(),
    );
    let mut client_node = Node::new(&CLIENT_POOL);
    let mut server_node = Node::new(&SERVER_POOL);
    let client_bearer = client_node.add_bearer(client_bearer).unwrap();
    server_node.add_bearer(server_bearer).unwrap();
    let (client, client_driver) = TokioNodeDriver::new(client_node, ConnectionLimits::default());
    let (server, server_driver) = TokioNodeDriver::new(server_node, ConnectionLimits::default());
    let scenario = async move {
        let association = client
            .associate(
                PacketMeta {
                    bearer: client_bearer,
                    peer_l2_address: PeerL2Address::new(1).unwrap(),
                    received_at_us: 0,
                },
                0,
            )
            .await
            .unwrap();
        association.wait_established().await.unwrap();
        let mut first = association.open_stream().await.unwrap();
        let mut second = association.open_stream().await.unwrap();

        let clients = async {
            let (a, b) = tokio::join!(
                async {
                    first.write_all(b"first").await?;
                    first.shutdown().await
                },
                async {
                    second.write_all(b"second").await?;
                    second.shutdown().await
                }
            );
            a.unwrap();
            b.unwrap();
            let mut first_response = Vec::new();
            let mut second_response = Vec::new();
            let (a, b) = tokio::join!(
                first.read_to_end(&mut first_response),
                second.read_to_end(&mut second_response)
            );
            a.unwrap();
            b.unwrap();
            assert_eq!(first_response, b"FIRST");
            assert_eq!(second_response, b"SECOND");
            association.finish().await.unwrap();
        };
        let servers = async {
            let first = server.accept_stream().await.unwrap();
            let second = server.accept_stream().await.unwrap();
            let serve = |mut stream: quic_lite::tokio::TokioStream| async move {
                let mut request = Vec::new();
                stream.read_to_end(&mut request).await.unwrap();
                request.make_ascii_uppercase();
                assert_eq!(stream.write(request.clone()).await.unwrap(), request.len());
                stream.finish().await.unwrap();
            };
            let first_task = tokio::spawn(serve(first));
            let second_task = tokio::spawn(serve(second));
            let (a, b) = tokio::join!(first_task, second_task);
            a.unwrap();
            b.unwrap();
        };
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            tokio::join!(clients, servers);
        })
        .await
        .unwrap();
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::select! {
            result = client_driver.run() => panic!("client driver stopped: {result:?}"),
            result = server_driver.run() => panic!("server driver stopped: {result:?}"),
            () = scenario => {}
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn one_association_reuses_stream_capacity_past_initial_limit() {
    static CLIENT_POOL: Pool = Pool::new();
    static SERVER_POOL: Pool = Pool::new();
    let (client_bearer, server_bearer) = FakePacketBearer::<Pool>::pair(
        BearerName::new("reuse-client").unwrap(),
        BearerName::new("reuse-server").unwrap(),
    );
    let mut client_node = Node::new(&CLIENT_POOL);
    let mut server_node = Node::new(&SERVER_POOL);
    let client_bearer = client_node.add_bearer(client_bearer).unwrap();
    server_node.add_bearer(server_bearer).unwrap();
    let (client, client_driver) = TokioNodeDriver::new(client_node, ConnectionLimits::default());
    let (server, server_driver) = TokioNodeDriver::new(server_node, ConnectionLimits::default());

    let scenario = async move {
        let association = client
            .associate(
                PacketMeta {
                    bearer: client_bearer,
                    peer_l2_address: PeerL2Address::new(1).unwrap(),
                    received_at_us: 0,
                },
                0,
            )
            .await
            .unwrap();
        association.wait_established().await.unwrap();

        let clients = async {
            for sequence in 0_u8..20 {
                let mut stream = association.open_stream().await.unwrap();
                stream.write_all(&[sequence]).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut response = Vec::new();
                stream.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, [sequence]);
            }
            association.finish().await.unwrap();
        };
        let servers = async {
            for _ in 0..20 {
                let mut stream = server.accept_stream().await.unwrap();
                let mut request = Vec::new();
                stream.read_to_end(&mut request).await.unwrap();
                assert_eq!(stream.write(request.clone()).await.unwrap(), request.len());
                stream.finish().await.unwrap();
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            tokio::join!(clients, servers);
        })
        .await
        .unwrap();
    };

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::select! {
            result = client_driver.run() => panic!("client driver stopped: {result:?}"),
            result = server_driver.run() => panic!("server driver stopped: {result:?}"),
            () = scenario => {}
        }
    })
    .await
    .unwrap();
}

/// The driver owns the node timers. A request larger than the initial pacing
/// burst (8 packets) needs the pacing timer to release the rest; before the
/// driver armed timers such a transfer stalled after the first burst.
#[tokio::test]
async fn paced_transfer_beyond_the_initial_burst_completes() {
    transfer_with_receive_window(ConnectionLimits::default(), false, false).await;
}

/// A slow application must release credit through AsyncRead, without a
/// transport-specific retry loop in either endpoint.
#[tokio::test]
async fn slow_reader_resumes_transfer_larger_than_receive_window() {
    transfer_with_receive_window(
        ConnectionLimits::with_receive_window(16 * 1024),
        true,
        false,
    )
    .await;
}

#[tokio::test]
async fn delayed_lossy_bearer_resumes_owned_stream_without_application_retries() {
    transfer_with_receive_window(ConnectionLimits::with_receive_window(16 * 1024), true, true)
        .await;
}

async fn transfer_with_receive_window(limits: ConnectionLimits, slow_reader: bool, faults: bool) {
    // Each concurrent test owns separate pools. Nodes require static pool
    // references, so these test-only allocations live until process exit.
    let client_pool = Box::leak(Box::new(Pool::new()));
    let server_pool = Box::leak(Box::new(Pool::new()));
    let names = (
        BearerName::new("paced-client").unwrap(),
        BearerName::new("paced-server").unwrap(),
    );
    let (client_bearer, server_bearer, mut network) = if faults {
        use quic_lite::fake::{FakeLinkProfile, FakeNetworkConfig};
        let profile = FakeLinkProfile {
            latency_us: 10_000,
            jitter_us: 5_000,
            loss_burst_start_packet: 8,
            loss_burst_packets: 2,
            would_block_every: 7,
            readiness_delay_us: 2_000,
            reorder_ready_batch: true,
            ..FakeLinkProfile::default()
        };
        let (a, b, network) = FakePacketBearer::<Pool>::pair_with_network(
            names.0,
            names.1,
            FakeNetworkConfig {
                first_to_second: profile,
                second_to_first: profile,
                ..FakeNetworkConfig::default()
            },
        );
        (a, b, Some(network))
    } else {
        let (a, b) = FakePacketBearer::<Pool>::pair(names.0, names.1);
        (a, b, None)
    };
    let mut client_node = Node::new(client_pool);
    let mut server_node = Node::new(server_pool);
    for node in [&mut client_node, &mut server_node] {
        node.set_default_association_limits(quic_lite::AssociationLimits::host())
            .unwrap();
    }
    let client_bearer = client_node.add_bearer(client_bearer).unwrap();
    server_node.add_bearer(server_bearer).unwrap();
    let (client, client_driver) = TokioNodeDriver::new(client_node, limits);
    let (server, server_driver) = TokioNodeDriver::new(server_node, limits);

    let body_bytes = if faults { 1024 * 1024 } else { 64 * 1024 };
    let scenario = async move {
        let association = client
            .associate(
                PacketMeta {
                    bearer: client_bearer,
                    peer_l2_address: PeerL2Address::new(1).unwrap(),
                    received_at_us: 0,
                },
                0,
            )
            .await
            .unwrap();
        association.wait_established().await.unwrap();
        let clients = async {
            let mut stream = association.open_stream().await.unwrap();
            stream.write_all(&vec![0x5a; body_bytes]).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, (body_bytes as u32).to_be_bytes());
            association.finish().await.unwrap();
        };
        let servers = async {
            let mut stream = server.accept_stream().await.unwrap();
            let mut request = Vec::new();
            if slow_reader {
                let mut chunk = [0; 512];
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                    let count = stream.read(&mut chunk).await.unwrap();
                    if count == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..count]);
                }
            } else {
                stream.read_to_end(&mut request).await.unwrap();
            }
            assert_eq!(request.len(), body_bytes);
            assert!(request.iter().all(|byte| *byte == 0x5a));
            let reply = (request.len() as u32).to_be_bytes().to_vec();
            assert_eq!(stream.write(reply.clone()).await.unwrap(), reply.len());
            stream.finish().await.unwrap();
        };
        tokio::join!(clients, servers);
    };

    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let network_driver = async {
            let started = tokio::time::Instant::now();
            loop {
                if let Some(network) = network.as_mut() {
                    network.advance_to(started.elapsed().as_micros() as u64);
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        };
        tokio::select! {
            result = client_driver.run() => panic!("client driver stopped: {result:?}"),
            result = server_driver.run() => panic!("server driver stopped: {result:?}"),
            () = network_driver => unreachable!(),
            () = scenario => {}
        }
    })
    .await
    .unwrap();
    if let Some(network) = network {
        let stats = network.stats();
        assert!(stats.loss_drops > 0, "loss recovery was not exercised");
        assert!(stats.would_block > 0, "bearer readiness was not exercised");
    }
}
