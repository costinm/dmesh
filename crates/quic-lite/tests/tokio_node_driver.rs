#![cfg(feature = "tokio")]

use quic_lite::{
    BearerName, ConnectionLimits, PacketMeta, PeerL2Address, QuicNode, fake::FakePacketBearer,
    packet_pool::PacketPool, tokio::TokioNodeDriver,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Pool = PacketPool<16, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
type Node = QuicNode<Pool>;

#[tokio::test]
async fn association_finish_waits_for_retained_close_submission() {
    use quic_lite::fake::{FakeLinkProfile, FakeNetworkConfig};
    use std::{sync::{Arc, Mutex}, time::Duration};
    let client_pool = Box::leak(Box::new(Pool::new()));
    let server_pool = Box::leak(Box::new(Pool::new()));
    let (first, second, network) = FakePacketBearer::<Pool>::pair_with_network(
        BearerName::new("close-client").unwrap(),
        BearerName::new("close-server").unwrap(),
        FakeNetworkConfig::default(),
    );
    let network = Arc::new(Mutex::new(network));
    let mut client_node = Node::new(client_pool);
    let mut server_node = Node::new(server_pool);
    let bearer = client_node.add_bearer(first).unwrap();
    server_node.add_bearer(second).unwrap();
    let (client, client_driver) = TokioNodeDriver::new(client_node, ConnectionLimits::default());
    let (_server, server_driver) = TokioNodeDriver::new(server_node, ConnectionLimits::default());
    let scenario = async {
        let association = client.associate(PacketMeta {
            bearer, peer_l2_address: PeerL2Address::new(1).unwrap(), received_at_us: 0,
        }, 0).await.unwrap();
        association.wait_established().await.unwrap();
        // Drain handshake control before making the final close unwritable.
        tokio::time::sleep(Duration::from_millis(50)).await;
        network.lock().unwrap().set_first_to_second_profile(FakeLinkProfile {
            would_block_every: 1, readiness_delay_us: 1_000,
            ..FakeLinkProfile::default()
        });
        let finish = association.finish();
        tokio::pin!(finish);
        assert!(tokio::time::timeout(Duration::from_millis(30), &mut finish).await.is_err(),
            "finish must not return while its close packet remains unsubmitted");
        network.lock().unwrap().set_first_to_second_profile(FakeLinkProfile::default());
        tokio::time::timeout(Duration::from_secs(1), finish).await.unwrap().unwrap();
    };
    let pump = async {
        let started = tokio::time::Instant::now();
        loop {
            network.lock().unwrap().advance_to(started.elapsed().as_micros() as u64);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::select! {
            result = client_driver.run() => panic!("client stopped: {result:?}"),
            result = server_driver.run() => panic!("server stopped: {result:?}"),
            () = pump => unreachable!(),
            () = scenario => {},
        }
    }).await.unwrap();
}

#[tokio::test]
async fn upload_resumes_after_three_second_peer_pause_and_dropped_replacements() {
    use quic_lite::fake::{FakeLinkProfile, FakeNetworkConfig};
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
    use std::time::Duration;
    let client_pool = Box::leak(Box::new(Pool::new()));
    let server_pool = Box::leak(Box::new(Pool::new()));
    let (first, second, mut network) = FakePacketBearer::<Pool>::pair_with_network(
        BearerName::new("paused-client").unwrap(),
        BearerName::new("paused-server").unwrap(),
        FakeNetworkConfig::default(),
    );
    let mut client_node = Node::new(client_pool);
    let mut server_node = Node::new(server_pool);
    client_node.set_default_association_limits(quic_lite::AssociationLimits::host()).unwrap();
    server_node.set_default_association_limits(quic_lite::AssociationLimits::embedded()).unwrap();
    let bearer = client_node.add_bearer(first).unwrap();
    server_node.add_bearer(second).unwrap();
    let (client, client_driver) = TokioNodeDriver::new(client_node, ConnectionLimits::default());
    let (server, server_driver) = TokioNodeDriver::new(server_node, quic_lite::AssociationLimits::embedded().connection);
    let pause = Arc::new(AtomicBool::new(false));
    let resumed = Arc::new(AtomicBool::new(false));
    let scenario = async {
        let association = client.associate(PacketMeta {
            bearer, peer_l2_address: PeerL2Address::new(1).unwrap(), received_at_us: 0,
        }, 0).await.unwrap();
        association.wait_established().await.unwrap();
        pause.store(true, Ordering::Release);
        // Let the fake network arm its pause before the first upload byte.
        tokio::time::sleep(Duration::from_millis(5)).await;
        let upload = async {
            let mut stream = association.open_stream().await.unwrap();
            stream.write_all(&vec![0x5a; 16 * 1024]).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"complete");
            association.finish().await.unwrap();
        };
        let receive = async {
            let mut stream = server.accept_stream().await.unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, vec![0x5a; 16 * 1024]);
            stream.write_all(b"complete").await.unwrap();
            stream.shutdown().await.unwrap();
        };
        tokio::join!(upload, receive);
        assert!(resumed.load(Ordering::Acquire));
    };
    tokio::time::timeout(Duration::from_secs(20), async {
        let network_driver = async {
            let started = tokio::time::Instant::now();
            let mut pause_at = None;
            loop {
                let now = started.elapsed().as_micros() as u64;
                if pause.load(Ordering::Acquire) && pause_at.is_none() {
                    pause_at = Some(now);
                    network.set_first_to_second_profile(FakeLinkProfile {
                        // Keep the initial seven data packets, but drop the
                        // subsequent replacement attempts during the pause.
                        latency_us: 3_000_000,
                        loss_burst_start_packet: 9, loss_burst_packets: 1000,
                        ..FakeLinkProfile::default()
                    });
                }
                if pause_at.is_some_and(|at| now >= at + 3_020_000)
                    && !resumed.swap(true, Ordering::AcqRel) {
                    network.set_first_to_second_profile(FakeLinkProfile::default());
                }
                network.advance_to(now);
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        };
        tokio::select! {
            result = client_driver.run() => panic!("client driver stopped: {result:?}"),
            result = server_driver.run() => panic!("server driver stopped: {result:?}"),
            () = network_driver => unreachable!(),
            () = scenario => {},
        }
    }).await.expect("ordinary write_all/read_to_end must resume after peer pause");
    assert!(network.stats().loss_drops > 0, "replacement loss was not exercised");
}

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

#[tokio::test]
async fn rows_describe_an_established_association_and_its_bearers() {
    static CLIENT_POOL: Pool = Pool::new();
    static SERVER_POOL: Pool = Pool::new();
    let (client_bearer, server_bearer) = FakePacketBearer::<Pool>::pair(
        BearerName::new("rows-client").unwrap(),
        BearerName::new("rows-server").unwrap(),
    );
    let mut client_node = Node::new(&CLIENT_POOL);
    let mut server_node = Node::new(&SERVER_POOL);
    let client_bearer = client_node.add_bearer(client_bearer).unwrap();
    server_node.add_bearer(server_bearer).unwrap();
    let (client, client_driver) = TokioNodeDriver::new(client_node, ConnectionLimits::default());
    let (server, server_driver) = TokioNodeDriver::new(server_node, ConnectionLimits::default());
    let peer = PeerL2Address::new(1).unwrap();
    let scenario = async move {
        let association = client
            .associate(
                PacketMeta {
                    bearer: client_bearer,
                    peer_l2_address: peer,
                    received_at_us: 0,
                },
                0,
            )
            .await
            .unwrap();
        association.wait_established().await.unwrap();
        // Move one stream across so the 1-RTT counters have something to count.
        let mut stream = association.open_stream().await.unwrap();
        stream.write_all(b"x").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut accepted = server.accept_stream().await.unwrap();
        let mut received = Vec::new();
        accepted.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"x");
        let (associations, bearers) = client.rows().await.unwrap();
        assert_eq!(associations.len(), 1);
        assert_eq!(associations[0].bearer, Some(client_bearer));
        assert_eq!(associations[0].peer, Some(peer));
        assert!(associations[0].telemetry.transport.sent_packets > 0);
        assert_eq!(bearers.len(), 1);
        assert_eq!(bearers[0].name.as_str(), "rows-client");
        assert!(bearers[0].enabled);
        assert!(bearers[0].submitted_packets > 0);
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

/// One association whose peer never answers fails that association only: the caller sees the
/// timeout, and the node (here, the driver itself) keeps running for the others. A node that
/// stopped on the first failed setup took a whole service down (lmesh pairing an absent device).
#[tokio::test]
async fn a_setup_that_times_out_fails_that_association_not_the_node() {
    use quic_lite::fake::{FakeLinkProfile, FakeNetworkConfig};
    use std::time::Duration;
    let client_pool = Box::leak(Box::new(Pool::new()));
    let (first, _silent_peer, mut network) = FakePacketBearer::<Pool>::pair_with_network(
        BearerName::new("silent-client").unwrap(),
        BearerName::new("silent-server").unwrap(),
        FakeNetworkConfig::default(),
    );
    // Every packet to the peer is lost.
    network.set_first_to_second_profile(FakeLinkProfile {
        loss_burst_start_packet: 0,
        loss_burst_packets: 1_000_000,
        ..FakeLinkProfile::default()
    });
    let mut client_node = Node::new(client_pool);
    let bearer = client_node.add_bearer(first).unwrap();
    let (client, client_driver) = TokioNodeDriver::new(client_node, ConnectionLimits::default());
    let scenario = async {
        let association = client
            .associate(
                PacketMeta { bearer, peer_l2_address: PeerL2Address::new(1).unwrap(), received_at_us: 0 },
                0,
            )
            .await
            .unwrap();
        let outcome = association.wait_established().await;
        assert!(outcome.is_err(), "an unanswered setup must fail the association: {outcome:?}");
        // The node still answers its owner after the failed setup.
        client.telemetry().await.expect("the node outlives a failed association");
    };
    let network_driver = async {
        loop {
            network.advance_to(0);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(60), async {
        tokio::select! {
            () = scenario => {}
            result = client_driver.run() => panic!("the driver stopped on one failed setup: {result:?}"),
            () = network_driver => unreachable!(),
        }
    })
    .await
    .expect("scenario finishes");
}

/// An association opened on a node that has been idle gets its full setup time. The node's clock
/// only moves when the driver moves it; a driver that acted on the command with the clock of
/// its last loop turn created the association in the past, so every bootstrap attempt and the
/// timeout fell due at once.
#[tokio::test]
async fn an_association_opened_after_an_idle_period_is_not_born_timed_out() {
    use quic_lite::fake::{FakeLinkProfile, FakeNetworkConfig};
    use std::time::Duration;
    let client_pool = Box::leak(Box::new(Pool::new()));
    let (first, _silent_peer, mut network) = FakePacketBearer::<Pool>::pair_with_network(
        BearerName::new("idle-client").unwrap(),
        BearerName::new("idle-server").unwrap(),
        FakeNetworkConfig::default(),
    );
    network.set_first_to_second_profile(FakeLinkProfile {
        loss_burst_start_packet: 0,
        loss_burst_packets: 1_000_000,
        ..FakeLinkProfile::default()
    });
    let mut client_node = Node::new(client_pool);
    let bearer = client_node.add_bearer(first).unwrap();
    let (client, client_driver) = TokioNodeDriver::new(client_node, ConnectionLimits::default());
    let scenario = async {
        // No association and no timer: the driver sleeps.
        tokio::time::sleep(Duration::from_secs(3)).await;
        let association = client
            .associate(
                PacketMeta { bearer, peer_l2_address: PeerL2Address::new(1).unwrap(), received_at_us: 0 },
                0,
            )
            .await
            .unwrap();
        let early = tokio::time::timeout(Duration::from_millis(300), association.wait_established()).await;
        assert!(early.is_err(), "the setup failed at once instead of retrying: {early:?}");
    };
    let network_driver = async {
        loop {
            network.advance_to(0);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(30), async {
        tokio::select! {
            () = scenario => {}
            result = client_driver.run() => panic!("the driver stopped: {result:?}"),
            () = network_driver => unreachable!(),
        }
    })
    .await
    .expect("scenario finishes");
}
