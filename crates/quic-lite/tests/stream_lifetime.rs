//! Regression coverage for stream-slot lifetime and cross-stream isolation on
//! one long-lived association.

#![cfg(feature = "tokio")]

use std::time::Duration;

use quic_lite::{
    BearerName, ConnectionLimits, PacketMeta, PeerL2Address, QuicNode, fake::FakePacketBearer,
    packet_pool::PacketPool, tokio::TokioNodeDriver,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Pool = PacketPool<16, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
type Node = QuicNode<Pool>;

/// Regression: one association must serve far more sequential streams than
/// any fixed stream-slot capacity.
///
/// Two defects stopped this earlier. First, `CallbackStreams` never removed
/// finished streams, so the 33rd stream hit `CallbackError::Capacity`.
/// Second, a stream whose last event was the peer's empty FIN (written by
/// `finish_stream`) was never retired: delivery reports no zero-byte
/// consumption, so `try_retire_stream` did not run, and after enough
/// exchanges `open_stream` waited on `StreamLimit` forever (intermittently,
/// depending on whether the FIN or our FIN's ACK arrived last).
#[tokio::test(flavor = "current_thread")]
async fn association_serves_more_streams_than_delivery_slots() {
    static CLIENT_POOL: Pool = Pool::new();
    static SERVER_POOL: Pool = Pool::new();
    const STREAMS: usize = 200;

    let (client_bearer, server_bearer) = FakePacketBearer::<Pool>::pair(
        BearerName::new("client").unwrap(),
        BearerName::new("server").unwrap(),
    );
    let mut client = Node::new(None, &CLIENT_POOL);
    let mut server = Node::new(None, &SERVER_POOL);
    let bearer = client.add_bearer(client_bearer).unwrap();
    server.add_bearer(server_bearer).unwrap();
    let (client, client_driver) = TokioNodeDriver::new(client, ConnectionLimits::default());
    let (server, server_driver) = TokioNodeDriver::new(server, ConnectionLimits::default());

    let application = async move {
        let association = client
            .associate(
                PacketMeta {
                    bearer,
                    peer_l2_address: PeerL2Address::new(1).unwrap(),
                    received_at_us: 0,
                },
                0,
            )
            .await
            .unwrap();
        let serve = async {
            for _ in 0..STREAMS {
                let mut stream = server.accept_stream().await.unwrap();
                let mut request = Vec::new();
                stream.read_to_end(&mut request).await.unwrap();
                stream.write_all(&request).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        };
        let call = async {
            association.wait_established().await.unwrap();
            for index in 0..STREAMS {
                let mut stream = association.open_stream().await.unwrap();
                let body = [index as u8; 10];
                stream.write_all(&body).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut response = Vec::new();
                tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
                    .await
                    .unwrap_or_else(|_| panic!("stream {index} received no response"))
                    .unwrap();
                assert_eq!(response, body);
            }
        };
        tokio::join!(serve, call);
    };
    tokio::select! {
        result = client_driver.run() => panic!("client driver stopped: {result:?}"),
        result = server_driver.run() => panic!("server driver stopped: {result:?}"),
        () = application => {}
    }
}

/// Regression: one unread stream must not block the other streams on the node.
///
/// Previously all received chunks shared one node-wide FIFO. A full
/// per-stream channel made `dispatch_stream_chunks` return `blocked`, and
/// `TokioNodeDriver::run` stopped polling the node: no other stream was
/// accepted and no ingress, ACK, or timer was processed until that reader
/// drained. Now each stream has its own queue limit, enforced by withholding
/// that stream's receive credit (`ChunkAdmission`), and retained bytes are
/// resumed once the reader drains.
#[tokio::test(flavor = "current_thread")]
async fn unread_stream_does_not_block_accepting_another_stream() {
    static CLIENT_POOL: Pool = Pool::new();
    static SERVER_POOL: Pool = Pool::new();

    let (client_bearer, server_bearer) = FakePacketBearer::<Pool>::pair(
        BearerName::new("client").unwrap(),
        BearerName::new("server").unwrap(),
    );
    let mut client = Node::new(None, &CLIENT_POOL);
    let mut server = Node::new(None, &SERVER_POOL);
    let bearer = client.add_bearer(client_bearer).unwrap();
    server.add_bearer(server_bearer).unwrap();
    let (client, client_driver) = TokioNodeDriver::new(client, ConnectionLimits::default());
    let (server, server_driver) = TokioNodeDriver::new(server, ConnectionLimits::default());

    let application = async move {
        let association = client
            .associate(
                PacketMeta {
                    bearer,
                    peer_l2_address: PeerL2Address::new(1).unwrap(),
                    received_at_us: 0,
                },
                0,
            )
            .await
            .unwrap();
        association.wait_established().await.unwrap();

        let mut bulk = association.open_stream().await.unwrap();
        let bulk_body = vec![7u8; 200_000];
        let send_bulk = async {
            bulk.write_all(&bulk_body).await.unwrap();
            bulk.shutdown().await.unwrap();
        };
        let second = async {
            // The server accepts the bulk stream but does not read it yet.
            let mut unread = server.accept_stream().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            // While the server driver is stalled it also stops sending ACKs,
            // so even the client's small write can wait forever. Bound the
            // whole second-stream exchange so the failure is reported
            // instead of hanging the test.
            let accepted = tokio::time::timeout(Duration::from_secs(2), async {
                let mut ping = association.open_stream().await.unwrap();
                ping.write_all(b"ping").await.unwrap();
                ping.shutdown().await.unwrap();
                server.accept_stream().await
            })
            .await;
            assert!(
                matches!(accepted, Ok(Some(_))),
                "second stream was not accepted while the first stream is unread"
            );
            // Bytes held back while the reader was idle must all arrive, in
            // order, once it reads.
            let mut received = Vec::new();
            tokio::time::timeout(Duration::from_secs(5), unread.read_to_end(&mut received))
                .await
                .expect("stalled stream did not resume")
                .unwrap();
            assert_eq!(received.len(), 200_000);
            assert!(received.iter().all(|byte| *byte == 7));
        };
        // The bulk upload may finish (it fits the receive window) or stay
        // flow-blocked; either way only the second stream is asserted, so the
        // bulk future parks instead of ending the select.
        let bulk_then_park = async {
            send_bulk.await;
            std::future::pending::<()>().await;
        };
        tokio::select! {
            () = bulk_then_park => {}
            () = second => {}
        }
    };
    tokio::select! {
        result = client_driver.run() => panic!("client driver stopped: {result:?}"),
        result = server_driver.run() => panic!("server driver stopped: {result:?}"),
        () = application => {}
    }
}

/// With a receive window smaller than the transfer, an idle reader must hold
/// the sender at the flow-control limit, and reading must release credit so
/// the whole stream completes. Covers resume of retained bytes plus the
/// MAX_DATA/MAX_STREAM_DATA publication that follows it.
#[tokio::test(flavor = "current_thread")]
async fn slow_reader_with_small_window_receives_complete_stream() {
    static CLIENT_POOL: Pool = Pool::new();
    static SERVER_POOL: Pool = Pool::new();
    const BODY: usize = 200_000;

    let (client_bearer, server_bearer) = FakePacketBearer::<Pool>::pair(
        BearerName::new("client").unwrap(),
        BearerName::new("server").unwrap(),
    );
    let mut client = Node::new(None, &CLIENT_POOL);
    let mut server = Node::new(None, &SERVER_POOL);
    let bearer = client.add_bearer(client_bearer).unwrap();
    server.add_bearer(server_bearer).unwrap();
    let (client, client_driver) = TokioNodeDriver::new(client, ConnectionLimits::default());
    let (server, server_driver) =
        TokioNodeDriver::new(server, ConnectionLimits::with_receive_window(16 * 1024));

    let application = async move {
        let association = client
            .associate(
                PacketMeta {
                    bearer,
                    peer_l2_address: PeerL2Address::new(1).unwrap(),
                    received_at_us: 0,
                },
                0,
            )
            .await
            .unwrap();
        association.wait_established().await.unwrap();
        let body: Vec<u8> = (0..BODY).map(|index| index as u8).collect();
        let send = async {
            let mut stream = association.open_stream().await.unwrap();
            stream.write_all(&body).await.unwrap();
            stream.shutdown().await.unwrap();
        };
        let receive = async {
            let mut stream = server.accept_stream().await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            let mut received = Vec::new();
            tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut received))
                .await
                .expect("flow-blocked stream did not resume")
                .unwrap();
            received
        };
        let ((), received) = tokio::join!(send, receive);
        assert_eq!(received.len(), BODY);
        assert!(received == body, "bytes arrived out of order or corrupted");
    };
    tokio::select! {
        result = client_driver.run() => panic!("client driver stopped: {result:?}"),
        result = server_driver.run() => panic!("server driver stopped: {result:?}"),
        () = application => {}
    }
}
