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
    let mut client_node = Node::new(None, &CLIENT_POOL);
    let mut server_node = Node::new(None, &SERVER_POOL);
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
    let mut client_node = Node::new(None, &CLIENT_POOL);
    let mut server_node = Node::new(None, &SERVER_POOL);
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
