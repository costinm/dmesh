#![cfg(feature = "tokio")]
#![deny(deprecated)]

use quic_lite::{
    AssociationEvent, BearerName, ConnectionLimits, PacketMeta, PeerL2Address, QuicAssociation,
    QuicNode, fake::FakePacketBearer, packet_pool::PacketPool,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Pool = PacketPool<8, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
type OneAssociationNode = QuicNode<(), 1, 1, Pool>;
type TwoAssociationNode = QuicNode<(), 2, 2, Pool>;

async fn client_request(
    node: &mut OneAssociationNode,
    association: QuicAssociation,
    request: &[u8],
) -> Vec<u8> {
    node.wait_established(association).await.unwrap();
    let stream = node.open_stream(association).unwrap();
    let mut stream = node.stream(stream);
    stream.write_all(request).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    drop(stream);
    node.finish_association(association).await.unwrap();
    response
}

async fn server_response(node: &mut OneAssociationNode, expected: &[u8], response: &[u8]) {
    let accepted = node
        .accept_stream(ConnectionLimits::default())
        .await
        .unwrap();
    let mut stream = node.accepted_stream(accepted);
    let mut request = Vec::new();
    stream.read_to_end(&mut request).await.unwrap();
    assert_eq!(request, expected);
    stream.write_all(response).await.unwrap();
    stream.shutdown().await.unwrap();
}

async fn process_peer_close(node: &mut OneAssociationNode) {
    let waiting = node.accept_stream(ConnectionLimits::default());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), waiting)
            .await
            .is_err(),
        "a close must retire state, not create an application stream"
    );
}

#[tokio::test]
async fn waiting_for_one_handshake_retains_stream_data_from_another_association() {
    static CLIENT_POOL: Pool = Pool::new();
    static SERVER_A_POOL: Pool = Pool::new();
    static SERVER_B_POOL: Pool = Pool::new();

    let (client_a_bearer, server_a_bearer) = FakePacketBearer::<Pool>::pair(
        BearerName::new("waiting-client-a").unwrap(),
        BearerName::new("waiting-server-a").unwrap(),
    );
    let (client_b_bearer, server_b_bearer) = FakePacketBearer::<Pool>::pair(
        BearerName::new("waiting-client-b").unwrap(),
        BearerName::new("waiting-server-b").unwrap(),
    );
    let mut client = TwoAssociationNode::new(None, &CLIENT_POOL);
    let mut server_a = OneAssociationNode::new(None, &SERVER_A_POOL);
    let mut server_b = OneAssociationNode::new(None, &SERVER_B_POOL);
    let client_a_bearer = client.add_bearer(client_a_bearer).unwrap();
    let client_b_bearer = client.add_bearer(client_b_bearer).unwrap();
    server_a.add_bearer(server_a_bearer).unwrap();
    server_b.add_bearer(server_b_bearer).unwrap();

    let association_a = client
        .associate(
            PacketMeta {
                bearer: client_a_bearer,
                peer_l2_address: PeerL2Address::new(1).unwrap(),
                received_at_us: 0,
            },
            0,
        )
        .unwrap();
    let receive_a = server_a.accept_stream(ConnectionLimits::default());
    let send_a = async {
        client.wait_established(association_a).await.unwrap();
        let mut stream = client.open_stream(association_a).unwrap();
        client.write_stream(&mut stream, b"request-a").unwrap();
        client.finish_stream(&mut stream).unwrap();
    };
    let (request_a, ()) = tokio::join!(receive_a, send_a);
    let mut request_a = request_a.unwrap();
    assert_eq!(request_a.bytes, b"request-a");

    let association_b = client
        .associate(
            PacketMeta {
                bearer: client_b_bearer,
                peer_l2_address: PeerL2Address::new(1).unwrap(),
                received_at_us: 0,
            },
            0,
        )
        .unwrap();
    server_a
        .write_stream(&mut request_a.stream, b"response-a")
        .unwrap();
    server_a.finish_stream(&mut request_a.stream).unwrap();

    let establish_b = async {
        client.wait_established(association_b).await.unwrap();
        let mut stream = client.open_stream(association_b).unwrap();
        client.write_stream(&mut stream, b"request-b").unwrap();
        client.finish_stream(&mut stream).unwrap();
    };
    let delayed_server_b = async {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        server_b
            .accept_stream(ConnectionLimits::default())
            .await
            .unwrap()
    };
    let ((), request_b) = tokio::join!(establish_b, delayed_server_b);
    assert_eq!(request_b.bytes, b"request-b");

    let response_a = client
        .accept_stream(ConnectionLimits::default())
        .await
        .unwrap();
    assert_eq!(response_a.bytes, b"response-a");
    assert!(!response_a.fin);
    let response_a_fin = client
        .accept_stream(ConnectionLimits::default())
        .await
        .unwrap();
    assert!(response_a_fin.bytes.is_empty());
    assert!(response_a_fin.fin);
}

#[tokio::test]
async fn finished_tokio_operation_retires_routes_and_one_slot_accepts_an_independent_client() {
    static CLIENT_A_POOL: Pool = Pool::new();
    static CLIENT_B_POOL: Pool = Pool::new();
    static SERVER_POOL: Pool = Pool::new();

    let (client_a_bearer, server_a_bearer) = FakePacketBearer::<Pool>::pair(
        BearerName::new("client-a").unwrap(),
        BearerName::new("server-a").unwrap(),
    );
    let (client_b_bearer, server_b_bearer) = FakePacketBearer::<Pool>::pair(
        BearerName::new("client-b").unwrap(),
        BearerName::new("server-b").unwrap(),
    );
    let mut client_a = OneAssociationNode::new(None, &CLIENT_A_POOL);
    let mut client_b = OneAssociationNode::new(None, &CLIENT_B_POOL);
    let mut server = OneAssociationNode::new(None, &SERVER_POOL);
    let client_a_bearer = client_a.add_bearer(client_a_bearer).unwrap();
    let client_b_bearer = client_b.add_bearer(client_b_bearer).unwrap();
    server.add_bearer(server_a_bearer).unwrap();
    server.add_bearer(server_b_bearer).unwrap();

    let association_a = client_a
        .associate(
            PacketMeta {
                bearer: client_a_bearer,
                peer_l2_address: PeerL2Address::new(1).unwrap(),
                received_at_us: 0,
            },
            0,
        )
        .unwrap();
    let ((), response_a) = tokio::join!(
        server_response(&mut server, b"request-a", b"response-a"),
        client_request(&mut client_a, association_a, b"request-a")
    );
    assert_eq!(response_a, b"response-a");
    assert_eq!(client_a.association_count(), 0);
    process_peer_close(&mut server).await;
    assert_eq!(server.association_count(), 0);
    assert!(matches!(
        server.next_association_event(),
        Some(AssociationEvent::Closed { code: 0, .. })
    ));

    let association_b = client_b
        .associate(
            PacketMeta {
                bearer: client_b_bearer,
                peer_l2_address: PeerL2Address::new(1).unwrap(),
                received_at_us: 0,
            },
            0,
        )
        .unwrap();
    let ((), response_b) = tokio::join!(
        server_response(&mut server, b"request-b", b"response-b"),
        client_request(&mut client_b, association_b, b"request-b")
    );
    assert_eq!(response_b, b"response-b");
    assert_eq!(client_b.association_count(), 0);
    process_peer_close(&mut server).await;
    assert_eq!(server.association_count(), 0);
    assert!(matches!(
        server.next_association_event(),
        Some(AssociationEvent::Closed { code: 0, .. })
    ));
}

#[tokio::test]
async fn abrupt_disappearance_is_retired_at_the_enforced_idle_deadline() {
    static CLIENT_POOL: Pool = Pool::new();
    static SERVER_POOL: Pool = Pool::new();
    let (client_bearer, server_bearer) = FakePacketBearer::<Pool>::pair(
        BearerName::new("idle-client").unwrap(),
        BearerName::new("idle-server").unwrap(),
    );
    let mut client = OneAssociationNode::new(None, &CLIENT_POOL);
    let mut server = OneAssociationNode::new(None, &SERVER_POOL);
    let client_bearer = client.add_bearer(client_bearer).unwrap();
    server.add_bearer(server_bearer).unwrap();
    server.set_idle_timeout_us(1_000);

    let association = client
        .associate(
            PacketMeta {
                bearer: client_bearer,
                peer_l2_address: PeerL2Address::new(1).unwrap(),
                received_at_us: 0,
            },
            0,
        )
        .unwrap();
    let server_receive = server.accept_stream(ConnectionLimits::default());
    let client_send = async {
        client.wait_established(association).await.unwrap();
        let mut stream = client.open_stream(association).unwrap();
        client.write_stream(&mut stream, b"last packet").unwrap();
        client.finish_stream(&mut stream).unwrap();
    };
    let (received, ()) = tokio::join!(server_receive, client_send);
    assert_eq!(received.unwrap().bytes, b"last packet");
    let received_fin = server
        .accept_stream(ConnectionLimits::default())
        .await
        .unwrap();
    assert!(received_fin.bytes.is_empty());
    assert!(received_fin.fin);
    drop(client);

    process_peer_close(&mut server).await;
    assert_eq!(server.association_count(), 0);
    assert!(matches!(
        server.next_association_event(),
        Some(AssociationEvent::IdleTimeout { .. })
    ));
}
