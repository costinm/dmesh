#![cfg(feature = "tokio")]
#![deny(deprecated)]

use quic_lite::bearer_framed::TokioFramedBearer;
use quic_lite::bearer_udp::TokioUdpBearer;
use quic_lite::fake::FakePacketBearer;
use quic_lite::{
    AddBearerError, BearerContext, BearerId, BearerInfo, BearerName, BearerRegistryError,
    EgressSubmission, PacketBearer, PacketEgress, PacketMeta, PacketPool as PacketPoolTrait,
    PacketSendOutcome, PacketSubmitError, PeerL2Address, QuicNode, QuicNodeEgressError,
    QuicNodeError,
};

const BEARER: BearerId = BearerId::new(1).unwrap();
type Pool = quic_lite::packet_pool::PacketPool<8, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
type Node = QuicNode<Pool>;
static CLIENT_POOL: Pool = Pool::new();

struct AttachFailure;

impl PacketEgress<<Pool as PacketPoolTrait>::Buffer> for AttachFailure {
    fn submit(
        &mut self,
        _peer: PeerL2Address,
        submission: EgressSubmission<<Pool as PacketPoolTrait>::Buffer>,
    ) -> Result<(), PacketSubmitError<<Pool as PacketPoolTrait>::Buffer>> {
        submission.complete(PacketSendOutcome::Sent, 0);
        Ok(())
    }
}

impl PacketBearer<Pool> for AttachFailure {
    type AttachError = &'static str;

    fn info(&self) -> BearerInfo {
        BearerInfo {
            name: BearerName::new("attach-failure").unwrap(),
            max_packet_size: quic_lite::DEFAULT_MAX_PACKET_SIZE,
            prefix_required: quic_lite::PACKET_PREFIX_RESERVE,
            suffix_required: quic_lite::PACKET_SUFFIX_RESERVE,
            requires_packet_encryption: false,
            secure_link: true,
            nominal_bitrate_bps: 1,
            local_mac: None,
        }
    }

    fn attach(&mut self, _context: BearerContext<Pool>) -> Result<(), Self::AttachError> {
        Err("attach rejected")
    }
}

#[test]
fn node_owns_the_complete_bearer() {
    let mut node = Node::new(None, &CLIENT_POOL);
    let name = BearerName::new("owned0").unwrap();
    assert_eq!(
        node.add_bearer(FakePacketBearer::<Pool>::new(name))
            .unwrap(),
        BEARER
    );
    assert_eq!(
        node.add_bearer(FakePacketBearer::<Pool>::new(name)),
        Err(AddBearerError::Registry(BearerRegistryError::DuplicateName))
    );
}

#[test]
fn removed_bearer_ids_are_retired_and_names_can_be_reused() {
    let mut node = Node::new(None, &CLIENT_POOL);
    let name = BearerName::new("replaceable").unwrap();
    let first = node
        .add_bearer(FakePacketBearer::<Pool>::new(name))
        .unwrap();

    assert!(node.remove_bearer(first));
    assert!(!node.remove_bearer(first));

    let second = node
        .add_bearer(FakePacketBearer::<Pool>::new(name))
        .unwrap();
    assert_ne!(first, second);
}

#[test]
fn bearer_attachment_and_registry_capacity_errors_are_public_and_distinct() {
    let mut failed = Node::new(None, &CLIENT_POOL);
    assert_eq!(
        failed.add_bearer(AttachFailure),
        Err(AddBearerError::Attach("attach rejected"))
    );

    let mut full = Node::new(None, &CLIENT_POOL);
    for index in 0..8 {
        let name = format!("full-{index}");
        full.add_bearer(FakePacketBearer::<Pool>::new(
            BearerName::new(&name).unwrap(),
        ))
        .unwrap();
    }
    assert_eq!(
        full.add_bearer(FakePacketBearer::<Pool>::new(
            BearerName::new("full-extra").unwrap()
        )),
        Err(AddBearerError::Registry(BearerRegistryError::Full))
    );
}

#[test]
fn node_reports_association_and_route_capacity_without_exposing_tables() {
    static ASSOCIATION_POOL: Pool = Pool::new();
    let mut association_full = QuicNode::<Pool>::new(None, &ASSOCIATION_POOL);
    association_full
        .set_limits(quic_lite::NodeLimits {
            max_associations: 1,
            max_routes: 1,
        })
        .unwrap();
    let bearer = association_full
        .add_bearer(FakePacketBearer::<Pool>::new(
            BearerName::new("association-full").unwrap(),
        ))
        .unwrap();
    let address = PacketMeta {
        bearer,
        peer_l2_address: PeerL2Address::new(1).unwrap(),
        received_at_us: 0,
    };
    association_full.associate(address, 0).unwrap();
    assert_eq!(
        association_full.associate(address, 1),
        Err(QuicNodeEgressError::Association(
            QuicNodeError::AssociationTableFull
        ))
    );
    assert_eq!(association_full.association_count(), 1);

    static ROUTE_POOL: Pool = Pool::new();
    let mut route_full = QuicNode::<Pool>::new(None, &ROUTE_POOL);
    route_full
        .set_limits(quic_lite::NodeLimits {
            max_associations: 2,
            max_routes: 1,
        })
        .unwrap();
    let bearer = route_full
        .add_bearer(FakePacketBearer::<Pool>::new(
            BearerName::new("route-full").unwrap(),
        ))
        .unwrap();
    route_full
        .associate(
            PacketMeta {
                bearer,
                peer_l2_address: PeerL2Address::new(1).unwrap(),
                received_at_us: 0,
            },
            0,
        )
        .unwrap();
    assert_eq!(
        route_full.associate(
            PacketMeta {
                bearer,
                peer_l2_address: PeerL2Address::new(2).unwrap(),
                received_at_us: 1,
            },
            1,
        ),
        Err(QuicNodeEgressError::Association(QuicNodeError::Routing))
    );
    assert_eq!(route_full.association_count(), 1);
}

#[test]
fn public_node_creates_and_owns_client_association_state() {
    let mut node = Node::new(None, &CLIENT_POOL);
    let bearer_impl = FakePacketBearer::<Pool>::new(BearerName::new("capture0").unwrap());
    let sent = bearer_impl.sent_packets();
    let bearer = node.add_bearer(bearer_impl).unwrap();
    let _association = node
        .associate(
            PacketMeta {
                bearer,
                peer_l2_address: PeerL2Address::new(1).unwrap(),
                received_at_us: 0,
            },
            0,
        )
        .unwrap();
    assert_eq!(node.association_count(), 1);
    assert!(!sent.lock().unwrap().is_empty());
}

#[tokio::test]
async fn framed_tcp_is_one_complete_node_bearer() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let connect = tokio::net::TcpStream::connect(listener.local_addr().unwrap());
    let accept = listener.accept();
    let (client, server) = tokio::join!(connect, accept);

    let mut client_node = Node::new(None, &CLIENT_POOL);
    let client_bearer = TokioFramedBearer::<Pool>::from_tcp(
        client.unwrap(),
        BearerName::new("tcp-client").unwrap(),
    );
    let client_bearer = client_node.add_bearer(client_bearer).unwrap();

    static SERVER_POOL: Pool = Pool::new();
    let mut server_node = Node::new(None, &SERVER_POOL);
    let server_bearer = TokioFramedBearer::<Pool>::from_tcp(
        server.unwrap().0,
        BearerName::new("tcp-server").unwrap(),
    );
    server_node.add_bearer(server_bearer).unwrap();

    let client_association = client_node
        .associate(
            PacketMeta {
                bearer: client_bearer,
                peer_l2_address: PeerL2Address::new(1).unwrap(),
                received_at_us: 0,
            },
            0,
        )
        .unwrap();
    let server = async {
        let first = server_node
            .accept_stream(quic_lite::ConnectionLimits::default())
            .await
            .unwrap();
        let second = server_node
            .accept_stream(quic_lite::ConnectionLimits::default())
            .await
            .unwrap();
        let fin = server_node
            .accept_stream(quic_lite::ConnectionLimits::default())
            .await
            .unwrap();
        (first, second, fin)
    };
    let client = async {
        client_node
            .wait_established(client_association)
            .await
            .unwrap();
        let mut stream = client_node.open_stream(client_association).unwrap();
        client_node.write_stream(&mut stream, b"over ").unwrap();
        client_node
            .write_stream(&mut stream, b"framed tcp")
            .unwrap();
        client_node.finish_stream(&mut stream).unwrap();
    };
    let ((first, second, fin), ()) = tokio::join!(server, client);
    assert_eq!(first.bytes, b"over ");
    assert_eq!(first.offset, 0);
    assert!(!first.fin);
    assert_eq!(second.bytes, b"framed tcp");
    assert_eq!(second.offset, 5);
    assert!(!second.fin);
    assert!(fin.bytes.is_empty());
    assert!(fin.fin);
}

#[tokio::test]
async fn framed_bearer_connects_through_its_public_tcp_initializer() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let connect =
        TokioFramedBearer::<Pool>::connect_tcp(address, BearerName::new("tcp-connect").unwrap());
    let accept = listener.accept();
    let (bearer, accepted) = tokio::join!(connect, accept);
    let mut node = Node::new(None, &CLIENT_POOL);
    assert!(node.add_bearer(bearer.unwrap()).is_ok());
    drop(accepted.unwrap());
}

#[tokio::test]
async fn paired_fake_establishes_and_delivers_multi_packet_fin_through_public_api() {
    static FIRST_POOL: Pool = Pool::new();
    static SECOND_POOL: Pool = Pool::new();
    let (first_bearer, second_bearer) = FakePacketBearer::<Pool>::pair(
        BearerName::new("fake-a").unwrap(),
        BearerName::new("fake-b").unwrap(),
    );
    let mut client = Node::new(None, &FIRST_POOL);
    let mut server = Node::new(None, &SECOND_POOL);
    let client_bearer = client.add_bearer(first_bearer).unwrap();
    server.add_bearer(second_bearer).unwrap();

    let client_association = client
        .associate(
            PacketMeta {
                bearer: client_bearer,
                peer_l2_address: PeerL2Address::new(1).unwrap(),
                received_at_us: 0,
            },
            0,
        )
        .unwrap();
    let server_future = async {
        let first = server
            .accept_stream(quic_lite::ConnectionLimits::default())
            .await
            .unwrap();
        let second = server
            .accept_stream(quic_lite::ConnectionLimits::default())
            .await
            .unwrap();
        let fin = server
            .accept_stream(quic_lite::ConnectionLimits::default())
            .await
            .unwrap();
        (first, second, fin)
    };
    let client_future = async {
        client.wait_established(client_association).await.unwrap();
        let mut stream = client.open_stream(client_association).unwrap();
        client.write_stream(&mut stream, b"first").unwrap();
        client.write_stream(&mut stream, b"second").unwrap();
        client.finish_stream(&mut stream).unwrap();
    };
    let ((first, second, fin), ()) = tokio::join!(server_future, client_future);
    assert_eq!(first.offset, 0);
    assert_eq!(first.bytes, b"first");
    assert!(!first.fin);
    assert_eq!(second.offset, 5);
    assert_eq!(second.bytes, b"second");
    assert!(!second.fin);
    assert!(fin.bytes.is_empty());
    assert!(fin.fin);
}

#[tokio::test]
async fn small_pool_handles_multiple_associations_and_streams_without_cross_delivery() {
    static FIRST_POOL: Pool = Pool::new();
    static SECOND_POOL: Pool = Pool::new();
    let (first_bearer, second_bearer) = FakePacketBearer::<Pool>::pair(
        BearerName::new("stress-a").unwrap(),
        BearerName::new("stress-b").unwrap(),
    );
    let mut client = Node::new(None, &FIRST_POOL);
    let mut server = Node::new(None, &SECOND_POOL);
    let client_bearer = client.add_bearer(first_bearer).unwrap();
    server.add_bearer(second_bearer).unwrap();
    let address = PacketMeta {
        bearer: client_bearer,
        peer_l2_address: PeerL2Address::new(1).unwrap(),
        received_at_us: 0,
    };

    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let mut associations = Vec::new();
        for association_index in 0..4 {
            let client_association = client.associate(address, 0).unwrap();
            let server_future = server.accept_stream(quic_lite::ConnectionLimits::default());
            let client_future = async {
                client.wait_established(client_association).await.unwrap();
                let mut stream = client.open_stream(client_association).unwrap();
                client
                    .write_stream(&mut stream, &[association_index as u8, 0xff])
                    .unwrap();
                client.finish_stream(&mut stream).unwrap();
            };
            let (received, ()) = tokio::join!(server_future, client_future);
            assert_eq!(received.unwrap().bytes, [association_index as u8, 0xff]);
            let fin = server
                .accept_stream(quic_lite::ConnectionLimits::default())
                .await
                .unwrap();
            assert!(fin.bytes.is_empty() && fin.fin);
            associations.push(client_association);
        }

        for (association_index, client_association) in associations.iter().copied().enumerate() {
            // This borrowed-node test deliberately does not run a client
            // ingress driver for pure ACK packets. Keep its unacknowledged
            // send history below the selected eight-packet limit; the owned
            // Tokio driver tests sustained stream recycling separately.
            for stream_index in 0..2 {
                let expected = [association_index as u8, stream_index as u8];
                let mut stream = client.open_stream(client_association).unwrap();
                client.write_stream(&mut stream, &expected).unwrap();
                let received = server
                    .accept_stream(quic_lite::ConnectionLimits::default())
                    .await
                    .unwrap();
                assert_eq!(received.offset, 0);
                assert_eq!(received.bytes, expected);
                assert!(!received.fin);
                client.finish_stream(&mut stream).unwrap();
                let fin = server
                    .accept_stream(quic_lite::ConnectionLimits::default())
                    .await
                    .unwrap();
                assert!(fin.bytes.is_empty() && fin.fin);
            }
        }

        // Queue one stream from every association before reading them in the
        // opposite order. Waiting for one association must retain, not discard,
        // chunks which arrived first for another association.
        for (association_index, client_association) in associations.iter().copied().enumerate() {
            let mut stream = client.open_stream(client_association).unwrap();
            client
                .write_stream(&mut stream, &[0xa0, association_index as u8])
                .unwrap();
            client.finish_stream(&mut stream).unwrap();
        }
        let mut received_ids = Vec::new();
        for _ in 0..associations.len() * 2 {
            let received = server
                .accept_stream(quic_lite::ConnectionLimits::default())
                .await
                .unwrap();
            if received.bytes.is_empty() {
                assert!(received.fin);
                continue;
            }
            assert_eq!(received.bytes[0], 0xa0);
            received_ids.push(received.bytes[1]);
            assert!(!received.fin);
        }
        received_ids.sort_unstable();
        assert_eq!(received_ids, vec![0, 1, 2, 3]);
    })
    .await
    .expect("small-pool multi-association stream traffic stalled");
}

#[tokio::test]
async fn udp_establishes_and_delivers_multi_packet_fin_through_public_api() {
    static UDP_CLIENT_POOL: Pool = Pool::new();
    static UDP_SERVER_POOL: Pool = Pool::new();
    let mut client_bearer = TokioUdpBearer::<8>::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let mut server_bearer = TokioUdpBearer::<8>::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    client_bearer.set_name(BearerName::new("udp-client").unwrap());
    server_bearer.set_name(BearerName::new("udp-server").unwrap());
    let server_address = server_bearer.local_addr().unwrap();
    let client_address = client_bearer.local_addr().unwrap();
    let server_peer = client_bearer.register_peer(server_address).unwrap();
    server_bearer.register_peer(client_address).unwrap();

    let mut client = Node::new(None, &UDP_CLIENT_POOL);
    let mut server = Node::new(None, &UDP_SERVER_POOL);
    let client_bearer = client.add_bearer(client_bearer).unwrap();
    server.add_bearer(server_bearer).unwrap();
    let client_association = client
        .associate(
            PacketMeta {
                bearer: client_bearer,
                peer_l2_address: server_peer,
                received_at_us: 0,
            },
            0,
        )
        .unwrap();
    let exchange = async {
        let server_future = async {
            let first = server
                .accept_stream(quic_lite::ConnectionLimits::default())
                .await
                .unwrap();
            let second = server
                .accept_stream(quic_lite::ConnectionLimits::default())
                .await
                .unwrap();
            let fin = server
                .accept_stream(quic_lite::ConnectionLimits::default())
                .await
                .unwrap();
            (first, second, fin)
        };
        let client_future = async {
            client.wait_established(client_association).await.unwrap();
            let mut stream = client.open_stream(client_association).unwrap();
            client.write_stream(&mut stream, b"udp-1").unwrap();
            client.write_stream(&mut stream, b"udp-2").unwrap();
            client.finish_stream(&mut stream).unwrap();
        };
        tokio::join!(server_future, client_future).0
    };
    let (first, second, fin) = tokio::time::timeout(std::time::Duration::from_secs(3), exchange)
        .await
        .expect("UDP association or stream exchange stalled");
    assert_eq!(first.offset, 0);
    assert_eq!(first.bytes, b"udp-1");
    assert!(!first.fin);
    assert_eq!(second.offset, 5);
    assert_eq!(second.bytes, b"udp-2");
    assert!(!second.fin);
    assert!(fin.bytes.is_empty());
    assert!(fin.fin);
}
