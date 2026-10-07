#![cfg(feature = "tokio")]
use quic_lite::{
    AssociationEvent, AssociationLimits, BearerName, ConnectionLimits, DatagramPriority,
    OwnedPacket, PacketMeta, PacketPool as _, PacketWriter as _, PeerL2Address, QuicNode,
    fake::FakePacketBearer, packet_pool::PacketPool, tokio::TokioNodeDriver,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
type Pool = PacketPool<16, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
type Buffer = <Pool as quic_lite::PacketPool>::Buffer;
type Node = QuicNode<Pool>;
fn pool() -> &'static Pool {
    Box::leak(Box::new(Pool::new()))
}
fn packet(pool: &'static Pool, bytes: &[u8]) -> OwnedPacket<Buffer> {
    let mut writer = quic_lite::PacketPool::acquire_writer(pool, 80, 0).unwrap();
    writer.payload_mut()[..bytes.len()].copy_from_slice(bytes);
    quic_lite::PacketWriter::commit(writer, bytes.len()).unwrap()
}
fn limits() -> ConnectionLimits {
    AssociationLimits::host().connection
}

#[tokio::test]
async fn registered_datagrams_and_regular_streams_share_the_tokio_driver() {
    let (ap, cp) = (pool(), pool());
    let (first, second) = FakePacketBearer::<Pool>::pair(
        BearerName::new("dg-first").unwrap(),
        BearerName::new("dg-second").unwrap(),
    );
    let mut a = Node::new(ap);
    let mut c = Node::new(cp);
    for node in [&mut a, &mut c] {
        node.set_default_association_limits(AssociationLimits {
            connection: limits(),
            ..AssociationLimits::host()
        })
        .unwrap();
    }
    let bearer = a.add_bearer(first).unwrap();
    c.add_bearer(second).unwrap();
    let (a, a_driver) = TokioNodeDriver::new(a, limits());
    let (c, c_driver) = TokioNodeDriver::new(c, limits());
    let scenario = async {
        let association = a
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
        let ca = loop {
            if let AssociationEvent::CircuitOpened { association, .. } =
                c.next_event().await.unwrap()
            {
                break association;
            }
        };
        let (received, mut incoming) = tokio::sync::mpsc::channel(1);
        c.set_datagram_handler::<Pool, { quic_lite::DEFAULT_MAX_PACKET_SIZE }>(ca, move |batch| {
            // Explicit one-record application admission: excess records drop
            // with their lease, without a hidden proxy forwarding queue.
            let _ = received.try_send(batch.packet);
        })
        .await
        .unwrap();
        for index in 0..64 {
            let bytes = [index as u8; 256];
            association
                .send_datagram(packet(ap, &bytes), DatagramPriority::High)
                .await
                .unwrap();
            let payload = incoming.recv().await.unwrap();
            assert_eq!(payload.bytes(), bytes);
            drop(payload);
        }
        let upload = async {
            let mut stream = association.open_stream().await.unwrap();
            stream.write_all(&vec![0x5a; 8192]).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"ok");
        };
        let server = async {
            let mut stream = c.accept_stream().await.unwrap();
            let mut body = Vec::new();
            stream.read_to_end(&mut body).await.unwrap();
            assert_eq!(body, vec![0x5a; 8192]);
            stream.write_all(b"ok").await.unwrap();
            stream.shutdown().await.unwrap();
        };
        tokio::join!(upload, server);
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! { () = scenario => {}, result = a_driver.run() => panic!("a driver {result:?}"), result = c_driver.run() => panic!("c driver {result:?}") }
    }).await.unwrap();
    assert_eq!(ap.available(), ap.capacity());
    assert_eq!(cp.available(), cp.capacity());
}

#[tokio::test]
async fn stopped_driver_returns_original_lease() {
    let ap = pool();
    let mut node = Node::new(ap);
    // Obtain a real public association handle before cancelling its driver.
    let bearer = node
        .add_bearer(FakePacketBearer::<Pool>::new(
            BearerName::new("admission").unwrap(),
        ))
        .unwrap();
    let (handle, mut driver) = TokioNodeDriver::new(node, limits());
    let association = {
        let request = handle.associate(
            PacketMeta {
                bearer,
                peer_l2_address: PeerL2Address::new(1).unwrap(),
                received_at_us: 0,
            },
            0,
        );
        tokio::pin!(request);
        tokio::select! { result = &mut request => result.unwrap(), result = driver.run() => panic!("driver {result:?}") }
    };
    // The driver future above was cancelled, dropping the driver. Verify the
    // public stopped-driver refusal preserves the same range and address.
    let input = packet(ap, b"unchanged");
    let pointer = input.bytes().as_ptr();
    let error = association
        .send_datagram(input, DatagramPriority::High)
        .await
        .unwrap_err();
    assert_eq!(error.packet.bytes(), b"unchanged");
    assert_eq!(error.packet.bytes().as_ptr(), pointer);
}
