//! Minimal client/server byte stream over two registered packet bearers.
//!
//! The application uses the same `AsyncRead` and `AsyncWrite` operations as a
//! TCP stream. Packet framing, association setup, flow control, ACKs, and FIN
//! remain inside `QuicNode`.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use quic_lite::{
    BearerName, ConnectionLimits, PacketMeta, PeerL2Address, QuicNode, fake::FakePacketBearer,
    packet_pool::PacketPool, tokio::TokioNodeDriver,
};

type Pool = PacketPool<8, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
type Node = QuicNode<Pool>;

static CLIENT_POOL: Pool = Pool::new();
static SERVER_POOL: Pool = Pool::new();

#[tokio::main(flavor = "current_thread")]
async fn main() {
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
            let mut stream = server.accept_stream().await.unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"one request split across writes");
            stream.write_all(b"one response").await.unwrap();
            stream.shutdown().await.unwrap();
        };

        let call = async {
            association.wait_established().await.unwrap();
            let mut stream = association.open_stream().await.unwrap();
            stream.write_all(b"one request ").await.unwrap();
            stream.write_all(b"split across writes").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"one response");
        };

        tokio::join!(serve, call);
    };
    tokio::select! {
        result = client_driver.run() => panic!("client driver stopped: {result:?}"),
        result = server_driver.run() => panic!("server driver stopped: {result:?}"),
        () = application => {}
    }
}
