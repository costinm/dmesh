//! Small host adapter around quic-lite's node-owned stream API.

use std::{net::SocketAddr, time::Duration};

use quic_lite::{
    BearerName, PacketMeta, PeerL2Address, QuicNode, QuicNodeEgressError,
    packet_pool::PacketPool,
    tokio::{TokioAssociation, TokioNodeDriver},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const POOL_SLOTS: usize = 16;
const SLOT_SIZE: usize = quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE;
type Pool = PacketPool<POOL_SLOTS, SLOT_SIZE>;
type Node = QuicNode<Pool>;

static UDP_POOL: Pool = Pool::new();
static UART_POOL: Pool = Pool::new();

pub(crate) struct Response {
    pub bytes: Vec<u8>,
}

async fn exchange(association: TokioAssociation, payload: &[u8]) -> Result<Response, String> {
    association
        .wait_established()
        .await
        .map_err(node_error("establish association"))?;
    let mut request = association
        .open_stream()
        .await
        .map_err(node_error("open request stream"))?;
    request
        .write_all(payload)
        .await
        .map_err(|error| format!("write request stream: {error}"))?;
    request
        .shutdown()
        .await
        .map_err(|error| format!("finish request stream: {error}"))?;
    let mut bytes = Vec::new();
    request
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| format!("read response stream: {error}"))?;
    association
        .finish()
        .await
        .map_err(node_error("finish association"))?;
    Ok(Response { bytes })
}

async fn flash_exchange(
    association: TokioAssociation,
    manifest: &[u8],
    image: &[u8],
) -> Result<Response, String> {
    let manifest_len = u32::try_from(manifest.len())
        .map_err(|_| "flash manifest exceeds the u32 wire length".to_owned())?;
    association
        .wait_established()
        .await
        .map_err(node_error("establish association"))?;
    let mut stream = association
        .open_stream()
        .await
        .map_err(node_error("open flash stream"))?;
    stream
        .write_all(&manifest_len.to_be_bytes())
        .await
        .map_err(|error| format!("write flash manifest length: {error}"))?;
    stream
        .write_all(manifest)
        .await
        .map_err(|error| format!("write flash manifest: {error}"))?;
    stream
        .write_all(image)
        .await
        .map_err(|error| format!("write flash image: {error}"))?;
    stream
        .shutdown()
        .await
        .map_err(|error| format!("finish flash stream: {error}"))?;

    let mut bytes = Vec::new();
    stream
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| format!("read flash result: {error}"))?;
    association
        .finish()
        .await
        .map_err(node_error("finish association"))?;
    Ok(Response { bytes })
}

fn node_error(context: &'static str) -> impl FnOnce(QuicNodeEgressError) -> String {
    move |error| format!("{context}: {error:?}")
}

pub(crate) async fn request_udp(
    bind: SocketAddr,
    peer: SocketAddr,
    payload: &[u8],
    timeout: Duration,
) -> Result<Response, String> {
    let future = async {
        let bearer_impl = quic_lite::bearer_udp::TokioUdpBearer::<8>::bind(bind)
            .await
            .map_err(|error| error.to_string())?;
        let peer_l2_address = bearer_impl
            .register_peer(peer)
            .map_err(|error| format!("register UDP peer: {error:?}"))?;
        let mut node = Node::new(None, &UDP_POOL);
        node.set_limits(quic_lite::NodeLimits::host())
            .expect("host QUIC node limits are valid");
        node.set_default_association_limits(quic_lite::AssociationLimits::host())
            .expect("host QUIC association limits are valid");
        let bearer = node
            .add_bearer(bearer_impl)
            .map_err(|error| format!("attach UDP bearer: {error:?}"))?;
        let (client, driver) =
            TokioNodeDriver::new(node, quic_lite::AssociationLimits::host().connection);
        let operation = async {
            let association = client
                .associate(
                    PacketMeta {
                        bearer,
                        peer_l2_address,
                        received_at_us: 0,
                    },
                    0,
                )
                .await
                .map_err(node_error("start UDP association"))?;
            exchange(association, payload).await
        };
        tokio::select! {
            result = driver.run() => Err(format!("UDP QUIC driver stopped: {result:?}")),
            result = operation => result,
        }
    };
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| format!("UDP stream request timed out after {timeout:?}"))?
}

pub(crate) async fn flash_udp(
    bind: SocketAddr,
    peer: SocketAddr,
    manifest: &[u8],
    image: &[u8],
    timeout: Duration,
) -> Result<Response, String> {
    let future = async {
        let bearer_impl = quic_lite::bearer_udp::TokioUdpBearer::<8>::bind(bind)
            .await
            .map_err(|error| error.to_string())?;
        let peer_l2_address = bearer_impl
            .register_peer(peer)
            .map_err(|error| format!("register UDP peer: {error:?}"))?;
        let mut node = Node::new(None, &UDP_POOL);
        node.set_limits(quic_lite::NodeLimits::host())
            .expect("host QUIC node limits are valid");
        node.set_default_association_limits(quic_lite::AssociationLimits::host())
            .expect("host QUIC association limits are valid");
        let bearer = node
            .add_bearer(bearer_impl)
            .map_err(|error| format!("attach UDP bearer: {error:?}"))?;
        let (client, driver) =
            TokioNodeDriver::new(node, quic_lite::AssociationLimits::host().connection);
        let operation = async {
            let association = client
                .associate(
                    PacketMeta {
                        bearer,
                        peer_l2_address,
                        received_at_us: 0,
                    },
                    0,
                )
                .await
                .map_err(node_error("start UDP association"))?;
            flash_exchange(association, manifest, image).await
        };
        tokio::select! {
            result = driver.run() => Err(format!("UDP QUIC driver stopped: {result:?}")),
            result = operation => result,
        }
    };
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| format!("UDP flash stream timed out after {timeout:?}"))?
}

pub(crate) async fn request_uart(
    path: &str,
    baud: Option<u32>,
    payload: &[u8],
    timeout: Duration,
) -> Result<Response, String> {
    let port = uart_codec::host::UartPort::open(path, baud).map_err(|error| error.to_string())?;
    let bearer_impl = port
        .into_tokio::<POOL_SLOTS, SLOT_SIZE>(BearerName::new("uart").unwrap())
        .map_err(|error| error.to_string())?;
    let future = async {
        let mut node = Node::new(None, &UART_POOL);
        node.set_limits(quic_lite::NodeLimits::host())
            .expect("host QUIC node limits are valid");
        node.set_default_association_limits(quic_lite::AssociationLimits::host())
            .expect("host QUIC association limits are valid");
        let bearer = node
            .add_bearer(bearer_impl)
            .map_err(|error| format!("attach UART bearer: {error:?}"))?;
        let (client, driver) =
            TokioNodeDriver::new(node, quic_lite::AssociationLimits::host().connection);
        let operation = async {
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
                .map_err(node_error("start UART association"))?;
            exchange(association, payload).await
        };
        tokio::select! {
            result = driver.run() => Err(format!("UART QUIC driver stopped: {result:?}")),
            result = operation => result,
        }
    };
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| format!("UART stream request timed out after {timeout:?}"))?
}
