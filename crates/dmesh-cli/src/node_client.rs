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

/// Run the binary QUIC probe workload over one UDP association. The request is
/// still the canonical tagged service record; the response body is validated
/// incrementally so large probes do not need to be retained in one Vec.
pub(crate) async fn probe_udp(
    bind: SocketAddr,
    peer: SocketAddr,
    payload: &[u8],
    request: dmesh_server::probe::ProbeServiceRequest,
    timeout: Duration,
) -> Result<quic_lite::probe::ProbeResult, String> {
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
            exchange_probe(association, payload, request).await
        };
        tokio::select! {
            result = driver.run() => Err(format!("UDP QUIC driver stopped: {result:?}")),
            result = operation => result,
        }
    };
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| format!("UDP QUIC probe timed out after {timeout:?}"))?
}

async fn exchange_probe(
    association: TokioAssociation,
    payload: &[u8],
    request: dmesh_server::probe::ProbeServiceRequest,
) -> Result<quic_lite::probe::ProbeResult, String> {
    association
        .wait_established()
        .await
        .map_err(node_error("establish UDP probe association"))?;
    let mut stream = association
        .open_stream()
        .await
        .map_err(node_error("open UDP probe stream"))?;
    stream
        .write_all(payload)
        .await
        .map_err(|error| format!("write UDP probe request: {error}"))?;
    stream
        .shutdown()
        .await
        .map_err(|error| format!("finish UDP probe request: {error}"))?;

    let plan =
        quic_lite::probe::ProbePlan::from_request(request, quic_lite::DEFAULT_MAX_STREAM_PAYLOAD);
    let mut receiver = quic_lite::probe::ProbeReceiver::new(2);
    let started = std::time::Instant::now();
    if let Some(delay) = request.initial_consume_delay_ms.filter(|delay| *delay != 0) {
        tokio::time::sleep(Duration::from_millis(u64::from(delay))).await;
    }
    let expected = request.bytes.min(quic_lite::probe::MAX_BYTES);
    let mut offset = 0u64;
    let mut bytes = vec![0u8; plan.packet_size.max(8)];
    loop {
        let len = stream
            .read(&mut bytes)
            .await
            .map_err(|error| format!("read UDP probe response: {error}"))?;
        if len == 0 {
            break;
        }
        if offset == 0
            && let Some(error) = tagged_stream_error(&bytes[..len])
        {
            return Err(format!("peer rejected UDP probe request: {error}"));
        }
        let fin = offset.saturating_add(len as u64) == expected;
        receiver
            .receive(offset, fin, &bytes[..len])
            .map_err(|error| format!("invalid UDP probe response: {error:?}"))?;
        offset = offset.saturating_add(len as u64);
        if let Some(delay) = request.consume_delay_ms.filter(|delay| *delay != 0) {
            tokio::time::sleep(Duration::from_millis(u64::from(delay))).await;
        }
    }
    if !receiver.is_complete() || receiver.bytes() != expected {
        return Err(format!(
            "UDP probe response ended after {} of {expected} bytes",
            receiver.bytes()
        ));
    }
    association
        .finish()
        .await
        .map_err(node_error("finish UDP probe association"))?;
    let elapsed_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    Ok(quic_lite::probe::ProbeResult {
        bytes: receiver.bytes(),
        normal_bytes: receiver.bytes(),
        high_bytes: 0,
        low_bytes: 0,
        elapsed_us,
        callback_errors: *receiver.callback_errors(),
    })
}

fn tagged_stream_error(bytes: &[u8]) -> Option<String> {
    let record = dmesh_server::tagged::decode(bytes)?;
    let error = record.error?;
    let mut decoder = dmesh_server::cbor::Decoder::new(error);
    let error = decoder.text_ref()?;
    decoder
        .is_finished()
        .then(|| String::from_utf8_lossy(error).into_owned())
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
    let mut bearer_impl = port
        .into_tokio::<POOL_SLOTS, SLOT_SIZE>(BearerName::new("uart").unwrap())
        .map_err(|error| error.to_string())?;
    bearer_impl.set_sideband_handler(|received| {
        for line in received.logs {
            eprintln!("dmesh_uart_console {line:?}");
        }
        for bytes in received.log_records {
            if let Ok(text) = std::str::from_utf8(&bytes) {
                for line in text.lines().filter(|line| !line.is_empty()) {
                    eprintln!("dmesh_uart_log {line:?}");
                }
            } else {
                let hex = bytes
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                eprintln!("dmesh_uart_log_packet hex={hex}");
            }
        }
        if received.pool_drops != 0 {
            eprintln!("dmesh_uart_log_drop pool={}", received.pool_drops);
        }
    });
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

#[cfg(test)]
mod tests {
    use super::request_udp;
    use std::{
        net::{SocketAddr, UdpSocket},
        thread,
        time::Duration,
    };

    use quic_lite::{
        AssociationLimits, NodeLimits, QuicNode, packet_pool::PacketPool, tokio::TokioNodeDriver,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    type TestPool = PacketPool<16, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
    type TestNode = QuicNode<TestPool>;

    #[test]
    fn udp_client_completes_a_quic_stream_request_and_response() {
        static SERVER_POOL: TestPool = TestPool::new();
        let request: Vec<u8> = (0..32 * 1024)
            .map(|index| b'a' + (index % 26) as u8)
            .collect();
        let expected: Vec<u8> = request.iter().map(u8::to_ascii_uppercase).collect();

        let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_address = server_socket.local_addr().unwrap();
        let server = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let bearer =
                    quic_lite::bearer_udp::TokioUdpBearer::<8>::from_std(server_socket).unwrap();
                let mut node = TestNode::new(None, &SERVER_POOL);
                node.set_limits(NodeLimits::host()).unwrap();
                node.set_default_association_limits(AssociationLimits::host())
                    .unwrap();
                node.add_bearer(bearer).unwrap();
                let (server, driver) =
                    TokioNodeDriver::new(node, AssociationLimits::host().connection);
                let serve = async {
                    let mut stream =
                        tokio::time::timeout(Duration::from_secs(3), server.accept_stream())
                            .await
                            .expect("server did not accept the UDP QUIC stream")
                            .expect("server stream acceptance failed");
                    let mut request = Vec::new();
                    stream.read_to_end(&mut request).await.unwrap();
                    request.make_ascii_uppercase();
                    stream.write_all(&request).await.unwrap();
                    stream.shutdown().await.unwrap();
                };
                tokio::select! {
                    result = driver.run() => panic!("UDP server driver stopped: {result:?}"),
                    () = serve => {},
                }
            });
        });

        let response = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(request_udp(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
                server_address,
                &request,
                Duration::from_secs(3),
            ))
            .expect("UDP QUIC request failed");
        server.join().unwrap();
        assert_eq!(response.bytes, expected);
    }

    #[test]
    fn udp_probe_without_a_registered_handler_finishes_with_a_tagged_error() {
        static SERVER_POOL: TestPool = TestPool::new();

        let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_address = server_socket.local_addr().unwrap();
        let server = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let bearer =
                    quic_lite::bearer_udp::TokioUdpBearer::<8>::from_std(server_socket).unwrap();
                let mut node = TestNode::new(None, &SERVER_POOL);
                node.set_limits(NodeLimits::host()).unwrap();
                node.set_default_association_limits(AssociationLimits::host())
                    .unwrap();
                node.add_bearer(bearer).unwrap();
                let (server, driver) =
                    TokioNodeDriver::new(node, AssociationLimits::host().connection);
                let serve = async {
                    let mut stream =
                        tokio::time::timeout(Duration::from_secs(3), server.accept_stream())
                            .await
                            .expect("server did not accept the UDP QUIC probe")
                            .expect("server stream acceptance failed");
                    let mut request = Vec::new();
                    stream.read_to_end(&mut request).await.unwrap();
                    let response = dmesh_server::services::dispatch_tagged_stream(&request)
                        .expect("valid unsupported probe should receive a tagged error");
                    stream.write_all(&response).await.unwrap();
                    stream.shutdown().await.unwrap();
                };
                tokio::select! {
                    result = driver.run() => panic!("UDP server driver stopped: {result:?}"),
                    () = serve => {},
                }
            });
        });

        let mut request_wire = [0u8; dmesh_server::probe::PROBE_RUN_REQUEST_MAX];
        let request_len = dmesh_server::probe::encode_probe_run_request(
            dmesh_server::probe::ProbeServiceRequest::new(4096, 512),
            0x1234,
            &mut request_wire,
        )
        .unwrap();

        let response = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(request_udp(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
                server_address,
                &request_wire[..request_len],
                Duration::from_secs(3),
            ))
            .expect("UDP QUIC probe request did not complete");
        server.join().unwrap();

        let record = dmesh_server::tagged::decode(&response.bytes).unwrap();
        assert_eq!(record.component, Some(dmesh_server::tagged::Name::Tag(8)));
        assert_eq!(record.method, Some(dmesh_server::tagged::Name::Tag(1)));
        assert_eq!(record.id, Some(0x1234));
        assert!(record.error.is_some());
    }

    #[test]
    fn udp_probe_stream_validates_the_peer_payload_and_completion() {
        static SERVER_POOL: TestPool = TestPool::new();

        let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_address = server_socket.local_addr().unwrap();
        let server = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let bearer =
                    quic_lite::bearer_udp::TokioUdpBearer::<8>::from_std(server_socket).unwrap();
                let mut node = TestNode::new(None, &SERVER_POOL);
                node.set_limits(NodeLimits::host()).unwrap();
                node.set_default_association_limits(AssociationLimits::host())
                    .unwrap();
                node.add_bearer(bearer).unwrap();
                let (server, driver) =
                    TokioNodeDriver::new(node, AssociationLimits::host().connection);
                let serve = async {
                    let mut stream =
                        tokio::time::timeout(Duration::from_secs(3), server.accept_stream())
                            .await
                            .expect("server did not accept the UDP probe")
                            .expect("server stream acceptance failed");
                    let mut request_wire = Vec::new();
                    stream.read_to_end(&mut request_wire).await.unwrap();
                    let record = dmesh_server::tagged::decode(&request_wire).unwrap();
                    let (_, request) =
                        dmesh_server::probe::decode_probe_run_record(record).unwrap();
                    let plan = quic_lite::probe::ProbePlan::from_request(
                        request,
                        quic_lite::DEFAULT_MAX_STREAM_PAYLOAD,
                    );
                    let mut sender = quic_lite::probe::ProbeSender::new(
                        0,
                        request.bytes as usize,
                        plan.packet_size,
                    )
                    .unwrap();
                    let mut payload = vec![0u8; plan.packet_size];
                    while !sender.is_complete() {
                        let chunk = sender.prepare(u64::MAX, &mut payload).unwrap();
                        stream.write_all(&payload[..chunk.len]).await.unwrap();
                        stream.flush().await.unwrap();
                        sender.commit(chunk).unwrap();
                    }
                    stream.shutdown().await.unwrap();
                };
                tokio::select! {
                    result = driver.run() => panic!("UDP server driver stopped: {result:?}"),
                    () = serve => {},
                }
            });
        });

        let probe_request = dmesh_server::probe::ProbeServiceRequest::new(256 * 1024, 512);
        let mut request_wire = [0u8; dmesh_server::probe::PROBE_RUN_REQUEST_MAX];
        let request_len =
            dmesh_server::probe::encode_probe_run_request(probe_request, 0x5678, &mut request_wire)
                .unwrap();
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(super::probe_udp(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
                server_address,
                &request_wire[..request_len],
                probe_request,
                Duration::from_secs(3),
            ))
            .expect("UDP probe did not finish");
        server.join().unwrap();
        assert_eq!(result.bytes, probe_request.bytes);
        assert_eq!(result.normal_bytes, probe_request.bytes);
        assert_eq!(result.callback_errors, [0; 6]);
        assert!(result.elapsed_us > 0);
    }
}
