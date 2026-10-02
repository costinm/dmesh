//! Small host adapter around quic-lite's node-owned stream API.

use std::{future::Future, net::SocketAddr, time::Duration};

use quic_lite::{
    BearerName, PacketMeta, PeerL2Address, QuicNode, QuicNodeEgressError,
    packet_pool::PacketPool,
    tokio::{TokioAssociation, TokioNodeDriver},
};

const POOL_SLOTS: usize = 16;
const SLOT_SIZE: usize = quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE;
type Pool = PacketPool<POOL_SLOTS, SLOT_SIZE>;
type Node = QuicNode<Pool>;

static CLIENT_POOL: Pool = Pool::new();
static UDP_POOL: Pool = Pool::new();

pub(crate) struct Response {
    pub bytes: Vec<u8>,
}

fn new_node() -> Node {
    let mut node = Node::new(&CLIENT_POOL);
    configure_node(&mut node);
    node
}

fn configure_node(node: &mut Node) {
    node.set_limits(quic_lite::NodeLimits::host())
        .expect("host QUIC node limits are valid");
    node.set_default_association_limits(quic_lite::AssociationLimits::host())
        .expect("host QUIC association limits are valid");
}

async fn run_node<T, F, Fut>(node: Node, operation: F) -> Result<T, String>
where
    F: FnOnce(quic_lite::tokio::TokioNode) -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    let (client, driver) =
        TokioNodeDriver::new(node, quic_lite::AssociationLimits::host().connection);
    tokio::select! {
        result = driver.run() => Err(format!("QUIC node driver stopped: {result:?}")),
        result = operation(client) => result,
    }
}

#[derive(Clone, Copy)]
struct ClientPath {
    bearer: quic_lite::BearerId,
    peer_l2_address: PeerL2Address,
}

async fn associate_paths(
    client: &quic_lite::tokio::TokioNode,
    primary: ClientPath,
    additional: &[ClientPath],
) -> Result<TokioAssociation, String> {
    let association = client
        .associate(
            PacketMeta {
                bearer: primary.bearer,
                peer_l2_address: primary.peer_l2_address,
                received_at_us: 0,
            },
            0,
        )
        .await
        .map_err(node_error("start QUIC association"))?;
    association
        .wait_established()
        .await
        .map_err(node_error("establish QUIC association"))?;
    for path in additional {
        let circuit = association
            .add_direct_circuit(
                quic_lite::CircuitNextHop {
                    bearer: path.bearer,
                    peer_l2_address: path.peer_l2_address,
                },
                0,
            )
            .await
            .map_err(node_error("join additional QUIC bearer"))?;
        eprintln!("dmesh_cli_path_join queued circuit={circuit:?}");
    }
    Ok(association)
}

fn attach_uart(node: &mut Node, path: &str, baud: Option<u32>) -> Result<ClientPath, String> {
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
    let bearer = node
        .add_bearer(bearer_impl)
        .map_err(|error| format!("attach UART bearer: {error:?}"))?;
    Ok(ClientPath {
        bearer,
        peer_l2_address: PeerL2Address::new(1).unwrap(),
    })
}

async fn attach_udp(
    node: &mut Node,
    bind: SocketAddr,
    peer: SocketAddr,
) -> Result<ClientPath, String> {
    let bearer_impl = quic_lite::bearer_udp::TokioUdpBearer::<8>::bind(bind)
        .await
        .map_err(|error| error.to_string())?;
    let peer_l2_address = bearer_impl
        .register_peer(peer)
        .map_err(|error| format!("register UDP peer: {error:?}"))?;
    let bearer = node
        .add_bearer(bearer_impl)
        .map_err(|error| format!("attach UDP bearer: {error:?}"))?;
    Ok(ClientPath {
        bearer,
        peer_l2_address,
    })
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
    let bytes = dmesh_server::stream_client::exchange(&mut request, &[payload])
        .await
        .map_err(|error| format!("request stream exchange: {error}"))?;
    association
        .finish()
        .await
        .map_err(node_error("finish association"))?;
    Ok(Response { bytes })
}

/// Send `object.flash`: the request header, then the object as the raw request
/// body (manifest length, manifest, image), then FIN. The response is the
/// terminal header.
async fn flash_exchange(
    association: TokioAssociation,
    request: &[u8],
    manifest: &[u8],
    image: &[u8],
) -> Result<Response, String> {
    let mut stream = association
        .open_stream()
        .await
        .map_err(node_error("open object.flash stream"))?;
    let bytes = dmesh_server::stream_client::flash(&mut stream, request, manifest, image)
        .await
        .map_err(|error| format!("object.flash stream exchange: {error}"))?;
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
        let mut node = Node::new(&UDP_POOL);
        configure_node(&mut node);
        let primary = attach_udp(&mut node, bind, peer).await?;
        run_node(node, |client| async move {
            let association = associate_paths(&client, primary, &[]).await?;
            exchange(association, payload).await
        })
        .await
    };
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| format!("UDP stream request timed out after {timeout:?}"))?
}

pub(crate) async fn request_udp_with_uart(
    bind: SocketAddr,
    peer: SocketAddr,
    uart_path: Option<&str>,
    uart_baud: Option<u32>,
    payload: &[u8],
    timeout: Duration,
) -> Result<Response, String> {
    let future = async {
        let mut node = new_node();
        let primary = attach_udp(&mut node, bind, peer).await?;
        let additional = uart_path
            .map(|path| attach_uart(&mut node, path, uart_baud))
            .transpose()?
            .into_iter()
            .collect::<Vec<_>>();
        let (client, driver) =
            TokioNodeDriver::new(node, quic_lite::AssociationLimits::host().connection);
        let operation = async move {
            let association = associate_paths(&client, primary, &additional).await?;
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
#[cfg(test)]
pub(crate) async fn probe_udp(
    bind: SocketAddr,
    peer: SocketAddr,
    payload: &[u8],
    request: dmesh_server::probe::ProbeServiceRequest,
    timeout: Duration,
) -> Result<quic_lite::probe::ProbeResult, String> {
    probe_udp_with_uart(bind, peer, None, None, payload, request, timeout).await
}

pub(crate) async fn probe_udp_with_uart(
    bind: SocketAddr,
    peer: SocketAddr,
    uart_path: Option<&str>,
    uart_baud: Option<u32>,
    payload: &[u8],
    request: dmesh_server::probe::ProbeServiceRequest,
    timeout: Duration,
) -> Result<quic_lite::probe::ProbeResult, String> {
    let future = async {
        let mut node = new_node();
        let primary = attach_udp(&mut node, bind, peer).await?;
        let additional = uart_path
            .map(|path| attach_uart(&mut node, path, uart_baud))
            .transpose()?
            .into_iter()
            .collect::<Vec<_>>();
        run_node(node, |client| async move {
            let association = associate_paths(&client, primary, &additional).await?;
            exchange_probe(association, payload, request).await
        })
        .await
    };
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| format!("UDP QUIC probe timed out after {timeout:?}"))?
}

/// Run the validated streaming probe over the host UART bearer. The result is
/// consumed in packet-sized chunks, so a large workload does not become a
/// correspondingly large host allocation.
pub(crate) async fn probe_uart(
    path: &str,
    baud: Option<u32>,
    payload: &[u8],
    request: dmesh_server::probe::ProbeServiceRequest,
    timeout: Duration,
) -> Result<quic_lite::probe::ProbeResult, String> {
    let future = async {
        let mut node = new_node();
        let primary = attach_uart(&mut node, path, baud)?;
        run_node(node, |client| async move {
            let association = associate_paths(&client, primary, &[]).await?;
            exchange_probe(association, payload, request).await
        })
        .await
    };
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| format!("UART QUIC probe timed out after {timeout:?}"))?
}

/// Run a probe as the client of the peer's `probe.handler` handler: send the
/// request header (no body, FIN right after it), then validate the response:
/// a header, then the probe payload, however the stream is chunked.
async fn exchange_probe(
    association: TokioAssociation,
    payload: &[u8],
    request: dmesh_server::probe::ProbeServiceRequest,
) -> Result<quic_lite::probe::ProbeResult, String> {
    let mut stream = association
        .open_stream()
        .await
        .map_err(node_error("open QUIC probe stream"))?;
    let result = dmesh_server::stream_client::probe(&mut stream, payload, request)
        .await
        .map_err(|error| format!("probe stream exchange: {error}"))?;
    association
        .finish()
        .await
        .map_err(node_error("finish QUIC probe association"))?;
    Ok(result)
}

pub(crate) async fn flash_udp(
    bind: SocketAddr,
    peer: SocketAddr,
    request: &[u8],
    manifest: &[u8],
    image: &[u8],
    timeout: Duration,
) -> Result<Response, String> {
    let future = async {
        let mut node = new_node();
        let primary = attach_udp(&mut node, bind, peer).await?;
        run_node(node, |client| async move {
            let association = associate_paths(&client, primary, &[]).await?;
            flash_exchange(association, request, manifest, image).await
        })
        .await
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
    request_uart_monitor(
        path,
        baud,
        || Ok(payload.to_vec()),
        timeout,
        None,
        Duration::ZERO,
        |_| {},
    )
    .await
}

/// Keep one physical UART bearer and Tokio node alive while issuing repeated
/// request streams. The payload factory lets callers assign a fresh request ID
/// to each iteration. After a one-shot response, or a failed repeated request,
/// the driver remains active for `linger` so late sideband/crash logs are saved.
pub(crate) async fn request_uart_monitor<F, G>(
    path: &str,
    baud: Option<u32>,
    mut payload: F,
    timeout: Duration,
    repeat_interval: Option<Duration>,
    linger: Duration,
    mut on_response: G,
) -> Result<Response, String>
where
    F: FnMut() -> Result<Vec<u8>, String>,
    G: FnMut(&Response),
{
    let mut node = new_node();
    let primary = attach_uart(&mut node, path, baud)?;
    let future = async {
        run_node(node, |client| async move {
            let mut last_response = None;
            loop {
                let request = payload()?;
                let attempt = async {
                    let association = associate_paths(&client, primary, &[]).await?;
                    exchange(association, &request).await
                };
                let response = match tokio::time::timeout(timeout, attempt).await {
                    Ok(Ok(response)) => response,
                    Ok(Err(error)) => {
                        tokio::time::sleep(linger).await;
                        return Err(error);
                    }
                    Err(_) => {
                        tokio::time::sleep(linger).await;
                        return Err(format!("UART stream request timed out after {timeout:?}"));
                    }
                };
                on_response(&response);
                last_response = Some(response);
                if let Some(interval) = repeat_interval {
                    tokio::time::sleep(interval).await;
                } else {
                    tokio::time::sleep(linger).await;
                    return Ok(last_response.expect("one UART request completed"));
                }
            }
        })
        .await
    };
    future.await
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
                let mut node = TestNode::new(&SERVER_POOL);
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
                let mut node = TestNode::new(&SERVER_POOL);
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
                    let response = dmesh_server::registry::dispatch(
                        &request,
                        true,
                        dmesh_server::registry::CallContext::default(),
                    )
                    .await
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

        let mut request_wire = [0u8; dmesh_server::probe::PROBE_REQUEST_MAX];
        let request_len = dmesh_server::probe::encode_probe_start_request(
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
                let mut node = TestNode::new(&SERVER_POOL);
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
                    // The probed node serves `probe.handler` as a registered
                    // handler: a header, then the payload as the body.
                    let registry = std::sync::Arc::new(dmesh_server::registry::Registry::new());
                    assert!(registry.register_stream(
                        dmesh_server::registry::methods::PROBE_HANDLER,
                        dmesh_server::probe::ProbeHandler,
                    ));
                    dmesh_server::stream_service::RegistryStreamHandler::new(registry)
                        .serve(&mut stream)
                        .await
                        .unwrap();
                };
                tokio::select! {
                    result = driver.run() => panic!("UDP server driver stopped: {result:?}"),
                    () = serve => {},
                }
            });
        });

        let probe_request = dmesh_server::probe::ProbeServiceRequest::new(256 * 1024, 512);
        let mut request_wire = [0u8; dmesh_server::probe::PROBE_REQUEST_MAX];
        let request_len = dmesh_server::probe::encode_probe_handler_request(
            probe_request,
            0x5678,
            &mut request_wire,
        )
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
