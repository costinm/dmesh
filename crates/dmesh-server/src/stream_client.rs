//! Application exchanges over ordinary Tokio byte streams.
//!
//! Association setup belongs to the caller. These helpers work unchanged with
//! TCP or QUIC streams; no packet, credit, pacing or retry policy lives here.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Run simultaneous upload/download over two ordinary streams. Each direction
/// has its own terminal response and FIN; neither waits for the other to start.
pub async fn probe_duplex<U, D>(
    upload: &mut U,
    download: &mut D,
    request: crate::probe::ProbeServiceRequest,
    id: u64,
) -> std::io::Result<quic_lite::probe::ProbeResult>
where
    U: AsyncRead + AsyncWrite + Unpin,
    D: AsyncRead + AsyncWrite + Unpin,
{
    let mut up = request;
    up.direction = crate::probe::ProbeDirection::Upload;
    up.peer = None;
    let mut down = up;
    down.direction = crate::probe::ProbeDirection::Download;
    let mut up_header = [0; crate::probe::PROBE_REQUEST_MAX];
    let mut down_header = [0; crate::probe::PROBE_REQUEST_MAX];
    let invalid = || std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid probe header");
    let up_len =
        crate::probe::encode_probe_handler_request(up, id, &mut up_header).ok_or_else(invalid)?;
    let down_len =
        crate::probe::encode_probe_handler_request(down, id.wrapping_add(1), &mut down_header)
            .ok_or_else(invalid)?;
    let started = std::time::Instant::now();
    let (up_result, down_result) = tokio::try_join!(
        probe(upload, &up_header[..up_len], up),
        probe(download, &down_header[..down_len], down),
    )?;
    Ok(quic_lite::probe::ProbeResult {
        bytes: up_result.bytes + down_result.bytes,
        normal_bytes: up_result.bytes + down_result.bytes,
        high_bytes: 0,
        low_bytes: 0,
        elapsed_us: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        callback_errors: core::array::from_fn(|index| {
            up_result.callback_errors[index].saturating_add(down_result.callback_errors[index])
        }),
    })
}

/// QUIC association adapter for the shared stream workload. Both streams use
/// this association's existing circuits and common connection flow control.
pub async fn probe_quic(
    association: &quic_lite::tokio::TokioAssociation,
    payload: &[u8],
    request: crate::probe::ProbeServiceRequest,
) -> std::io::Result<quic_lite::probe::ProbeResult> {
    let error = |error| std::io::Error::other(format!("open probe stream: {error:?}"));
    let mut stream = association.open_stream().await.map_err(error)?;
    if request.direction == crate::probe::ProbeDirection::Both {
        let mut download = association.open_stream().await.map_err(error)?;
        let id = crate::tagged::decode(payload)
            .and_then(|record| record.id)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid probe request")
            })?;
        probe_duplex(&mut stream, &mut download, request, id).await
    } else {
        probe(&mut stream, payload, request).await
    }
}

/// Write the request parts in order, half-close, and collect the response.
/// Reading concurrently permits a server to respond while receiving a body.
pub async fn exchange<S>(stream: &mut S, parts: &[&[u8]]) -> std::io::Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let send = async {
        for part in parts {
            writer.write_all(part).await?;
        }
        writer.shutdown().await
    };
    let receive = async {
        let mut response = Vec::new();
        reader.read_to_end(&mut response).await?;
        Ok::<_, std::io::Error>(response)
    };
    let (_, response) = tokio::try_join!(send, receive)?;
    Ok(response)
}

/// `POST /flash`: send the REST request (path `/flash`, headers from the caller's `object.flash`
/// command plus `content-length` set to the image length), then the image bytes, then FIN, and
/// return the terminal response. The command may omit `len` (a schema-built one does); a different
/// declared `len` is an error.
pub async fn flash<S>(stream: &mut S, request: &[u8], image: &[u8]) -> std::io::Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let invalid = |message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message);
    let (id, mut flash) = crate::object_transfer::decode_flash_command(request)
        .ok_or_else(|| invalid("invalid object.flash request"))?;
    let len = u32::try_from(image.len()).map_err(|_| invalid("flash image exceeds u32 length"))?;
    if flash.len != 0 && flash.len != len {
        return Err(invalid("object.flash len differs from the image length"));
    }
    flash.len = len;
    let mut header = [0u8; crate::object_transfer::REQUEST_MAX];
    let used = crate::object_transfer::encode_flash_handler_request(flash, id, &mut header)
        .ok_or_else(|| invalid("object.flash request does not fit"))?;
    exchange(stream, &[&header[..used], image]).await
}

/// Request and validate a probe response over any asynchronous byte stream.
/// Consumer delays are workload options, not transport backpressure policy.
pub async fn probe<S>(
    stream: &mut S,
    payload: &[u8],
    request: crate::probe::ProbeServiceRequest,
) -> std::io::Result<quic_lite::probe::ProbeResult>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let invalid = |message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message);
    let plan = quic_lite::probe::ProbePlan::from_request(
        request.workload(),
        quic_lite::DEFAULT_MAX_STREAM_PAYLOAD,
    );
    if request.direction == crate::probe::ProbeDirection::Both {
        return Err(invalid("both requires probe_duplex or probe_quic"));
    }
    if request.bytes == 0 || request.bytes > quic_lite::probe::MAX_BYTES {
        return Err(invalid("probe bytes outside supported range"));
    }
    let expected = request.download_bytes();
    let started = std::time::Instant::now();
    let (mut input, mut output) = tokio::io::split(stream);
    let send = async {
        output.write_all(payload).await?;
        if request.upload_bytes() != 0 {
            let mut source =
                quic_lite::probe::ProbePayload::new(request.upload_bytes(), plan.packet_size)
                    .ok_or_else(|| invalid("invalid probe workload"))?;
            let mut chunk = vec![0; plan.packet_size];
            while !source.is_complete() {
                let count = source.fill(&mut chunk);
                output.write_all(&chunk[..count]).await?;
            }
        }
        output.shutdown().await
    };
    let receive = async {
        let mut reader = crate::probe::ProbeResponseReader::for_request(request);
        if let Some(delay) = request.initial_consume_delay_ms.filter(|delay| *delay != 0) {
            tokio::time::sleep(std::time::Duration::from_millis(u64::from(delay))).await;
        }
        let mut bytes = vec![0; plan.packet_size.max(8)];
        loop {
            let len = input.read(&mut bytes).await?;
            if len == 0 {
                break;
            }
            reader.push(&bytes[..len]).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("probe response: {error:?}"),
                )
            })?;
            if let Some(delay) = request.consume_delay_ms.filter(|delay| *delay != 0) {
                tokio::time::sleep(std::time::Duration::from_millis(u64::from(delay))).await;
            }
        }
        if !reader.is_complete() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!(
                    "probe response ended after {} of {expected} bytes",
                    reader.bytes()
                ),
            ));
        }
        Ok::<_, std::io::Error>(reader.bytes() + reader.uploaded_bytes())
    };
    let (_, bytes) = tokio::try_join!(send, receive)?;
    Ok(quic_lite::probe::ProbeResult {
        bytes,
        normal_bytes: bytes,
        high_bytes: 0,
        low_bytes: 0,
        elapsed_us: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        callback_errors: [0; 6],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn duplex_directions_start_before_either_can_finish() {
        use crate::stream::{
            BodySink, BodySource, OpenFuture, Outcome, Request, Response, StreamHandler,
        };
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        struct Gate {
            upload: Arc<AtomicBool>,
            download: Arc<AtomicBool>,
        }
        struct Sink {
            inner: Box<dyn BodySink>,
            upload: Arc<AtomicBool>,
            download: Arc<AtomicBool>,
        }
        impl BodySink for Sink {
            fn write(&mut self, chunk: &[u8], fin: bool) -> Result<usize, Vec<u8>> {
                if !chunk.is_empty() {
                    self.upload.store(true, Ordering::Release);
                }
                if !self.download.load(Ordering::Acquire) {
                    return Ok(0);
                }
                self.inner.write(chunk, fin)
            }
            fn finish(self: Box<Self>) -> Response {
                self.inner.finish()
            }
        }
        struct Source {
            inner: Box<dyn BodySource>,
            upload: Arc<AtomicBool>,
            download: Arc<AtomicBool>,
        }
        impl BodySource for Source {
            fn read(&mut self, out: &mut [u8]) -> (usize, bool) {
                if !self.upload.load(Ordering::Acquire) {
                    return (0, false);
                }
                let result = self.inner.read(out);
                if result.0 != 0 {
                    self.download.store(true, Ordering::Release);
                }
                result
            }
        }
        impl StreamHandler for Gate {
            fn open<'a>(&'a self, request: Request<'a>) -> OpenFuture<'a> {
                Box::pin(async move {
                    let outcome = crate::probe::ProbeHandler.open(request).await?;
                    Some(match outcome {
                        Outcome::Receive(inner) => Outcome::Receive(Box::new(Sink {
                            inner,
                            upload: self.upload.clone(),
                            download: self.download.clone(),
                        })),
                        Outcome::Respond(mut response) => {
                            response.body = response.body.map(|inner| {
                                Box::new(Source {
                                    inner,
                                    upload: self.upload.clone(),
                                    download: self.download.clone(),
                                }) as Box<dyn BodySource>
                            });
                            Outcome::Respond(response)
                        }
                        other => other,
                    })
                })
            }
        }
        let upload = Arc::new(AtomicBool::new(false));
        let download = Arc::new(AtomicBool::new(false));
        let registry = Arc::new(crate::registry::Registry::new());
        registry.register_stream(
            crate::registry::methods::PROBE_HANDLER,
            Gate {
                upload: upload.clone(),
                download: download.clone(),
            },
        );
        let service = crate::stream_service::RegistryStreamHandler::new(registry);
        let (mut up, mut sink) = tokio::io::duplex(31);
        let (mut down, mut source) = tokio::io::duplex(31);
        let request = crate::probe::ProbeServiceRequest::new(32_769, 512);
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let (result, (), ()) = tokio::try_join!(
                probe_duplex(&mut up, &mut down, request, 42),
                service.serve(&mut sink),
                service.serve(&mut source)
            )
            .unwrap();
            assert_eq!(result.bytes, request.bytes * 2);
        })
        .await
        .unwrap();
        assert!(upload.load(Ordering::Acquire) && download.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn probe_modes_use_the_same_client_and_handler_over_tcp() {
        use crate::probe::{
            ProbeDirection, ProbeHandler, ProbeServiceRequest, encode_probe_handler_request,
        };
        let registry = std::sync::Arc::new(crate::registry::Registry::new());
        registry.register_stream(crate::registry::methods::PROBE_HANDLER, ProbeHandler);
        let service = crate::stream_service::RegistryStreamHandler::new(registry);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        for direction in [
            ProbeDirection::Download,
            ProbeDirection::Upload,
            ProbeDirection::Both,
        ] {
            let mut request = ProbeServiceRequest::new(65_537, 512);
            request.direction = direction;
            let mut header = [0; 160];
            let len = encode_probe_handler_request(request, 42, &mut header).unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                let client = async {
                    let mut socket = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                        .await
                        .unwrap();
                    let result = if direction == ProbeDirection::Both {
                        let mut second =
                            tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                                .await
                                .unwrap();
                        probe_duplex(&mut socket, &mut second, request, 42).await
                    } else {
                        probe(&mut socket, &header[..len], request).await
                    };
                    assert_eq!(result.unwrap().bytes, request.total_bytes());
                };
                let server = async {
                    let mut first = listener.accept().await.unwrap().0;
                    if direction == ProbeDirection::Both {
                        let mut second = listener.accept().await.unwrap().0;
                        tokio::try_join!(service.serve(&mut first), service.serve(&mut second))
                            .unwrap();
                    } else {
                        service.serve(&mut first).await.unwrap();
                    }
                };
                tokio::join!(client, server);
            })
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn payload_without_response_fin_does_not_complete_probe() {
        let request = crate::probe::ProbeServiceRequest::new(100, 32);
        let mut header = [0; 160];
        let len = crate::probe::encode_probe_handler_request(request, 1, &mut header).unwrap();
        let (mut client, mut server) = tokio::io::duplex(256);
        let serve = async {
            let mut received = Vec::new();
            server.read_to_end(&mut received).await.unwrap();
            let mut response = [0; 64];
            let len =
                crate::probe::encode_probe_handler_response(1, 100, 32, &mut response).unwrap();
            server.write_all(&response[..len]).await.unwrap();
            let mut body = [0; 100];
            quic_lite::probe::ProbePayload::new(100, 32)
                .unwrap()
                .fill(&mut body);
            server.write_all(&body).await.unwrap();
            std::future::pending::<()>().await;
        };
        let outcome = tokio::time::timeout(std::time::Duration::from_millis(100), async {
            tokio::select! {
                result = probe(&mut client, &header[..len], request) => result,
                _ = serve => panic!("fixture must retain the response half"),
            }
        })
        .await;
        assert!(outcome.is_err());
    }

    #[tokio::test]
    async fn probe_modes_use_registered_handler_with_small_stream_buffers() {
        use crate::probe::{
            ProbeDirection, ProbeHandler, ProbeServiceRequest, encode_probe_handler_request,
        };
        for direction in [
            ProbeDirection::Download,
            ProbeDirection::Upload,
            ProbeDirection::Both,
        ] {
            let registry = std::sync::Arc::new(crate::registry::Registry::new());
            assert!(
                registry.register_stream(crate::registry::methods::PROBE_HANDLER, ProbeHandler)
            );
            let service = crate::stream_service::RegistryStreamHandler::new(registry);
            let mut request = ProbeServiceRequest::new(131_073, 512);
            request.direction = direction;
            let mut header = [0; 160];
            let used = encode_probe_handler_request(request, 42, &mut header).unwrap();
            let (mut client, mut server) = tokio::io::duplex(31);
            let (mut download, mut source) = tokio::io::duplex(31);
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                let run = async {
                    if direction == ProbeDirection::Both {
                        probe_duplex(&mut client, &mut download, request, 42).await
                    } else {
                        probe(&mut client, &header[..used], request).await
                    }
                };
                let serve = async {
                    if direction == ProbeDirection::Both {
                        tokio::try_join!(service.serve(&mut server), service.serve(&mut source))
                            .map(|_| ())
                    } else {
                        service.serve(&mut server).await
                    }
                };
                tokio::join!(run, serve)
            })
            .await
            .unwrap();
            result.1.unwrap();
            assert_eq!(result.0.unwrap().bytes, request.total_bytes());
        }
    }

    #[tokio::test]
    async fn probe_modes_use_the_same_client_and_handler_over_quic() {
        run_quic_probe_control(false, 1_048_577, 1).await;
    }

    // Opt-in performance controls: use the ordinary probe, not a benchmark-
    // specific stream protocol. Run release builds without concurrent builds.
    #[tokio::test]
    #[ignore = "host performance measurement"]
    async fn probe_performance_in_memory() {
        run_quic_probe_control(false, 8 * 1024 * 1024, 3).await;
    }

    #[tokio::test]
    #[ignore = "host performance measurement"]
    async fn probe_performance_udp_loopback() {
        run_quic_probe_control(true, 8 * 1024 * 1024, 3).await;
    }

    async fn run_quic_probe_control(udp: bool, bytes: u64, repetitions: usize) {
        use crate::probe::{
            ProbeDirection, ProbeHandler, ProbeServiceRequest, encode_probe_handler_request,
        };
        use quic_lite::{
            AssociationLimits, BearerName, PacketMeta, PeerL2Address, QuicNode,
            fake::FakePacketBearer, packet_pool::PacketPool, tokio::TokioNodeDriver,
        };
        type Pool = PacketPool<16, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
        let ap = Box::leak(Box::new(Pool::new()));
        let bp = Box::leak(Box::new(Pool::new()));
        let (first, second) = FakePacketBearer::<Pool>::pair(
            BearerName::new("client").unwrap(),
            BearerName::new("server").unwrap(),
        );
        let mut a = QuicNode::<Pool>::new(ap);
        let mut b = QuicNode::<Pool>::new(bp);
        for node in [&mut a, &mut b] {
            node.set_default_association_limits(AssociationLimits::host())
                .unwrap();
        }
        let (bearer, peer) = if udp {
            let first = quic_lite::bearer_udp::TokioUdpBearer::<16>::bind(
                "[::1]:0".parse().unwrap(),
            )
            .await
            .unwrap();
            let second = quic_lite::bearer_udp::TokioUdpBearer::<16>::bind(
                "[::1]:0".parse().unwrap(),
            )
            .await
            .unwrap();
            let peer = first
                .register_peer(second.local_addr().unwrap())
                .unwrap();
            b.add_bearer(second).unwrap();
            (a.add_bearer(first).unwrap(), peer)
        } else {
            b.add_bearer(second).unwrap();
            (a.add_bearer(first).unwrap(), PeerL2Address::new(1).unwrap())
        };
        let (a, ad) = TokioNodeDriver::new(a, AssociationLimits::host().connection);
        let (b, bd) = TokioNodeDriver::new(b, AssociationLimits::host().connection);
        let registry = std::sync::Arc::new(crate::registry::Registry::new());
        registry.register_stream(crate::registry::methods::PROBE_HANDLER, ProbeHandler);
        let service = crate::stream_service::RegistryStreamHandler::new(registry);
        let client = async {
            let association = a
                .associate(
                    PacketMeta {
                        bearer,
                        peer_l2_address: peer,
                        received_at_us: 0,
                    },
                    0,
                )
                .await
                .unwrap();
            association.wait_established().await.unwrap();
            for (index, direction) in [
                ProbeDirection::Download,
                ProbeDirection::Upload,
                ProbeDirection::Both,
            ]
            .into_iter()
            .cycle()
            .take(3 * repetitions)
            .enumerate()
            {
                let mut request = ProbeServiceRequest::new(bytes, 1024);
                request.direction = direction;
                let mut header = [0; 160];
                let len = encode_probe_handler_request(request, 42, &mut header).unwrap();
                let result = probe_quic(&association, &header[..len], request).await.unwrap();
                assert_eq!(result.bytes, request.total_bytes());
                println!("transport={} run={} direction={} bytes={} verified=true fin=true elapsed_us={} mbps={:.3}",
                    if udp { "udp-loopback" } else { "in-memory" }, index / 3 + 1,
                    direction.as_str(), result.bytes, result.elapsed_us,
                    result.bits_per_second() as f64 / 1_000_000.0);
            }
        };
        let server = async {
            for index in 0..3 * repetitions {
                let mut stream = b.accept_stream().await.unwrap();
                if index % 3 == 2 {
                    let mut second = b.accept_stream().await.unwrap();
                    tokio::try_join!(service.serve(&mut stream), service.serve(&mut second))
                        .unwrap();
                } else {
                    service.serve(&mut stream).await.unwrap();
                }
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            tokio::select! {
                _ = async { tokio::join!(client, server); } => {},
                result = ad.run() => panic!("client driver stopped: {result:?}"),
                result = bd.run() => panic!("server driver stopped: {result:?}"),
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn flash_uses_the_same_helper_over_tcp() {
        use crate::object_transfer::{
            FlashRequest, ObjectId, decode_flash_handler_request, encode_flash_command,
        };
        let mut header = [0; 160];
        let len = encode_flash_command(
            FlashRequest {
                object: ObjectId {
                    name: None,
                    cpu: 13,
                    target: 3,
                },
                address: None,
                transport: 0,
                dry_run: true,
                len: 0,
            },
            42,
            &mut header,
        )
        .unwrap();
        let header = &header[..len];
        let image = vec![0x5a; 1024 * 1024];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let client = async {
                let mut socket = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                    .await
                    .unwrap();
                assert_eq!(
                    flash(&mut socket, header, &image).await.unwrap(),
                    b"terminal fixture"
                );
            };
            let server = async {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut body = Vec::new();
                socket.read_to_end(&mut body).await.unwrap();
                // The header declares the content length; the image follows it unchanged.
                let split = body.len() - image.len();
                let (id, request) = decode_flash_handler_request(&body[..split]).unwrap();
                assert_eq!((id, request.len), (42, image.len() as u32));
                assert_eq!(&body[split..], &image[..]);
                socket.write_all(b"terminal fixture").await.unwrap();
                socket.shutdown().await.unwrap();
            };
            tokio::join!(client, server);
        })
        .await
        .unwrap();
    }

    // Both directions exceed the socket buffers: sequential request/response
    // I/O would deadlock when the server writes before draining the request.
    #[tokio::test]
    async fn exchange_is_duplex_and_preserves_parts_and_half_close() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let body = vec![0x5a; 32 * 1024];
        let reply = vec![0xa5; 32 * 1024];
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let parts: [&[u8]; 2] = [b"header", &body];
            let send = exchange(&mut client, &parts);
            let serve = async {
                server.write_all(&reply).await.unwrap();
                server.shutdown().await.unwrap();
                let mut received = Vec::new();
                server.read_to_end(&mut received).await.unwrap();
                assert_eq!(&received[..6], b"header");
                assert_eq!(&received[6..], body);
            };
            let (response, ()) = tokio::join!(send, serve);
            assert_eq!(response.unwrap(), reply);
        })
        .await
        .unwrap();
    }
}
