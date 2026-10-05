//! Application exchanges over ordinary Tokio byte streams.
//!
//! Association setup belongs to the caller. These helpers work unchanged with
//! TCP or QUIC streams; no packet, credit, pacing or retry policy lives here.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
    stream.write_all(payload).await?;
    stream.shutdown().await?;
    let plan = quic_lite::probe::ProbePlan::from_request(
        request.workload(),
        quic_lite::DEFAULT_MAX_STREAM_PAYLOAD,
    );
    let expected = request.bytes.min(quic_lite::probe::MAX_BYTES);
    let mut reader = crate::probe::ProbeResponseReader::new(expected);
    let started = std::time::Instant::now();
    if let Some(delay) = request.initial_consume_delay_ms.filter(|delay| *delay != 0) {
        tokio::time::sleep(std::time::Duration::from_millis(u64::from(delay))).await;
    }
    let mut bytes = vec![0; plan.packet_size.max(8)];
    loop {
        let len = stream.read(&mut bytes).await?;
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
    Ok(quic_lite::probe::ProbeResult {
        bytes: reader.bytes(),
        normal_bytes: reader.bytes(),
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
