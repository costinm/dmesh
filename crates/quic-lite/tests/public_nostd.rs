#![deny(deprecated)]

//! External coverage for synchronous/no-executor node driving.

use std::sync::{Arc, Mutex};

use quic_lite::{
    BearerContext, BearerInfo, BearerName, ConnectionLimits, EgressSubmission, PacketBearer,
    PacketEgress, PacketMeta, PacketPool as PacketPoolTrait, PacketSendOutcome, PacketSubmitError,
    PacketWriter, PeerL2Address, QuicNode, QuicNodeEgressError, nostd::NoStdRuntime,
    packet_pool::PacketPool,
};

type Pool = PacketPool<8, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
static CLIENT_POOL: Pool = Pool::new();
static SERVER_POOL: Pool = Pool::new();
static DELAYED_CLIENT_POOL: Pool = Pool::new();
static DELAYED_SERVER_POOL: Pool = Pool::new();

#[test]
fn retryability_is_available_to_external_no_std_drivers() {
    assert!(QuicNodeEgressError::BearerBusy.is_retryable());
    assert!(QuicNodeEgressError::PoolUnavailable.is_retryable());
    assert!(QuicNodeEgressError::Transport(quic_lite::Error::FlowControl).is_retryable());
    assert!(!QuicNodeEgressError::MissingBearer.is_retryable());
}

struct Capture<P: PacketPoolTrait + 'static> {
    name: BearerName,
    context: Arc<Mutex<Option<BearerContext<P>>>>,
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl<P: PacketPoolTrait + 'static> Capture<P> {
    fn new(
        name: &str,
    ) -> (
        Self,
        Arc<Mutex<Option<BearerContext<P>>>>,
        Arc<Mutex<Vec<Vec<u8>>>>,
    ) {
        let context = Arc::new(Mutex::new(None));
        let sent = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                name: BearerName::new(name).unwrap(),
                context: context.clone(),
                sent: sent.clone(),
            },
            context,
            sent,
        )
    }
}

impl<P> PacketEgress<P::Buffer> for Capture<P>
where
    P: PacketPoolTrait + 'static,
{
    fn submit(
        &mut self,
        _peer: PeerL2Address,
        submission: EgressSubmission<P::Buffer>,
    ) -> Result<(), PacketSubmitError<P::Buffer>> {
        let (packet, completion) = submission.into_parts();
        self.sent.lock().unwrap().push(packet.bytes().to_vec());
        completion.complete(packet, PacketSendOutcome::Sent, 0);
        Ok(())
    }
}

impl<P> PacketBearer<P> for Capture<P>
where
    P: PacketPoolTrait + 'static,
{
    type AttachError = core::convert::Infallible;

    fn info(&self) -> BearerInfo {
        BearerInfo {
            name: self.name,
            max_packet_size: quic_lite::DEFAULT_MAX_PACKET_SIZE,
            prefix_required: quic_lite::PACKET_PREFIX_RESERVE,
            suffix_required: quic_lite::PACKET_SUFFIX_RESERVE,
            requires_packet_encryption: false,
            secure_link: true,
            nominal_bitrate_bps: 115_200,
            local_mac: None,
        }
    }

    fn attach(&mut self, context: BearerContext<P>) -> Result<(), Self::AttachError> {
        *self.context.lock().unwrap() = Some(context);
        Ok(())
    }
}

fn copy_into_pool(
    pool: &'static Pool,
    bytes: &[u8],
) -> quic_lite::OwnedPacket<<Pool as PacketPoolTrait>::Buffer> {
    let mut writer = pool
        .acquire_writer(quic_lite::PACKET_PREFIX_RESERVE, 0)
        .unwrap();
    writer.payload_mut()[..bytes.len()].copy_from_slice(bytes);
    writer.commit(bytes.len()).unwrap()
}

#[test]
fn synchronous_driver_receives_and_replies_to_stream_shaped_message() {
    run_synchronous_response(false);
}

#[test]
fn client_stream_consumption_preserves_delayed_ack_policy() {
    run_synchronous_response(true);
}

fn run_synchronous_response(check_delayed_ack: bool) {
    let client_pool = if check_delayed_ack { &DELAYED_CLIENT_POOL } else { &CLIENT_POOL };
    let server_pool = if check_delayed_ack { &DELAYED_SERVER_POOL } else { &SERVER_POOL };
    let (client_bearer, client_context, client_sent) = Capture::<Pool>::new("client-uart");
    let client = QuicNode::<Pool>::new(client_pool);
    let mut client = NoStdRuntime::new(client, ConnectionLimits::default());
    let client_bearer_id = client.add_bearer(client_bearer).unwrap();
    let client_address = PacketMeta {
        bearer: client_bearer_id,
        peer_l2_address: PeerL2Address::new(1).unwrap(),
        received_at_us: 1,
    };
    let (server_bearer, server_context, server_sent) = Capture::<Pool>::new("server-uart");
    let server = QuicNode::<Pool>::new(server_pool);
    let mut server = NoStdRuntime::new(server, ConnectionLimits::default());
    let server_bearer_id = server.add_bearer(server_bearer).unwrap();
    let server_address = PacketMeta {
        bearer: server_bearer_id,
        peer_l2_address: PeerL2Address::new(2).unwrap(),
        received_at_us: 2,
    };

    let association = client.associate(client_address, 1).unwrap();
    let initial = client_sent.lock().unwrap().pop().unwrap();
    server_context
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .enqueue_packet(server_address, copy_into_pool(server_pool, &initial));
    assert!(server.progress().unwrap());
    assert!(server.next_association().is_some());
    let open_ack = server_sent.lock().unwrap().pop().unwrap();
    client_context
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .enqueue_packet(client_address, copy_into_pool(client_pool, &open_ack));
    assert!(client.progress().unwrap());
    assert!(client.association_is_established(association));

    let mut request = client.open_stream(association).unwrap();
    assert_eq!(client.write_stream(&mut request, b"ping").unwrap(), 4);
    client.finish_stream(&mut request).unwrap();
    let request_packets = core::mem::take(&mut *client_sent.lock().unwrap());
    // This matches the host service client, which writes its request and then
    // shuts down the stream in a separate transport packet.
    assert_eq!(request_packets.len(), 2);
    let mut received_stream = None;
    let mut received_bytes = Vec::new();
    let mut received_fin = false;
    for request_packet in request_packets {
        server_context
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .enqueue_packet(
                server_address,
                copy_into_pool(server_pool, &request_packet),
            );
        assert!(
            server
                .progress_with_stream(|stream, offset, fin, bytes| {
                    assert_eq!(offset, received_bytes.len() as u64);
                    if received_stream.is_none() {
                        received_stream = Some(stream);
                    }
                    received_bytes.extend_from_slice(bytes);
                    received_fin |= fin;
                    Ok(bytes.len())
                })
                .unwrap()
        );
    }

    assert_eq!(received_bytes, b"ping");
    assert!(received_fin);
    assert!(server.next_stream_chunk().is_none());
    let mut received = received_stream.unwrap();

    if check_delayed_ack {
        for (index, body) in [b"first".as_slice(), b"second".as_slice()].into_iter().enumerate() {
            assert_eq!(server.write_stream(&mut received, body).unwrap(), body.len());
            let packet = server_sent.lock().unwrap().pop().unwrap();
            client_context.lock().unwrap().as_ref().unwrap().enqueue_packet(
                client_address, copy_into_pool(client_pool, &packet));
            assert!(client.progress().unwrap());
            let chunk = client.next_stream_chunk().unwrap();
            assert_eq!(chunk.bytes, body);
            assert!(!chunk.fin);
            if index == 0 {
                assert!(!client.progress().unwrap(),
                    "consuming the first response chunk must not force an immediate ACK");
                assert!(client_sent.lock().unwrap().is_empty());
            } else {
                assert!(client.progress().unwrap(), "the second response packet makes ACK due");
                assert_eq!(client_sent.lock().unwrap().len(), 1);
            }
        }
        return;
    }

    let control_packets = server_sent.lock().unwrap().len();
    assert_eq!(control_packets, 0,
        "the due request ACK gets a response-piggyback opportunity before standalone submission");
    assert_eq!(
        server
            .write_stream_and_finish(&mut received, b"pong")
            .unwrap(),
        4
    );
    assert_eq!(server_sent.lock().unwrap().len(), control_packets + 1);
    assert!(
        server
            .write_stream(&mut received, b"second response")
            .is_err()
    );
    let responses = core::mem::take(&mut *server_sent.lock().unwrap());
    for response in responses {
        client_context
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .enqueue_packet(client_address, copy_into_pool(client_pool, &response));
        assert!(client.progress().unwrap());
    }
    let response = client.next_stream_chunk().unwrap();
    assert_eq!(response.bytes, b"pong");
    assert!(response.fin);
    assert!(client.next_stream_chunk().is_none());
    let before_flush = client_sent.lock().unwrap().len();
    assert!(client.progress().unwrap(),
        "without response data, the next owner turn must flush its owed ACK/window update");
    assert_eq!(client_sent.lock().unwrap().len(), before_flush + 1);
    assert!(!client.progress().unwrap());
    assert!(!server.progress().unwrap(),
        "piggybacked control must not produce a duplicate standalone packet or false progress");
    assert!(server_sent.lock().unwrap().is_empty());
}
