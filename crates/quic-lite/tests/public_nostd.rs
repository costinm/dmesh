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
    let (client_bearer, client_context, client_sent) = Capture::<Pool>::new("client-uart");
    let client = QuicNode::<Pool>::new(None, &CLIENT_POOL);
    let mut client = NoStdRuntime::new(client, ConnectionLimits::default());
    let client_bearer_id = client.add_bearer(client_bearer).unwrap();
    let client_address = PacketMeta {
        bearer: client_bearer_id,
        peer_l2_address: PeerL2Address::new(1).unwrap(),
        received_at_us: 1,
    };
    let (server_bearer, server_context, server_sent) = Capture::<Pool>::new("server-uart");
    let server = QuicNode::<Pool>::new(None, &SERVER_POOL);
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
        .enqueue_packet(server_address, copy_into_pool(&SERVER_POOL, &initial));
    assert!(server.progress().unwrap());
    assert!(server.next_association().is_some());
    let open_ack = server_sent.lock().unwrap().pop().unwrap();
    client_context
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .enqueue_packet(client_address, copy_into_pool(&CLIENT_POOL, &open_ack));
    assert!(client.progress().unwrap());
    assert!(client.association_is_established(association));

    let mut request = client.open_stream(association).unwrap();
    assert_eq!(
        client
            .write_stream_and_finish(&mut request, b"ping")
            .unwrap(),
        4
    );
    let request_packets = core::mem::take(&mut *client_sent.lock().unwrap());
    assert_eq!(request_packets.len(), 1);
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
                copy_into_pool(&SERVER_POOL, &request_packet),
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

    let control_packets = server_sent.lock().unwrap().len();
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
            .enqueue_packet(client_address, copy_into_pool(&CLIENT_POOL, &response));
        assert!(client.progress().unwrap());
    }
    let response = client.next_stream_chunk().unwrap();
    assert_eq!(response.bytes, b"pong");
    assert!(response.fin);
    assert!(client.next_stream_chunk().is_none());
    assert!(!client.progress().unwrap());
}
