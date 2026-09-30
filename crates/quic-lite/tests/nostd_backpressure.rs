//! Regression coverage for no-std receive backpressure.

use std::sync::{Arc, Mutex};

use quic_lite::{
    AssociationLimits, BearerContext, BearerInfo, BearerName, EgressSubmission, NodeLimits,
    PacketBearer, PacketEgress, PacketMeta, PacketPool as PacketPoolTrait, PacketSendOutcome,
    PacketSubmitError, PacketWriter, PeerL2Address, QuicNode, nostd::NoStdRuntime,
    packet_pool::PacketPool,
};

type Pool = PacketPool<8, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
static CLIENT_POOL: Pool = Pool::new();
static SERVER_POOL: Pool = Pool::new();

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

/// Regression: a slow consumer on the copying `NoStdRuntime::progress` path
/// must receive the complete stream.
///
/// Earlier failures, all now fixed:
/// - a full `next_stream_chunk` queue made the callback fail after the packet
///   had been committed (ACKed), so data the peer would never resend was
///   dropped; the callback now accepts 0 bytes and QUIC-lite retains them
///   without granting credit;
/// - retention was capped at 4 KiB while the advertised receive window was
///   256 KiB, so retained bytes overflowed after the ACK; retention is now
///   sized from the advertised `max_data` window;
/// - a retained empty FIN was re-delivered on every resume, spinning the
///   drain loop.
#[test]
fn slow_queue_consumer_receives_complete_stream() {
    let (client_bearer, client_context, client_sent) = Capture::<Pool>::new("client");
    let embedded = AssociationLimits::embedded();
    let mut client = NoStdRuntime::new(
        QuicNode::<Pool>::new(None, &CLIENT_POOL),
        embedded.connection,
    );
    client.set_limits(NodeLimits::embedded()).unwrap();
    client.set_default_association_limits(embedded).unwrap();
    let client_bearer_id = client.add_bearer(client_bearer).unwrap();
    let client_address = PacketMeta {
        bearer: client_bearer_id,
        peer_l2_address: PeerL2Address::new(1).unwrap(),
        received_at_us: 1,
    };
    let (server_bearer, server_context, server_sent) = Capture::<Pool>::new("server");
    let mut server = NoStdRuntime::new(
        QuicNode::<Pool>::new(None, &SERVER_POOL),
        embedded.connection,
    );
    server.set_limits(NodeLimits::embedded()).unwrap();
    server.set_default_association_limits(embedded).unwrap();
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
    server.progress().unwrap();
    let open_ack = server_sent.lock().unwrap().pop().unwrap();
    client_context
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .enqueue_packet(client_address, copy_into_pool(&CLIENT_POOL, &open_ack));
    client.progress().unwrap();
    assert!(client.association_is_established(association));

    let mut stream = client.open_stream(association).unwrap();
    // Cross the default 64 KiB initial stream credit several times. This
    // verifies that a slowly drained no-std stream receives fresh credit
    // instead of silently stopping at its bootstrap window.
    let data: Vec<u8> = (0..256 * 1024u32).map(|index| index as u8).collect();
    let mut sent = 0;
    let mut finished = false;
    let mut received = Vec::new();
    let mut now = 10u64;
    for round in 0..2_000 {
        now += 5_000;
        while sent < data.len() {
            let end = (sent + 1_000).min(data.len());
            match client.write_stream(&mut stream, &data[sent..end]) {
                Ok(accepted) => sent += accepted,
                Err(_) => break,
            }
        }
        if sent == data.len() && !finished {
            finished = client.finish_stream(&mut stream).is_ok();
        }
        let client_burst = core::mem::take(&mut *client_sent.lock().unwrap());
        for burst in client_burst.chunks(2) {
            for packet in burst {
                server_context
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .enqueue_packet(
                        PacketMeta {
                            received_at_us: now,
                            ..server_address
                        },
                        copy_into_pool(&SERVER_POOL, packet),
                    );
            }
            // Multiple packets can be covered by one callback wake marker.
            server.progress_all().unwrap();
        }
        // The event source coalesces these datagrams into one owner wake.
        // Drain the full burst so a queued MAX_STREAM_DATA update cannot be
        // stranded behind an earlier ACK-only packet.
        // The application drains its queue only every fourth round.
        if round % 4 == 0 {
            while let Some(chunk) = server.next_stream_chunk() {
                received.extend_from_slice(&chunk.bytes);
            }
        }
        let _ = server.advance_time(now);
        let server_burst = core::mem::take(&mut *server_sent.lock().unwrap());
        for burst in server_burst.chunks(2) {
            for packet in burst {
                client_context
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .enqueue_packet(
                        PacketMeta {
                            received_at_us: now,
                            ..client_address
                        },
                        copy_into_pool(&CLIENT_POOL, packet),
                    );
            }
            client.progress_all().unwrap();
        }
        let _ = client.advance_time(now);
        if received.len() == data.len() {
            break;
        }
    }
    while let Some(chunk) = server.next_stream_chunk() {
        received.extend_from_slice(&chunk.bytes);
    }
    assert_eq!(
        received.len(),
        data.len(),
        "stream stalled after a queue-full drop"
    );
    assert_eq!(received, data);
}
