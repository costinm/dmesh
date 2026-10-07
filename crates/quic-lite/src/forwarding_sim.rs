//! Host-only forwarding correctness and opt-in performance measurements.
//! Comparisons exercise real node routing and association stream machinery.
use crate::bearer::{OwnedPacket, PacketBuffer, PacketPool, PacketWriter};
use crate::node::{InitialAdmission, NodeIngress};
use crate::relay::{ForwardDestination, ForwardNextHop, ForwardRule};
use crate::{ConnectionId, Error, Frame, PacketMeta, QuicNode, ShortHeader};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use std::{boxed::Box, vec, vec::Vec};

type RawPool = crate::packet_pool::PacketPool<32, { crate::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
pub(super) type Buffer = <RawPool as PacketPool>::Buffer;

// This microbenchmark delivers directly to the serialized owner. Unexpected
// asynchronous ingress is a test failure rather than a hidden packet queue.
struct DirectIngress;
impl crate::bearer::PacketIngressQueue<Buffer> for DirectIngress {
    fn enqueue_packet(&self, _: PacketMeta, _: OwnedPacket<Buffer>) {
        panic!("simulator uses direct owner ingress");
    }
}
pub(super) fn register(node: &mut QuicNode<Pool>, name: &str) {
    node.register_bearer_with_ingress(
        crate::fake::FakePacketBearer::<Pool>::new(crate::BearerName::new(name).unwrap()),
        std::sync::Arc::new(DirectIngress),
    )
    .unwrap();
}

pub(super) struct Pool {
    raw: RawPool,
    pub(super) acquisitions: AtomicUsize,
    pub(super) peak: AtomicUsize,
}
impl Pool {
    pub(super) fn new() -> &'static Self {
        Box::leak(Box::new(Self {
            raw: RawPool::new(),
            acquisitions: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }))
    }
    fn reset(&self) {
        self.acquisitions.store(0, Ordering::Relaxed);
        self.peak.store(0, Ordering::Relaxed);
    }
}
impl PacketPool for Pool {
    type Buffer = Buffer;
    type Writer = <RawPool as PacketPool>::Writer;
    fn acquire_writer(&'static self, headroom: usize, reserved: usize) -> Option<Self::Writer> {
        let writer = PacketPool::acquire_writer(&self.raw, headroom, reserved)?;
        self.acquisitions.fetch_add(1, Ordering::Relaxed);
        self.peak
            .fetch_max(self.capacity() - self.available(), Ordering::Relaxed);
        Some(writer)
    }
    fn capacity(&self) -> usize {
        PacketPool::capacity(&self.raw)
    }
    fn available(&self) -> usize {
        self.raw.available()
    }
}
pub(super) fn cid(value: u64) -> ConnectionId {
    ConnectionId::new(value).unwrap()
}
pub(super) fn meta() -> PacketMeta {
    PacketMeta {
        bearer: crate::BearerId::new(1).unwrap(),
        peer_l2_address: crate::PeerL2Address::new(1).unwrap(),
        received_at_us: 1,
    }
}
pub(super) fn pooled(pool: &'static Pool, bytes: &[u8], headroom: usize) -> OwnedPacket<Buffer> {
    let mut writer = pool.acquire_writer(headroom, 0).unwrap();
    writer.payload_mut()[..bytes.len()].copy_from_slice(bytes);
    PacketWriter::commit(writer, bytes.len()).unwrap()
}
fn fixture(size: usize, destination: ConnectionId) -> Vec<u8> {
    let mut bytes = vec![0; size];
    let used = ShortHeader {
        flags: crate::FLAG_FIXED,
        dcid: destination,
        packet_number: 17,
        packet_number_len: 2,
    }
    .encode(&mut bytes)
    .unwrap();
    let data = vec![0x5a; size - used - 8];
    let frames = Frame::Stream(crate::StreamFrame {
        id: 0,
        offset: 0,
        fin: false,
        data: &data,
    })
    .encode(&mut bytes[used..])
    .unwrap();
    bytes.truncate(used + frames);
    bytes
}
fn rule(destination: ConnectionId) -> ForwardRule<ForwardNextHop> {
    ForwardRule {
        next_hop: ForwardNextHop {
            bearer: meta().bearer,
            peer_l2_address: meta().peer_l2_address,
        },
        destination: ForwardDestination::Connection(destination),
        lease_duration_us: 1_000_000,
        lease_expires_at_us: 1_000_000,
        lease_group_id: 0,
        packet_quota: 0,
        forwarded_packets: 0,
        forwarded_control_packets: 0,
        quota_window_started_us: 0,
    }
}
fn relay(pool: &'static Pool) -> QuicNode<Pool> {
    let mut node = QuicNode::new(pool);
    node.set_limits(crate::NodeLimits {
        relay_control_packet_reserve: 0,
        ..crate::NodeLimits::host()
    })
    .unwrap();
    register(&mut node, "sim-relay");
    node.register_forward(cid(42), rule(cid(12345))).unwrap();
    node
}

#[test]
fn rewrite_matches_oracle_and_keeps_body_address_across_cid_widths() {
    let pool = Pool::new();
    for inbound in [1, 128, 16384, 1 << 30] {
        for outbound in [2, 129, 16385, (1 << 30) + 1] {
            let bytes = fixture(1050, cid(inbound));
            let original = pooled(pool, &bytes, crate::PACKET_PREFIX_RESERVE);
            let prefix = ShortHeader::decode_prefix(original.bytes()).unwrap();
            let tail = original.bytes().as_ptr() as usize + 1 + prefix.dcid.encoded_len();
            let mut expected = [0; crate::DEFAULT_PACKET_POOL_SLOT_SIZE];
            let used = crate::rewrite_dcid(&bytes, cid(outbound), &mut expected).unwrap();
            let rewritten = crate::rewrite_dcid_in_place(
                original,
                cid(outbound),
                0,
                crate::DEFAULT_MAX_PACKET_SIZE,
            )
            .unwrap();
            assert_eq!(rewritten.bytes(), &expected[..used]);
            let prefix = ShortHeader::decode_prefix(rewritten.bytes()).unwrap();
            assert_eq!(
                rewritten.bytes().as_ptr() as usize + 1 + prefix.dcid.encoded_len(),
                tail
            );
            assert_eq!(pool.available(), pool.capacity() - 1);
            drop(rewritten);
            assert_eq!(pool.available(), pool.capacity());
        }
    }
}

#[test]
fn refusal_preserves_bytes_pointer_and_pool_ownership() {
    let pool = Pool::new();
    for (headroom, required, max) in [(0, 0, 1100), (80, 80, 1100), (80, 0, 16)] {
        let bytes = fixture(64, cid(1));
        let input = pooled(pool, &bytes, headroom);
        let pointer = input.bytes().as_ptr();
        let (_, unchanged) =
            crate::rewrite_dcid_in_place(input, cid(1 << 30), required, max).unwrap_err();
        assert_eq!(unchanged.bytes(), bytes);
        assert_eq!(unchanged.bytes().as_ptr(), pointer);
        drop(unchanged);
        assert_eq!(pool.available(), pool.capacity());
    }
}

#[test]
fn plaintext_relay_rewrite_and_companion_preserve_prefix_space() {
    let pool = Pool::new();
    let bearer_prefix = 12;
    for inbound in [1, 128, 16384, 1 << 30] {
        // Preserve, grow and shrink the CID using every supported width.
        for outbound in [inbound, 2, 129, 16385, (1 << 30) + 1] {
            let source = cid(inbound);
            let destination = cid(outbound);
            let headroom = bearer_prefix + destination.encoded_len() - source.encoded_len();
            let bytes = fixture(1024, source);
            assert_eq!(bytes[0] & crate::FLAG_KEY_PHASE, 0);
            let input = pooled(pool, &bytes, headroom);
            let range = input.packet_range();
            let tail = input.bytes().as_ptr() as usize + 1 + source.encoded_len();
            let before = pool.acquisitions.load(Ordering::Relaxed);
            let output = crate::rewrite_dcid_in_place(
                input,
                destination,
                bearer_prefix,
                crate::DEFAULT_MAX_PACKET_SIZE,
            )
            .unwrap();
            let header = ShortHeader::decode_prefix(output.bytes()).unwrap();
            assert_eq!(header.dcid, destination);
            assert_eq!(
                output.bytes().as_ptr() as usize + 1 + destination.encoded_len(),
                tail
            );
            assert!(output.packet_range().start >= bearer_prefix);
            assert_eq!(pool.acquisitions.load(Ordering::Relaxed), before);
            let mut oracle = [0; crate::DEFAULT_PACKET_POOL_SLOT_SIZE];
            let used = crate::rewrite_dcid(&bytes, destination, &mut oracle).unwrap();
            assert_eq!(output.bytes(), &oracle[..used]);
            if inbound == outbound {
                assert_eq!(output.packet_range(), range);
                assert_eq!(output.bytes(), bytes);
            }
            drop(output);

            // One byte below the exact required prefix must refuse unchanged,
            // even when preserving the CID rather than growing it.
            let input = pooled(pool, &bytes, headroom - 1);
            let range = input.packet_range();
            let pointer = input.bytes().as_ptr();
            let (_, unchanged) = crate::rewrite_dcid_in_place(
                input,
                destination,
                bearer_prefix,
                crate::DEFAULT_MAX_PACKET_SIZE,
            )
            .unwrap_err();
            assert_eq!(unchanged.packet_range(), range);
            assert_eq!(unchanged.bytes().as_ptr(), pointer);
            assert_eq!(unchanged.bytes(), bytes);
            drop(unchanged);
            assert_eq!(pool.available(), pool.capacity());
        }
    }
}

#[test]
#[ignore = "plaintext host comparison; use release --ignored --nocapture"]
fn plaintext_relay_rewrite_vs_companion_performance() {
    let count = std::env::var("DMESH_FORWARDING_PACKETS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000usize);
    assert!(count > 0);
    std::println!("mode,wire_bytes,ns_per_packet,pool_acquisitions,peak_slots");
    for size in [64, 256, 1024, 1050] {
        let bytes = fixture(size, cid(42));
        assert_eq!(bytes[0] & crate::FLAG_KEY_PHASE, 0);
        for (mode, destination) in [
            ("companion_preserve", cid(42)),
            ("relay_grow", cid(1 << 30)),
        ] {
            let pool = Pool::new();
            let mut node = QuicNode::new(pool);
            register(&mut node, "sim-plain-relay");
            node.register_forward(cid(42), rule(destination)).unwrap();
            let started = Instant::now();
            for _ in 0..count {
                let input = pooled(pool, &bytes, crate::PACKET_PREFIX_RESERVE);
                let tail = input.bytes().as_ptr() as usize + 1 + cid(42).encoded_len();
                let NodeIngress::Forward { packet, .. } = node
                    .receive_owned_packet(
                        meta(),
                        input,
                        |_| None,
                        |_, _, _, _, data| Ok(data.len()),
                    )
                    .unwrap()
                else {
                    panic!("forward");
                };
                assert_eq!(
                    ShortHeader::decode_prefix(packet.bytes()).unwrap().dcid,
                    destination
                );
                assert_eq!(
                    packet.bytes().as_ptr() as usize + 1 + destination.encoded_len(),
                    tail
                );
                std::hint::black_box(packet.bytes());
            }
            std::println!(
                "{mode},{},{:.1},{},{}",
                bytes.len(),
                started.elapsed().as_secs_f64() * 1e9 / count as f64,
                pool.acquisitions.load(Ordering::Relaxed),
                pool.peak.load(Ordering::Relaxed)
            );
            assert_eq!(pool.acquisitions.load(Ordering::Relaxed), count);
            assert_eq!(pool.peak.load(Ordering::Relaxed), 1);
            assert_eq!(pool.available(), pool.capacity());
        }
    }
}

#[test]
fn plaintext_node_relay_rewrite_matches_companion_without_rewrite() {
    let pool = Pool::new();
    for destination in [cid(42), cid(1 << 30)] {
        let mut node = QuicNode::new(pool);
        register(&mut node, "sim-plain-relay");
        node.register_forward(cid(42), rule(destination)).unwrap();
        let bytes = fixture(1024, cid(42));
        let input = pooled(pool, &bytes, crate::PACKET_PREFIX_RESERVE);
        let original_range = input.packet_range();
        let tail = input.bytes().as_ptr() as usize + 1 + cid(42).encoded_len();
        let before = pool.acquisitions.load(Ordering::Relaxed);
        let NodeIngress::Forward { packet, .. } = node
            .receive_owned_packet(meta(), input, |_| None, |_, _, _, _, data| Ok(data.len()))
            .unwrap()
        else {
            panic!("forward");
        };
        assert_eq!(pool.acquisitions.load(Ordering::Relaxed), before);
        assert_eq!(
            packet.bytes().as_ptr() as usize + 1 + destination.encoded_len(),
            tail
        );
        let mut expected = [0; crate::DEFAULT_PACKET_POOL_SLOT_SIZE];
        let used = crate::rewrite_dcid(&bytes, destination, &mut expected).unwrap();
        assert_eq!(packet.bytes(), &expected[..used]);
        if destination == cid(42) {
            assert_eq!(packet.packet_range(), original_range);
            assert_eq!(packet.bytes(), bytes);
        } else {
            assert_eq!(packet.packet_range().start, original_range.start - 7);
            assert_eq!(packet.packet_range().end, original_range.end);
        }
        drop(packet);
        assert_eq!(pool.available(), pool.capacity());
    }
}

#[test]
fn shared_buffer_is_not_mutated() {
    struct Shared(std::sync::Arc<Vec<u8>>);
    impl AsRef<[u8]> for Shared {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }
    impl PacketBuffer for Shared {
        fn as_mut_unique(&mut self) -> Option<&mut [u8]> {
            std::sync::Arc::get_mut(&mut self.0).map(Vec::as_mut_slice)
        }
    }
    let bytes = fixture(64, cid(42));
    let backing = std::sync::Arc::new(bytes.clone());
    let packet = OwnedPacket::new(Shared(backing.clone()), 0..bytes.len())
        .ok()
        .unwrap();
    let (error, unchanged) = crate::rewrite_dcid_in_place(packet, cid(43), 0, 1100)
        .err()
        .unwrap();
    assert_eq!(error, Error::Blocked);
    assert_eq!(unchanged.bytes(), bytes);
    assert_eq!(&**backing, bytes);
}

#[test]
fn rewrite_preserves_packet_numbers_and_opaque_payload_and_rejects_bad_headers() {
    let pool = Pool::new();
    for packet_number_len in 1..=4 {
        let mut bytes = vec![0; 128];
        let len = ShortHeader {
            flags: crate::FLAG_FIXED,
            dcid: cid(42),
            packet_number: 0x12345678,
            packet_number_len,
        }
        .encode(&mut bytes)
        .unwrap();
        // Opaque bytes include values that are not valid QUIC frames. A relay
        // must preserve these (including ciphertext/tags), not decode them.
        for (index, byte) in bytes[len..].iter_mut().enumerate() {
            *byte = index as u8;
        }
        let original = pooled(pool, &bytes, 80);
        let rewritten = crate::rewrite_dcid_in_place(original, cid(1 << 30), 0, 1100).unwrap();
        assert_eq!(
            &rewritten.bytes()[1 + cid(1 << 30).encoded_len()..],
            &bytes[2..]
        );
    }
    for bytes in [
        vec![],
        vec![crate::FLAG_FIXED],
        vec![crate::FLAG_FIXED, 42],
        vec![0x80, 1, 2, 3],
    ] {
        let original = pooled(pool, &bytes, 80);
        let (_, unchanged) =
            crate::rewrite_dcid_in_place(original, cid(12345), 0, 1100).unwrap_err();
        assert_eq!(unchanged.bytes(), bytes);
    }
    assert_eq!(pool.available(), pool.capacity());
}

#[test]
fn runtime_falls_back_to_copy_when_cid_growth_has_no_headroom() {
    let pool = Pool::new();
    let mut node = relay(pool);
    let bytes = fixture(64, cid(42));
    let input = pooled(pool, &bytes, 0);
    let before = pool.acquisitions.load(Ordering::Relaxed);
    let NodeIngress::Forward { packet, .. } = node
        .receive_owned_packet(meta(), input, |_| None, |_, _, _, _, bytes| Ok(bytes.len()))
        .unwrap()
    else {
        panic!("forward");
    };
    assert_eq!(pool.acquisitions.load(Ordering::Relaxed), before + 1);
    let mut expected = [0; 1100];
    let used = crate::rewrite_dcid(&bytes, cid(12345), &mut expected).unwrap();
    assert_eq!(packet.bytes(), &expected[..used]);
    drop(packet);
    assert_eq!(pool.available(), pool.capacity());
}

#[test]
fn reuse_leaves_control_reserve_free_and_control_can_forward_at_full_pool() {
    for control in [false, true] {
        let pool = Pool::new();
        let mut node = relay(pool);
        let mut limits = node.limits();
        limits.relay_control_packet_reserve = 2;
        node.set_limits(limits).unwrap();
        let mut bytes = fixture(64, cid(42));
        if control {
            let header = ShortHeader::decode_prefix(&bytes).unwrap();
            bytes.truncate(header.header_len);
            let mut control = [0; 16];
            let used = Frame::MaxData(32).encode(&mut control).unwrap();
            bytes.extend_from_slice(&control[..used]);
        }
        let input = pooled(pool, &bytes, 80);
        let held: Vec<_> = (0..if control { 31 } else { 29 })
            .map(|_| pooled(pool, b"held", 0))
            .collect();
        let before = pool.available();
        let result = node
            .receive_owned_packet(meta(), input, |_| None, |_, _, _, _, bytes| Ok(bytes.len()))
            .unwrap();
        assert!(matches!(result, NodeIngress::Forward { .. }));
        assert_eq!(pool.available(), before);
        drop(result);
        drop(held);
        assert_eq!(pool.available(), pool.capacity());
    }
}

#[test]
fn relay_runtime_preserves_rx_lease_without_a_free_output_slot() {
    let pool = Pool::new();
    let mut node = relay(pool);
    let bytes = fixture(1050, cid(42));
    let input = pooled(pool, &bytes, crate::PACKET_PREFIX_RESERVE);
    let tail = input.bytes().as_ptr() as usize + 1 + cid(42).encoded_len();
    let held: Vec<_> = (0..31).map(|_| pooled(pool, b"held", 0)).collect();
    let before = pool.acquisitions.load(Ordering::Relaxed);
    let NodeIngress::Forward { packet, .. } = node
        .receive_owned_packet(meta(), input, |_| None, |_, _, _, _, bytes| Ok(bytes.len()))
        .unwrap()
    else {
        panic!("forwarded packet");
    };
    assert_eq!(pool.acquisitions.load(Ordering::Relaxed), before);
    assert_eq!(
        packet.bytes().as_ptr() as usize + 1 + cid(12345).encoded_len(),
        tail
    );
    let mut expected = [0; crate::DEFAULT_PACKET_POOL_SLOT_SIZE];
    let used = crate::rewrite_dcid(&bytes, cid(12345), &mut expected).unwrap();
    assert_eq!(packet.bytes(), &expected[..used]);
    drop(packet);
    drop(held);
    assert_eq!(pool.available(), pool.capacity());
}

#[test]
fn runtime_preserves_expiry_quota_and_control_reserve_policy() {
    // A quota of two reserves one slot for control, leaving one data packet.
    for (quota, expiry, reserve) in [(2, 1_000_000, 0), (0, 1, 0), (0, 1_000_000, 32)] {
        let pool = Pool::new();
        let mut node = relay(pool);
        let mut settings = node.limits();
        settings.relay_control_packet_reserve = reserve;
        node.set_limits(settings).unwrap();
        node.remove_forward(cid(42));
        let mut rule = rule(cid(12345));
        rule.packet_quota = quota;
        rule.lease_expires_at_us = expiry;
        node.register_forward(cid(42), rule).unwrap();
        let bytes = fixture(64, cid(42));
        for iteration in 0..2 {
            let input = pooled(pool, &bytes, 80);
            let result = node
                .receive_owned_packet(meta(), input, |_| None, |_, _, _, _, bytes| Ok(bytes.len()))
                .unwrap();
            let expected_forward = quota == 2 && iteration == 0;
            assert_eq!(
                matches!(result, NodeIngress::Forward { .. }),
                expected_forward
            );
            if let NodeIngress::Unknown { packet, .. } = result {
                assert_eq!(packet.bytes(), bytes);
            }
        }
        assert_eq!(pool.available(), pool.capacity());
    }
}

fn association_pair() -> (
    QuicNode<Pool>,
    QuicNode<Pool>,
    crate::QuicAssociation,
    crate::QuicAssociation,
    &'static Pool,
    &'static Pool,
) {
    association_pair_with_limits(crate::AssociationLimits::host().connection)
}

pub(super) fn association_pair_with_limits(
    limits: crate::ConnectionLimits,
) -> (
    QuicNode<Pool>,
    QuicNode<Pool>,
    crate::QuicAssociation,
    crate::QuicAssociation,
    &'static Pool,
    &'static Pool,
) {
    let (a, b) = (Pool::new(), Pool::new());
    let mut client = QuicNode::new(a);
    let mut server = QuicNode::new(b);
    for node in [&mut client, &mut server] {
        node.set_limits(crate::NodeLimits::host()).unwrap();
        node.set_default_association_limits(crate::AssociationLimits {
            connection: limits,
            ..crate::AssociationLimits::host()
        })
        .unwrap();
        register(node, "sim-stream");
    }
    let initial = client.start_association(cid(111), meta(), 0).unwrap();
    let client_id = initial.association;
    let NodeIngress::Initial {
        association: server_id,
        response,
    } = server
        .receive_owned_packet(
            meta(),
            initial.packet,
            |_| {
                Some(InitialAdmission {
                    local_limits: limits,
                })
            },
            |_, _, _, _, bytes| Ok(bytes.len()),
        )
        .unwrap()
    else {
        panic!("initial");
    };
    client
        .receive_owned_packet(
            meta(),
            response.packet,
            |_| None,
            |_, _, _, _, bytes| Ok(bytes.len()),
        )
        .unwrap();
    (client, server, client_id, server_id, a, b)
}

// Simulator-only u16 record length, NOT a proposed companion wire format.
// No PHY delivery is timed; stream recovery/encode/receive/credit are real.
fn stream_records(count: usize, size: usize) -> (usize, usize, usize) {
    let (mut client, mut server, client_id, server_id, a, b) = association_pair();
    let stream = client.allocate_stream(client_id).unwrap();
    let bytes = fixture(size, cid(42));
    let mut record = Vec::with_capacity(bytes.len() + 2);
    record.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    record.extend_from_slice(&bytes);
    let mut received = Vec::with_capacity(record.len());
    let mut offset = 0;
    let mut packets = 0;
    a.reset();
    b.reset();
    for _ in 0..count {
        for chunk in record.chunks(crate::DEFAULT_MAX_STREAM_PAYLOAD) {
            let now = packets as u64 * 10_000 + 10_000;
            client.advance_clock(now);
            let output = client
                .send_stream(client_id, stream, offset, false, chunk)
                .unwrap();
            let acceptance = client
                .packet_acceptance_for(client_id, &output.packet)
                .unwrap();
            client.record_packet_acceptance(acceptance, now);
            offset += chunk.len() as u64;
            packets += 1;
            let mut received_meta = meta();
            received_meta.received_at_us = now + 100;
            server
                .receive_owned_packet(
                    received_meta,
                    output.packet,
                    |_| None,
                    |_, _, _, _, data| {
                        received.extend_from_slice(data);
                        Ok(data.len())
                    },
                )
                .unwrap();
            if let Some(ack) = server.poll_association_control(server_id).unwrap() {
                let acceptance = server
                    .packet_acceptance_for(server_id, &ack.packet)
                    .unwrap();
                server.record_packet_acceptance(acceptance, now + 100);
                received_meta.received_at_us = now + 200;
                client
                    .receive_owned_packet(
                        received_meta,
                        ack.packet,
                        |_| None,
                        |_, _, _, _, data| Ok(data.len()),
                    )
                    .unwrap();
            }
        }
        assert_eq!(received, record);
        received.clear();
    }
    assert_eq!(a.available(), a.capacity());
    assert_eq!(b.available(), b.capacity());
    (
        packets,
        a.acquisitions.load(Ordering::Relaxed) + b.acquisitions.load(Ordering::Relaxed),
        a.peak
            .load(Ordering::Relaxed)
            .max(b.peak.load(Ordering::Relaxed)),
    )
}

#[test]
fn stream_forwarding_reassembles_records_split_across_packets() {
    let (packets, _, _) = stream_records(8, 1050);
    assert!(packets >= 16);
}

#[test]
#[ignore = "host performance experiment; use release --ignored --nocapture"]
fn forwarding_performance_comparison() {
    let count = std::env::var("DMESH_FORWARDING_PACKETS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000usize);
    assert!(count > 0);
    std::println!(
        "mode,record_bytes,records,stream_packets,ns_per_record,MiB_per_s,pool_acquisitions,peak_slots"
    );
    for size in [64, 256, 1024, 1050] {
        let bytes = fixture(size, cid(42));
        for mode in ["relay_copy", "relay_inplace"] {
            let pool = Pool::new();
            let mut node = relay(pool);
            let start = Instant::now();
            for _ in 0..count {
                let input = pooled(pool, &bytes, crate::PACKET_PREFIX_RESERVE);
                let result = if mode == "relay_copy" {
                    node.receive_packet(meta(), input, |_| None, |_, _, _, _, data| Ok(data.len()))
                } else {
                    node.receive_owned_packet(
                        meta(),
                        input,
                        |_| None,
                        |_, _, _, _, data| Ok(data.len()),
                    )
                }
                .unwrap();
                let NodeIngress::Forward { packet, .. } = result else {
                    panic!("forward");
                };
                std::hint::black_box(packet.bytes());
                drop(packet);
            }
            let elapsed = start.elapsed().as_secs_f64();
            std::println!(
                "{mode},{},{count},0,{:.1},{:.2},{},{}",
                bytes.len(),
                elapsed * 1e9 / count as f64,
                (bytes.len() * count) as f64 / elapsed / 1048576.0,
                pool.acquisitions.load(Ordering::Relaxed),
                pool.peak.load(Ordering::Relaxed)
            );
            assert_eq!(pool.available(), pool.capacity());
        }
        let start = Instant::now();
        let (packets, acquisitions, peak) = stream_records(count, size);
        let elapsed = start.elapsed().as_secs_f64();
        std::println!(
            "mc_stream,{},{count},{packets},{:.1},{:.2},{acquisitions},{peak}",
            bytes.len(),
            elapsed * 1e9 / count as f64,
            (bytes.len() * count) as f64 / elapsed / 1048576.0
        );
    }
}
