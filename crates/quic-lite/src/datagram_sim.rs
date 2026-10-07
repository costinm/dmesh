//! Generic host-only datagram and A -> forwarding adapter -> B scenarios.
use super::forwarding_sim::{
    Buffer, Pool, association_pair_with_limits, cid, meta, pooled, register,
};
use super::*;
use crate::bearer::{PacketBuffer, PacketPool};
use crate::{DatagramPriority, Frame, ShortHeader};
use std::{
    boxed::Box,
    sync::{Arc, Mutex},
    vec,
    vec::Vec,
};
type Node = QuicNode<Pool>;

fn limits() -> crate::ConnectionLimits {
    AssociationLimits::host().connection
}
fn endpoint(node: &mut Node, id: QuicAssociation) -> &mut crate::EndpointState {
    match &mut node.slot_mut(id).unwrap().state {
        Association::Client(client) => client.connection_mut().endpoint_mut().unwrap(),
        Association::Server(server) => &mut server.mux.endpoint,
    }
}
fn accept(node: &mut Node, output: &NodeEgress<Buffer>, now: u64) {
    let acceptance = node
        .packet_acceptance_for(output.association, &output.packet)
        .unwrap();
    node.record_packet_acceptance(acceptance, now);
}
fn at(now: u64) -> PacketMeta {
    PacketMeta {
        received_at_us: now,
        ..meta()
    }
}
fn rx(node: &mut Node, pool: &'static Pool, packet: OwnedPacket<Buffer>, now: u64) {
    let received = pooled(pool, packet.bytes(), PACKET_PREFIX_RESERVE);
    drop(packet);
    node.receive_owned_packet(
        at(now),
        received,
        |_| None,
        |_, _, _, _, data| Ok(data.len()),
    )
    .unwrap();
}
fn flush_ack(
    source: &mut Node,
    target: &mut Node,
    target_pool: &'static Pool,
    id: QuicAssociation,
    now: u64,
) {
    source.advance_clock(now);
    if let Some(ack) = source.poll_association_control(id).unwrap() {
        accept(source, &ack, now);
        rx(target, target_pool, ack.packet, now + 100);
    }
}

#[test]
fn datagrams_preserve_lease_and_flow_credit_and_retire_metadata_on_ack() {
    let (mut a, mut c, aid, cid, ap, cp) = association_pair_with_limits(limits());
    let saved = Arc::new(Mutex::new(None));
    let received = saved.clone();
    c.set_datagram_handler(cid, move |batch| *received.lock().unwrap() = Some(batch))
        .unwrap();
    let send_credit = endpoint(&mut a, aid).send.sent_data;
    let receive_credit = endpoint(&mut c, cid).receive.received_data;
    let payload = pooled(ap, b"opaque\x00\xff", 80);
    let pointer = payload.bytes().as_ptr();
    let before = ap.acquisitions.load(core::sync::atomic::Ordering::Relaxed);
    let output = a
        .prepare_datagram(aid, payload, DatagramPriority::High)
        .unwrap();
    assert_eq!(
        ap.acquisitions.load(core::sync::atomic::Ordering::Relaxed),
        before
    );
    assert!(
        endpoint(&mut a, aid)
            .send_buffer
            .iter()
            .all(Option::is_none)
    );
    assert_eq!(endpoint(&mut a, aid).send.sent_data, send_credit);
    let header = ShortHeader::decode_prefix(output.packet.bytes()).unwrap();
    assert_eq!(
        output.packet.bytes()[header.header_len + 1..].as_ptr(),
        pointer
    );
    accept(&mut a, &output, 1);
    let input = pooled(cp, output.packet.bytes(), 80);
    let pointer = input.bytes()[header.header_len + 1..].as_ptr();
    drop(output);
    c.receive_owned_packet(at(100), input, |_| None, |_, _, _, _, data| Ok(data.len()))
        .unwrap();
    let batch = saved.lock().unwrap().take().unwrap();
    let payload = batch.packet;
    assert_eq!(payload.bytes(), b"opaque\x00\xff");
    assert_eq!(payload.bytes().as_ptr(), pointer);
    assert_eq!(endpoint(&mut c, cid).receive.received_data, receive_credit);
    assert!(endpoint(&mut c, cid).receive.streams.is_empty());
    drop(payload);
    flush_ack(&mut c, &mut a, ap, cid, 30_000);
    assert_eq!(endpoint(&mut a, aid).in_flight_packet_count(), 0);
    assert_eq!(ap.available(), ap.capacity());
    assert_eq!(cp.available(), cp.capacity());
}

#[test]
fn refusal_is_transactional_for_support_size_headroom_congestion_and_low_priority() {
    for case in 0..6 {
        let (mut a, _, aid, _, ap, _) = association_pair_with_limits(limits());
        match case {
            0 => endpoint(&mut a, aid).set_peer_datagram_limit(0),
            1 => endpoint(&mut a, aid).set_peer_datagram_limit(2),
            3 => {
                let e = endpoint(&mut a, aid);
                e.paths[0].congestion.bytes_in_flight = e.paths[0].congestion.congestion_window;
            }
            4 => {
                let e = endpoint(&mut a, aid);
                e.send.sent_data = e.send.max_data;
            }
            5 => {
                endpoint(&mut a, aid).close_code = Some(0);
            }
            _ => {}
        }
        let packet = pooled(ap, b"payload", if case == 2 { 0 } else { 80 });
        let pointer = packet.bytes().as_ptr();
        let range = packet.packet_range();
        let number = endpoint(&mut a, aid).next_packet_number;
        let error = a
            .prepare_datagram(
                aid,
                packet,
                if case == 4 {
                    DatagramPriority::Low
                } else {
                    DatagramPriority::High
                },
            )
            .err()
            .unwrap();
        assert_eq!(error.packet.bytes(), b"payload");
        assert_eq!(error.packet.bytes().as_ptr(), pointer);
        assert_eq!(error.packet.packet_range(), range);
        assert_eq!(endpoint(&mut a, aid).next_packet_number, number);
    }
}

#[test]
fn default_datagrams_are_dedicated_and_callback_owns_the_payload() {
    let defaults = crate::ConnectionLimits::default();
    assert_eq!(
        defaults.max_datagram_frame_size,
        crate::DEFAULT_MAX_DATAGRAM_FRAME_SIZE as u64
    );
    assert_eq!(
        crate::ConnectionLimits::with_receive_window(4096).max_datagram_frame_size,
        crate::DEFAULT_MAX_DATAGRAM_FRAME_SIZE as u64
    );
    let (mut a, mut c, aid, cid, ap, cp) = association_pair_with_limits(defaults);
    let saved = Arc::new(Mutex::new(None));
    let received = saved.clone();
    c.set_datagram_handler(cid, move |datagram| {
        *received.lock().unwrap() = Some(datagram);
    })
    .unwrap();
    // Reliable data and control can exist without being piggybacked onto DG.
    let stream = a.allocate_stream(aid).unwrap();
    let reliable = a.send_stream(aid, stream, 0, true, b"reliable").unwrap();
    let input = pooled(ap, b"datagram", crate::PACKET_PREFIX_RESERVE);
    let payload_pointer = input.bytes().as_ptr();
    let packet = a
        .prepare_datagram(aid, input, DatagramPriority::High)
        .unwrap();
    let (_, header_len) = ShortHeader::decode(packet.packet.bytes()).unwrap();
    let (frame, used) = crate::decode_frame(&packet.packet.bytes()[header_len..]).unwrap();
    assert_eq!(
        frame,
        Frame::Datagram {
            data: b"datagram",
            length: false
        }
    );
    assert_eq!(header_len + used, packet.packet.bytes().len());
    assert_eq!(
        packet.packet.bytes()[header_len + 1..].as_ptr(),
        payload_pointer
    );
    let input = pooled(cp, packet.packet.bytes(), crate::PACKET_PREFIX_RESERVE);
    let pointer = input.bytes()[header_len + 1..].as_ptr();
    let before = cp.acquisitions.load(core::sync::atomic::Ordering::Relaxed);
    c.receive_owned_packet(
        at(100),
        input,
        |_| None,
        |_, _, _, _, _| panic!("no stream in datagram packet"),
    )
    .unwrap();
    let mut datagram = saved.lock().unwrap().take().unwrap();
    assert_eq!(datagram.association, cid);
    assert_eq!(datagram.meta.received_at_us, 100);
    assert_eq!(datagram.packet.bytes(), b"datagram");
    assert_eq!(datagram.packet.bytes().as_ptr(), pointer);
    assert!(datagram.packet.prefix_capacity() >= crate::PACKET_PREFIX_RESERVE);
    assert!(datagram.packet.bytes_mut_unique().is_some());
    assert_eq!(
        cp.acquisitions.load(core::sync::atomic::Ordering::Relaxed),
        before
    );
    // Forward the received ownership directly, using its existing headroom.
    let forwarded = c
        .prepare_datagram(cid, datagram.packet, DatagramPriority::High)
        .unwrap();
    let header = ShortHeader::decode_prefix(forwarded.packet.bytes()).unwrap();
    assert_eq!(
        forwarded.packet.bytes()[header.header_len + 1..].as_ptr(),
        pointer
    );
    drop((reliable, packet, forwarded));
    assert_eq!(ap.available(), ap.capacity());
    assert_eq!(cp.available(), cp.capacity());
}

#[test]
fn loss_does_not_retain_or_retransmit_a_datagram_and_duplicate_is_not_delivered_twice() {
    let (mut a, mut c, aid, cid, ap, _) = association_pair_with_limits(limits());
    let received = Arc::new(Mutex::new(0));
    let count = received.clone();
    c.set_datagram_handler(cid, move |_| *count.lock().unwrap() += 1)
        .unwrap();
    let output = a
        .prepare_datagram(
            aid,
            pooled(ap, b"must-not-retransmit", 80),
            DatagramPriority::High,
        )
        .unwrap();
    accept(&mut a, &output, 1);
    drop(output); // Outer loss: no application/recovery payload retained.
    for now in [300_000, 900_000, 2_000_000] {
        if let Some(NodeTimer::Egress(output)) = a.timer_expired(now).unwrap() {
            assert!(
                !output
                    .packet
                    .bytes()
                    .windows(19)
                    .any(|bytes| bytes == b"must-not-retransmit")
            );
            accept(&mut a, &output, now);
        }
    }
    assert!(
        endpoint(&mut a, aid)
            .send_buffer
            .iter()
            .all(Option::is_none)
    );
    a.advance_clock(3_000_000);
    let output = a
        .prepare_datagram(aid, pooled(ap, b"once", 80), DatagramPriority::High)
        .unwrap();
    let bytes = output.packet.bytes().to_vec();
    drop(output);
    for _ in 0..2 {
        c.receive_owned_packet(
            at(3_000_100),
            pooled(ap, &bytes, 80),
            |_| None,
            |_, _, _, _, data| Ok(data.len()),
        )
        .unwrap();
    }
    assert_eq!(*received.lock().unwrap(), 1);
}

// The adapter's routing metadata is application-owned test CBOR, never parsed
// by QUIC. 1=interface, 2=peer; the inner packet and its DCID remain unchanged.
const ROUTE: &[u8] = &[0xa2, 1, 1, 2, 1];
fn wrap(packet: OwnedPacket<Buffer>) -> OwnedPacket<Buffer> {
    let (mut buffer, range) = packet.into_parts();
    let start = range.start - ROUTE.len();
    buffer.as_mut_unique().unwrap()[start..range.start].copy_from_slice(ROUTE);
    OwnedPacket::new(buffer, start..range.end).ok().unwrap()
}
fn strip(batch: crate::ReceivedDatagram<Buffer>) -> OwnedPacket<Buffer> {
    let packet = batch.packet;
    assert_eq!(&packet.bytes()[..ROUTE.len()], ROUTE);
    let (buffer, range) = packet.into_parts();
    OwnedPacket::new(buffer, range.start + ROUTE.len()..range.end)
        .ok()
        .unwrap()
}

struct Scenario {
    a: Node,
    c: Node,
    b: Node,
    aid: QuicAssociation,
    bid: QuicAssociation,
    ac: Option<(QuicAssociation, QuicAssociation)>,
    ap: &'static Pool,
    cp: &'static Pool,
    bp: &'static Pool,
    at_a: Arc<Mutex<Option<OwnedPacket<Buffer>>>>,
    at_c: Arc<Mutex<Option<OwnedPacket<Buffer>>>>,
    now: u64,
}
impl Scenario {
    fn new(datagrams: bool) -> Self {
        let (mut a, b, aid, bid, ap, bp) = association_pair_with_limits(limits());
        let cp = Pool::new();
        let mut c = Node::new(cp);
        c.set_default_association_limits(AssociationLimits {
            connection: limits(),
            ..AssociationLimits::host()
        })
        .unwrap();
        register(&mut c, "sim-companion");
        // Independent virtual namespace, including without the Tokio seed.
        c.next_local_cid = 900;
        let at_a = Arc::new(Mutex::new(None));
        let at_c = Arc::new(Mutex::new(None));
        let ac = if datagrams {
            let initial = a.start_association(cid(222), meta(), 0).unwrap();
            let ac = initial.association;
            let NodeIngress::Initial {
                association: ca,
                response,
            } = c
                .receive_owned_packet(
                    meta(),
                    initial.packet,
                    |_| {
                        Some(InitialAdmission {
                            local_limits: limits(),
                        })
                    },
                    |_, _, _, _, bytes| Ok(bytes.len()),
                )
                .unwrap()
            else {
                panic!("initial");
            };
            a.receive_owned_packet(
                meta(),
                response.packet,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
            let received = at_a.clone();
            a.set_datagram_handler(ac, move |batch| {
                let mut slot = received.lock().unwrap();
                assert!(slot.is_none());
                *slot = Some(strip(batch));
            })
            .unwrap();
            let received = at_c.clone();
            c.set_datagram_handler(ca, move |batch| {
                let mut slot = received.lock().unwrap();
                assert!(slot.is_none());
                *slot = Some(strip(batch));
            })
            .unwrap();
            Some((ac, ca))
        } else {
            for destination in [
                a.slot(aid).unwrap().receive_cids[0].unwrap(),
                b.slot(bid).unwrap().receive_cids[0].unwrap(),
            ] {
                c.register_forward(
                    destination,
                    crate::relay::ForwardRule {
                        next_hop: crate::relay::ForwardNextHop {
                            bearer: meta().bearer,
                            peer_l2_address: meta().peer_l2_address,
                        },
                        destination: crate::relay::ForwardDestination::Connection(destination),
                        lease_duration_us: 60_000_000,
                        lease_expires_at_us: 60_000_000,
                        lease_group_id: 0,
                        packet_quota: 0,
                        forwarded_packets: 0,
                        forwarded_control_packets: 0,
                        quota_window_started_us: 0,
                    },
                )
                .unwrap();
            }
            None
        };
        Self {
            a,
            b,
            c,
            aid,
            bid,
            ac,
            ap,
            cp,
            bp,
            at_a,
            at_c,
            now: 1,
        }
    }

    fn transit(
        &mut self,
        inner: OwnedPacket<Buffer>,
        forward: bool,
        drop_outer: bool,
    ) -> Option<OwnedPacket<Buffer>> {
        self.now += 50_000;
        self.a.advance_clock(self.now);
        self.b.advance_clock(self.now);
        self.c.advance_clock(self.now);
        let expected = inner.bytes().to_vec();
        let output = if let Some((ac, ca)) = self.ac {
            if forward {
                let inner_pointer = inner.bytes().as_ptr();
                let output = self
                    .a
                    .prepare_datagram(ac, wrap(inner), DatagramPriority::High)
                    .unwrap();
                let header = ShortHeader::decode_prefix(output.packet.bytes()).unwrap();
                assert_eq!(
                    output.packet.bytes()[header.header_len + 1 + ROUTE.len()..].as_ptr(),
                    inner_pointer
                );
                accept(&mut self.a, &output, self.now);
                if drop_outer {
                    drop(output);
                    return None;
                }
                rx(&mut self.c, self.cp, output.packet, self.now + 100);
                let packet = self.at_c.lock().unwrap().take().unwrap();
                flush_ack(&mut self.c, &mut self.a, self.ap, ca, self.now + 30_000);
                packet
            } else {
                let input = pooled(self.cp, inner.bytes(), 80);
                drop(inner);
                let output = self
                    .c
                    .prepare_datagram(ca, wrap(input), DatagramPriority::High)
                    .unwrap();
                accept(&mut self.c, &output, self.now);
                if drop_outer {
                    drop(output);
                    return None;
                }
                rx(&mut self.a, self.ap, output.packet, self.now + 100);
                let packet = self.at_a.lock().unwrap().take().unwrap();
                flush_ack(&mut self.a, &mut self.c, self.cp, ac, self.now + 30_000);
                packet
            }
        } else {
            let input = pooled(self.cp, inner.bytes(), 80);
            drop(inner);
            let pointer = input.bytes().as_ptr();
            let before = self
                .cp
                .acquisitions
                .load(core::sync::atomic::Ordering::Relaxed);
            let NodeIngress::Forward { packet, .. } = self
                .c
                .receive_owned_packet(
                    at(self.now),
                    input,
                    |_| None,
                    |_, _, _, _, bytes| Ok(bytes.len()),
                )
                .unwrap()
            else {
                panic!("relay");
            };
            assert_eq!(packet.bytes().as_ptr(), pointer);
            assert_eq!(
                self.cp
                    .acquisitions
                    .load(core::sync::atomic::Ordering::Relaxed),
                before
            );
            if drop_outer {
                drop(packet);
                return None;
            }
            packet
        };
        assert_eq!(output.bytes(), expected);
        Some(output)
    }

    fn receive_b(&mut self, inner: OwnedPacket<Buffer>, received: &mut Vec<u8>) {
        let input = pooled(self.bp, inner.bytes(), 80);
        drop(inner);
        self.b
            .receive_owned_packet(
                at(self.now + 100),
                input,
                |_| None,
                |_, _, _, _, bytes| {
                    received.extend_from_slice(bytes);
                    Ok(bytes.len())
                },
            )
            .unwrap();
        self.b.advance_clock(self.now + 30_000);
        if let Some(ack) = self.b.poll_association_control(self.bid).unwrap() {
            accept(&mut self.b, &ack, self.now + 30_000);
            let inner = self.transit(ack.packet, false, false).unwrap();
            rx(&mut self.a, self.ap, inner, self.now + 100);
        }
    }
}

fn transfer(datagrams: bool, drop_first: bool) {
    transfer_with_protection(datagrams, drop_first, false);
}

fn transfer_with_protection(datagrams: bool, drop_first: bool, protected: bool) -> (usize, usize) {
    let mut sim = Scenario::new(datagrams);
    #[cfg(feature = "packet-protection")]
    if protected {
        protect_pair(&mut sim.a, &mut sim.b, sim.aid, sim.bid, 0x42);
        if let Some((ac, ca)) = sim.ac {
            protect_pair(&mut sim.a, &mut sim.c, ac, ca, 0x43);
        }
    }
    #[cfg(not(feature = "packet-protection"))]
    assert!(!protected);
    let stream = sim.a.allocate_stream(sim.aid).unwrap();
    let mut received = Vec::new();
    let expected = vec![0x5a; 64 * 1024];
    let mut offset = 0;
    for (index, chunk) in expected.chunks(512).enumerate() {
        sim.a.advance_clock(sim.now + 50_000);
        let output = sim
            .a
            .send_stream(
                sim.aid,
                stream,
                offset,
                offset + chunk.len() as u64 == expected.len() as u64,
                chunk,
            )
            .unwrap();
        accept(&mut sim.a, &output, sim.now + 50_000);
        let inner = sim.transit(output.packet, true, drop_first && index == 0);
        if let Some(inner) = inner {
            sim.receive_b(inner, &mut received);
        }
        if drop_first && index == 0 {
            // Recovery belongs to A-B, not the unreliable A-C DATAGRAM.
            for _ in 0..20 {
                sim.now += 100_000;
                if let Some(NodeTimer::Egress(output)) = sim.a.timer_expired(sim.now).unwrap() {
                    accept(&mut sim.a, &output, sim.now);
                    if output.association == sim.aid {
                        let inner = sim.transit(output.packet, true, false).unwrap();
                        sim.receive_b(inner, &mut received);
                    } else {
                        rx(&mut sim.c, sim.cp, output.packet, sim.now + 100);
                    }
                }
                if !received.is_empty() {
                    break;
                }
            }
            assert_eq!(
                received.len(),
                512,
                "end-to-end stream recovered the dropped inner packet"
            );
        }
        offset += chunk.len() as u64;
    }
    assert_eq!(received, expected);
    let response = sim
        .b
        .send_stream(sim.bid, stream, 0, true, b"reply")
        .unwrap();
    accept(&mut sim.b, &response, sim.now);
    let inner = sim.transit(response.packet, false, false).unwrap();
    let mut reply = Vec::new();
    sim.a
        .receive_owned_packet(
            at(sim.now),
            inner,
            |_| None,
            |_, _, _, _, bytes| {
                reply.extend_from_slice(bytes);
                Ok(bytes.len())
            },
        )
        .unwrap();
    assert_eq!(reply, b"reply");
    assert_eq!(sim.c.association_count(), usize::from(datagrams));
    assert_eq!(sim.b.association_count(), 1);
    for pool in [sim.ap, sim.cp, sim.bp] {
        assert_eq!(pool.available(), pool.capacity());
    }
    let acquisitions = [sim.ap, sim.cp, sim.bp]
        .iter()
        .map(|pool| {
            pool.acquisitions
                .load(core::sync::atomic::Ordering::Relaxed)
        })
        .sum();
    let peak = [sim.ap, sim.cp, sim.bp]
        .iter()
        .map(|pool| pool.peak.load(core::sync::atomic::Ordering::Relaxed))
        .max()
        .unwrap();
    (acquisitions, peak)
}

#[test]
#[ignore = "host three-node CPU comparison; release --ignored --nocapture"]
fn three_node_forwarding_performance_comparison() {
    let count = 50;
    std::println!(
        "mode,transfers,body_bytes,ns_per_512_byte_record,MiB_per_s,pool_acquisitions_per_transfer,peak_slots_per_pool"
    );
    for datagrams in [false, true] {
        let start = std::time::Instant::now();
        let mut acquisitions = 0;
        let mut peak = 0;
        for _ in 0..count {
            let (used, high_water) = transfer_with_protection(datagrams, false, false);
            acquisitions += used;
            peak = peak.max(high_water);
        }
        let elapsed = start.elapsed().as_secs_f64();
        std::println!(
            "{},{count},65536,{:.1},{:.2},{},{}",
            if datagrams {
                "datagram_tunnel"
            } else {
                "relay"
            },
            elapsed * 1e9 / (count * 128) as f64,
            (count * 65536) as f64 / elapsed / 1048576.0,
            acquisitions / count,
            peak
        );
    }
}

#[test]
fn a_companion_b_relay_preserves_inner_packets_bidirectionally() {
    transfer(false, false);
}
#[test]
fn a_companion_b_datagrams_preserve_inner_packets_bidirectionally() {
    transfer(true, false);
}
#[test]
fn a_companion_b_relay_recovers_a_dropped_inner_packet() {
    transfer(false, true);
}
#[test]
fn a_companion_b_datagrams_recover_a_dropped_outer_packet() {
    transfer(true, true);
}

#[cfg(feature = "packet-protection")]
fn protect_pair(
    a: &mut Node,
    b: &mut Node,
    aid: QuicAssociation,
    bid: QuicAssociation,
    secret: u8,
) {
    let client_cid = endpoint(a, aid).local_connection_id_on_path(0).unwrap();
    let server_cid = endpoint(b, bid).local_connection_id_on_path(0).unwrap();
    let keys = || {
        crate::crypto::derive_traffic_keys(
            &[secret; 32],
            &[0x11; crate::crypto::ASSOCIATION_RANDOM_LEN],
            &[0x22; crate::crypto::ASSOCIATION_RANDOM_LEN],
            client_cid,
            server_cid,
        )
        .unwrap()
    };
    endpoint(a, aid).protection = Some(keys().for_role(crate::Role::Client));
    endpoint(b, bid).protection = Some(keys().for_role(crate::Role::Server));
}

#[cfg(feature = "packet-protection")]
#[test]
fn a_companion_b_relay_recovers_encrypted_end_to_end_stream() {
    transfer_with_protection(false, true, true);
}

#[cfg(feature = "packet-protection")]
#[test]
fn a_companion_b_datagrams_recover_encrypted_inner_stream_with_separate_outer_keys() {
    transfer_with_protection(true, true, true);
}

#[test]
fn coalesced_datagrams_streams_and_control_validate_before_delivery() {
    let (mut a, mut c, aid, cid, _, cp) = association_pair_with_limits(limits());
    let received = Arc::new(Mutex::new(Vec::new()));
    let output = received.clone();
    c.set_datagram_handler(cid, move |batch| {
        output.lock().unwrap().push(batch.packet);
    })
    .unwrap();
    let mut bytes = [0; 256];
    let e = endpoint(&mut a, aid);
    let mut used = ShortHeader {
        flags: crate::FLAG_FIXED,
        dcid: e.peer_connection_id_on_path(0).unwrap(),
        packet_number: e.next_packet_number,
        packet_number_len: 4,
    }
    .encode(&mut bytes)
    .unwrap();
    for frame in [
        Frame::Datagram {
            data: b"one",
            length: true,
        },
        Frame::Ping,
        Frame::Stream(crate::StreamFrame {
            id: crate::FIRST_CLIENT_BIDI_STREAM_ID,
            offset: 0,
            fin: true,
            data: b"stream",
        }),
        Frame::Datagram {
            data: b"two",
            length: true,
        },
    ] {
        used += frame.encode(&mut bytes[used..]).unwrap();
    }
    let mut stream = Vec::new();
    let mut malformed = bytes[..used].to_vec();
    malformed.push(0xff);
    assert!(
        c.receive_owned_packet(
            at(1),
            pooled(cp, &malformed, 80),
            |_| None,
            |_, _, _, _, data| {
                stream.extend_from_slice(data);
                Ok(data.len())
            }
        )
        .is_err()
    );
    assert!(received.lock().unwrap().is_empty());
    assert!(stream.is_empty());
    c.receive_owned_packet(
        at(2),
        pooled(cp, &bytes[..used], 80),
        |_| None,
        |_, _, _, _, data| {
            stream.extend_from_slice(data);
            Ok(data.len())
        },
    )
    .unwrap();
    let mut packets = received.lock().unwrap();
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].bytes(), b"one");
    assert_eq!(packets[1].bytes(), b"two");
    assert_ne!(packets[0].bytes().as_ptr(), packets[1].bytes().as_ptr());
    for packet in packets.iter_mut() {
        assert!(packet.bytes_mut_unique().is_some());
    }
    packets.clear();
    assert_eq!(cp.available(), cp.capacity());
    assert_eq!(stream, b"stream");
}

#[test]
fn unsupported_or_oversize_receive_is_protocol_violation() {
    for limit in [0, 2] {
        let (mut a, mut c, aid, cid, _, cp) =
            association_pair_with_limits(crate::ConnectionLimits {
                max_datagram_frame_size: limit,
                ..limits()
            });
        let e = endpoint(&mut a, aid);
        let mut bytes = [0; 64];
        let mut used = ShortHeader {
            flags: crate::FLAG_FIXED,
            dcid: e.peer_connection_id_on_path(0).unwrap(),
            packet_number: e.next_packet_number,
            packet_number_len: 4,
        }
        .encode(&mut bytes)
        .unwrap();
        used += Frame::Datagram {
            data: b"too-large",
            length: true,
        }
        .encode(&mut bytes[used..])
        .unwrap();
        let result = c
            .receive_owned_packet(
                at(100),
                pooled(cp, &bytes[..used], 80),
                |_| None,
                |_, _, _, _, data| Ok(data.len()),
            )
            .unwrap();
        let NodeIngress::PathControl { response, .. } = result else {
            panic!("protocol CLOSE");
        };
        let (_, header_len) = ShortHeader::decode(response.packet.bytes()).unwrap();
        assert_eq!(
            crate::decode_frame(&response.packet.bytes()[header_len..])
                .unwrap()
                .0,
            Frame::Close { code: 0x0a }
        );
        assert!(c.slot(cid).is_none());
    }
}

#[test]
fn foreign_coalesced_datagrams_drop_copy_fallback_at_full_pool() {
    let (mut a, mut c, aid, cid, _, cp) = association_pair_with_limits(limits());
    let saved = Arc::new(Mutex::new(Vec::new()));
    let received = saved.clone();
    c.set_datagram_handler(cid, move |datagram| {
        received.lock().unwrap().push(datagram.packet)
    })
    .unwrap();
    let e = endpoint(&mut a, aid);
    let mut bytes = [0; 128];
    let mut used = ShortHeader {
        flags: crate::FLAG_FIXED,
        dcid: e.peer_connection_id_on_path(0).unwrap(),
        packet_number: e.next_packet_number,
        packet_number_len: 4,
    }
    .encode(&mut bytes)
    .unwrap();
    for data in [&b"needs-extra-slot"[..], &b"original-lease"[..]] {
        used += Frame::Datagram { data, length: true }
            .encode(&mut bytes[used..])
            .unwrap();
    }
    let input = pooled(cp, &bytes[..used], crate::PACKET_PREFIX_RESERVE);
    let mut held = Vec::new();
    while let Some(writer) = cp.acquire_writer(0, 0) {
        held.push(crate::bearer::PacketWriter::commit(writer, 0).unwrap());
    }
    assert_eq!(cp.available(), 0);
    let before = cp.acquisitions.load(core::sync::atomic::Ordering::Relaxed);
    c.receive_owned_packet(at(1), input, |_| None, |_, _, _, _, data| Ok(data.len()))
        .unwrap();
    let mut received = saved.lock().unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].bytes(), b"original-lease");
    assert!(received[0].bytes_mut_unique().is_some());
    assert_eq!(
        cp.acquisitions.load(core::sync::atomic::Ordering::Relaxed),
        before
    );
    received.clear();
    drop(held);
    assert_eq!(cp.available(), cp.capacity());
}

#[cfg(feature = "packet-protection")]
#[test]
fn protected_datagram_decrypts_in_same_lease_and_tampering_has_no_delivery() {
    let (mut a, mut c, aid, cid, ap, cp) = association_pair_with_limits(limits());
    let client_cid = endpoint(&mut a, aid)
        .local_connection_id_on_path(0)
        .unwrap();
    let server_cid = endpoint(&mut c, cid)
        .local_connection_id_on_path(0)
        .unwrap();
    let keys = || {
        crate::crypto::derive_traffic_keys(
            &[0x42; 32],
            &[0x11; crate::crypto::ASSOCIATION_RANDOM_LEN],
            &[0x22; crate::crypto::ASSOCIATION_RANDOM_LEN],
            client_cid,
            server_cid,
        )
        .unwrap()
    };
    endpoint(&mut a, aid).protection = Some(keys().for_role(crate::Role::Client));
    endpoint(&mut c, cid).protection = Some(keys().for_role(crate::Role::Server));
    let saved = Arc::new(Mutex::new(None));
    let received = saved.clone();
    c.set_datagram_handler(cid, move |batch| *received.lock().unwrap() = Some(batch))
        .unwrap();
    let payload = pooled(ap, b"secret", 80);
    let pointer = payload.bytes().as_ptr();
    let output = a
        .prepare_datagram(aid, payload, DatagramPriority::High)
        .unwrap();
    let header = ShortHeader::decode_prefix(output.packet.bytes()).unwrap();
    assert_eq!(
        output.packet.bytes()[header.header_len + 1..].as_ptr(),
        pointer
    );
    assert!(
        !output
            .packet
            .bytes()
            .windows(6)
            .any(|bytes| bytes == b"secret")
    );
    let mut tampered = output.packet.bytes().to_vec();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(
        c.receive_owned_packet(
            at(1),
            pooled(cp, &tampered, 80),
            |_| None,
            |_, _, _, _, data| Ok(data.len())
        )
        .is_err()
    );
    assert!(saved.lock().unwrap().is_none());
    let input = pooled(cp, output.packet.bytes(), 80);
    let pointer = input.bytes()[header.header_len + 1..].as_ptr();
    drop(output);
    c.receive_owned_packet(at(2), input, |_| None, |_, _, _, _, data| Ok(data.len()))
        .unwrap();
    let payload = saved.lock().unwrap().take().unwrap().packet;
    assert_eq!(payload.bytes(), b"secret");
    assert_eq!(payload.bytes().as_ptr(), pointer);
    drop(payload);
    flush_ack(&mut c, &mut a, ap, cid, 30_000);
    assert_eq!(endpoint(&mut a, aid).in_flight_packet_count(), 0);
}

#[test]
fn full_pool_datagram_uses_existing_lease_and_missing_handler_releases_rx() {
    let (mut a, mut c, aid, _, ap, cp) = association_pair_with_limits(limits());
    let payload = pooled(ap, b"full-pool", 80);
    let held: Vec<_> = (0..31).map(|_| pooled(ap, b"held", 0)).collect();
    assert_eq!(ap.available(), 0);
    let output = a
        .prepare_datagram(aid, payload, DatagramPriority::High)
        .unwrap();
    let input = pooled(cp, output.packet.bytes(), 80);
    drop(output);
    drop(held);
    c.receive_owned_packet(at(1), input, |_| None, |_, _, _, _, data| Ok(data.len()))
        .unwrap();
    assert_eq!(ap.available(), ap.capacity());
    assert_eq!(cp.available(), cp.capacity());
}

#[cfg(feature = "tokio")]
#[test]
fn late_bearer_would_block_retries_exact_datagram_and_completes_once() {
    use crate::bearer::{
        BearerContext, BearerInfo, EgressSubmission, PacketBearer, PacketEgress, PacketSubmitError,
    };
    struct RetryBearer {
        context: Arc<Mutex<Option<BearerContext<Pool>>>>,
        calls: Arc<Mutex<Vec<(usize, Vec<u8>)>>>,
    }
    impl PacketEgress<Buffer> for RetryBearer {
        fn submit(
            &mut self,
            _: PeerL2Address,
            submission: EgressSubmission<Buffer>,
        ) -> Result<(), PacketSubmitError<Buffer>> {
            let mut calls = self.calls.lock().unwrap();
            calls.push((
                submission.packet().bytes().as_ptr() as usize,
                submission.packet().bytes().to_vec(),
            ));
            if calls.len() == 1 {
                return Err(PacketSubmitError::WouldBlock(submission));
            }
            submission.complete(crate::PacketSendOutcome::Sent, 100);
            Ok(())
        }
    }
    impl PacketBearer<Pool> for RetryBearer {
        type AttachError = core::convert::Infallible;
        fn info(&self) -> BearerInfo {
            BearerInfo {
                name: crate::BearerName::new("retry-datagram").unwrap(),
                max_packet_size: crate::DEFAULT_MAX_PACKET_SIZE,
                prefix_required: 0,
                suffix_required: 0,
                requires_packet_encryption: false,
                secure_link: true,
                nominal_bitrate_bps: 0,
                local_mac: None,
            }
        }
        fn attach(&mut self, context: BearerContext<Pool>) -> Result<(), Self::AttachError> {
            *self.context.lock().unwrap() = Some(context);
            Ok(())
        }
    }
    let (ap, cp) = (Pool::new(), Pool::new());
    let mut a = Node::new(ap);
    let mut c = Node::new(cp);
    a.set_default_association_limits(AssociationLimits {
        connection: limits(),
        ..AssociationLimits::host()
    })
    .unwrap();
    let context = Arc::new(Mutex::new(None));
    let calls = Arc::new(Mutex::new(Vec::new()));
    a.add_bearer(RetryBearer {
        context: context.clone(),
        calls: calls.clone(),
    })
    .unwrap();
    let initial = a.start_association(cid(111), meta(), 0).unwrap();
    let association = initial.association;
    let NodeIngress::Initial { response, .. } = c
        .receive_owned_packet(
            meta(),
            initial.packet,
            |_| {
                Some(InitialAdmission {
                    local_limits: limits(),
                })
            },
            |_, _, _, _, data| Ok(data.len()),
        )
        .unwrap()
    else {
        panic!("initial");
    };
    a.receive_owned_packet(
        meta(),
        response.packet,
        |_| None,
        |_, _, _, _, data| Ok(data.len()),
    )
    .unwrap();
    a.send_datagram(
        association,
        pooled(ap, b"unchanged-through-retry", 80),
        DatagramPriority::High,
    )
    .unwrap();
    assert_eq!(ap.available(), ap.capacity() - 1);
    assert_eq!(endpoint(&mut a, association).in_flight_packet_count(), 0);
    let packet = pooled(ap, b"other", 80);
    let pointer = packet.bytes().as_ptr();
    let error = a
        .send_datagram(association, packet, DatagramPriority::High)
        .unwrap_err();
    assert_eq!(error.packet.bytes().as_ptr(), pointer);
    assert_eq!(error.packet.bytes(), b"other");
    drop(error);
    context.lock().unwrap().as_ref().unwrap().send_ready();
    a.drain_bearer_events();
    a.drain_bearer_events();
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0], calls[1]);
    assert_eq!(ap.available(), ap.capacity());
    assert_eq!(
        a.bearers
            .get(meta().bearer)
            .unwrap()
            .stats()
            .completed_packets,
        1
    );
    assert_eq!(endpoint(&mut a, association).in_flight_packet_count(), 1);
}
