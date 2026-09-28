#![deny(deprecated)]

//! Public, runtime-independent bearer and packet-pool contract tests.
//!
//! This is an external test crate on purpose: using a crate-private helper here
//! would fail to compile and expose an unintended dependency before a platform
//! bearer copies it.

use quic_lite::bearer_framed::{
    FramedPacketError, LENGTH_HEADER_BYTES, MAX_FRAMED_PACKET_BYTES, decode_packet_length,
    encode_packet_length,
};
use quic_lite::heap_packet_pool::{
    HEAP_PACKET_SLOT_OVERHEAD, HeapPacketAllocator, HeapPacketPool, HeapPacketPoolError,
};
use quic_lite::packet_pool::PacketPool as FixedPacketPool;
use quic_lite::{
    BearerId, BearerName, ConnectionLimits, OwnedPacket, PacketBuildError, PacketPool,
    PeerL2Address, QuicNode, StatelessResetKey,
};

#[test]
fn fixed_pool_enforces_headroom_reserve_and_returns_its_lease() {
    static POOL: FixedPacketPool<2, 32> = FixedPacketPool::new();

    let packet = POOL
        .build_packet(4, 1, |output| -> Result<usize, ()> {
            output[..3].copy_from_slice(b"qui");
            Ok(3)
        })
        .unwrap();
    assert_eq!(packet.bytes(), b"qui");
    assert_eq!(POOL.available(), 1);
    assert!(matches!(
        POOL.build_packet(0, 1, |_| Ok::<usize, ()>(0)),
        Err(PacketBuildError::Unavailable)
    ));

    drop(packet);
    assert_eq!(POOL.available(), 2);
}

#[test]
fn common_packet_builder_preserves_serializer_and_length_failures() {
    static POOL: FixedPacketPool<1, 8> = FixedPacketPool::new();

    assert!(matches!(
        POOL.build_packet(0, 0, |_| Err::<usize, _>("serialize")),
        Err(PacketBuildError::Serialize("serialize"))
    ));
    assert!(matches!(
        POOL.build_packet(0, 0, |_| Ok::<usize, ()>(9)),
        Err(PacketBuildError::InvalidLength)
    ));
    assert_eq!(POOL.available(), 1);

    let lease = POOL.acquire_with(b"packet").unwrap();
    assert_eq!(lease.bytes(), b"packet");
    assert_eq!(lease.payload(), b"packet");
    assert_eq!(lease.len(), 6);
}

#[test]
fn owned_packet_preserves_exact_range_and_bearer_envelope_capacity() {
    let packet = OwnedPacket::new(vec![9, 8, 1, 2, 3, 7], 2..5).unwrap();
    assert_eq!(packet.bytes(), &[1, 2, 3]);
    assert_eq!(packet.packet_range(), 2..5);
    assert_eq!(packet.prefix_capacity(), 2);
    assert_eq!(packet.suffix_capacity(), 1);
    let (buffer, range) = packet.into_parts();
    assert_eq!(buffer, [9, 8, 1, 2, 3, 7]);
    assert_eq!(range, 2..5);

    let packet = OwnedPacket::new(vec![1, 2, 3], 1..2).unwrap();
    assert_eq!(packet.into_buffer(), [1, 2, 3]);
    assert!(matches!(
        OwnedPacket::new(vec![1, 2], 1..3),
        Err(buffer) if buffer == vec![1, 2]
    ));
}

#[test]
fn compact_bearer_identifiers_reject_reserved_or_invalid_values() {
    assert!(BearerId::new(0).is_none());
    assert_eq!(BearerId::new(7).unwrap().value(), 7);
    assert!(PeerL2Address::new(0).is_none());
    assert_eq!(PeerL2Address::new(9).unwrap().value(), 9);
    assert!(BearerName::new("").is_none());
    assert!(BearerName::new("0123456789abcdefg").is_none());
    assert!(BearerName::new("uarté").is_none());
    assert_eq!(BearerName::new("uart0").unwrap().as_str(), "uart0");
}

#[test]
fn common_node_reports_its_owned_pool_capacity() {
    static POOL: FixedPacketPool<3, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }> =
        FixedPacketPool::new();
    let node = QuicNode::<(), 1, 0, _>::new(None, &POOL);
    assert_eq!(node.packet_capacity(), 3);
    assert_eq!(node.available_packets(), 3);
}

#[test]
fn public_connection_limits_and_reset_key_validate_application_input() {
    let profile = ConnectionLimits::with_receive_profile(4096, 1024, 3);
    assert_eq!(profile.max_data, 4096);
    assert_eq!(profile.max_stream_data, 1024);
    assert_eq!(profile.max_streams_bidi, 3);
    assert_eq!(profile.max_streams_uni, 4);
    let window = ConnectionLimits::with_receive_window(2048);
    assert_eq!(window.max_data, 2048);
    assert_eq!(window.max_stream_data, 2048);
    assert!(StatelessResetKey::from_device_secret(&[0; 15]).is_err());
    assert!(StatelessResetKey::from_device_secret(&[0; 16]).is_ok());
}

#[test]
fn heap_pool_shrinks_after_the_last_outstanding_lease_returns() {
    static POOL: HeapPacketPool<4, 64> = HeapPacketPool::new();

    POOL.resize(2).unwrap();
    let packet = POOL
        .build_packet(5, 0, |output| -> Result<usize, ()> {
            output[..4].copy_from_slice(b"mesh");
            Ok(4)
        })
        .unwrap();
    assert_eq!(packet.bytes(), b"mesh");

    POOL.resize(0).unwrap();
    assert_eq!(POOL.capacity(), 0);
    assert_eq!(POOL.allocated(), 1);
    drop(packet);
    assert_eq!(POOL.allocated(), 0);
}

#[test]
fn heap_pool_growth_respects_ram_policy_and_compile_time_limit() {
    static POOL: HeapPacketPool<4, 100> = HeapPacketPool::new();
    let slot_bytes = 100 + HEAP_PACKET_SLOT_OVERHEAD;

    assert_eq!(
        POOL.resize_with_budget(4, 2_000 + 2 * slot_bytes, 2_000),
        Ok(2)
    );
    assert_eq!(POOL.available(), 2);
    assert_eq!(POOL.resize(5), Err(HeapPacketPoolError::CapacityTooLarge));
    POOL.resize(0).unwrap();
}

fn fail_allocation(_bytes: usize) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe fn ignore_deallocation(_buffer: *mut u8, _bytes: usize) {}

#[test]
fn heap_pool_reports_platform_allocator_failure_without_partial_growth() {
    static POOL: HeapPacketPool<2, 64> = HeapPacketPool::new_with_allocator(
        HeapPacketAllocator::new(fail_allocation, ignore_deallocation),
    );
    assert_eq!(POOL.resize(2), Err(HeapPacketPoolError::AllocationFailed));
    assert_eq!(POOL.capacity(), 0);
    assert_eq!(POOL.allocated(), 0);
}

#[test]
fn public_global_allocator_can_back_an_explicit_heap_pool() {
    static POOL: HeapPacketPool<1, 32> =
        HeapPacketPool::new_with_allocator(HeapPacketAllocator::global());
    POOL.resize(1).unwrap();
    assert_eq!(POOL.capacity(), 1);
    POOL.resize(0).unwrap();
}

#[test]
fn heap_pool_worker_maintains_free_slots_and_shrinks_after_use() {
    static POOL: HeapPacketPool<4, 64> = HeapPacketPool::new();
    let slot_bytes = 64 + HEAP_PACKET_SLOT_OVERHEAD;
    assert_eq!(
        POOL.maintain_free(2, 4, 1_000 + 4 * slot_bytes, 256, 1_000),
        Ok(2)
    );
    let packet = POOL
        .build_packet(0, 0, |output| -> Result<usize, ()> {
            output[0] = 1;
            Ok(1)
        })
        .unwrap();
    assert_eq!(POOL.in_use(), 1);
    assert_eq!(
        POOL.maintain_free(1, 4, 1_000 + 4 * slot_bytes, 256, 1_000),
        Ok(2)
    );
    drop(packet);
    assert_eq!(
        POOL.maintain_free(1, 4, 1_000 + 4 * slot_bytes, 256, 1_000),
        Ok(1)
    );
    POOL.resize(0).unwrap();
}

#[test]
fn reliable_stream_packet_length_is_a_two_byte_carrier_header() {
    assert_eq!(LENGTH_HEADER_BYTES, 2);
    assert_eq!(encode_packet_length(513), Ok([2, 1]));
    assert_eq!(decode_packet_length([2, 1], 600), Ok(513));
    assert_eq!(encode_packet_length(0), Err(FramedPacketError::Empty));
    assert_eq!(
        encode_packet_length(MAX_FRAMED_PACKET_BYTES + 1),
        Err(FramedPacketError::TooLarge(MAX_FRAMED_PACKET_BYTES + 1))
    );
    assert_eq!(
        decode_packet_length([2, 1], 512),
        Err(FramedPacketError::TooLarge(513))
    );
}
