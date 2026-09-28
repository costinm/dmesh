#![deny(deprecated)]

#[path = "../examples/leased_stream.rs"]
mod example;

use quic_lite::{
    callback::{CallbackError, CallbackStreams, StreamChunk, StreamDone, StreamEvents},
    packet_pool::{PacketPool, PoolLease},
};

#[test]
fn handler_returns_the_immutable_packet_lease_to_the_pool() {
    let observation = example::run_demo();
    assert_eq!(&observation.body, b"payload");
    assert!(observation.same_packet);
    assert_eq!(observation.available_while_held, 1);
    assert_eq!(observation.available_after_done, 2);
}

type Lease = PoolLease<'static, 4, 64>;
static PACKETS: PacketPool<4, 64> = PacketPool::new();
static ERROR_PACKETS: PacketPool<4, 64> = PacketPool::new();

#[derive(Default)]
struct Events {
    chunks: Vec<StreamChunk<Lease>>,
    finished: Vec<u64>,
    resets: Vec<(u64, u64)>,
}

impl StreamEvents<Lease> for Events {
    fn stream_chunk(&mut self, chunk: StreamChunk<Lease>) {
        self.chunks.push(chunk);
    }

    fn stream_finished(&mut self, stream: u64) {
        self.finished.push(stream);
    }

    fn stream_reset(&mut self, stream: u64, code: u64) {
        self.resets.push((stream, code));
    }
}

#[test]
fn callback_lifecycle_accounts_for_ordered_leases_and_reset() {
    let mut streams = CallbackStreams::new(2, 32);
    let mut events = Events::default();

    let tail = PACKETS.acquire_with(b"tail").unwrap();
    streams
        .receive_leased(9, tail, 4, 0..4, true, &mut events)
        .unwrap();
    assert!(events.chunks.is_empty());
    assert_eq!(streams.stream_count(), 1);
    assert_eq!(streams.retained_bytes(), 4);

    let head = PACKETS.acquire_with(b"head").unwrap();
    streams
        .receive_leased(9, head, 0, 0..4, false, &mut events)
        .unwrap();
    let first = events.chunks.pop().unwrap();
    assert_eq!(first.bytes(), b"head");
    let first_done = StreamDone {
        stream: first.stream,
        delivery_id: first.delivery_id,
    };
    assert_eq!(streams.outstanding(9), Some(first_done));
    drop(first);
    streams.done(first_done, &mut events).unwrap();

    let tail = events.chunks.pop().unwrap();
    assert_eq!(tail.bytes(), b"tail");
    assert_eq!(streams.retained_bytes(), 4);
    drop(tail);
    streams.reset(9, 77, &mut events);
    assert_eq!(events.resets, [(9, 77)]);
    assert_eq!(streams.stream_count(), 0);
    assert_eq!(streams.retained_bytes(), 0);
    assert_eq!(streams.outstanding(9), None);
}

#[test]
fn callback_rejects_invalid_completion_overlap_fin_capacity_and_reset() {
    let mut events = Events::default();

    let mut no_streams = CallbackStreams::new(0, 32);
    assert_eq!(
        no_streams.receive_leased(
            1,
            ERROR_PACKETS.acquire_with(b"x").unwrap(),
            0,
            0..1,
            true,
            &mut events,
        ),
        Err(CallbackError::Capacity)
    );

    let mut streams = CallbackStreams::new(2, 8);
    streams
        .receive_leased(
            2,
            ERROR_PACKETS.acquire_with(b"tail").unwrap(),
            4,
            0..4,
            false,
            &mut events,
        )
        .unwrap();
    assert_eq!(
        streams.receive_leased(
            2,
            ERROR_PACKETS.acquire_with(b"lap!").unwrap(),
            6,
            0..4,
            false,
            &mut events,
        ),
        Err(CallbackError::InvalidOverlap)
    );
    streams
        .receive_leased(
            3,
            ERROR_PACKETS.acquire_with(b"last").unwrap(),
            4,
            0..4,
            true,
            &mut events,
        )
        .unwrap();
    assert_eq!(
        streams.receive_leased(
            3,
            ERROR_PACKETS.acquire_with(b"end").unwrap(),
            4,
            0..3,
            true,
            &mut events,
        ),
        Err(CallbackError::InvalidFin)
    );
    assert_eq!(
        streams.done(
            StreamDone {
                stream: 2,
                delivery_id: 99,
            },
            &mut events,
        ),
        Err(CallbackError::InvalidCompletion)
    );

    streams.reset(2, 7, &mut events);
    assert!(events.resets.contains(&(2, 7)));
    assert_eq!(streams.outstanding(2), None);
}
