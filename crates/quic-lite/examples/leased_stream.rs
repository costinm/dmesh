//! Pool-backed stream delivery with explicit application completion.
//!
//! This demonstrates the packet ownership used by the no-std stream API. The
//! handler receives an immutable lease plus the stream payload range, and the
//! pool slot is recycled only after `done`. The completed stream integration
//! must use this as a delivery option of `QuicNode`; `CallbackStreams` is not a
//! second application or transport interface.

use quic_lite::{
    callback::{CallbackStreams, StreamChunk, StreamDone, StreamEvents},
    packet_pool::{PacketPool, PoolLease},
};

const SLOTS: usize = 2;
const MTU: usize = 64;
type Lease = PoolLease<'static, SLOTS, MTU>;

static PACKETS: PacketPool<SLOTS, MTU> = PacketPool::new();

#[derive(Debug, Eq, PartialEq)]
pub struct Observation {
    pub body: [u8; 7],
    pub same_packet: bool,
    pub available_while_held: usize,
    pub available_after_done: usize,
}

#[derive(Default)]
struct Handler {
    chunk: Option<StreamChunk<Lease>>,
    finished: bool,
}

impl StreamEvents<Lease> for Handler {
    fn stream_chunk(&mut self, chunk: StreamChunk<Lease>) {
        self.chunk = Some(chunk);
    }

    fn stream_finished(&mut self, _stream: u64) {
        self.finished = true;
    }

    fn stream_reset(&mut self, _stream: u64, _code: u64) {}
}

pub fn run_demo() -> Observation {
    let packet = PACKETS.acquire_with(b"HEAD:payload:TAG").unwrap();
    let packet_address = packet.bytes().as_ptr();
    let mut streams = CallbackStreams::new(2, MTU);
    let mut handler = Handler::default();

    streams
        .receive_leased(4, packet, 0, 5..12, true, &mut handler)
        .unwrap();
    let available_while_held = PACKETS.available();
    let chunk = handler.chunk.take().expect("one leased stream chunk");
    let same_packet = chunk.packet.bytes().as_ptr() == packet_address;
    let mut body = [0; 7];
    body.copy_from_slice(chunk.bytes());
    let completion = StreamDone {
        stream: chunk.stream,
        delivery_id: chunk.delivery_id,
    };
    drop(chunk);

    streams.done(completion, &mut handler).unwrap();
    assert!(handler.finished);
    Observation {
        body,
        same_packet,
        available_while_held,
        available_after_done: PACKETS.available(),
    }
}

#[allow(dead_code)]
fn main() {
    println!("{:?}", run_demo());
}
