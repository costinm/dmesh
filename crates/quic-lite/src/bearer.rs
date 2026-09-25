//! The contract between packet bearers and QUIC-lite.
//!
//! A bearer moves opaque packets over UART, BLE, UDP, or another link. It does
//! not inspect, classify, encrypt, or decrypt their contents. QUIC-lite owns
//! packet protection because its keys are associated with the connection ID.
//!
//! # Receive
//!
//! Send and receive use the same shared packet pool. A bearer fills one pool
//! buffer with one complete packet exactly as received. It transfers that buffer,
//! an opaque [`LocalAddress`], and monotonic receive time to
//! [`DatagramIngress::receive_datagram`] if QUIC processing may run immediately
//! on the current thread.
//!
//! A driver callback or separate read loop that must return without running
//! QUIC calls [`DatagramIngress::enqueue_datagram`] instead. This transfers
//! ownership to the bounded QUIC ingress queue without waiting. A full queue
//! drops the packet; transport loss recovery handles retransmission. ESP
//! receive callbacks run in task context and use this queued entry point.
//!
//! # Send
//!
//! QUIC selects a ready local address and transfers one
//! [`OwnedDatagram`] to its registered [`DatagramEgress::submit`] callback. A
//! packet stays owned by the bearer until send completion. The bearer then
//! releases it and calls [`DatagramEgressEvents::send_ready`]. Callback
//! registration identifies which sender became ready. A busy bearer returns the
//! unchanged packet immediately so another sender can be selected. A byte-stream
//! bearer may retain one partially written packet, but it must not queue later
//! packets. Once any byte has been written, the packet must never be returned to
//! QUIC or moved to another bearer.

use core::ops::Range;

/// Opaque, process-local handle for one bearer endpoint.
///
/// This is neither a circuit path nor a peer identity. The bearer owns its
/// mapping to local socket, radio, UART, or other endpoint state.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct LocalAddress(u64);

impl LocalAddress {
    pub const fn new(value: u64) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Metadata supplied with one received opaque packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatagramMeta {
    /// Bearer-assigned local endpoint handle.
    pub local_address: LocalAddress,
    /// Monotonic receive time in microseconds.
    pub received_at_us: u64,
}

/// An owned received packet waiting for QUIC processing.
#[derive(Debug)]
pub struct ReceivedDatagram<B> {
    pub meta: DatagramMeta,
    pub packet: OwnedDatagram<B>,
}

/// The two entry points for received packets.
///
/// Both methods transfer ownership of one complete packet exactly as received.
/// Use `receive_datagram` if QUIC processing may run immediately on the current
/// thread. Use `enqueue_datagram` when the driver callback or read loop must
/// return without running QUIC.
pub trait DatagramIngress<B: AsRef<[u8]>> {
    type Error;

    /// Process the packet immediately on the current thread.
    fn receive_datagram(
        &mut self,
        meta: DatagramMeta,
        packet: OwnedDatagram<B>,
    ) -> Result<(), Self::Error>;

    /// Transfer the packet to the bounded QUIC ingress queue without waiting.
    ///
    /// This method must not allocate, inspect packet bytes, or run QUIC. A full
    /// queue drops the packet and releases its buffer.
    fn enqueue_datagram(&self, meta: DatagramMeta, packet: OwnedDatagram<B>);
}

/// Completion callback from a registered sender to QUIC.
pub trait DatagramEgressEvents {
    /// Report that this registered sender can accept another complete packet.
    fn send_ready(&mut self);
}

/// One complete packet and ownership of its backing buffer.
///
/// The range permits a shared pool to reserve link-layer headroom without
/// moving the packet bytes.
#[derive(Debug)]
pub struct OwnedDatagram<B> {
    buffer: B,
    range: Range<usize>,
}

impl<B: AsRef<[u8]>> OwnedDatagram<B> {
    pub fn new(buffer: B, range: Range<usize>) -> Result<Self, B> {
        if range.start <= range.end && range.end <= buffer.as_ref().len() {
            Ok(Self { buffer, range })
        } else {
            Err(buffer)
        }
    }

    pub fn from_buffer(buffer: B) -> Self {
        let len = buffer.as_ref().len();
        Self {
            buffer,
            range: 0..len,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.buffer.as_ref()[self.range.clone()]
    }

    pub fn into_buffer(self) -> B {
        self.buffer
    }
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for OwnedDatagram<B> {
    fn as_ref(&self) -> &[u8] {
        self.bytes()
    }
}

/// A bearer rejected a packet without taking ownership of it.
#[derive(Debug)]
pub enum DatagramSubmitError<B, E> {
    /// The sender is temporarily full and consumed no bytes.
    WouldBlock(OwnedDatagram<B>),
    /// The sender rejected the packet without consuming any bytes.
    Failed(OwnedDatagram<B>, E),
}

/// Callback used to transfer one complete packet to a bearer.
///
/// `Ok(())` transfers ownership to the bearer. It must retain a partially
/// written packet until the complete packet is written or the link fails
/// terminally. It must never return a partially written packet. On completion
/// it releases the packet and emits `send_ready` when capacity becomes available
/// again. An error is valid only before any byte is consumed and returns the
/// unchanged packet.
pub trait DatagramEgress<B: AsRef<[u8]>> {
    type Error;

    fn submit(
        &mut self,
        local_address: LocalAddress,
        packet: OwnedDatagram<B>,
    ) -> Result<(), DatagramSubmitError<B, Self::Error>>;
}

impl<B, E, F> DatagramEgress<B> for F
where
    B: AsRef<[u8]>,
    F: FnMut(LocalAddress, OwnedDatagram<B>) -> Result<(), DatagramSubmitError<B, E>>,
{
    type Error = E;

    fn submit(
        &mut self,
        local_address: LocalAddress,
        packet: OwnedDatagram<B>,
    ) -> Result<(), DatagramSubmitError<B, Self::Error>> {
        self(local_address, packet)
    }
}

#[cfg(feature = "tokio")]
pub mod tokio {
    //! Tokio bounded handoff for socket and asynchronous read-loop bearers.
    //!
    //! Create one channel per QUIC owner and clone its sender for every bearer.
    //! QUIC retains the root sender for the lifetime of the owner. Disabling a
    //! transport does not close the queue. The queue owns shared counters; do
    //! not create a queue or counters per bearer.

    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};

    use super::{DatagramIngress, ReceivedDatagram};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct DatagramIngressStats {
        pub enqueued: u64,
        pub dropped_full: u64,
    }

    #[derive(Default)]
    struct Counters {
        enqueued: AtomicU64,
        dropped_full: AtomicU64,
    }

    /// Cloneable nonblocking producer for driver callbacks and read loops.
    pub struct DatagramSender<B> {
        sender: ::tokio::sync::mpsc::Sender<ReceivedDatagram<B>>,
        counters: Arc<Counters>,
    }

    impl<B> Clone for DatagramSender<B> {
        fn clone(&self) -> Self {
            Self {
                sender: self.sender.clone(),
                counters: self.counters.clone(),
            }
        }
    }

    /// Single consumer owned by the QUIC task.
    pub struct DatagramReceiver<B> {
        receiver: ::tokio::sync::mpsc::Receiver<ReceivedDatagram<B>>,
        counters: Arc<Counters>,
    }

    /// Create the one shared ingress queue for a QUIC owner.
    pub fn channel<B>(capacity: usize) -> (DatagramSender<B>, DatagramReceiver<B>) {
        assert!(capacity != 0, "datagram queue capacity must be nonzero");
        let (sender, receiver) = ::tokio::sync::mpsc::channel(capacity);
        let counters = Arc::new(Counters::default());
        (
            DatagramSender {
                sender,
                counters: counters.clone(),
            },
            DatagramReceiver { receiver, counters },
        )
    }

    impl<B> DatagramSender<B> {
        /// Transfer a packet to the shared QUIC ingress queue without waiting.
        pub fn enqueue_datagram(&self, meta: super::DatagramMeta, packet: super::OwnedDatagram<B>) {
            let datagram = ReceivedDatagram { meta, packet };
            match self.sender.try_send(datagram) {
                Ok(()) => {
                    self.counters.enqueued.fetch_add(1, Ordering::Relaxed);
                }
                Err(::tokio::sync::mpsc::error::TrySendError::Full(datagram)) => {
                    drop(datagram);
                    self.counters.dropped_full.fetch_add(1, Ordering::Relaxed);
                }
                Err(::tokio::sync::mpsc::error::TrySendError::Closed(datagram)) => {
                    drop(datagram);
                    panic!("QUIC ingress queue lifetime invariant violated");
                }
            }
        }
    }

    impl<B: AsRef<[u8]>> DatagramReceiver<B> {
        pub async fn dispatch_next<I: DatagramIngress<B>>(
            &mut self,
            ingress: &mut I,
        ) -> Result<(), I::Error> {
            let datagram = self
                .receiver
                .recv()
                .await
                .expect("QUIC ingress queue lifetime invariant violated");
            ingress.receive_datagram(datagram.meta, datagram.packet)?;
            Ok(())
        }

        pub fn try_receive(&mut self) -> Option<ReceivedDatagram<B>> {
            self.receiver.try_recv().ok()
        }

        pub fn stats(&self) -> DatagramIngressStats {
            DatagramIngressStats {
                enqueued: self.counters.enqueued.load(Ordering::Relaxed),
                dropped_full: self.counters.dropped_full.load(Ordering::Relaxed),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ReceiveProbe {
        bytes: [u8; 2],
        ready: bool,
    }

    impl DatagramIngress<[u8; 4]> for ReceiveProbe {
        type Error = ();

        fn receive_datagram(
            &mut self,
            _meta: DatagramMeta,
            packet: OwnedDatagram<[u8; 4]>,
        ) -> Result<(), Self::Error> {
            self.bytes.copy_from_slice(packet.bytes());
            Ok(())
        }

        fn enqueue_datagram(&self, _meta: DatagramMeta, _packet: OwnedDatagram<[u8; 4]>) {
            panic!("test probe has no queue");
        }
    }

    impl DatagramEgressEvents for ReceiveProbe {
        fn send_ready(&mut self) {
            self.ready = true;
        }
    }

    #[test]
    fn receive_transfers_one_owned_packet() {
        let local_address = LocalAddress::new(1).unwrap();
        let packet = OwnedDatagram::new([1, 2, 3, 4], 1..3).unwrap();
        let mut receiver = ReceiveProbe {
            bytes: [0; 2],
            ready: false,
        };
        receiver
            .receive_datagram(
                DatagramMeta {
                    local_address,
                    received_at_us: 7,
                },
                packet,
            )
            .unwrap();
        receiver.send_ready();
        assert_eq!(receiver.bytes, [2, 3]);
        assert!(receiver.ready);
    }

    #[test]
    fn rejected_submit_returns_the_same_owned_buffer() {
        let local_address = LocalAddress::new(1).unwrap();
        let packet = OwnedDatagram::new([1, 2, 3, 4], 1..3).unwrap();
        let mut submit = |_local_address, packet| {
            Err::<(), _>(DatagramSubmitError::<[u8; 4], ()>::WouldBlock(packet))
        };
        let DatagramSubmitError::WouldBlock(packet) =
            submit.submit(local_address, packet).unwrap_err()
        else {
            panic!("unexpected permanent failure");
        };
        assert_eq!(packet.bytes(), &[2, 3]);
        assert_eq!(packet.into_buffer(), [1, 2, 3, 4]);
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_handoff_is_bounded_and_drops_on_pressure() {
        let local_address = LocalAddress::new(1).unwrap();
        let meta = DatagramMeta {
            local_address,
            received_at_us: 7,
        };
        let (sender, mut receiver) = tokio::channel(1);
        sender.enqueue_datagram(meta, OwnedDatagram::from_buffer([1, 2]));
        sender.enqueue_datagram(meta, OwnedDatagram::from_buffer([3, 4]));
        assert_eq!(
            receiver.stats(),
            tokio::DatagramIngressStats {
                enqueued: 1,
                dropped_full: 1,
            }
        );
        assert_eq!(receiver.try_receive().unwrap().packet.bytes(), &[1, 2]);
    }
}
