//! UART L2 pacing primitives shared by direct host tests and managed adapters.
//!
//! A USB serial driver can accept a burst much faster than a physical UART can
//! transmit it. The bounded queue below optionally accounts for 8N1 wire time
//! when the L2 really is a physical UART. Virtual USB serial endpoints must
//! use driver backpressure instead: assigning them a nominal baud rate would
//! create an artificial transport bottleneck.

use std::collections::VecDeque;

pub struct UartEgressPacer {
    baud: Option<u32>,
    max_packets: usize,
    queue: VecDeque<Vec<u8>>,
    ready_at_us: u64,
    outstanding_packets: usize,
}

impl UartEgressPacer {
    pub fn new(baud: u32, max_packets: usize) -> Self {
        Self {
            baud: Some(baud.max(1)),
            max_packets: max_packets.max(1),
            queue: VecDeque::new(),
            ready_at_us: 0,
            outstanding_packets: 0,
        }
    }

    /// Bound driver buffering without inventing an 8N1 wire rate.  This is
    /// appropriate for USB-JTAG/CDC and other packetized serial adapters.
    pub fn unpaced(max_packets: usize) -> Self {
        Self {
            baud: None,
            max_packets: max_packets.max(1),
            queue: VecDeque::new(),
            ready_at_us: 0,
            outstanding_packets: 0,
        }
    }

    /// Returns false when a full bounded UART path must drop a datagram.
    pub fn enqueue(&mut self, wire: Vec<u8>) -> bool {
        if !self.has_capacity() {
            return false;
        }
        self.queue.push_back(wire);
        true
    }

    pub fn take_ready(&mut self, now_us: u64) -> Option<Vec<u8>> {
        if now_us < self.ready_at_us {
            return None;
        }
        self.queue.pop_front()
    }

    /// Account for a complete 8N1 serial write accepted by the kernel.
    pub fn completed_write(&mut self, wire_len: usize, now_us: u64) {
        self.outstanding_packets = self.outstanding_packets.saturating_add(1);
        let Some(baud) = self.baud else {
            self.ready_at_us = now_us;
            return;
        };
        let wire_us = (wire_len as u64)
            .saturating_mul(10)
            .saturating_mul(1_000_000)
            .div_ceil(baud as u64);
        self.ready_at_us = now_us.saturating_add(wire_us.max(1));
    }

    /// A nonblocking write accepted only part of a frame. Preserve ordering
    /// and retry soon; do not charge a second whole-frame wire interval.
    pub fn retry_front(&mut self, remaining: Vec<u8>, now_us: u64) {
        self.queue.push_front(remaining);
        self.ready_at_us = now_us.saturating_add(1_000);
    }

    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// All L2 work accepted locally but not yet confirmed by peer traffic.
    /// This is the value an adapter must report as `PathCapacity` occupancy;
    /// reporting only `queued()` would make a fast USB driver look empty
    /// immediately after it accepted a burst.
    pub fn occupied(&self) -> usize {
        self.queue.len().saturating_add(self.outstanding_packets)
    }

    pub fn capacity(&self) -> usize {
        self.max_packets
    }

    /// Capacity visible to the path scheduler. A USB or UART driver accepting
    /// a write is not receiver capacity: each transport packet received back
    /// from the peer releases one conservative credit.
    pub fn has_capacity(&self) -> bool {
        self.occupied() < self.max_packets
    }

    /// Feed bearer progress back from the peer. This deliberately needs no
    /// UART protocol knowledge; the caller invokes it for any validated
    /// QUIC-lite packet observed on this L2 path.
    pub fn on_path_feedback(&mut self) {
        self.outstanding_packets = self.outstanding_packets.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::UartEgressPacer;

    #[test]
    fn paces_a_full_ppp_packet_at_configured_baud() {
        let mut pacer = UartEgressPacer::new(115_200, 2);
        assert!(pacer.enqueue(vec![0; 1_202]));
        assert!(pacer.enqueue(vec![1]));
        let packet = pacer.take_ready(0).unwrap();
        pacer.completed_write(packet.len(), 0);
        assert!(pacer.take_ready(104_340).is_none());
        assert_eq!(pacer.take_ready(104_341), Some(vec![1]));
    }

    #[test]
    fn queue_is_bounded_and_preserves_partial_frame_order() {
        let mut pacer = UartEgressPacer::new(1_000_000, 1);
        assert!(pacer.enqueue(vec![1, 2]));
        assert!(!pacer.enqueue(vec![3]));
        let first = pacer.take_ready(0).unwrap();
        pacer.retry_front(first[1..].to_vec(), 0);
        assert_eq!(pacer.take_ready(999), None);
        assert_eq!(pacer.take_ready(1_000), Some(vec![2]));
    }

    #[test]
    fn virtual_serial_is_not_limited_by_nominal_uart_wire_time() {
        let mut pacer = UartEgressPacer::unpaced(2);
        assert!(pacer.enqueue(vec![0; 1_202]));
        assert!(pacer.enqueue(vec![1]));
        let packet = pacer.take_ready(0).unwrap();
        pacer.completed_write(packet.len(), 0);
        assert_eq!(pacer.take_ready(0), Some(vec![1]));
    }

    #[test]
    fn receiver_feedback_bounds_a_packetized_serial_path() {
        let mut pacer = UartEgressPacer::unpaced(1);
        assert!(pacer.enqueue(vec![1]));
        let packet = pacer.take_ready(0).unwrap();
        pacer.completed_write(packet.len(), 0);
        assert!(!pacer.has_capacity());
        pacer.on_path_feedback();
        assert!(pacer.has_capacity());
    }

    #[test]
    fn occupancy_includes_accepted_writes_until_peer_feedback() {
        let mut pacer = UartEgressPacer::unpaced(8);
        assert!(pacer.enqueue(vec![1]));
        let packet = pacer.take_ready(0).unwrap();
        pacer.completed_write(packet.len(), 0);
        assert_eq!(pacer.queued(), 0);
        assert_eq!(pacer.occupied(), 1);
        pacer.on_path_feedback();
        assert_eq!(pacer.occupied(), 0);
    }
}
