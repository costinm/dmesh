//! Fixed MTU packet slots shared by every bearer and relay path.
//!
//! A slot is device-owned rather than ingress- or egress-owned. A relay keeps
//! the same slot while handing a received packet to another bearer, so RX for
//! one connection can be TX for another without reserving a second MTU.

use core::{
    cell::UnsafeCell,
    ops::Range,
    sync::atomic::{AtomicU8, AtomicU32, Ordering},
};

/// Fixed-capacity queue of metadata and leases from a node-owned packet pool.
/// It stores no packet bytes and never creates a transport-private MTU pool;
/// dropping or removing an entry transfers or releases the original lease.
pub struct PacketLeaseQueue<M: Copy, B: AsRef<[u8]>, const N: usize> {
    state: spin::Mutex<PacketLeaseQueueState<M, B, N>>,
}

struct PacketLeaseQueueState<M: Copy, B: AsRef<[u8]>, const N: usize> {
    entries: [Option<(M, crate::OwnedPacket<B>)>; N],
    head: usize,
    len: usize,
}

impl<M: Copy, B: AsRef<[u8]>, const N: usize> PacketLeaseQueue<M, B, N> {
    /// Construct an empty fixed-capacity lease queue.
    pub const fn new() -> Self {
        assert!(N != 0, "packet lease queue capacity must be nonzero");
        Self {
            state: spin::Mutex::new(PacketLeaseQueueState {
                entries: [const { None }; N],
                head: 0,
                len: 0,
            }),
        }
    }

    /// Try to enqueue without waiting. On lock contention or capacity pressure,
    /// the caller retains the exact packet lease for drop or retry.
    pub fn try_push(
        &self,
        metadata: M,
        packet: crate::OwnedPacket<B>,
    ) -> Result<(), (M, crate::OwnedPacket<B>)> {
        let Some(mut state) = self.state.try_lock() else {
            return Err((metadata, packet));
        };
        if state.len == N {
            return Err((metadata, packet));
        }
        let tail = (state.head + state.len) % N;
        state.entries[tail] = Some((metadata, packet));
        state.len += 1;
        Ok(())
    }

    /// Try to remove the oldest entry without waiting.
    pub fn try_pop(&self) -> Option<(M, crate::OwnedPacket<B>)> {
        let mut state = self.state.try_lock()?;
        if state.len == 0 {
            return None;
        }
        let head = state.head;
        state.head = (head + 1) % N;
        state.len -= 1;
        state.entries[head].take()
    }

    /// Read queue emptiness without waiting; `None` means another owner holds
    /// the brief metadata lock.
    pub fn try_is_empty(&self) -> Option<bool> {
        self.state.try_lock().map(|state| state.len == 0)
    }
}

/// Opaque ownership token for one packet slot.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketSlot(u8);

impl PacketSlot {
    pub(crate) const fn index(self) -> usize {
        self.0 as usize
    }
}

/// One device-wide MTU packet pool. `SLOTS` is a hard upper bound of 32.
pub struct PacketPool<const SLOTS: usize, const MTU: usize> {
    free: AtomicU32,
    references: [AtomicU8; SLOTS],
    packets: UnsafeCell<[[u8; MTU]; SLOTS]>,
}

/// A clonable reference to one device-pool packet. Cloning retains the slot;
/// dropping the final lease returns it to the common device budget. This is
/// the connection/ordered-delivery ownership primitive, never a bearer queue.
pub struct PoolLease<'a, const SLOTS: usize, const MTU: usize> {
    pool: &'a PacketPool<SLOTS, MTU>,
    slot: PacketSlot,
    start: usize,
    len: usize,
}

/// Pool lease view for [`crate::OwnedPacket`]. `AsRef` exposes the complete
/// slot while `packet_range` identifies the initialized packet bytes.
pub struct PoolBufferLease<'a, const SLOTS: usize, const MTU: usize> {
    lease: PoolLease<'a, SLOTS, MTU>,
}

impl<const SLOTS: usize, const MTU: usize> core::fmt::Debug for PoolBufferLease<'_, SLOTS, MTU> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PoolBufferLease")
            .field("slot", &self.lease.slot)
            .field("range", &self.packet_range())
            .finish()
    }
}

impl<const SLOTS: usize, const MTU: usize> PoolBufferLease<'_, SLOTS, MTU> {
    pub(crate) fn packet_range(&self) -> Range<usize> {
        self.lease.start..self.lease.start + self.lease.len
    }
}

impl<const SLOTS: usize, const MTU: usize> AsRef<[u8]> for PoolBufferLease<'_, SLOTS, MTU> {
    fn as_ref(&self) -> &[u8] {
        self.lease
            .pool
            .packet(self.lease.slot, MTU)
            .expect("valid pool buffer lease")
    }
}

/// Exclusive construction access to one slot in a `QuicNode` packet pool.
///
/// A producer reserves bearer headroom, serializes directly into
/// the [`crate::PacketWriter`] trait's writable region, then commits a normal
/// [`PoolLease`].
/// Unlike `PoolLease`, this value cannot be cloned, so mutable access cannot
/// race a relayed or retained read lease. Dropping it without committing
/// returns the slot to the device-wide pool.
pub struct PacketWriter<'a, const SLOTS: usize, const MTU: usize> {
    pool: &'a PacketPool<SLOTS, MTU>,
    slot: PacketSlot,
    start: usize,
    active: bool,
}

impl<'a, const SLOTS: usize, const MTU: usize> PacketWriter<'a, SLOTS, MTU> {
    /// Writable application/transport payload after the caller-reserved
    /// bearer headroom.
    pub(crate) fn payload_mut(&mut self) -> &mut [u8] {
        unsafe { &mut (&mut (*self.pool.packets.get())[self.slot.index()])[self.start..] }
    }

    /// Full packet storage, including the reserved prefix. A bearer uses this
    /// after the producer has serialized its payload to fill headers in place.
    pub(crate) fn frame_mut(&mut self) -> &mut [u8] {
        unsafe { &mut (*self.pool.packets.get())[self.slot.index()] }
    }

    /// Commit `len` payload bytes and turn exclusive construction access into
    /// a clonable shared lease. The producer must have initialized those bytes.
    pub(crate) fn commit(mut self, len: usize) -> Option<PoolLease<'a, SLOTS, MTU>> {
        if len > MTU.saturating_sub(self.start) {
            return None;
        }
        self.active = false;
        Some(PoolLease {
            pool: self.pool,
            slot: self.slot,
            start: self.start,
            len,
        })
    }

    /// Commit packet bytes while preserving access to the complete pool slot.
    pub(crate) fn commit_buffer(self, len: usize) -> Option<PoolBufferLease<'a, SLOTS, MTU>> {
        self.commit(len).map(|lease| PoolBufferLease { lease })
    }

    /// Commit a complete bearer frame after its reserved prefix was filled in
    /// place. The resulting lease begins at byte zero.
    pub(crate) fn commit_frame(mut self, payload_len: usize) -> Option<PoolLease<'a, SLOTS, MTU>> {
        let len = self.start.checked_add(payload_len)?;
        if len > MTU {
            return None;
        }
        self.active = false;
        Some(PoolLease {
            pool: self.pool,
            slot: self.slot,
            start: 0,
            len,
        })
    }
}

impl<const SLOTS: usize, const MTU: usize> crate::PacketWriter
    for PacketWriter<'static, SLOTS, MTU>
{
    type Buffer = PoolBufferLease<'static, SLOTS, MTU>;

    fn payload_mut(&mut self) -> &mut [u8] {
        PacketWriter::payload_mut(self)
    }

    fn commit(self, len: usize) -> Option<crate::OwnedPacket<Self::Buffer>> {
        let buffer = self.commit_buffer(len)?;
        let range = buffer.packet_range();
        crate::OwnedPacket::new(buffer, range).ok()
    }
}

impl<const SLOTS: usize, const MTU: usize> Drop for PacketWriter<'_, SLOTS, MTU> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.pool.release(self.slot);
        }
    }
}

impl<const SLOTS: usize, const MTU: usize> Clone for PoolLease<'_, SLOTS, MTU> {
    fn clone(&self) -> Self {
        let references = &self.pool.references[self.slot.index()];
        let previous = references.fetch_add(1, Ordering::AcqRel);
        assert!(
            previous != 0 && previous != u8::MAX,
            "packet lease reference overflow"
        );
        Self {
            pool: self.pool,
            slot: self.slot,
            start: self.start,
            len: self.len,
        }
    }
}

impl<const SLOTS: usize, const MTU: usize> Drop for PoolLease<'_, SLOTS, MTU> {
    fn drop(&mut self) {
        let references = &self.pool.references[self.slot.index()];
        if references.fetch_sub(1, Ordering::AcqRel) == 1 {
            let _ = self.pool.release(self.slot);
        }
    }
}

impl<const SLOTS: usize, const MTU: usize> PoolLease<'_, SLOTS, MTU> {
    /// Borrow the initialized packet bytes selected by this lease.
    pub fn bytes(&self) -> &[u8] {
        self.payload()
    }
    /// View beginning at the current header offset rather than byte zero.
    pub fn payload(&self) -> &[u8] {
        &self.pool.packet(self.slot, MTU).expect("valid pool lease")
            [self.start..self.start + self.len]
    }
    /// Length of the initialized packet range.
    pub const fn len(&self) -> usize {
        self.len
    }
    pub(crate) const fn slot(&self) -> PacketSlot {
        self.slot
    }

    /// Add a bearer header in already-reserved headroom. The payload bytes are
    /// not moved, which is essential when they are end-to-end ciphertext.
    pub(crate) fn prepend(&mut self, header: &[u8]) -> bool {
        if header.len() > self.start {
            return false;
        }
        let start = self.start - header.len();
        if !self.pool.write_at(self.slot, start, header) {
            return false;
        }
        self.start = start;
        self.len += header.len();
        true
    }

    /// Remove a bearer header by changing metadata only.
    pub(crate) fn strip_prefix(&mut self, bytes: usize) -> bool {
        if bytes > self.len {
            return false;
        }
        self.start += bytes;
        self.len -= bytes;
        true
    }
}

impl<const SLOTS: usize, const MTU: usize> AsRef<[u8]> for PoolLease<'_, SLOTS, MTU> {
    fn as_ref(&self) -> &[u8] {
        self.bytes()
    }
}

// A caller may access a packet only while it owns the corresponding cleared
// bit. Firmware queues carry the slot token, never a duplicate MTU payload.
unsafe impl<const SLOTS: usize, const MTU: usize> Sync for PacketPool<SLOTS, MTU> {}

impl<const SLOTS: usize, const MTU: usize> PacketPool<SLOTS, MTU> {
    /// Construct a fixed-capacity pool with every slot initially free.
    ///
    /// The pool is public so a no-std application can place its node-owned
    /// packet storage explicitly; bearers only borrow it through the node.
    pub const fn new() -> Self {
        assert!(SLOTS <= 32);
        Self {
            free: AtomicU32::new(mask(SLOTS)),
            references: [const { AtomicU8::new(0) }; SLOTS],
            packets: UnsafeCell::new([[0; MTU]; SLOTS]),
        }
    }

    pub(crate) fn acquire(&self) -> Option<PacketSlot> {
        self.acquire_reserving(0)
    }

    /// Acquire one slot while leaving `reserved` slots available.
    ///
    /// RX and TX share this pool. A receiver can reserve reply capacity without
    /// maintaining a separate ingress or egress pool. The availability check
    /// and acquisition are one atomic operation.
    pub(crate) fn acquire_reserving(&self, reserved: usize) -> Option<PacketSlot> {
        let mut current = self.free.load(Ordering::Acquire);
        loop {
            if current.count_ones() as usize <= reserved {
                return None;
            }
            let bit = current.trailing_zeros();
            let next = current & !(1 << bit);
            match self.free.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.references[bit as usize].store(1, Ordering::Release);
                    return Some(PacketSlot(bit as u8));
                }
                Err(observed) => current = observed,
            }
        }
    }

    /// Number of slots immediately available for ingress or egress.
    pub fn available(&self) -> usize {
        self.free.load(Ordering::Acquire).count_ones() as usize
    }

    /// Acquire a node-owned packet slot and initialize its bytes in one copy.
    /// The returned lease may be retained by connection ordering or handed to
    /// a bearer without allocating a second packet.
    pub fn acquire_with(&self, data: &[u8]) -> Option<PoolLease<'_, SLOTS, MTU>> {
        self.acquire_with_headroom(0, data)
    }

    /// Acquire a slot with prefix space reserved for the selected bearer.
    pub(crate) fn acquire_with_headroom(
        &self,
        headroom: usize,
        data: &[u8],
    ) -> Option<PoolLease<'_, SLOTS, MTU>> {
        if headroom.saturating_add(data.len()) > MTU {
            return None;
        }
        let slot = self.acquire()?;
        if !self.write_at(slot, headroom, data) {
            let _ = self.release(slot);
            return None;
        }
        Some(PoolLease {
            pool: self,
            slot,
            start: headroom,
            len: data.len(),
        })
    }

    /// Reserve a shared slot for a producer that can serialize directly into
    /// the packet. This avoids copying CBOR, stream bytes, or proxy payloads
    /// into a bearer-owned scratch frame just to add a prefix later.
    pub(crate) fn acquire_writer(&self, headroom: usize) -> Option<PacketWriter<'_, SLOTS, MTU>> {
        self.acquire_writer_reserving(headroom, 0)
    }

    /// Reserve a writer while atomically leaving `reserved` slots free.
    pub(crate) fn acquire_writer_reserving(
        &self,
        headroom: usize,
        reserved: usize,
    ) -> Option<PacketWriter<'_, SLOTS, MTU>> {
        if headroom > MTU {
            return None;
        }
        Some(PacketWriter {
            pool: self,
            slot: self.acquire_reserving(reserved)?,
            start: headroom,
            active: true,
        })
    }

    pub(crate) fn write(&self, slot: PacketSlot, data: &[u8]) -> bool {
        self.write_at(slot, 0, data)
    }

    pub(crate) fn write_at(&self, slot: PacketSlot, offset: usize, data: &[u8]) -> bool {
        if slot.index() >= SLOTS || offset.saturating_add(data.len()) > MTU {
            return false;
        }
        unsafe {
            (&mut (*self.packets.get())[slot.index()])[offset..offset + data.len()]
                .copy_from_slice(data)
        };
        true
    }

    pub(crate) fn packet(&self, slot: PacketSlot, len: usize) -> Option<&[u8]> {
        if slot.index() >= SLOTS || len > MTU {
            return None;
        }
        Some(unsafe { &(&(*self.packets.get())[slot.index()])[..len] })
    }

    /// Transfer a lease between bearer/connection/path queues. This does not
    /// change memory usage or copy bytes; the next owner must eventually call
    /// `release` exactly once.
    pub(crate) const fn transfer(&self, slot: PacketSlot) -> PacketSlot {
        slot
    }

    pub(crate) fn release(&self, slot: PacketSlot) -> bool {
        if slot.index() >= SLOTS {
            return false;
        }
        let bit = 1u32 << slot.0;
        let previous = self.free.fetch_or(bit, Ordering::AcqRel);
        previous & bit == 0
    }
}

impl<const SLOTS: usize, const MTU: usize> crate::PacketPool for PacketPool<SLOTS, MTU> {
    type Buffer = PoolBufferLease<'static, SLOTS, MTU>;
    type Writer = PacketWriter<'static, SLOTS, MTU>;

    fn acquire_writer(&'static self, headroom: usize, reserved: usize) -> Option<Self::Writer> {
        self.acquire_writer_reserving(headroom, reserved)
    }

    fn capacity(&self) -> usize {
        SLOTS
    }

    fn available(&self) -> usize {
        PacketPool::available(self)
    }
}

impl<const SLOTS: usize, const MTU: usize> crate::callback::PacketLease
    for PoolLease<'_, SLOTS, MTU>
{
    fn bytes(&self) -> &[u8] {
        self.bytes()
    }
}

const fn mask(slots: usize) -> u32 {
    if slots == 32 {
        u32::MAX
    } else {
        (1u32 << slots) - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PacketPool as _;

    type TestPool = PacketPool<2, 16>;
    type TestPacket = crate::OwnedPacket<PoolBufferLease<'static, 2, 16>>;
    static QUEUE_POOL: TestPool = TestPool::new();
    static QUEUE: PacketLeaseQueue<u8, PoolBufferLease<'static, 2, 16>, 2> =
        PacketLeaseQueue::new();
    static FULL_QUEUE_POOL: PacketPool<3, 16> = PacketPool::new();
    static FULL_QUEUE: PacketLeaseQueue<u8, PoolBufferLease<'static, 3, 16>, 2> =
        PacketLeaseQueue::new();

    #[test]
    fn lease_queue_moves_metadata_without_copying_packet_storage() {
        let packet: TestPacket = QUEUE_POOL
            .build_packet(3, 0, |output| -> Result<usize, ()> {
                output[..6].copy_from_slice(b"packet");
                Ok(6)
            })
            .unwrap();
        assert_eq!(QUEUE_POOL.available(), 1);
        QUEUE.try_push(7, packet).unwrap();
        assert_eq!(QUEUE_POOL.available(), 1);

        let (metadata, packet) = QUEUE.try_pop().unwrap();
        assert_eq!(metadata, 7);
        assert_eq!(packet.bytes(), b"packet");
        assert_eq!(QUEUE_POOL.available(), 1);
        drop(packet);
        assert_eq!(QUEUE_POOL.available(), 2);
        assert_eq!(QUEUE.try_is_empty(), Some(true));
    }

    #[test]
    fn full_lease_queue_returns_the_packet_for_backpressure_without_leaking_a_slot() {
        for metadata in 0..3 {
            let packet = FULL_QUEUE_POOL
                .build_packet(0, 0, |output| -> Result<usize, ()> {
                    output[0] = metadata;
                    Ok(1)
                })
                .unwrap();
            match FULL_QUEUE.try_push(metadata, packet) {
                Ok(()) if metadata < 2 => {}
                Err((returned_metadata, packet)) if metadata == 2 => {
                    assert_eq!(returned_metadata, metadata);
                    assert_eq!(packet.bytes(), &[metadata]);
                    drop(packet);
                }
                result => panic!("unexpected enqueue result for {metadata}: {result:?}"),
            }
        }
        assert_eq!(FULL_QUEUE_POOL.available(), 1);
        assert_eq!(
            FULL_QUEUE.try_pop().map(|(metadata, packet)| {
                let bytes = packet.bytes()[0];
                drop(packet);
                (metadata, bytes)
            }),
            Some((0, 0))
        );
        assert_eq!(FULL_QUEUE_POOL.available(), 2);
        assert_eq!(
            FULL_QUEUE.try_pop().map(|(metadata, packet)| {
                let bytes = packet.bytes()[0];
                drop(packet);
                (metadata, bytes)
            }),
            Some((1, 1))
        );
        assert_eq!(FULL_QUEUE_POOL.available(), 3);
    }

    #[test]
    fn relay_transfers_one_slot_without_an_egress_copy() {
        let pool = PacketPool::<2, 8>::new();
        let incoming = pool.acquire().unwrap();
        assert!(pool.write(incoming, b"udp"));
        let outgoing = pool.transfer(incoming);
        assert_eq!(incoming, outgoing);
        assert_eq!(pool.packet(outgoing, 3), Some(&b"udp"[..]));
        assert_eq!(pool.available(), 1);
        assert!(pool.release(outgoing));
        assert_eq!(pool.available(), 2);
    }

    #[test]
    fn cloned_lease_keeps_one_slot_across_connection_and_bearer() {
        let pool = PacketPool::<1, 8>::new();
        let connection = pool.acquire_with(b"packet").unwrap();
        let bearer = connection.clone();
        assert_eq!(pool.available(), 0);
        assert_eq!(bearer.bytes(), b"packet");
        drop(bearer);
        assert_eq!(pool.available(), 0);
        drop(connection);
        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn prefix_headroom_leaves_payload_bytes_unmoved() {
        let pool = PacketPool::<1, 16>::new();
        let mut packet = pool.acquire_with_headroom(4, b"ciphertext").unwrap();
        assert!(packet.prepend(b"udp!"));
        assert_eq!(packet.payload(), b"udp!ciphertext");
        assert!(packet.strip_prefix(4));
        assert_eq!(packet.payload(), b"ciphertext");
    }

    #[test]
    fn writer_reserves_headroom_without_copying_payload() {
        let pool = PacketPool::<1, 16>::new();
        let mut writer = pool.acquire_writer(4).unwrap();
        writer.payload_mut()[..6].copy_from_slice(b"direct");
        writer.frame_mut()[..4].copy_from_slice(b"wire");
        let packet = writer.commit_frame(6).unwrap();
        assert_eq!(packet.payload(), b"wiredirect");
        assert_eq!(pool.available(), 0);
        drop(packet);
        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn dropped_writer_returns_its_slot() {
        let pool = PacketPool::<1, 8>::new();
        let writer = pool.acquire_writer(2).unwrap();
        assert_eq!(pool.available(), 0);
        drop(writer);
        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn common_pool_interface_serializes_directly_into_owned_packet() {
        use crate::PacketPool as _;

        static POOL: PacketPool<2, 16> = PacketPool::new();
        let packet = POOL
            .build_packet(4, 1, |output| -> Result<usize, ()> {
                output[..3].copy_from_slice(&[7, 8, 9]);
                Ok(3)
            })
            .unwrap();
        assert_eq!(packet.bytes(), &[7, 8, 9]);
        assert_eq!(packet.prefix_capacity(), 4);
        assert_eq!(POOL.available(), 1);
        drop(packet);
        assert_eq!(POOL.available(), 2);
    }

    #[test]
    fn reserved_slots_remain_available_for_the_other_direction() {
        let pool = PacketPool::<3, 8>::new();
        let first = pool.acquire_reserving(1).unwrap();
        let second = pool.acquire_reserving(1).unwrap();
        assert!(pool.acquire_reserving(1).is_none());
        let reserved = pool.acquire().unwrap();
        assert_eq!(pool.available(), 0);
        assert!(pool.release(first));
        assert!(pool.release(second));
        assert!(pool.release(reserved));
    }
}
