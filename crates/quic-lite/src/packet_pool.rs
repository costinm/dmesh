//! Fixed MTU packet slots shared by every bearer and relay path.
//!
//! A slot is device-owned rather than ingress- or egress-owned. A relay keeps
//! the same slot while handing a received packet to another bearer, so RX for
//! one connection can be TX for another without reserving a second MTU.

use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicU8, AtomicU32, Ordering},
};

/// Opaque ownership token for one packet slot.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketSlot(u8);

impl PacketSlot {
    pub const fn index(self) -> usize {
        self.0 as usize
    }
    /// Queue-only sentinel used by an adapter work item that carries no
    /// packet-slot ownership. It must never reach packet access or release.
    pub const fn sentinel() -> Self {
        Self(u8::MAX)
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
    pub fn bytes(&self) -> &[u8] {
        self.payload()
    }
    /// View beginning at the current header offset rather than byte zero.
    pub fn payload(&self) -> &[u8] {
        &self.pool.packet(self.slot, MTU).expect("valid pool lease")
            [self.start..self.start + self.len]
    }
    pub const fn len(&self) -> usize {
        self.len
    }
    pub const fn slot(&self) -> PacketSlot {
        self.slot
    }

    /// Add a bearer header in already-reserved headroom. The payload bytes are
    /// not moved, which is essential when they are end-to-end ciphertext.
    pub fn prepend(&mut self, header: &[u8]) -> bool {
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
    pub fn strip_prefix(&mut self, bytes: usize) -> bool {
        if bytes > self.len {
            return false;
        }
        self.start += bytes;
        self.len -= bytes;
        true
    }
}

// A caller may access a packet only while it owns the corresponding cleared
// bit. Firmware queues carry the slot token, never a duplicate MTU payload.
unsafe impl<const SLOTS: usize, const MTU: usize> Sync for PacketPool<SLOTS, MTU> {}

impl<const SLOTS: usize, const MTU: usize> PacketPool<SLOTS, MTU> {
    pub const fn new() -> Self {
        assert!(SLOTS <= 32);
        Self {
            free: AtomicU32::new(mask(SLOTS)),
            references: [const { AtomicU8::new(0) }; SLOTS],
            packets: UnsafeCell::new([[0; MTU]; SLOTS]),
        }
    }

    pub fn acquire(&self) -> Option<PacketSlot> {
        let mut current = self.free.load(Ordering::Acquire);
        loop {
            if current == 0 {
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

    pub fn available(&self) -> usize {
        self.free.load(Ordering::Acquire).count_ones() as usize
    }

    /// Acquire a shared packet and initialize its bytes in one bounded copy.
    /// The returned lease may be retained by connection ordering or handed to
    /// a bearer without allocating a second packet.
    pub fn acquire_with(&self, data: &[u8]) -> Option<PoolLease<'_, SLOTS, MTU>> {
        self.acquire_with_headroom(0, data)
    }

    /// Acquire a slot with prefix space reserved for the selected bearer.
    pub fn acquire_with_headroom(
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

    pub fn write(&self, slot: PacketSlot, data: &[u8]) -> bool {
        self.write_at(slot, 0, data)
    }

    pub fn write_at(&self, slot: PacketSlot, offset: usize, data: &[u8]) -> bool {
        if slot.index() >= SLOTS || offset.saturating_add(data.len()) > MTU {
            return false;
        }
        unsafe {
            (&mut (*self.packets.get())[slot.index()])[offset..offset + data.len()]
                .copy_from_slice(data)
        };
        true
    }

    pub fn packet(&self, slot: PacketSlot, len: usize) -> Option<&[u8]> {
        if slot.index() >= SLOTS || len > MTU {
            return None;
        }
        Some(unsafe { &(&(*self.packets.get())[slot.index()])[..len] })
    }

    /// Transfer a lease between bearer/connection/path queues. This does not
    /// change memory usage or copy bytes; the next owner must eventually call
    /// `release` exactly once.
    pub const fn transfer(&self, slot: PacketSlot) -> PacketSlot {
        slot
    }

    pub fn release(&self, slot: PacketSlot) -> bool {
        if slot.index() >= SLOTS {
            return false;
        }
        let bit = 1u32 << slot.0;
        let previous = self.free.fetch_or(bit, Ordering::AcqRel);
        previous & bit == 0
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
}
