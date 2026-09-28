//! Heap-backed packet slots for devices whose transport RAM must be reclaimable.

use alloc::{boxed::Box, vec::Vec};
use core::{
    cell::UnsafeCell,
    ptr,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicUsize, Ordering},
};

use crate::{OwnedPacket, PacketPool, PacketWriter};

const WRITER: u8 = u8::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Failure to resize a heap-backed node packet pool.
///
/// Public device setup code needs this distinction to lower its requested
/// capacity after allocation pressure without inspecting pool internals.
pub enum HeapPacketPoolError {
    /// Requested active slots exceed the pool's compile-time table size.
    CapacityTooLarge,
    /// The allocator could not provide all slots for an atomic growth step.
    AllocationFailed,
}

/// Conservative allocator/header allowance charged to every heap packet.
/// Platforms may pass a larger reserve for their allocator and driver needs.
pub const HEAP_PACKET_SLOT_OVERHEAD: usize = 32;

#[derive(Clone, Copy)]
/// Allocation hooks used by embedded devices with a platform heap.
///
/// The type is public because ESP targets must check/select their heap region;
/// ordinary host users should use [`HeapPacketAllocator::global`].
pub struct HeapPacketAllocator {
    allocate: fn(usize) -> *mut u8,
    deallocate: unsafe fn(*mut u8, usize),
}

impl HeapPacketAllocator {
    /// Define platform allocation and matching deallocation callbacks.
    ///
    /// The allocator must return storage aligned for bytes and valid for the
    /// requested size; the same size is passed back on final release.
    pub const fn new(
        allocate: fn(usize) -> *mut u8,
        deallocate: unsafe fn(*mut u8, usize),
    ) -> Self {
        Self {
            allocate,
            deallocate,
        }
    }

    /// Use Rust's global allocator for host and standard `alloc` targets.
    pub const fn global() -> Self {
        Self::new(global_allocate, global_deallocate)
    }
}

struct PendingSlot<const MTU: usize> {
    slot: usize,
    buffer: *mut u8,
    deallocate: unsafe fn(*mut u8, usize),
}

impl<const MTU: usize> Drop for PendingSlot<MTU> {
    fn drop(&mut self) {
        if !self.buffer.is_null() {
            unsafe { (self.deallocate)(self.buffer, MTU) };
        }
    }
}

/// One logical device packet pool with individually allocated MTU slots.
///
/// Only its small pointer/reference table is static. `resize` grows from the
/// heap and shrinking frees idle slots immediately. A removed slot which is
/// still leased is freed by the final lease drop, so resize never invalidates
/// an ingress, connection, relay, or egress owner.
pub struct HeapPacketPool<const MAX_SLOTS: usize, const MTU: usize> {
    lock: AtomicBool,
    capacity: AtomicUsize,
    buffers: [AtomicPtr<u8>; MAX_SLOTS],
    references: [AtomicU8; MAX_SLOTS],
    allocator: HeapPacketAllocator,
    _exclusive_write: UnsafeCell<()>,
}

unsafe impl<const MAX_SLOTS: usize, const MTU: usize> Sync for HeapPacketPool<MAX_SLOTS, MTU> {}

impl<const MAX_SLOTS: usize, const MTU: usize> HeapPacketPool<MAX_SLOTS, MTU> {
    /// Create an empty pool using Rust's global allocator.
    ///
    /// Call [`Self::resize`] before constructing a node so initial ingress has
    /// packet leases available.
    pub const fn new() -> Self {
        Self::new_with_allocator(HeapPacketAllocator::global())
    }

    /// Create an empty pool using platform allocation callbacks.
    pub const fn new_with_allocator(allocator: HeapPacketAllocator) -> Self {
        assert!(MAX_SLOTS <= u8::MAX as usize);
        Self {
            lock: AtomicBool::new(false),
            capacity: AtomicUsize::new(0),
            buffers: [const { AtomicPtr::new(ptr::null_mut()) }; MAX_SLOTS],
            references: [const { AtomicU8::new(WRITER) }; MAX_SLOTS],
            allocator,
            _exclusive_write: UnsafeCell::new(()),
        }
    }

    /// Change active capacity. Growth is fallible and allocates each slot
    /// separately; a failed growth leaves the prior capacity unchanged.
    pub fn resize(&self, target: usize) -> Result<(), HeapPacketPoolError> {
        if target > MAX_SLOTS {
            return Err(HeapPacketPoolError::CapacityTooLarge);
        }
        let current = self.capacity();
        if target > current {
            let mut pending: Vec<PendingSlot<MTU>> = Vec::new();
            pending
                .try_reserve_exact(target - current)
                .map_err(|_| HeapPacketPoolError::AllocationFailed)?;
            for slot in current..target {
                if self.buffers[slot].load(Ordering::Acquire).is_null() {
                    pending.push(PendingSlot {
                        slot,
                        buffer: self.allocate_slot()?,
                        deallocate: self.allocator.deallocate,
                    });
                }
            }
            let _guard = self.guard();
            for mut pending in pending {
                if self.buffers[pending.slot].load(Ordering::Relaxed).is_null() {
                    self.buffers[pending.slot].store(pending.buffer, Ordering::Release);
                    self.references[pending.slot].store(0, Ordering::Release);
                    pending.buffer = ptr::null_mut();
                }
            }
            self.capacity.store(target, Ordering::Release);
            return Ok(());
        }
        if target < current {
            let _guard = self.guard();
            self.capacity.store(target, Ordering::Release);
            for slot in target..current {
                if self.references[slot].load(Ordering::Acquire) == 0 {
                    self.retire_locked(slot);
                }
            }
        }
        Ok(())
    }

    /// Grow only from RAM available above `reserve_bytes`.
    ///
    /// The returned capacity is authoritative. A caller uses it to clamp
    /// advertised receive windows. Allocation failure is reported as the
    /// capacity reached so far; packet acquisition subsequently returns
    /// `None`, allowing normal QUIC loss recovery instead of heap exhaustion.
    pub fn resize_with_budget(
        &self,
        target: usize,
        available_bytes: usize,
        reserve_bytes: usize,
    ) -> Result<usize, HeapPacketPoolError> {
        if target > MAX_SLOTS {
            return Err(HeapPacketPoolError::CapacityTooLarge);
        }
        let current = self.capacity();
        if target <= current {
            self.resize(target)?;
            return Ok(target);
        }
        let slot_bytes = MTU.saturating_add(HEAP_PACKET_SLOT_OVERHEAD).max(1);
        let affordable_growth = available_bytes.saturating_sub(reserve_bytes) / slot_bytes;
        let admitted = target.min(current.saturating_add(affordable_growth));
        for capacity in current + 1..=admitted {
            if self.resize(capacity).is_err() {
                return Ok(self.capacity());
            }
        }
        Ok(self.capacity())
    }

    /// Worker/task-context maintenance for a free-packet target.
    ///
    /// Callbacks never call this method: they only try `acquire_writer` and
    /// drop a packet when it returns `None`. The owner task samples the
    /// platform heap and calls this after processing packets or memory-policy
    /// changes. Idle slots above `target_free` are released; growth stops at
    /// `device_limit`, the RAM reserve, the largest free block, or allocation
    /// failure.
    pub fn maintain_free(
        &self,
        target_free: usize,
        device_limit: usize,
        available_bytes: usize,
        largest_free_block: usize,
        reserve_bytes: usize,
    ) -> Result<usize, HeapPacketPoolError> {
        if device_limit > MAX_SLOTS {
            return Err(HeapPacketPoolError::CapacityTooLarge);
        }
        let in_use = self.in_use();
        let desired = in_use.saturating_add(target_free).min(device_limit);
        if desired <= self.capacity() {
            self.resize(desired)?;
            return Ok(self.capacity());
        }
        let slot_bytes = MTU.saturating_add(HEAP_PACKET_SLOT_OVERHEAD).max(1);
        if largest_free_block < slot_bytes {
            return Ok(self.capacity());
        }
        self.resize_with_budget(desired, available_bytes, reserve_bytes)
    }

    /// Number of active slots which may currently be acquired.
    pub fn capacity(&self) -> usize {
        self.capacity.load(Ordering::Acquire)
    }

    /// Number of slots which still own heap allocations, including retired
    /// slots whose outstanding leases have not yet returned.
    pub fn allocated(&self) -> usize {
        self.buffers
            .iter()
            .filter(|buffer| !buffer.load(Ordering::Acquire).is_null())
            .count()
    }

    /// Number of active slots immediately available for acquisition.
    pub fn available(&self) -> usize {
        let capacity = self.capacity();
        self.references[..capacity]
            .iter()
            .filter(|references| references.load(Ordering::Acquire) == 0)
            .count()
    }

    /// Number of committed leases or in-progress writers currently retained.
    pub fn in_use(&self) -> usize {
        self.references
            .iter()
            .filter(|references| {
                let value = references.load(Ordering::Acquire);
                value != 0 && value != WRITER
            })
            .count()
            + self
                .references
                .iter()
                .zip(self.buffers.iter())
                .filter(|(references, buffer)| {
                    references.load(Ordering::Acquire) == WRITER
                        && !buffer.load(Ordering::Acquire).is_null()
                })
                .count()
    }

    pub(crate) fn acquire_writer_reserving(
        &'static self,
        headroom: usize,
        reserved: usize,
    ) -> Option<HeapPacketWriter<'static, MAX_SLOTS, MTU>> {
        if headroom > MTU {
            return None;
        }
        // Driver callbacks must never spin behind a lower-priority worker
        // which is resizing the pool. This is especially important on a
        // single-core MCU: the callback may have preempted the only task able
        // to release the lock. Treat contention exactly like an empty pool and
        // let transport loss recovery retry the packet.
        let _guard = self.try_guard()?;
        let capacity = self.capacity.load(Ordering::Relaxed);
        let available = self.references[..capacity]
            .iter()
            .filter(|references| references.load(Ordering::Relaxed) == 0)
            .count();
        if available <= reserved {
            return None;
        }
        let slot = self.references[..capacity]
            .iter()
            .position(|references| references.load(Ordering::Relaxed) == 0)?;
        debug_assert!(!self.buffers[slot].load(Ordering::Relaxed).is_null());
        self.references[slot].store(WRITER, Ordering::Release);
        Some(HeapPacketWriter {
            pool: self,
            slot: slot as u8,
            start: headroom,
            active: true,
        })
    }

    fn guard(&self) -> PoolGuard<'_> {
        while self
            .lock
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        PoolGuard { lock: &self.lock }
    }

    fn try_guard(&self) -> Option<PoolGuard<'_>> {
        self.lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| PoolGuard { lock: &self.lock })
    }

    fn retire_locked(&self, slot: usize) {
        debug_assert_eq!(self.references[slot].load(Ordering::Relaxed), 0);
        self.references[slot].store(WRITER, Ordering::Release);
        let buffer = self.buffers[slot].swap(ptr::null_mut(), Ordering::AcqRel);
        if !buffer.is_null() {
            unsafe { (self.allocator.deallocate)(buffer, MTU) };
        }
    }

    fn final_release(&self, slot: usize) {
        if slot < self.capacity() {
            return;
        }
        let _guard = self.guard();
        if slot >= self.capacity() && self.references[slot].load(Ordering::Acquire) == 0 {
            self.retire_locked(slot);
        }
    }

    unsafe fn slot(&self, slot: usize) -> &[u8] {
        let pointer = self.buffers[slot].load(Ordering::Acquire);
        debug_assert!(!pointer.is_null());
        unsafe { core::slice::from_raw_parts(pointer, MTU) }
    }

    unsafe fn slot_mut(&self, slot: usize) -> &mut [u8] {
        let pointer = self.buffers[slot].load(Ordering::Acquire);
        debug_assert!(!pointer.is_null());
        unsafe { core::slice::from_raw_parts_mut(pointer, MTU) }
    }

    fn allocate_slot(&self) -> Result<*mut u8, HeapPacketPoolError> {
        let buffer = (self.allocator.allocate)(MTU);
        if buffer.is_null() {
            Err(HeapPacketPoolError::AllocationFailed)
        } else {
            Ok(buffer)
        }
    }
}

struct PoolGuard<'a> {
    lock: &'a AtomicBool,
}

impl Drop for PoolGuard<'_> {
    fn drop(&mut self) {
        self.lock.store(false, Ordering::Release);
    }
}

fn global_allocate(bytes: usize) -> *mut u8 {
    let mut storage = Vec::new();
    if storage.try_reserve_exact(bytes).is_err() {
        return ptr::null_mut();
    }
    storage.resize(bytes, 0);
    Box::into_raw(storage.into_boxed_slice()).cast::<u8>()
}

unsafe fn global_deallocate(buffer: *mut u8, bytes: usize) {
    let slice = ptr::slice_from_raw_parts_mut(buffer, bytes);
    unsafe { drop(Box::from_raw(slice)) };
}

/// Exclusive initialization lease used as [`PacketPool::Writer`].
///
/// It is public only because Rust requires the associated type of the public
/// `PacketPool` implementation to be nameable; applications do not construct it.
pub struct HeapPacketWriter<'a, const MAX_SLOTS: usize, const MTU: usize> {
    pool: &'a HeapPacketPool<MAX_SLOTS, MTU>,
    slot: u8,
    start: usize,
    active: bool,
}

impl<const MAX_SLOTS: usize, const MTU: usize> PacketWriter
    for HeapPacketWriter<'static, MAX_SLOTS, MTU>
{
    type Buffer = HeapPacketLease<'static, MAX_SLOTS, MTU>;

    fn payload_mut(&mut self) -> &mut [u8] {
        unsafe { &mut self.pool.slot_mut(self.slot as usize)[self.start..] }
    }

    fn commit(mut self, len: usize) -> Option<OwnedPacket<Self::Buffer>> {
        if len > MTU.saturating_sub(self.start) {
            return None;
        }
        self.pool.references[self.slot as usize].store(1, Ordering::Release);
        self.active = false;
        let range = self.start..self.start + len;
        OwnedPacket::new(
            HeapPacketLease {
                pool: self.pool,
                slot: self.slot,
            },
            range,
        )
        .ok()
    }
}

impl<const MAX_SLOTS: usize, const MTU: usize> Drop for HeapPacketWriter<'_, MAX_SLOTS, MTU> {
    fn drop(&mut self) {
        if self.active {
            self.pool.references[self.slot as usize].store(0, Ordering::Release);
            self.pool.final_release(self.slot as usize);
        }
    }
}

/// Reference-counted heap slot used as [`PacketPool::Buffer`].
///
/// It is public because bearers parameterized by the node pool carry this
/// associated buffer type. Only the pool creates leases.
pub struct HeapPacketLease<'a, const MAX_SLOTS: usize, const MTU: usize> {
    pool: &'a HeapPacketPool<MAX_SLOTS, MTU>,
    slot: u8,
}

impl<const MAX_SLOTS: usize, const MTU: usize> Clone for HeapPacketLease<'_, MAX_SLOTS, MTU> {
    fn clone(&self) -> Self {
        let previous = self.pool.references[self.slot as usize].fetch_add(1, Ordering::AcqRel);
        assert!(
            previous != 0 && previous < WRITER - 1,
            "packet lease reference overflow"
        );
        Self {
            pool: self.pool,
            slot: self.slot,
        }
    }
}

impl<const MAX_SLOTS: usize, const MTU: usize> Drop for HeapPacketLease<'_, MAX_SLOTS, MTU> {
    fn drop(&mut self) {
        if self.pool.references[self.slot as usize].fetch_sub(1, Ordering::AcqRel) == 1 {
            self.pool.final_release(self.slot as usize);
        }
    }
}

impl<const MAX_SLOTS: usize, const MTU: usize> AsRef<[u8]> for HeapPacketLease<'_, MAX_SLOTS, MTU> {
    fn as_ref(&self) -> &[u8] {
        unsafe { self.pool.slot(self.slot as usize) }
    }
}

impl<const MAX_SLOTS: usize, const MTU: usize> core::fmt::Debug
    for HeapPacketLease<'_, MAX_SLOTS, MTU>
{
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("HeapPacketLease")
            .field(&self.slot)
            .finish()
    }
}

impl<const MAX_SLOTS: usize, const MTU: usize> PacketPool for HeapPacketPool<MAX_SLOTS, MTU> {
    type Buffer = HeapPacketLease<'static, MAX_SLOTS, MTU>;
    type Writer = HeapPacketWriter<'static, MAX_SLOTS, MTU>;

    fn acquire_writer(&'static self, headroom: usize, reserved: usize) -> Option<Self::Writer> {
        self.acquire_writer_reserving(headroom, reserved)
    }

    fn capacity(&self) -> usize {
        HeapPacketPool::capacity(self)
    }

    fn available(&self) -> usize {
        HeapPacketPool::available(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static POOL: HeapPacketPool<8, 64> = HeapPacketPool::new();

    #[test]
    fn growth_and_shrink_release_heap_slots_after_leases_finish() {
        POOL.resize(4).unwrap();
        assert_eq!(
            (POOL.capacity(), POOL.allocated(), POOL.available()),
            (4, 4, 4)
        );
        let packet = POOL
            .build_packet(8, 1, |output| -> Result<usize, ()> {
                output[..3].copy_from_slice(&[1, 2, 3]);
                Ok(3)
            })
            .unwrap();
        assert_eq!(packet.bytes(), &[1, 2, 3]);
        POOL.resize(0).unwrap();
        assert_eq!(
            (POOL.capacity(), POOL.allocated(), POOL.available()),
            (0, 1, 0)
        );
        drop(packet);
        assert_eq!(POOL.allocated(), 0);
    }

    #[test]
    fn budget_gate_preserves_platform_reserve_and_reports_admitted_capacity() {
        static BUDGETED: HeapPacketPool<8, 100> = HeapPacketPool::new();
        let per_slot = 100 + HEAP_PACKET_SLOT_OVERHEAD;
        assert_eq!(
            BUDGETED
                .resize_with_budget(8, 1_000 + 3 * per_slot, 1_000)
                .unwrap(),
            3
        );
        assert_eq!(BUDGETED.available(), 3);
        assert!(BUDGETED.acquire_writer_reserving(0, 3).is_none());
        BUDGETED.resize(0).unwrap();
    }

    #[test]
    fn worker_maintains_free_target_and_callbacks_drop_at_zero() {
        static MAINTAINED: HeapPacketPool<16, 100> = HeapPacketPool::new();
        let slot_bytes = 100 + HEAP_PACKET_SLOT_OVERHEAD;
        assert_eq!(
            MAINTAINED
                .maintain_free(8, 12, 4_096 + 12 * slot_bytes, 2_048, 4_096)
                .unwrap(),
            8
        );
        let mut leases = Vec::new();
        for value in 0..8 {
            leases.push(
                MAINTAINED
                    .build_packet(0, 0, |output| -> Result<usize, ()> {
                        output[0] = value;
                        Ok(1)
                    })
                    .unwrap(),
            );
        }
        assert_eq!(MAINTAINED.available(), 0);
        assert!(MAINTAINED.acquire_writer_reserving(0, 0).is_none());
        assert_eq!(
            MAINTAINED
                .maintain_free(8, 12, 4_096 + 4 * slot_bytes, 2_048, 4_096)
                .unwrap(),
            12
        );
        drop(leases);
        assert_eq!(
            MAINTAINED
                .maintain_free(8, 12, 4_096, 2_048, 4_096)
                .unwrap(),
            8
        );
        MAINTAINED.resize(0).unwrap();
        assert_eq!(MAINTAINED.allocated(), 0);
    }

    #[test]
    fn callback_drops_instead_of_spinning_during_resize_lock_contention() {
        static CONTENDED: HeapPacketPool<2, 32> = HeapPacketPool::new();
        CONTENDED.resize(2).unwrap();
        CONTENDED.lock.store(true, Ordering::Release);
        assert!(CONTENDED.acquire_writer_reserving(0, 0).is_none());
        CONTENDED.lock.store(false, Ordering::Release);
        assert!(CONTENDED.acquire_writer_reserving(0, 0).is_some());
        CONTENDED.resize(0).unwrap();
    }
}
