// Bounded object-store records and the binary GET request.
//
// Transport supplies ordered stream bytes. This module does not parse packets,
// create sockets, or implement flow control.

extern crate alloc;
use super::cbor::Decoder;
use alloc::{boxed::Box, vec::Vec};
use sha2::{Digest, Sha256};

#[allow(clippy::result_unit_err)]

pub const BLOCK_SIZE: usize = 4096;
pub const FRAME_MANIFEST: u16 = 6;
pub const FRAME_BLOCK: u16 = 8;
pub const FRAME_DONE: u16 = 10;
pub const FRAME_MANIFEST_OK: u16 = 13;
const IMAGE_MAGIC: u32 = 0x4452_5332;

pub const FRAME_GET: u8 = 1;
pub const RECORD_MANIFEST: u8 = 1;
pub const RECORD_BLOB: u8 = 2;
pub const RECORD_DONE: u8 = 3;
pub const MAX_RECORD: usize = 16 * 1024 * 1024;
pub const REQUEST_MAX: usize = 1024;
/// The image digest remains full SHA-256. Per-block proofs use a 128-bit
/// prefix so the bounded firmware manifest scales with image size without a
/// CBOR item wrapper per block.
/// A block proof is a prefix of SHA-256.  The full image digest remains
/// SHA-256 and the signed manifest binds this table; eight bytes keeps a
/// 4-MiB/4-KiB image manifest below 9 KiB without allocating one CBOR object
/// per block.
pub const BLOCK_DIGEST_BYTES: usize = 8;
/// The sole currently supported immutable-object wire format.
pub const VERIFIED_OBJECT_VERSION: u8 = 1;
pub const OBJECT_COMPONENT: u64 = 10;
pub const OBJECT_GET_METHOD: u64 = 1;
pub const OBJECT_FLASH_METHOD: u64 = 2;
pub const FLASH_BUSY_ERROR: &[u8] = b"flash already in progress";

/// Immutable application storage policy for a streaming object consumer.
///
/// This is application capacity, not QUIC packet credit. Firmware supplies a
/// current heap observation; host tests inject the same observation and policy
/// before they create a sink. The caller still allocates selected slots
/// fallibly and advertises only the capacity actually obtained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageSlotPolicy {
    pub reserve_bytes: usize,
    pub bytes_per_slot: usize,
    pub minimum_slots: usize,
    pub maximum_slots: usize,
}

impl StorageSlotPolicy {
    /// Select bounded application storage from an observed free-memory value.
    pub const fn slots_for(self, available_bytes: usize) -> usize {
        if self.bytes_per_slot == 0
            || self.minimum_slots == 0
            || self.maximum_slots < self.minimum_slots
        {
            return 0;
        }
        let slots = available_bytes.saturating_sub(self.reserve_bytes) / self.bytes_per_slot;
        if slots < self.minimum_slots {
            0
        } else if slots > self.maximum_slots {
            self.maximum_slots
        } else {
            slots
        }
    }
}

/// Compatibility helper for call sites that receive policy fields separately.
pub const fn bounded_storage_slots(
    available_bytes: usize,
    reserve_bytes: usize,
    bytes_per_slot: usize,
    minimum_slots: usize,
    maximum_slots: usize,
) -> usize {
    StorageSlotPolicy {
        reserve_bytes,
        bytes_per_slot,
        minimum_slots,
        maximum_slots,
    }
    .slots_for(available_bytes)
}

/// One association-scoped owner for a verified immutable-object sink.
///
/// The receiver storage may be platform-specific, but admission is shared:
/// a competing association cannot replace or release the current writer.
/// Zero is reserved by `ConnectionId`, so it is also the unowned sentinel.
pub struct ExclusiveTransfer<T> {
    active: Option<ExclusiveTransferEntry<T>>,
}

struct ExclusiveTransferEntry<T> {
    owner: quic_lite::ConnectionId,
    request_id: u64,
    expires_at: u64,
    value: T,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExclusiveTransferStartError<E> {
    Busy,
    Start(E),
}

impl<T> ExclusiveTransfer<T> {
    pub const fn new() -> Self {
        Self { active: None }
    }

    /// Start and install an operation as one application-level transition.
    /// A contender never invokes `start`, which is important when construction
    /// allocates scarce firmware memory or opens a host file.
    pub fn try_start_with<E>(
        &mut self,
        owner: quic_lite::ConnectionId,
        request_id: u64,
        now: u64,
        idle_timeout: u64,
        start: impl FnOnce() -> Result<T, E>,
    ) -> Result<(), ExclusiveTransferStartError<E>> {
        if self.active.is_some() {
            return Err(ExclusiveTransferStartError::Busy);
        }
        let value = start().map_err(ExclusiveTransferStartError::Start)?;
        self.active = Some(ExclusiveTransferEntry {
            owner,
            request_id,
            expires_at: now.saturating_add(idle_timeout),
            value,
        });
        Ok(())
    }

    /// Start an operation, replacing an existing one only when the
    /// application explicitly declares that existing value pristine/stale.
    ///
    /// This is deliberately association- rather than bearer-scoped. A fresh
    /// client CID may take over an operation which has not consumed any
    /// application bytes after its predecessor disappeared, while a duplicate
    /// request on the same association and every operation with admitted data
    /// remains exclusive. The predicate is application-owned: transport ACKs,
    /// packet counters, and bearer identity never participate.
    pub fn try_start_or_replace_if<E>(
        &mut self,
        owner: quic_lite::ConnectionId,
        request_id: u64,
        now: u64,
        idle_timeout: u64,
        replace: impl FnOnce(&T) -> bool,
        start: impl FnOnce() -> Result<T, E>,
    ) -> Result<(), ExclusiveTransferStartError<E>> {
        if let Some(active) = self.active.as_ref() {
            if active.owner == owner || !replace(&active.value) {
                return Err(ExclusiveTransferStartError::Busy);
            }
            // The application says no bytes reached this receiver, so it has
            // no durable state to preserve. Release scarce storage before the
            // replacement constructor runs.
            let _ = self.active.take();
        }
        let value = start().map_err(ExclusiveTransferStartError::Start)?;
        self.active = Some(ExclusiveTransferEntry {
            owner,
            request_id,
            expires_at: now.saturating_add(idle_timeout),
            value,
        });
        Ok(())
    }

    pub fn owner(&self) -> Option<quic_lite::ConnectionId> {
        self.active.as_ref().map(|entry| entry.owner)
    }

    pub fn request_id_for(&self, owner: quic_lite::ConnectionId) -> Option<u64> {
        self.active
            .as_ref()
            .filter(|entry| entry.owner == owner)
            .map(|entry| entry.request_id)
    }

    pub fn get_mut_for(&mut self, owner: quic_lite::ConnectionId) -> Option<&mut T> {
        self.active
            .as_mut()
            .filter(|entry| entry.owner == owner)
            .map(|entry| &mut entry.value)
    }

    /// Refresh liveness only for application bytes consumed by the owner.
    /// ACKs, control packets, and traffic from another association cannot keep
    /// a stalled operation alive.
    pub fn touch(&mut self, owner: quic_lite::ConnectionId, now: u64, idle_timeout: u64) -> bool {
        let Some(entry) = self.active.as_mut().filter(|entry| entry.owner == owner) else {
            return false;
        };
        entry.expires_at = now.saturating_add(idle_timeout);
        true
    }

    /// Only the owning association may remove the operation. The returned
    /// value lets the application perform any platform-specific teardown.
    pub fn take_for(&mut self, owner: quic_lite::ConnectionId) -> Option<T> {
        if self.owner() != Some(owner) {
            return None;
        }
        self.active.take().map(|entry| entry.value)
    }

    /// Expire one stalled application operation. This does not inspect QUIC
    /// packet or ACK state; the deadline advances only through [`Self::touch`].
    pub fn take_expired(&mut self, now: u64) -> Option<(quic_lite::ConnectionId, u64, T)> {
        if !self
            .active
            .as_ref()
            .is_some_and(|entry| now >= entry.expires_at)
        {
            return None;
        }
        self.active
            .take()
            .map(|entry| (entry.owner, entry.request_id, entry.value))
    }
}

impl<T> Default for ExclusiveTransfer<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Credit return after one verified object record. This policy is independent
/// of UDP/UART/radio: a persistent sink returns blob credit only when it has
/// reclaimed storage, while a benchmark/fake sink can reuse it immediately.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectRecordCredit {
    Immediate(usize),
    Deferred,
}

/// Coalesced readiness for application storage which must start outside the
/// stream callback that requested it.
///
/// One later maintenance turn consumes the edge. Requiring a second turn can
/// deadlock a fully ACKed sender at its advertised receive-window boundary,
/// while duplicate requests before that turn need no additional queue item.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeferredStorageWork {
    pending: bool,
}

impl DeferredStorageWork {
    pub const fn new() -> Self {
        Self { pending: false }
    }

    pub fn request(&mut self) {
        self.pending = true;
    }

    pub const fn is_pending(&self) -> bool {
        self.pending
    }

    pub fn take(&mut self) -> bool {
        core::mem::take(&mut self.pending)
    }
}

pub const fn verified_object_record_credit(
    kind: u8,
    payload_len: usize,
    immediately_reusable: bool,
) -> Option<ObjectRecordCredit> {
    let record_len = payload_len.saturating_add(5);
    match kind {
        RECORD_MANIFEST | RECORD_DONE => Some(ObjectRecordCredit::Immediate(record_len)),
        RECORD_BLOB if immediately_reusable => Some(ObjectRecordCredit::Immediate(record_len)),
        RECORD_BLOB => Some(ObjectRecordCredit::Deferred),
        _ => None,
    }
}

/// Encode the object-store GET map. Transport wraps the returned bytes in its
/// own stream packet; this function has no bearer or packet dependency.
pub fn encode_get(out: &mut [u8], name: Option<&[u8]>, cpu: u8, target: u8) -> Option<usize> {
    let mut encoder = super::cbor::Encoder::new(out);
    encoder.map(if name.is_some() { 3 } else { 2 })?;
    if let Some(name) = name {
        encoder.uint(0)?;
        encoder.bytes_value(name)?;
    }
    encoder.uint(1)?;
    encoder.uint(cpu as u64)?;
    encoder.uint(2)?;
    encoder.uint(target as u64)?;
    Some(encoder.len())
}

/// Encode a correlated object GET handler request for a normal QUIC stream.
pub fn encode_get_request(
    out: &mut [u8],
    id: u64,
    name: Option<&[u8]>,
    cpu: u8,
    target: u8,
) -> Option<usize> {
    let mut fields = [0u8; REQUEST_MAX];
    let fields_len = encode_get(&mut fields, name, cpu, target)?;
    let mut encoder = super::cbor::Encoder::new(out);
    encoder.map(4)?;
    encoder.uint(1)?;
    encoder.uint(OBJECT_COMPONENT)?;
    encoder.uint(2)?;
    encoder.uint(OBJECT_GET_METHOD)?;
    encoder.uint(3)?;
    encoder.uint(id)?;
    encoder.uint(5)?;
    encoder.encoded_value(&fields[..fields_len])?;
    Some(encoder.len())
}

/// Decode a complete tagged object GET request. Routing must be resolved
/// before the local object store is invoked.
pub fn decode_get_request(input: &[u8]) -> Option<(u64, GetRequest<'_>)> {
    let record = super::tagged::decode(input)?;
    if record.component != Some(super::tagged::Name::Tag(OBJECT_COMPONENT))
        || record.method != Some(super::tagged::Name::Tag(OBJECT_GET_METHOD))
        || record.to.is_some()
        || record.params.is_some()
        || record.data.is_some()
        || record.result.is_some()
        || record.error.is_some()
    {
        return None;
    }
    Some((record.id?, decode_get(record.fields?)?))
}

/// One contiguous chunk in the ordered object-response stream.
///
/// The five-byte record header is part of the stream.  This is deliberately
/// below UDP, UART, ESP-NOW/action, and any future bearer: the transport owns
/// packetisation, ACKs, loss recovery, and flow control, while this type owns
/// only the canonical record order and stream offsets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectStreamChunk {
    pub offset: u64,
    pub len: usize,
    pub fin: bool,
    pub record_index: usize,
}

/// Turn materialised object records into bounded chunks of one ordered stream.
///
/// A packet never crosses a record boundary. This preserves the existing
/// manifest-before-blob admission barrier while allowing the transport to fill
/// its congestion/credit window with consecutive blob chunks. `out` is owned
/// by the bearer adapter, so this core helper neither allocates per packet nor
/// knows which bearer will transmit the result.
#[derive(Clone)]
pub struct ObjectBodyStream {
    records: Vec<(u8, Vec<u8>)>,
    record_index: usize,
    record_offset: usize,
    stream_offset: u64,
    sent_bytes: usize,
    /// New wire format: exactly one CBOR manifest followed by raw body bytes.
    /// The legacy record vector remains temporarily accepted by `new` so
    /// downstream tests can be migrated independently; production uses this
    /// flat entry point.
    flat: Option<Vec<u8>>,
}

impl ObjectBodyStream {
    pub fn new(records: Vec<(u8, Vec<u8>)>) -> Self {
        Self {
            records,
            record_index: 0,
            record_offset: 0,
            stream_offset: 0,
            sent_bytes: 0,
            flat: None,
        }
    }

    pub fn from_object(manifest: Vec<u8>, body: Vec<u8>) -> Self {
        let mut bytes = Vec::with_capacity(manifest.len().saturating_add(body.len()));
        bytes.extend_from_slice(&manifest);
        bytes.extend_from_slice(&body);
        Self {
            records: Vec::new(),
            record_index: 0,
            record_offset: 0,
            stream_offset: 0,
            sent_bytes: 0,
            flat: Some(bytes),
        }
    }

    pub fn is_complete(&self) -> bool {
        self.flat
            .as_ref()
            .map_or(self.record_index == self.records.len(), |bytes| {
                self.sent_bytes == bytes.len()
            })
    }

    pub fn sent_bytes(&self) -> usize {
        self.sent_bytes
    }

    pub fn record_index(&self) -> usize {
        self.record_index
    }

    /// Copy the next bounded ordered chunk into `out` without advancing.
    ///
    /// A bearer must call [`Self::advance`] only after quic-lite accepted the
    /// resulting packet. That distinction prevents a congestion/credit
    /// rejection from skipping object bytes. A zero-sized output is never a
    /// valid transport packet and returns `None` without changing state.
    pub fn copy_next(&self, out: &mut [u8]) -> Option<ObjectStreamChunk> {
        if out.is_empty() || self.is_complete() {
            return None;
        }
        if let Some(bytes) = self.flat.as_ref() {
            let remaining = &bytes[self.sent_bytes..];
            let len = out.len().min(remaining.len());
            out[..len].copy_from_slice(&remaining[..len]);
            return Some(ObjectStreamChunk {
                offset: self.stream_offset,
                len,
                fin: len == remaining.len(),
                record_index: 0,
            });
        }
        let (kind, body) = self.records.get(self.record_index)?;
        let record_len = body.len().checked_add(5)?;
        if self.record_offset >= record_len {
            return None;
        }
        let len = out.len().min(record_len - self.record_offset);
        for (index, destination) in out[..len].iter_mut().enumerate() {
            let position = self.record_offset + index;
            *destination = match position {
                0 => *kind,
                1..=4 => (body.len() as u32).to_be_bytes()[position - 1],
                _ => body[position - 5],
            };
        }
        let offset = self.stream_offset;
        let completed_record = self.record_offset + len == record_len;
        let fin = completed_record && *kind == RECORD_DONE;
        Some(ObjectStreamChunk {
            offset,
            len,
            fin,
            record_index: self.record_index,
        })
    }

    /// Commit exactly the preceding [`Self::copy_next`] result after the
    /// transport has accepted it for transmission.
    pub fn advance(&mut self, chunk: ObjectStreamChunk) -> bool {
        if let Some(bytes) = self.flat.as_ref() {
            let remaining = bytes.len().saturating_sub(self.sent_bytes);
            if chunk.offset != self.stream_offset
                || chunk.record_index != 0
                || chunk.len == 0
                || chunk.len > remaining
                || chunk.fin != (chunk.len == remaining)
            {
                return false;
            }
            self.stream_offset = self.stream_offset.saturating_add(chunk.len as u64);
            self.sent_bytes += chunk.len;
            return true;
        }
        let Some(expected) = self.copy_next(&mut [0u8; 1]) else {
            return false;
        };
        // The one-byte probe above deliberately verifies only the current
        // record/offset. Its length differs for larger caller buffers, so
        // validate the stable fields and calculate the remaining bound here.
        if chunk.offset != expected.offset || chunk.record_index != expected.record_index {
            return false;
        }
        let Some((kind, body)) = self.records.get(self.record_index) else {
            return false;
        };
        let remaining = body
            .len()
            .saturating_add(5)
            .saturating_sub(self.record_offset);
        if chunk.len == 0 || chunk.len > remaining {
            return false;
        }
        let completes = chunk.len == remaining;
        if chunk.fin != (completes && *kind == RECORD_DONE) {
            return false;
        }
        self.record_offset += chunk.len;
        self.stream_offset = self.stream_offset.saturating_add(chunk.len as u64);
        self.sent_bytes = self.sent_bytes.saturating_add(chunk.len);
        if completes {
            self.record_index += 1;
            self.record_offset = 0;
        }
        true
    }

    /// Copy and advance the next bounded ordered chunk. This convenience is
    /// suitable for deterministic in-process links; real bearer adapters use
    /// `copy_next`/`advance` around their transport admission call.
    pub fn next_chunk(&mut self, out: &mut [u8]) -> Option<ObjectStreamChunk> {
        let chunk = self.copy_next(out)?;
        self.advance(chunk).then_some(chunk)
    }
}

#[cfg(test)]
type ObjectRecordStream = ObjectBodyStream;

/// Byte-record extraction over an already ordered transport stream. The
/// transport owns packet reassembly and flow control; this only handles the
/// object stream's five-byte `(kind, length)` record prefix.
pub struct RecordBuffer {
    data: Vec<u8>,
}

/// A bounded incremental decoder for an already ordered object stream.
///
/// Unlike `RecordBuffer`, this never grows, allocates a completed record, or
/// shifts following bytes. Callers select explicit manifest and blob bounds;
/// that makes it suitable for firmware where blobs are fixed 4 KiB image
/// blocks and the manifest is the only variable-size record.
pub trait RecordEvents {
    type Error;
    /// Bytes copied into handler-owned storage. This is deliberately distinct
    /// from record completion: a manifest can be consumed into its bounded
    /// parser buffer incrementally while QUIC retains only its small sliding
    /// receive window.
    fn consumed(&mut self, _kind: u8, _bytes: usize) -> Result<(), Self::Error> {
        Ok(())
    }
    fn record(&mut self, kind: u8, payload: &[u8]) -> Result<(), Self::Error>;
}

/// Ordered bytes supplied by a transport-owned stream reader.
///
/// Object verification deliberately depends on this small read boundary rather
/// than a transport's packet/chunk representation.  A QUIC adapter retains
/// out-of-order packets and returns flow credit only for bytes read here; the
/// object handler sees neither packet ownership nor a receive window.
pub trait OrderedStreamRead {
    /// Copy the next ordered prefix into `out`, returning zero only when no
    /// committed bytes are currently available.
    fn read(&mut self, out: &mut [u8]) -> usize;

    /// True once the reader has consumed through the peer's stream FIN.
    fn is_finished(&self) -> bool {
        false
    }
}

/// An in-memory implementation of [`OrderedStreamRead`] for a currently
/// borrowed ordered prefix. It is useful to synchronous handlers on both host
/// and firmware: the transport retains any unread suffix and decides credit.
pub struct BorrowedOrderedRead<'a> {
    bytes: &'a [u8],
    used: usize,
    fin: bool,
}

impl<'a> BorrowedOrderedRead<'a> {
    pub const fn new(bytes: &'a [u8], fin: bool) -> Self {
        Self {
            bytes,
            used: 0,
            fin,
        }
    }

    pub const fn consumed(&self) -> usize {
        self.used
    }
}

impl OrderedStreamRead for BorrowedOrderedRead<'_> {
    fn read(&mut self, out: &mut [u8]) -> usize {
        let len = out.len().min(self.bytes.len().saturating_sub(self.used));
        out[..len].copy_from_slice(&self.bytes[self.used..self.used + len]);
        self.used += len;
        len
    }

    fn is_finished(&self) -> bool {
        self.fin && self.used == self.bytes.len()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedRecordError<E> {
    Invalid,
    Callback(E),
}

pub struct FixedRecordDecoder<const MAX_MANIFEST: usize, const MAX_BLOB: usize> {
    header: [u8; 5],
    header_len: usize,
    kind: u8,
    expected: usize,
    used: usize,
    manifest: [u8; MAX_MANIFEST],
    blob: [u8; MAX_BLOB],
}

impl<const MAX_MANIFEST: usize, const MAX_BLOB: usize> FixedRecordDecoder<MAX_MANIFEST, MAX_BLOB> {
    pub const fn new() -> Self {
        Self {
            header: [0; 5],
            header_len: 0,
            kind: 0,
            expected: 0,
            used: 0,
            manifest: [0; MAX_MANIFEST],
            blob: [0; MAX_BLOB],
        }
    }

    pub const fn at_record_boundary(&self) -> bool {
        self.header_len == 0
    }

    pub fn push<E: RecordEvents>(
        &mut self,
        mut input: &[u8],
        events: &mut E,
    ) -> Result<usize, FixedRecordError<E::Error>> {
        let mut consumed = 0usize;
        while !input.is_empty() {
            if self.header_len < self.header.len() {
                let copied = (self.header.len() - self.header_len).min(input.len());
                self.header[self.header_len..self.header_len + copied]
                    .copy_from_slice(&input[..copied]);
                self.header_len += copied;
                input = &input[copied..];
                consumed = consumed.saturating_add(copied);
                if self.header_len < self.header.len() {
                    continue;
                }
                self.kind = self.header[0];
                self.expected = u32::from_be_bytes(self.header[1..5].try_into().unwrap()) as usize;
                self.used = 0;
                let max = match self.kind {
                    RECORD_MANIFEST => MAX_MANIFEST,
                    RECORD_BLOB => MAX_BLOB,
                    RECORD_DONE => 0,
                    _ => return Err(FixedRecordError::Invalid),
                };
                if self.expected > max {
                    return Err(FixedRecordError::Invalid);
                }
                events
                    .consumed(self.kind, self.header.len())
                    .map_err(FixedRecordError::Callback)?;
                if self.expected == 0 {
                    if self.kind != RECORD_DONE {
                        return Err(FixedRecordError::Invalid);
                    }
                    events
                        .record(self.kind, &[])
                        .map_err(FixedRecordError::Callback)?;
                    self.header_len = 0;
                    // A receiver may need to start durable work after a
                    // complete record (notably manifest-triggered erase)
                    // before admitting the following record.  Stop exactly
                    // at this record boundary; the caller retains any tail
                    // and QUIC returns credit only for `consumed` bytes.
                    return Ok(consumed);
                }
                continue;
            }

            let copied = (self.expected - self.used).min(input.len());
            let dst = match self.kind {
                RECORD_MANIFEST => &mut self.manifest[self.used..self.used + copied],
                RECORD_BLOB => &mut self.blob[self.used..self.used + copied],
                _ => return Err(FixedRecordError::Invalid),
            };
            dst.copy_from_slice(&input[..copied]);
            self.used += copied;
            input = &input[copied..];
            consumed = consumed.saturating_add(copied);
            events
                .consumed(self.kind, copied)
                .map_err(FixedRecordError::Callback)?;
            if self.used == self.expected {
                let payload = match self.kind {
                    RECORD_MANIFEST => &self.manifest[..self.expected],
                    RECORD_BLOB => &self.blob[..self.expected],
                    _ => return Err(FixedRecordError::Invalid),
                };
                events
                    .record(self.kind, payload)
                    .map_err(FixedRecordError::Callback)?;
                self.header_len = 0;
                // See the zero-length DONE branch above.  One record per
                // callback is a storage boundary, not a transport policy.
                return Ok(consumed);
            }
        }
        Ok(consumed)
    }

    /// Read exactly the next available ordered prefix, stopping after one
    /// completed record.  The destination is this decoder's bounded header,
    /// manifest, or blob storage, so callers never retain a QUIC packet or
    /// need to know how transport chunks were divided.
    pub fn read_one<R: OrderedStreamRead, E: RecordEvents>(
        &mut self,
        reader: &mut R,
        events: &mut E,
    ) -> Result<usize, FixedRecordError<E::Error>> {
        let mut consumed = 0usize;
        loop {
            if self.header_len < self.header.len() {
                let copied = reader.read(&mut self.header[self.header_len..]);
                if copied == 0 {
                    return Ok(consumed);
                }
                self.header_len += copied;
                consumed = consumed.saturating_add(copied);
                if self.header_len < self.header.len() {
                    continue;
                }
                self.kind = self.header[0];
                self.expected = u32::from_be_bytes(self.header[1..5].try_into().unwrap()) as usize;
                self.used = 0;
                let max = match self.kind {
                    RECORD_MANIFEST => MAX_MANIFEST,
                    RECORD_BLOB => MAX_BLOB,
                    RECORD_DONE => 0,
                    _ => return Err(FixedRecordError::Invalid),
                };
                if self.expected > max {
                    return Err(FixedRecordError::Invalid);
                }
                events
                    .consumed(self.kind, self.header.len())
                    .map_err(FixedRecordError::Callback)?;
                if self.expected == 0 {
                    if self.kind != RECORD_DONE {
                        return Err(FixedRecordError::Invalid);
                    }
                    events
                        .record(self.kind, &[])
                        .map_err(FixedRecordError::Callback)?;
                    self.header_len = 0;
                    return Ok(consumed);
                }
            }

            let destination = match self.kind {
                RECORD_MANIFEST => &mut self.manifest[self.used..self.expected],
                RECORD_BLOB => &mut self.blob[self.used..self.expected],
                _ => return Err(FixedRecordError::Invalid),
            };
            let copied = reader.read(destination);
            if copied == 0 {
                return Ok(consumed);
            }
            self.used += copied;
            consumed = consumed.saturating_add(copied);
            events
                .consumed(self.kind, copied)
                .map_err(FixedRecordError::Callback)?;
            if self.used == self.expected {
                let payload = match self.kind {
                    RECORD_MANIFEST => &self.manifest[..self.expected],
                    RECORD_BLOB => &self.blob[..self.expected],
                    _ => return Err(FixedRecordError::Invalid),
                };
                events
                    .record(self.kind, payload)
                    .map_err(FixedRecordError::Callback)?;
                self.header_len = 0;
                return Ok(consumed);
            }
        }
    }
}

impl RecordBuffer {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }
    pub fn push(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }
    pub fn next(&mut self) -> Option<(u8, Vec<u8>)> {
        if self.data.len() < 5 {
            return None;
        }
        let kind = self.data[0];
        let len = u32::from_be_bytes(self.data[1..5].try_into().ok()?) as usize;
        if len > MAX_RECORD || self.data.len() < 5 + len {
            return None;
        }
        let body = self.data[5..5 + len].to_vec();
        self.data.drain(..5 + len);
        Some((kind, body))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GetRequest<'a> {
    pub name: Option<&'a [u8]>,
    pub cpu: u8,
    pub target: u8,
}

/// Bearer-neutral request to fetch a signed object and install it through an
/// application-provided sink.  The caller selects the object by the same
/// `(name, cpu, target)` tuple used by [`GetRequest`]; transport selection and
/// dry-run are execution policy, not object-store metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlashRequest<'a> {
    pub object: GetRequest<'a>,
    pub address: Option<u32>,
    /// `0` lets the active connection select a path. Other values are a
    /// handler-defined path preference, never a bearer-specific wire format.
    pub transport: u8,
    pub dry_run: bool,
}

/// Canonically encode the `flash` handler body.  Field keys are shared by
/// Recovery, Main, host tests, and future Android clients: 0=name, 1=cpu,
/// 2=target, 3=address, 4=transport, 5=dry_run.
pub fn encode_flash_request(request: FlashRequest<'_>, out: &mut [u8]) -> Option<usize> {
    if request.object.target == 0 {
        return None;
    }
    let mut encoder = super::cbor::Encoder::new(out);
    let fields =
        4 + usize::from(request.object.name.is_some()) + usize::from(request.address.is_some());
    encoder.map(fields as u64)?;
    if let Some(name) = request.object.name {
        encoder.uint(0)?;
        encoder.bytes_value(name)?;
    }
    encoder.uint(1)?;
    encoder.uint(u64::from(request.object.cpu))?;
    encoder.uint(2)?;
    encoder.uint(u64::from(request.object.target))?;
    if let Some(address) = request.address {
        encoder.uint(3)?;
        encoder.uint(u64::from(address))?;
    }
    encoder.uint(4)?;
    encoder.uint(u64::from(request.transport))?;
    encoder.uint(5)?;
    encoder.boolean(request.dry_run)?;
    Some(encoder.len())
}

/// Encode a correlated flash handler request on the normal QUIC stream plane.
pub fn encode_flash_handler_request(
    request: FlashRequest<'_>,
    id: u64,
    out: &mut [u8],
) -> Option<usize> {
    let mut fields = [0u8; REQUEST_MAX];
    let fields_len = encode_flash_request(request, &mut fields)?;
    let mut encoder = super::cbor::Encoder::new(out);
    encoder.map(4)?;
    encoder.uint(1)?;
    encoder.uint(OBJECT_COMPONENT)?;
    encoder.uint(2)?;
    encoder.uint(OBJECT_FLASH_METHOD)?;
    encoder.uint(3)?;
    encoder.uint(id)?;
    encoder.uint(5)?;
    encoder.encoded_value(&fields[..fields_len])?;
    Some(encoder.len())
}

pub fn decode_flash_handler_request(input: &[u8]) -> Option<(u64, FlashRequest<'_>)> {
    let record = super::tagged::decode(input)?;
    if record.component != Some(super::tagged::Name::Tag(OBJECT_COMPONENT))
        || record.method != Some(super::tagged::Name::Tag(OBJECT_FLASH_METHOD))
        || record.to.is_some()
        || record.params.is_some()
        || record.data.is_some()
        || record.result.is_some()
        || record.error.is_some()
    {
        return None;
    }
    Some((record.id?, decode_flash_request(record.fields?)?))
}

/// Decode a correlated `object.flash` application error. Transport clients
/// use this after QUIC has delivered the terminal response; no handler error
/// is inferred from ACK, CLOSE, timeout, or bearer state.
pub fn decode_flash_handler_error(input: &[u8]) -> Option<&[u8]> {
    let record = super::tagged::decode(input)?;
    if record.component != Some(super::tagged::Name::Tag(OBJECT_COMPONENT))
        || record.method != Some(super::tagged::Name::Tag(OBJECT_FLASH_METHOD))
        || record.result.is_some()
    {
        return None;
    }
    let mut decoder = super::cbor::Decoder::new(record.error?);
    let error = decoder.text_ref()?;
    decoder.is_finished().then_some(error)
}

/// Decode a complete canonical `flash` handler body. Duplicate, unknown, or
/// trailing fields are rejected before a platform sink can erase anything.
pub fn decode_flash_request(input: &[u8]) -> Option<FlashRequest<'_>> {
    let mut d = Decoder::new(input);
    let (major, count) = d.head()?;
    // `transport=0` (automatic/default bearer selection) and `dry_run=false`
    // are operator-facing defaults.  Keep the canonical encoder explicit,
    // but accept their omission so a normal `object.flash cpu=N target=N`
    // command has the same meaning on every client and device.
    if major != 5 || !(2..=6).contains(&count) {
        return None;
    }
    let mut name = None;
    let mut cpu = None;
    let mut target = None;
    let mut address = None;
    let mut transport = None;
    let mut dry_run = None;
    let mut seen = 0u8;
    for _ in 0..count {
        let key = d.uint()?;
        let bit = 1u8.checked_shl(key as u32)?;
        if key > 5 || seen & bit != 0 {
            return None;
        }
        seen |= bit;
        match key {
            0 => name = Some(d.bytes_or_text_ref()?),
            1 => cpu = Some(d.uint()?.try_into().ok()?),
            2 => target = Some(d.uint()?.try_into().ok()?),
            3 => address = Some(d.uint()?.try_into().ok()?),
            4 => transport = Some(d.uint()?.try_into().ok()?),
            5 => dry_run = Some(d.boolean()?),
            _ => return None,
        }
    }
    Some(FlashRequest {
        object: GetRequest {
            name,
            cpu: cpu?,
            target: target.filter(|target| *target != 0)?,
        },
        address,
        transport: transport.unwrap_or(0),
        dry_run: dry_run.unwrap_or(false),
    })
    .filter(|_| d.is_finished())
}

/// Decode the compact CBOR GET map. Numeric keys are 0=name, 1=cpu,
/// 2=target. Values are byte strings and unsigned integers; no text or UTF-8
/// is involved.
pub fn decode_get(input: &[u8]) -> Option<GetRequest<'_>> {
    let mut d = Decoder::new(input);
    let (major, count) = d.head()?;
    if major != 5 || count > 3 {
        return None;
    }
    let mut request = GetRequest {
        name: None,
        cpu: 0,
        target: 0,
    };
    let mut seen = 0u8;
    for _ in 0..count {
        let key = d.uint()?;
        match key {
            0 => {
                if seen & 1 != 0 {
                    return None;
                }
                seen |= 1;
                request.name = Some(d.bytes_or_text_ref()?);
            }
            1 => {
                if seen & 2 != 0 {
                    return None;
                }
                seen |= 2;
                request.cpu = d.uint()?.try_into().ok()?;
            }
            2 => {
                if seen & 4 != 0 {
                    return None;
                }
                seen |= 4;
                request.target = d.uint()?.try_into().ok()?;
            }
            _ => return None,
        }
    }
    (request.target != 0 && d.is_finished()).then_some(request)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectTarget {
    Module,
}

impl ObjectTarget {
    fn from_wire(v: u8) -> Result<Self, Error> {
        if v == 7 {
            Ok(Self::Module)
        } else {
            Err(Error::UnsupportedTarget)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Manifest {
    pub target: ObjectTarget,
    pub size: u64,
    pub block_size: u16,
    pub block_count: u32,
    pub sha256: [u8; 32],
    pub name: [u8; 32],
    pub name_len: u8,
}

impl Manifest {
    /// Compact signed-object metadata. Signature bytes remain outside this
    /// parser and are verified by the platform policy before `begin`.
    pub const WIRE_LEN: usize = 4 + 1 + 2 + 8 + 4 + 32 + 1 + 32;

    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() < Self::WIRE_LEN {
            return Err(Error::Truncated);
        }
        if u32::from_be_bytes(input[0..4].try_into().unwrap()) != IMAGE_MAGIC {
            return Err(Error::BadMagic);
        }
        let target = ObjectTarget::from_wire(input[4])?;
        let block_size = u16::from_be_bytes(input[5..7].try_into().unwrap());
        if block_size == 0 || block_size as usize > BLOCK_SIZE {
            return Err(Error::InvalidManifest);
        }
        let size = u64::from_be_bytes(input[7..15].try_into().unwrap());
        let block_count = u32::from_be_bytes(input[15..19].try_into().unwrap());
        if block_count == 0
            || block_count as u64 > (size + block_size as u64 - 1) / block_size as u64
        {
            return Err(Error::InvalidManifest);
        }
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&input[19..51]);
        let name_len = input[51];
        if name_len > 32 {
            return Err(Error::InvalidManifest);
        }
        let mut name = [0u8; 32];
        name.copy_from_slice(&input[52..84]);
        Ok(Self {
            target,
            size,
            block_size,
            block_count,
            sha256,
            name,
            name_len,
        })
    }
}

pub trait ObjectSink {
    type Error;
    fn begin(&mut self, manifest: &Manifest) -> Result<(), Self::Error>;
    fn write_block(&mut self, index: u32, offset: u64, data: &[u8]) -> Result<(), Self::Error>;
    fn finish(&mut self, manifest: &Manifest) -> Result<(), Self::Error>;
    fn abort(&mut self);
}

pub trait SignatureVerifier {
    fn verify(&self, manifest_bytes: &[u8], signature: &[u8]) -> bool;
}

pub struct NoSignatureVerifier;

impl SignatureVerifier for NoSignatureVerifier {
    fn verify(&self, _manifest_bytes: &[u8], _signature: &[u8]) -> bool {
        false
    }
}

/// The DRS2 image wire format used by the host UDP object sender.
///
/// This is deliberately separate from the older module-object format above:
/// Main/Recovery images carry a compact versioned header followed by blocks,
/// while module objects carry a named manifest.  Both receivers are bearer
/// independent and therefore usable from `no_std` firmware and host tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageManifest {
    pub target: u8,
    /// CPU family selected by the host artifact catalog. This is part of the
    /// immutable manifest so a receiver can reject a valid-but-wrong-family
    /// ESP image before it erases its destination partition.
    pub cpu: u8,
    pub version: u8,
    pub block_size: u32,
    pub block_count: u32,
    pub image_size: u32,
    pub image_sha256: [u8; 32],
    pub block_digests: Vec<[u8; BLOCK_DIGEST_BYTES]>,
    pub signature: Option<Vec<u8>>,
}

impl ImageManifest {
    pub const HEADER_LEN: usize = 20;

    pub fn decode(input: &[u8]) -> Result<Self, ImageError> {
        let (manifest, used) = Self::decode_prefix(input)?;
        if used != input.len() {
            return Err(ImageError::InvalidManifest);
        }
        Ok(manifest)
    }

    /// Decode the first complete CBOR value and return its exact boundary.
    /// Bytes after that boundary are the raw immutable-object body.
    pub fn decode_prefix(input: &[u8]) -> Result<(Self, usize), ImageError> {
        let mut decoder = Decoder::new(input);
        let (major, count) = decoder.head().ok_or(ImageError::Truncated)?;
        if major != 5 {
            return Err(ImageError::InvalidManifest);
        }
        let mut target = None;
        let mut cpu = None;
        let mut version = None;
        let mut block_size = 0u32;
        let mut block_count = 0u32;
        let mut image_size = 0u32;
        let mut image_sha256 = None;
        let mut block_digest_bytes = None;
        let mut signature = None;
        let mut seen = 0u16;
        for _ in 0..count {
            let key = decoder.uint().ok_or(ImageError::Truncated)?;
            match key {
                0 => {
                    if seen & 1 != 0 {
                        return Err(ImageError::InvalidManifest);
                    }
                    seen |= 1;
                    target = Some(
                        decoder
                            .uint()
                            .ok_or(ImageError::Truncated)?
                            .try_into()
                            .map_err(|_| ImageError::InvalidManifest)?,
                    );
                }
                1 => {
                    if seen & 2 != 0 {
                        return Err(ImageError::InvalidManifest);
                    }
                    seen |= 2;
                    version = Some(
                        decoder
                            .uint()
                            .ok_or(ImageError::Truncated)?
                            .try_into()
                            .map_err(|_| ImageError::InvalidManifest)?,
                    );
                }
                8 => {
                    if seen & 256 != 0 {
                        return Err(ImageError::InvalidManifest);
                    }
                    seen |= 256;
                    cpu = Some(
                        decoder
                            .uint()
                            .ok_or(ImageError::Truncated)?
                            .try_into()
                            .map_err(|_| ImageError::InvalidManifest)?,
                    );
                }
                2 => {
                    if seen & 4 != 0 {
                        return Err(ImageError::InvalidManifest);
                    }
                    seen |= 4;
                    block_size = decoder
                        .uint()
                        .ok_or(ImageError::Truncated)?
                        .try_into()
                        .map_err(|_| ImageError::InvalidManifest)?;
                }
                3 => {
                    if seen & 8 != 0 {
                        return Err(ImageError::InvalidManifest);
                    }
                    seen |= 8;
                    block_count = decoder
                        .uint()
                        .ok_or(ImageError::Truncated)?
                        .try_into()
                        .map_err(|_| ImageError::InvalidManifest)?;
                }
                4 => {
                    if seen & 16 != 0 {
                        return Err(ImageError::InvalidManifest);
                    }
                    seen |= 16;
                    image_size = decoder
                        .uint()
                        .ok_or(ImageError::Truncated)?
                        .try_into()
                        .map_err(|_| ImageError::InvalidManifest)?;
                }
                5 => {
                    if seen & 32 != 0 {
                        return Err(ImageError::InvalidManifest);
                    }
                    seen |= 32;
                    let bytes = decoder.bytes_ref().ok_or(ImageError::Truncated)?;
                    if bytes.len() != 32 {
                        return Err(ImageError::InvalidManifest);
                    }
                    let mut digest = [0u8; 32];
                    digest.copy_from_slice(bytes);
                    image_sha256 = Some(digest);
                }
                6 => {
                    if seen & 64 != 0 {
                        return Err(ImageError::InvalidManifest);
                    }
                    seen |= 64;
                    let bytes = decoder.bytes_ref().ok_or(ImageError::Truncated)?;
                    if bytes.len() % BLOCK_DIGEST_BYTES != 0 {
                        return Err(ImageError::InvalidManifest);
                    }
                    block_digest_bytes = Some(bytes);
                }
                7 => {
                    if seen & 128 != 0 {
                        return Err(ImageError::InvalidManifest);
                    }
                    seen |= 128;
                    let bytes = decoder.bytes_ref().ok_or(ImageError::Truncated)?;
                    if bytes.len() > 256 {
                        return Err(ImageError::InvalidManifest);
                    }
                    signature = Some(bytes.to_vec());
                }
                _ => decoder.skip().ok_or(ImageError::Truncated)?,
            }
        }
        let used = decoder.position();
        // Field 6 is one flat byte string in the sole current wire format.
        // Retaining just the fixed-width values avoids both CBOR wrapper
        // overhead and a variable number of nested decoder states.
        if version != Some(VERIFIED_OBJECT_VERSION) {
            return Err(ImageError::InvalidManifest);
        }
        let bytes = block_digest_bytes.ok_or(ImageError::InvalidManifest)?;
        let expected_digest_bytes = usize::try_from(block_count)
            .ok()
            .and_then(|count| count.checked_mul(BLOCK_DIGEST_BYTES))
            .ok_or(ImageError::InvalidManifest)?;
        if bytes.len() != expected_digest_bytes {
            return Err(ImageError::InvalidManifest);
        }
        let mut block_digests = Vec::new();
        block_digests
            .try_reserve_exact(block_count as usize)
            // A syntactically valid manifest can still be too large for the
            // receiver's current application heap.  Preserve that distinction
            // for the caller: `InvalidManifest` means reject the wire object,
            // while `Allocation` lets a constrained device report ordinary
            // local resource exhaustion without blaming the sender's bytes.
            .map_err(|_| ImageError::Allocation)?;
        for bytes in bytes.chunks_exact(BLOCK_DIGEST_BYTES) {
            let mut digest = [0u8; BLOCK_DIGEST_BYTES];
            digest.copy_from_slice(bytes);
            block_digests.push(digest);
        }
        let manifest = Self {
            target: target.ok_or(ImageError::InvalidManifest)?,
            cpu: cpu.ok_or(ImageError::InvalidManifest)?,
            version: version.ok_or(ImageError::InvalidManifest)?,
            block_size,
            block_count,
            image_size,
            image_sha256: image_sha256.ok_or(ImageError::InvalidManifest)?,
            block_digests,
            signature,
        };
        if manifest.version != VERIFIED_OBJECT_VERSION
            || manifest.block_size == 0
            || manifest.block_count == 0
            || manifest.block_count as u64
                != (manifest.image_size as u64 + manifest.block_size as u64 - 1)
                    / manifest.block_size as u64
            || manifest.block_digests.len() != manifest.block_count as usize
        {
            return Err(ImageError::InvalidManifest);
        }
        Ok((manifest, used))
    }
}

pub trait ImageSink {
    type Error;
    fn begin(&mut self, manifest: &ImageManifest) -> Result<(), Self::Error>;
    fn write_block(&mut self, index: u32, data: &[u8]) -> Result<(), Self::Error>;
    fn finish(&mut self, manifest: &ImageManifest) -> Result<(), Self::Error>;
    fn abort(&mut self);
}

/// Incremental storage lifecycle used by a streamed verified-object consumer.
///
/// Flash, disk, RAM, and delayed probe sinks implement this same interface.
/// QUIC is deliberately absent: ordered bytes have been copied out of its
/// receive buffers before this sink is called, so QUIC credits them through
/// its ordinary stream-consumption API.
/// Result of an ordinary asynchronous-storage poll.
///
/// This is deliberately application state rather than a transport signal. A
/// [`Pending`] result merely means that a following call to the record reader
/// must leave its ordered bytes unread; QUIC observes only bytes actually
/// copied through that reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoragePoll {
    Ready,
    Pending,
}

pub trait StreamingImageSink: ImageSink {
    /// Poll asynchronous storage completion and report whether the sink can
    /// accept the next complete record. Storage availability is handler state;
    /// it must never be converted into a QUIC receive-window value.
    fn poll_completed(&mut self) -> Result<StoragePoll, Self::Error>;

    /// Allow storage work such as an erase to start before a transport poll.
    fn poll_before_transport(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Apply one complete signed-object record sequence to an arbitrary sink.
///
/// Host and firmware clients use this same manifest/signature/block validation
/// path; only the sink differs (a host file versus an ESP partition writer).
/// Transport code is responsible for feeding complete ordered records and for
/// returning its own stream credit after a sink has reclaimed storage.
pub fn apply_signed_object_records<S, V>(
    receiver: &mut ImageReceiver<S, V>,
    records: &[(u8, Vec<u8>)],
) -> Result<ImageEvent, ImageError>
where
    S: ImageSink,
    V: SignatureVerifier,
{
    let mut complete = None;
    for (kind, payload) in records {
        let event = match *kind {
            RECORD_MANIFEST => receiver.on_manifest(payload)?,
            RECORD_BLOB => receiver.on_block(payload)?,
            RECORD_DONE => receiver.on_done()?,
            _ => return Err(ImageError::InvalidBlock),
        };
        if matches!(event, ImageEvent::Complete) {
            complete = Some(event);
        }
    }
    complete.ok_or(ImageError::InvalidManifest)
}

/// Incremental, bearer-neutral consumer for a `signed_object` response.
///
/// QUIC-lite (or any later transport) has already put bytes in stream order
/// before calling [`Self::push_ordered`].  This type owns only record framing
/// and object verification: it does not retain packet history, select a
/// bearer, or return transport credit.  The same client therefore works with
/// an ESP partition sink and the host file sink.
pub struct SignedObjectReceiver<S, V, const MAX_MANIFEST: usize, const MAX_BLOB: usize> {
    // A manifest is immutable-object metadata, not a permanently resident
    // packet buffer.  Keep only the bytes actually received, with fallible
    // bounded growth, so a small image does not reserve the worst-case
    // 4-MiB-image digest table for the lifetime of every flash receiver.
    manifest_bytes: Vec<u8>,
    manifest_used: usize,
    prefetched_body_offset: usize,
    block: [u8; MAX_BLOB],
    block_used: usize,
    image: ImageReceiver<S, V>,
    complete: bool,
}

/// Result of reading one verified-object record from an ordered stream.
///
/// The reader owns transport buffering and reports consumed bytes to its
/// dispatcher.  This remains object framing only: the same receiver is used
/// by host file tests, Main, and Recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectStreamRead {
    pub application_progress: bool,
    pub consumed_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoxedReceiverError<E> {
    Allocation,
    Sink(E),
}

impl<S, const MAX_MANIFEST: usize, const MAX_BLOB: usize>
    SignedObjectReceiver<S, NoSignatureVerifier, MAX_MANIFEST, MAX_BLOB>
{
    pub const fn new(sink: S) -> Self {
        Self {
            manifest_bytes: Vec::new(),
            manifest_used: 0,
            prefetched_body_offset: 0,
            block: [0; MAX_BLOB],
            block_used: 0,
            image: ImageReceiver::new(sink),
            complete: false,
        }
    }

    /// Initialize a receiver in caller-owned storage without materializing
    /// its bounded manifest/blob buffers on the current stack. Firmware uses
    /// this when a flash command is received from a small packet task.
    pub fn new_in_place(storage: &mut core::mem::MaybeUninit<Self>, sink: S) -> &mut Self {
        unsafe {
            let receiver = storage.as_mut_ptr();
            core::ptr::addr_of_mut!((*receiver).manifest_bytes).write(Vec::new());
            core::ptr::addr_of_mut!((*receiver).manifest_used).write(0);
            core::ptr::addr_of_mut!((*receiver).prefetched_body_offset).write(0);
            core::ptr::write_bytes(core::ptr::addr_of_mut!((*receiver).block), 0, 1);
            core::ptr::addr_of_mut!((*receiver).block_used).write(0);
            core::ptr::addr_of_mut!((*receiver).image).write(ImageReceiver::new(sink));
            core::ptr::addr_of_mut!((*receiver).complete).write(false);
            storage.assume_init_mut()
        }
    }

    /// Fallibly allocate the receiver in its final heap location and
    /// initialize its bounded parser buffers in place. Host and firmware use
    /// this same ordinary allocator path; allocation failure is returned to
    /// the application instead of invoking the global OOM handler.
    pub fn try_new_boxed(sink: S) -> Result<Box<Self>, ()> {
        Self::try_new_boxed_with(|| Ok::<_, core::convert::Infallible>(sink)).map_err(|_| ())
    }

    /// Allocate parser/manifest storage before constructing a platform sink.
    ///
    /// A firmware sink may create a task, queues, or file/partition handles.
    /// Deferring that work until the largest allocation succeeds prevents a
    /// rejected request from leaking platform resources. It also lets the sink
    /// choose its dynamic storage window from the post-receiver heap.
    pub fn try_new_boxed_with<E>(
        sink: impl FnOnce() -> Result<S, E>,
    ) -> Result<Box<Self>, BoxedReceiverError<E>> {
        let mut allocation = Vec::<core::mem::MaybeUninit<Self>>::new();
        allocation
            .try_reserve_exact(1)
            .map_err(|_| BoxedReceiverError::Allocation)?;
        allocation.push(core::mem::MaybeUninit::uninit());
        let mut allocation = allocation.into_boxed_slice();
        let sink = sink().map_err(BoxedReceiverError::Sink)?;
        Self::new_in_place(&mut allocation[0], sink);
        let raw = Box::into_raw(allocation) as *mut core::mem::MaybeUninit<Self>;
        Ok(unsafe { Box::from_raw(raw.cast::<Self>()) })
    }
}

impl<S, V, const MAX_MANIFEST: usize, const MAX_BLOB: usize>
    SignedObjectReceiver<S, V, MAX_MANIFEST, MAX_BLOB>
where
    S: ImageSink,
    V: SignatureVerifier,
{
    pub fn new_with_verifier(sink: S, verifier: V) -> Self {
        Self {
            manifest_bytes: Vec::new(),
            manifest_used: 0,
            prefetched_body_offset: 0,
            block: [0; MAX_BLOB],
            block_used: 0,
            image: ImageReceiver::new_with_verifier(sink, verifier),
            complete: false,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn received_body_bytes(&self) -> u64 {
        self.image.bytes
    }

    pub fn buffered_body_bytes(&self) -> usize {
        self.block_used
    }

    pub fn body_is_fully_consumed(&self) -> bool {
        self.image.manifest.is_some()
            && self.prefetched_body_offset == self.manifest_used
            && self.block_used == 0
            && self
                .image
                .manifest()
                .is_some_and(|manifest| self.image.bytes == manifest.image_size as u64)
    }

    /// Whether the last incremental push finished a complete object record.
    /// A stream adapter may retain the following bytes until its sink has
    /// completed the storage work initiated by that record.
    pub const fn at_record_boundary(&self) -> bool {
        self.block_used == 0
    }

    /// Whether the signed manifest boundary has been fully decoded and
    /// accepted. This is application-state diagnostics, not transport state.
    pub fn sink_mut(&mut self) -> &mut S {
        self.image.sink_mut()
    }

    /// Feed any ordered response fragment. A fragment may split either the
    /// five-byte record header or a blob body.
    pub fn push_ordered(&mut self, bytes: &[u8]) -> Result<usize, ImageError> {
        let mut reader = BorrowedOrderedRead::new(bytes, false);
        loop {
            let before_reader = reader.consumed();
            let before = self.image.bytes;
            self.consume_ordered(&mut reader)?;
            // A synchronous consumer must drain every immediately usable
            // byte from this ordered callback. Stopping merely because one
            // image block completed leaves a suffix under QUIC's ordering
            // ownership after the object parser has already advanced to the
            // next block. A later resume would then duplicate that boundary.
            // An asynchronous sink uses `consume_stream_body`, which polls
            // storage readiness and intentionally stops at its own boundary.
            if reader.consumed() == bytes.len()
                || (reader.consumed() == before_reader && self.image.bytes == before)
            {
                break;
            }
        }
        Ok(reader.consumed())
    }

    /// Read at most one complete object record from owned ordered chunks.
    /// A manifest can schedule asynchronous erase work; stopping at its
    /// boundary prevents a following blob from reaching a not-yet-ready sink.
    pub fn consume_stream_body<R: OrderedStreamRead>(
        &mut self,
        reader: &mut R,
    ) -> Result<ObjectStreamRead, ImageError>
    where
        S: StreamingImageSink,
    {
        // Complete any asynchronous sink work before deciding whether the
        // next ordered record is admissible. This is independent of the
        // stream reader and applies equally to flash, a delayed host file,
        // or a probe sink: the handler owns storage readiness while QUIC
        // observes only bytes subsequently copied by `read()`.
        let storage = self
            .image
            .sink_mut()
            .poll_completed()
            .map_err(|_| ImageError::Sink)?;
        // Once admitted, an asynchronous erase/write gates only further
        // application reads. QUIC sees ordinary consumption and owns credit.
        if self.image.manifest.is_some() && storage == StoragePoll::Pending {
            return Ok(ObjectStreamRead {
                application_progress: false,
                consumed_bytes: 0,
            });
        }
        let initial_image_bytes = self.image.bytes;
        let mut consumed_bytes = 0usize;
        loop {
            let copied = self.consume_ordered(reader)?;
            consumed_bytes = consumed_bytes.saturating_add(copied);
            if copied == 0 {
                break;
            }
            if self.image.manifest.is_some()
                && self
                    .image
                    .sink_mut()
                    .poll_completed()
                    .map_err(|_| ImageError::Sink)?
                    == StoragePoll::Pending
            {
                break;
            }
        }
        if reader.is_finished() && self.body_is_fully_consumed() && !self.complete {
            self.finish_ordered()?;
        }
        Ok(ObjectStreamRead {
            application_progress: consumed_bytes != 0 || self.image.bytes != initial_image_bytes,
            consumed_bytes,
        })
    }

    fn consume_ordered<R: OrderedStreamRead>(
        &mut self,
        reader: &mut R,
    ) -> Result<usize, ImageError> {
        let mut consumed = 0usize;
        if self.image.manifest.is_none() {
            if self.manifest_used == MAX_MANIFEST {
                return Err(ImageError::InvalidManifest);
            }
            // Grow in bounded chunks and expose only initialized bytes to the
            // stream reader.  `try_reserve_exact` turns a constrained-device
            // manifest allocation into an ordinary application error instead
            // of the global OOM path.
            // A CBOR manifest normally reaches its digest-table length in
            // the first read.  Give that first bounded read two MTUs of
            // backing storage, then only grow when the *allocated capacity*
            // cannot hold the next parser read.  `try_reserve_exact` takes
            // an additional length relative to `len`, not relative to the
            // spare capacity: calling it unconditionally here used to force
            // a needless realloc for every MTU fragment.  That is harmless
            // on a host allocator but turns an otherwise adequate fragmented
            // ESP heap into a spurious object `Allocation` error.
            let read_capacity = (MAX_MANIFEST - self.manifest_used).min(1024);
            let wanted = self.manifest_used.saturating_add(read_capacity);
            if self.manifest_bytes.capacity() < wanted {
                let initial_capacity = if self.manifest_used == 0 {
                    wanted.max(2 * 1024).min(MAX_MANIFEST)
                } else {
                    wanted
                };
                let additional = initial_capacity.saturating_sub(self.manifest_bytes.len());
                self.manifest_bytes
                    .try_reserve_exact(additional)
                    .map_err(|_| ImageError::Allocation)?;
            }
            let start = self.manifest_used;
            unsafe {
                self.manifest_bytes.set_len(start + read_capacity);
            }
            let copied = reader.read(&mut self.manifest_bytes[start..start + read_capacity]);
            self.manifest_bytes.truncate(start + copied);
            self.manifest_used += copied;
            consumed += copied;
            if copied == 0 {
                return Ok(consumed);
            }
            match ImageManifest::decode_prefix(&self.manifest_bytes[..self.manifest_used]) {
                Ok((_, used)) => {
                    self.image.on_manifest(&self.manifest_bytes[..used])?;
                    self.prefetched_body_offset = used;
                    // Manifest admission may start asynchronous erase work.
                    // Retain any already-copied body tail, but do not read or
                    // submit a body block until the next storage-ready turn.
                    return Ok(consumed);
                }
                Err(ImageError::Truncated) if self.manifest_used < MAX_MANIFEST => {
                    return Ok(consumed);
                }
                Err(error) => return Err(error),
            }
        }
        loop {
            let manifest = self.image.manifest().ok_or(ImageError::InvalidManifest)?;
            let remaining_image = manifest.image_size as usize - self.image.bytes as usize;
            let next_len = (manifest.block_size as usize).min(remaining_image);
            if next_len == 0 {
                break;
            }
            if self.block_used < next_len {
                let prefetched = self
                    .manifest_used
                    .saturating_sub(self.prefetched_body_offset)
                    .min(next_len - self.block_used);
                if prefetched != 0 {
                    self.block[self.block_used..self.block_used + prefetched].copy_from_slice(
                        &self.manifest_bytes
                            [self.prefetched_body_offset..self.prefetched_body_offset + prefetched],
                    );
                    self.prefetched_body_offset += prefetched;
                    self.block_used += prefetched;
                }
                let copied = if self.block_used < next_len {
                    reader.read(&mut self.block[self.block_used..next_len])
                } else {
                    0
                };
                self.block_used += copied;
                consumed += copied;
                if (copied == 0 && prefetched == 0) || self.block_used < next_len {
                    break;
                }
            }
            self.image.on_raw_block(&self.block[..next_len])?;
            self.block_used = 0;
            break;
        }
        Ok(consumed)
    }

    pub fn finish_ordered(&mut self) -> Result<(), ImageError> {
        if self.block_used != 0 {
            return Err(ImageError::InvalidBlock);
        }
        self.image.on_done()?;
        self.complete = true;
        Ok(())
    }

    /// Consume already ordered chunks. This is the exact handler-side
    /// operation shared by host tests and ESP flash; it neither parses nor
    /// emits transport packets or transport-credit values.
    pub fn push_stream_chunks<I, B>(&mut self, chunks: I) -> Result<bool, ImageError>
    where
        S: StreamingImageSink,
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut received = false;
        for bytes in chunks {
            let mut bytes = bytes.as_ref();
            while !bytes.is_empty() {
                let consumed = self.push_ordered(bytes)?;
                if consumed == 0 || consumed > bytes.len() {
                    return Err(ImageError::InvalidBlock);
                }
                bytes = &bytes[consumed..];
                received = true;
            }
        }
        let _ = self
            .image
            .sink_mut()
            .poll_completed()
            .map_err(|_| ImageError::Sink)?;
        Ok(received)
    }

    pub fn poll_storage_before_transport(&mut self) -> Result<(), ImageError>
    where
        S: StreamingImageSink,
    {
        self.image
            .sink_mut()
            .poll_before_transport()
            .map_err(|_| ImageError::Sink)
    }
}

/// Device-owned state for one asynchronous `flash` operation.
///
/// The device command handler sends [`Self::get_request`] through its active
/// authenticated stream connection, then feeds ordered object-response bytes into
/// [`Self::receive_ordered`]. Both methods are bounded CPU work only; bearer
/// I/O and durable-sink polling stay with the platform adapter.
pub struct SignedObjectFlashSession<'a, S, V, const MAX_MANIFEST: usize, const MAX_BLOB: usize> {
    request: FlashRequest<'a>,
    receiver: SignedObjectReceiver<S, V, MAX_MANIFEST, MAX_BLOB>,
}

impl<'a, S, const MAX_MANIFEST: usize, const MAX_BLOB: usize>
    SignedObjectFlashSession<'a, S, NoSignatureVerifier, MAX_MANIFEST, MAX_BLOB>
{
    pub const fn new(request: FlashRequest<'a>, sink: S) -> Self {
        Self {
            request,
            receiver: SignedObjectReceiver::new(sink),
        }
    }
}

impl<'a, S, V, const MAX_MANIFEST: usize, const MAX_BLOB: usize>
    SignedObjectFlashSession<'a, S, V, MAX_MANIFEST, MAX_BLOB>
where
    S: ImageSink,
    V: SignatureVerifier,
{
    pub fn new_with_verifier(request: FlashRequest<'a>, sink: S, verifier: V) -> Self {
        Self {
            request,
            receiver: SignedObjectReceiver::new_with_verifier(sink, verifier),
        }
    }

    pub fn request(&self) -> FlashRequest<'a> {
        self.request
    }

    /// Encode the signed-object GET body. The selected stream adapter prefixes
    /// its service tag and handles OPEN/ACK/retransmission separately.
    pub fn get_request(&self, out: &mut [u8]) -> Option<usize> {
        encode_get(
            out,
            self.request.object.name,
            self.request.object.cpu,
            self.request.object.target,
        )
    }

    pub fn receive_ordered(&mut self, bytes: &[u8]) -> Result<(), ImageError> {
        let mut bytes = bytes;
        while !bytes.is_empty() {
            let consumed = self.receiver.push_ordered(bytes)?;
            if consumed == 0 || consumed > bytes.len() {
                return Err(ImageError::InvalidBlock);
            }
            bytes = &bytes[consumed..];
        }
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.receiver.is_complete()
    }

    pub fn sink_mut(&mut self) -> &mut S {
        self.receiver.sink_mut()
    }
}

/// Host-only durable sink used by signed-object handler tests and by local
/// deployment tools. It deliberately follows the same `ImageSink` lifecycle
/// as firmware: write a temporary image, sync it, then atomically publish it.
#[cfg(feature = "std")]
pub struct FileImageSink {
    destination: std::path::PathBuf,
    temporary: std::path::PathBuf,
    file: Option<std::fs::File>,
    dry_run: bool,
}

#[cfg(feature = "std")]
impl FileImageSink {
    pub fn new(destination: impl Into<std::path::PathBuf>, dry_run: bool) -> Self {
        let destination = destination.into();
        let temporary = destination.with_extension("part");
        Self {
            destination,
            temporary,
            file: None,
            dry_run,
        }
    }
}

#[cfg(feature = "std")]
impl ImageSink for FileImageSink {
    type Error = std::io::Error;

    fn begin(&mut self, _: &ImageManifest) -> Result<(), Self::Error> {
        if self.dry_run {
            return Ok(());
        }
        self.file = Some(std::fs::File::create(&self.temporary)?);
        Ok(())
    }

    fn write_block(&mut self, _: u32, data: &[u8]) -> Result<(), Self::Error> {
        if let Some(file) = self.file.as_mut() {
            use std::io::Write;
            file.write_all(data)?;
        }
        Ok(())
    }

    fn finish(&mut self, _: &ImageManifest) -> Result<(), Self::Error> {
        if self.dry_run {
            return Ok(());
        }
        if let Some(file) = self.file.take() {
            file.sync_all()?;
        }
        std::fs::rename(&self.temporary, &self.destination)
    }

    fn abort(&mut self) {
        self.file = None;
        if !self.dry_run {
            let _ = std::fs::remove_file(&self.temporary);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageError {
    Truncated,
    /// The bounded application receiver could not grow its manifest storage.
    /// This is neither malformed metadata nor a QUIC transport failure.
    Allocation,
    InvalidManifest,
    InvalidBlock,
    InvalidSignature,
    Sink,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageEvent {
    ManifestAccepted,
    BlockAccepted { index: u32, bytes: usize },
    Complete,
}

pub struct ImageReceiver<S, V = NoSignatureVerifier> {
    sink: S,
    verifier: V,
    manifest: Option<ImageManifest>,
    next_block: u32,
    bytes: u64,
    complete: bool,
}

impl<S> ImageReceiver<S, NoSignatureVerifier> {
    pub const fn new(sink: S) -> Self {
        Self {
            sink,
            verifier: NoSignatureVerifier,
            manifest: None,
            next_block: 0,
            bytes: 0,
            complete: false,
        }
    }
}

impl<S, V: SignatureVerifier> ImageReceiver<S, V> {
    pub fn new_with_verifier(sink: S, verifier: V) -> Self {
        Self {
            sink,
            verifier,
            manifest: None,
            next_block: 0,
            bytes: 0,
            complete: false,
        }
    }
    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }
    pub fn manifest(&self) -> Option<&ImageManifest> {
        self.manifest.as_ref()
    }
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn on_manifest(&mut self, bytes: &[u8]) -> Result<ImageEvent, ImageError>
    where
        S: ImageSink,
    {
        if self.manifest.is_some() {
            return Err(ImageError::InvalidManifest);
        }
        let manifest = ImageManifest::decode(bytes)?;
        if let Some(signature) = manifest.signature.as_deref() {
            if !self.verifier.verify(bytes, signature) {
                return Err(ImageError::InvalidSignature);
            }
        }
        self.sink.begin(&manifest).map_err(|_| ImageError::Sink)?;
        self.manifest = Some(manifest);
        Ok(ImageEvent::ManifestAccepted)
    }

    /// Consume one complete DRS2 FRAME_BLOCK payload.  The first four bytes
    /// are reserved in the deployed wire format and must remain zero.
    pub fn on_block(&mut self, payload: &[u8]) -> Result<ImageEvent, ImageError>
    where
        S: ImageSink,
    {
        self.on_block_with_hasher(payload, |block| {
            let digest = Sha256::digest(block);
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest);
            Some(out)
        })
    }

    /// Accept the next raw body block. Its index, offset, and exact length are
    /// derived from the signed manifest and current body position; none are
    /// repeated on the wire.
    pub fn on_raw_block(&mut self, block: &[u8]) -> Result<ImageEvent, ImageError>
    where
        S: ImageSink,
    {
        let manifest = self.manifest.as_ref().ok_or(ImageError::InvalidManifest)?;
        let remaining = manifest.image_size as usize - self.bytes as usize;
        let expected = (manifest.block_size as usize).min(remaining);
        if self.complete || block.len() != expected || self.next_block >= manifest.block_count {
            return Err(ImageError::InvalidBlock);
        }
        let digest = Sha256::digest(block);
        if digest[..BLOCK_DIGEST_BYTES] != manifest.block_digests[self.next_block as usize] {
            return Err(ImageError::InvalidBlock);
        }
        let index = self.next_block;
        self.sink
            .write_block(index, block)
            .map_err(|_| ImageError::Sink)?;
        self.next_block += 1;
        self.bytes += block.len() as u64;
        Ok(ImageEvent::BlockAccepted {
            index,
            bytes: block.len(),
        })
    }

    /// Same block-proof validation with a caller-selected SHA-256 primitive.
    /// The object protocol remains platform-neutral; embedded callers can use
    /// their hardware accelerator while host tests use the default above.
    pub fn on_block_with_hasher<F>(
        &mut self,
        payload: &[u8],
        hash: F,
    ) -> Result<ImageEvent, ImageError>
    where
        S: ImageSink,
        F: FnOnce(&[u8]) -> Option<[u8; 32]>,
    {
        let manifest = self.manifest.as_ref().ok_or(ImageError::InvalidManifest)?;
        if payload.len() < 12 || payload[..4] != [0, 0, 0, 0] {
            return Err(ImageError::InvalidBlock);
        }
        let index = u32::from_be_bytes(payload[4..8].try_into().unwrap());
        let len = u32::from_be_bytes(payload[8..12].try_into().unwrap()) as usize;
        if self.complete
            || index != self.next_block
            || len == 0
            || len > manifest.block_size as usize
            || payload.len() < 12 + len
            || self.bytes + len as u64 > manifest.image_size as u64
        {
            return Err(ImageError::InvalidBlock);
        }
        let block = &payload[12..12 + len];
        let actual = hash(block).ok_or(ImageError::InvalidBlock)?;
        if actual[..BLOCK_DIGEST_BYTES] != manifest.block_digests[index as usize] {
            return Err(ImageError::InvalidBlock);
        }
        self.sink
            .write_block(index, block)
            .map_err(|_| ImageError::Sink)?;
        self.next_block += 1;
        self.bytes += len as u64;
        Ok(ImageEvent::BlockAccepted { index, bytes: len })
    }

    pub fn on_done(&mut self) -> Result<ImageEvent, ImageError>
    where
        S: ImageSink,
    {
        let manifest = self.manifest.as_ref().ok_or(ImageError::InvalidManifest)?;
        if self.bytes != manifest.image_size as u64 || self.next_block != manifest.block_count {
            return Err(ImageError::InvalidBlock);
        }
        self.sink.finish(manifest).map_err(|_| ImageError::Sink)?;
        self.complete = true;
        Ok(ImageEvent::Complete)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    BadMagic,
    InvalidManifest,
    UnsupportedTarget,
    InvalidBlock,
    OutOfOrder,
    Sink,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    ManifestAccepted,
    BlockAccepted { index: u32, bytes: usize },
    Complete,
    Rejected(Error),
}

pub struct Receiver<S> {
    sink: S,
    manifest: Option<Manifest>,
    next_block: u32,
    bytes: u64,
    complete: bool,
}

impl<S> Receiver<S> {
    pub const fn new(sink: S) -> Self {
        Self {
            sink,
            manifest: None,
            next_block: 0,
            bytes: 0,
            complete: false,
        }
    }
    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }
    pub fn manifest(&self) -> Option<Manifest> {
        self.manifest
    }
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn on_manifest(&mut self, bytes: &[u8]) -> Result<Event, Error>
    where
        S: ObjectSink,
    {
        if self.manifest.is_some() {
            return Err(Error::InvalidManifest);
        }
        let manifest = Manifest::decode(bytes)?;
        self.sink.begin(&manifest).map_err(|_| Error::Sink)?;
        self.manifest = Some(manifest);
        Ok(Event::ManifestAccepted)
    }

    pub fn on_block(&mut self, index: u32, offset: u64, data: &[u8]) -> Result<Event, Error>
    where
        S: ObjectSink,
    {
        let manifest = self.manifest.ok_or(Error::InvalidManifest)?;
        if self.complete
            || index != self.next_block
            || offset != self.bytes
            || data.is_empty()
            || data.len() > manifest.block_size as usize
            || offset + data.len() as u64 > manifest.size
        {
            return Err(Error::InvalidBlock);
        }
        self.sink
            .write_block(index, offset, data)
            .map_err(|_| Error::Sink)?;
        self.next_block += 1;
        self.bytes += data.len() as u64;
        Ok(Event::BlockAccepted {
            index,
            bytes: data.len(),
        })
    }

    pub fn on_done(&mut self) -> Result<Event, Error>
    where
        S: ObjectSink,
    {
        let manifest = self.manifest.ok_or(Error::InvalidManifest)?;
        if self.bytes != manifest.size || self.next_block != manifest.block_count {
            return Err(Error::InvalidBlock);
        }
        self.sink.finish(&manifest).map_err(|_| Error::Sink)?;
        self.complete = true;
        Ok(Event::Complete)
    }

    pub fn abort(&mut self)
    where
        S: ObjectSink,
    {
        self.sink.abort();
        self.manifest = None;
        self.next_block = 0;
        self.bytes = 0;
        self.complete = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_ordered_reader_reports_fin_only_after_consumption() {
        let mut reader = BorrowedOrderedRead::new(b"final", true);
        assert!(!reader.is_finished());
        let mut out = [0u8; 8];
        assert_eq!(reader.read(&mut out), 5);
        assert_eq!(&out[..5], b"final");
        assert_eq!(reader.consumed(), 5);
        assert!(reader.is_finished());
    }

    #[test]
    fn storage_slots_follow_injected_memory_without_becoming_transport_credit() {
        let flash_policy = StorageSlotPolicy {
            reserve_bytes: 16 * 1024,
            bytes_per_slot: 4 * 1024,
            minimum_slots: 1,
            maximum_slots: 1,
        };
        // This is the classic-ESP flash admission boundary: the receiver must
        // reject before it opens an object stream when it cannot preserve the
        // worker/runtime reserve and one ordinary 4 KiB image block. Host
        // tests inject the same heap observation instead of discovering it
        // only on a board.
        assert_eq!(flash_policy.slots_for(20 * 1024 - 1), 0);
        assert_eq!(flash_policy.slots_for(20 * 1024), 1);
        assert_eq!(flash_policy.slots_for(24 * 1024), 1);
        assert_eq!(flash_policy.slots_for(64 * 1024), 1);
        assert_eq!(
            bounded_storage_slots(64 * 1024, 16 * 1024, 4 * 1024, 1, 1),
            1
        );
        assert_eq!(
            bounded_storage_slots(24 * 1024, 16 * 1024, 4 * 1024, 1, 1),
            1
        );
        assert_eq!(
            bounded_storage_slots(20 * 1024 - 1, 16 * 1024, 4 * 1024, 1, 1),
            0
        );
        assert_eq!(
            bounded_storage_slots(512 * 1024, 16 * 1024, 4 * 1024, 1, 1),
            1
        );
        assert_eq!(bounded_storage_slots(64 * 1024, 0, 0, 1, 4), 0);
        assert_eq!(bounded_storage_slots(64 * 1024, 0, 8 * 1024, 0, 4), 0);
    }

    #[test]
    fn boxed_receiver_factory_reports_sink_failure_without_installing_receiver() {
        type Receiver = SignedObjectReceiver<(), NoSignatureVerifier, 256, 256>;
        let mut called = false;
        let result = Receiver::try_new_boxed_with(|| {
            called = true;
            Err::<(), _>(7_u8)
        });
        assert!(called);
        assert!(matches!(result, Err(BoxedReceiverError::Sink(7))));
    }

    #[test]
    fn exclusive_transfer_rejects_contender_and_only_owner_releases() {
        let mut operation = ExclusiveTransfer::new();
        let first = quic_lite::ConnectionId::new(0x4101).unwrap();
        let second = quic_lite::ConnectionId::new(0x4102).unwrap();

        assert_eq!(
            operation.try_start_with(first, 7, 100, 50, || Ok::<_, ()>(11)),
            Ok(())
        );
        assert_eq!(
            operation.try_start_with(second, 8, 101, 50, || Ok::<_, ()>(22)),
            Err(ExclusiveTransferStartError::Busy)
        );
        assert_eq!(operation.owner(), Some(first));
        assert_eq!(operation.get_mut_for(second), None);
        assert_eq!(operation.take_for(second), None);
        assert_eq!(operation.take_for(first), Some(11));
        assert_eq!(
            operation.try_start_with(second, 8, 101, 50, || Ok::<_, ()>(22)),
            Ok(())
        );
    }

    #[test]
    fn exclusive_transfer_does_not_construct_a_busy_operation() {
        let mut operation = ExclusiveTransfer::new();
        let first = quic_lite::ConnectionId::new(0x5101).unwrap();
        let second = quic_lite::ConnectionId::new(0x5102).unwrap();
        let mut starts = 0;

        assert_eq!(
            operation.try_start_with(first, 7, 100, 50, || {
                starts += 1;
                Ok::<_, ()>(11)
            }),
            Ok(())
        );
        assert_eq!(
            operation.try_start_with(second, 8, 101, 50, || {
                starts += 1;
                Ok::<_, ()>(22)
            }),
            Err(ExclusiveTransferStartError::Busy)
        );
        assert_eq!(starts, 1);
        assert_eq!(operation.take_for(first), Some(11));
    }

    #[test]
    fn exclusive_transfer_replaces_only_pristine_operation_from_new_owner() {
        let mut operation = ExclusiveTransfer::new();
        let first = quic_lite::ConnectionId::new(0x5201).unwrap();
        let second = quic_lite::ConnectionId::new(0x5202).unwrap();
        operation
            .try_start_with(first, 7, 100, 50, || Ok::<_, ()>(0usize))
            .unwrap();

        assert_eq!(
            operation.try_start_or_replace_if(
                second,
                8,
                101,
                50,
                |value| *value == 0,
                || { Ok::<_, ()>(1usize) }
            ),
            Ok(())
        );
        assert_eq!(operation.owner(), Some(second));
        assert_eq!(operation.take_for(second), Some(1));

        operation
            .try_start_with(first, 9, 102, 50, || Ok::<_, ()>(2usize))
            .unwrap();
        assert_eq!(
            operation.try_start_or_replace_if(
                second,
                10,
                103,
                50,
                |_| false,
                || { Ok::<_, ()>(3usize) }
            ),
            Err(ExclusiveTransferStartError::Busy)
        );
        assert_eq!(operation.owner(), Some(first));
    }

    #[test]
    fn exclusive_transfer_timeout_tracks_only_owner_application_progress() {
        let mut operation = ExclusiveTransfer::new();
        let first = quic_lite::ConnectionId::new(0x6101).unwrap();
        let second = quic_lite::ConnectionId::new(0x6102).unwrap();
        operation
            .try_start_with(first, 91, 100, 20, || Ok::<_, ()>(11))
            .unwrap();

        assert!(!operation.touch(second, 115, 20));
        assert_eq!(operation.take_expired(119), None);
        assert!(operation.touch(first, 119, 20));
        assert_eq!(operation.take_expired(120), None);
        assert_eq!(operation.request_id_for(first), Some(91));
        assert_eq!(operation.take_expired(138), None);
        assert_eq!(operation.take_expired(139), Some((first, 91, 11)));
        assert_eq!(operation.owner(), None);
    }

    #[test]
    fn verified_object_credit_is_storage_not_bearer_policy() {
        assert_eq!(
            verified_object_record_credit(RECORD_MANIFEST, 10, false),
            Some(ObjectRecordCredit::Immediate(15))
        );
        assert_eq!(
            verified_object_record_credit(RECORD_BLOB, 4096, false),
            Some(ObjectRecordCredit::Deferred)
        );
        assert_eq!(
            verified_object_record_credit(RECORD_BLOB, 4096, true),
            Some(ObjectRecordCredit::Immediate(4101))
        );
    }

    #[test]
    fn deferred_storage_work_needs_exactly_one_later_turn() {
        let mut work = DeferredStorageWork::new();
        assert!(!work.is_pending());
        assert!(!work.take());

        work.request();
        work.request();
        assert!(work.is_pending());
        assert!(work.take(), "the first later maintenance turn starts work");
        assert!(!work.is_pending());
        assert!(!work.take(), "no unrequested second wake is required");

        work.request();
        assert!(
            work.take(),
            "a failed platform enqueue can explicitly retry"
        );
    }

    struct Sink {
        blocks: u32,
        bytes: usize,
        done: bool,
    }
    impl ObjectSink for Sink {
        type Error = ();
        fn begin(&mut self, _: &Manifest) -> Result<(), Self::Error> {
            Ok(())
        }
        fn write_block(&mut self, _: u32, _: u64, data: &[u8]) -> Result<(), Self::Error> {
            self.blocks += 1;
            self.bytes += data.len();
            Ok(())
        }
        fn finish(&mut self, _: &Manifest) -> Result<(), Self::Error> {
            self.done = true;
            Ok(())
        }
        fn abort(&mut self) {}
    }

    #[test]
    fn receiver_accepts_ordered_module_blocks() {
        let mut bytes = [0u8; Manifest::WIRE_LEN];
        bytes[0..4].copy_from_slice(&IMAGE_MAGIC.to_be_bytes());
        bytes[4] = 7;
        bytes[5..7].copy_from_slice(&(4u16).to_be_bytes());
        bytes[7..15].copy_from_slice(&(8u64).to_be_bytes());
        bytes[15..19].copy_from_slice(&(2u32).to_be_bytes());
        bytes[51] = 4;
        bytes[52..56].copy_from_slice(b"test");
        let mut receiver = Receiver::new(Sink {
            blocks: 0,
            bytes: 0,
            done: false,
        });
        receiver.on_manifest(&bytes).unwrap();
        receiver.on_block(0, 0, b"1234").unwrap();
        receiver.on_block(1, 4, b"5678").unwrap();
        assert_eq!(receiver.on_done().unwrap(), Event::Complete);
        assert!(receiver.sink_mut().done);
    }

    struct ImageTestSink {
        blocks: u32,
        bytes: usize,
        done: bool,
    }
    impl ImageSink for ImageTestSink {
        type Error = ();
        fn begin(&mut self, _: &ImageManifest) -> Result<(), Self::Error> {
            Ok(())
        }
        fn write_block(&mut self, _: u32, data: &[u8]) -> Result<(), Self::Error> {
            self.blocks += 1;
            self.bytes += data.len();
            Ok(())
        }
        fn finish(&mut self, _: &ImageManifest) -> Result<(), Self::Error> {
            self.done = true;
            Ok(())
        }
        fn abort(&mut self) {}
    }

    #[test]
    fn signed_object_receiver_initializes_large_buffers_in_caller_storage() {
        type Receiver = SignedObjectReceiver<ImageTestSink, NoSignatureVerifier, 64, 128>;
        let mut storage = Box::new(core::mem::MaybeUninit::<Receiver>::uninit());
        let receiver = Receiver::new_in_place(
            &mut storage,
            ImageTestSink {
                blocks: 0,
                bytes: 0,
                done: false,
            },
        );
        assert!(!receiver.is_complete());
        assert_eq!(receiver.sink_mut().bytes, 0);

        let mut boxed = Receiver::try_new_boxed(ImageTestSink {
            blocks: 0,
            bytes: 0,
            done: false,
        })
        .expect("one receiver allocation");
        assert!(!boxed.is_complete());
        assert_eq!(boxed.sink_mut().bytes, 0);
    }

    #[test]
    fn image_receiver_accepts_main_wire_records() {
        let first = Sha256::digest(b"1234");
        let second = Sha256::digest(b"5678");
        let image = Sha256::digest(b"12345678");
        let mut manifest = Vec::new();
        crate::cbor::encode::map(8, &mut manifest);
        for (key, value) in [(0, 6), (1, VERIFIED_OBJECT_VERSION), (2, 4), (3, 2), (4, 8)] {
            crate::cbor::encode::uint(key, &mut manifest);
            crate::cbor::encode::uint(u64::from(value), &mut manifest);
        }
        crate::cbor::encode::uint(5, &mut manifest);
        crate::cbor::encode::bytes(&image, &mut manifest);
        crate::cbor::encode::uint(6, &mut manifest);
        let mut block_digests = Vec::new();
        block_digests.extend_from_slice(&first[..BLOCK_DIGEST_BYTES]);
        block_digests.extend_from_slice(&second[..BLOCK_DIGEST_BYTES]);
        crate::cbor::encode::bytes(&block_digests, &mut manifest);
        crate::cbor::encode::uint(8, &mut manifest);
        crate::cbor::encode::uint(13, &mut manifest);
        let mut receiver = ImageReceiver::new(ImageTestSink {
            blocks: 0,
            bytes: 0,
            done: false,
        });
        assert_eq!(
            receiver.on_manifest(&manifest),
            Ok(ImageEvent::ManifestAccepted)
        );
        let mut block = [0u8; 16];
        block[4..8].copy_from_slice(&0u32.to_be_bytes());
        block[8..12].copy_from_slice(&4u32.to_be_bytes());
        block[12..16].copy_from_slice(b"1234");
        assert_eq!(
            receiver.on_block(&block),
            Ok(ImageEvent::BlockAccepted { index: 0, bytes: 4 })
        );
        block[4..8].copy_from_slice(&1u32.to_be_bytes());
        block[12..16].copy_from_slice(b"5678");
        assert_eq!(
            receiver.on_block(&block),
            Ok(ImageEvent::BlockAccepted { index: 1, bytes: 4 })
        );
        assert_eq!(receiver.on_done(), Ok(ImageEvent::Complete));
        assert!(receiver.sink_mut().done);
    }

    #[test]
    fn image_receiver_rejects_a_legacy_manifest_without_cpu_before_sink_begin() {
        let mut manifest = test_image_manifest(None);
        // Test construction writes the required CPU field last. An old host
        // used the otherwise identical seven-field encoding; accepting it
        // would let the ESP partition sink erase a destination before it can
        // distinguish an S3, C6, or classic image.
        assert_eq!(manifest[0], 0xa8);
        assert_eq!(&manifest[manifest.len() - 2..], &[8, 13]);
        manifest[0] = 0xa7;
        manifest.truncate(manifest.len() - 2);

        let mut receiver = ImageReceiver::new(ImageTestSink {
            blocks: 0,
            bytes: 0,
            done: false,
        });
        assert_eq!(
            receiver.on_manifest(&manifest),
            Err(ImageError::InvalidManifest)
        );
        assert_eq!(receiver.sink_mut().blocks, 0);
        assert_eq!(receiver.sink_mut().bytes, 0);
        assert!(!receiver.sink_mut().done);
    }

    #[test]
    fn fixed_record_decoder_is_bounded_and_preserves_split_records() {
        #[derive(Default)]
        struct Sink(Vec<(u8, Vec<u8>)>);
        impl RecordEvents for Sink {
            type Error = ();
            fn record(&mut self, kind: u8, payload: &[u8]) -> Result<(), Self::Error> {
                self.0.push((kind, payload.to_vec()));
                Ok(())
            }
        }
        let mut decoder = FixedRecordDecoder::<8, 16>::new();
        let mut sink = Sink::default();
        decoder
            .push(&[RECORD_MANIFEST, 0, 0, 0], &mut sink)
            .unwrap();
        let tail = [3, b'a', b'b', b'c', RECORD_DONE, 0, 0, 0, 0];
        let consumed = decoder.push(&tail, &mut sink).unwrap();
        assert_eq!(consumed, 4);
        assert!(decoder.at_record_boundary());
        assert_eq!(decoder.push(&tail[consumed..], &mut sink), Ok(5));
        assert_eq!(
            sink.0,
            vec![
                (RECORD_MANIFEST, b"abc".to_vec()),
                (RECORD_DONE, Vec::new())
            ]
        );
        assert_eq!(
            decoder.push(&[RECORD_BLOB, 0, 0, 0, 17], &mut sink),
            Err(FixedRecordError::Invalid)
        );
    }

    fn test_image_manifest(signature: Option<&[u8]>) -> Vec<u8> {
        let first = Sha256::digest(b"1234");
        let second = Sha256::digest(b"5678");
        let image = Sha256::digest(b"12345678");
        let mut manifest = Vec::new();
        crate::cbor::encode::map(if signature.is_some() { 9 } else { 8 }, &mut manifest);
        for (key, value) in [(0, 6), (1, VERIFIED_OBJECT_VERSION), (2, 4), (3, 2), (4, 8)] {
            crate::cbor::encode::uint(key, &mut manifest);
            crate::cbor::encode::uint(u64::from(value), &mut manifest);
        }
        crate::cbor::encode::uint(5, &mut manifest);
        crate::cbor::encode::bytes(&image, &mut manifest);
        crate::cbor::encode::uint(6, &mut manifest);
        let mut block_digests = Vec::new();
        block_digests.extend_from_slice(&first[..BLOCK_DIGEST_BYTES]);
        block_digests.extend_from_slice(&second[..BLOCK_DIGEST_BYTES]);
        crate::cbor::encode::bytes(&block_digests, &mut manifest);
        crate::cbor::encode::uint(8, &mut manifest);
        crate::cbor::encode::uint(13, &mut manifest);
        if let Some(signature) = signature {
            crate::cbor::encode::uint(7, &mut manifest);
            crate::cbor::encode::bytes(signature, &mut manifest);
        }
        manifest
    }

    struct DelayedStreamSink {
        bytes: usize,
        polls: usize,
        release_every: usize,
        done: bool,
    }

    impl ImageSink for DelayedStreamSink {
        type Error = ();

        fn begin(&mut self, _: &ImageManifest) -> Result<(), Self::Error> {
            Ok(())
        }

        fn write_block(&mut self, _: u32, data: &[u8]) -> Result<(), Self::Error> {
            self.bytes = self.bytes.saturating_add(data.len());
            Ok(())
        }

        fn finish(&mut self, _: &ImageManifest) -> Result<(), Self::Error> {
            self.done = true;
            Ok(())
        }

        fn abort(&mut self) {}
    }

    impl StreamingImageSink for DelayedStreamSink {
        fn poll_completed(&mut self) -> Result<StoragePoll, Self::Error> {
            self.polls = self.polls.saturating_add(1);
            Ok(if self.polls % self.release_every == 0 {
                StoragePoll::Ready
            } else {
                StoragePoll::Pending
            })
        }
    }

    #[test]
    fn streamed_consumer_is_transport_credit_independent() {
        type Receiver = SignedObjectReceiver<DelayedStreamSink, NoSignatureVerifier, 256, 64>;
        let mut receiver = Receiver::new(DelayedStreamSink {
            bytes: 0,
            polls: 0,
            release_every: 1,
            done: false,
        });

        let manifest = test_image_manifest(None);
        let received = receiver
            .push_stream_chunks([manifest[..3].to_vec()])
            .unwrap();
        assert!(received);
        assert!(
            receiver
                .push_stream_chunks([manifest[3..].to_vec()])
                .unwrap()
        );

        let first = b"1234";
        assert!(receiver.push_stream_chunks([first[..2].to_vec()]).unwrap());
        assert!(receiver.push_stream_chunks([first[2..].to_vec()]).unwrap());

        assert!(receiver.push_stream_chunks([b"5678"]).unwrap());
        assert!(
            !receiver
                .push_stream_chunks(core::iter::empty::<Vec<u8>>())
                .unwrap()
        );

        receiver.finish_ordered().unwrap_or_else(|error| {
            panic!(
                "finish {error:?}: received={} buffered={}",
                receiver.received_body_bytes(),
                receiver.buffered_body_bytes()
            )
        });
        assert!(receiver.is_complete());
        assert!(receiver.sink_mut().done);
    }

    #[test]
    fn ordered_reader_polls_async_sink_before_retaining_the_next_record() {
        struct EmptyReader;

        impl OrderedStreamRead for EmptyReader {
            fn read(&mut self, _: &mut [u8]) -> usize {
                0
            }
        }

        type Receiver = SignedObjectReceiver<DelayedStreamSink, NoSignatureVerifier, 256, 64>;
        let mut receiver = Receiver::new(DelayedStreamSink {
            bytes: 0,
            polls: 0,
            release_every: 1,
            done: false,
        });
        let mut reader = EmptyReader;

        let read = receiver.consume_stream_body(&mut reader).unwrap();
        assert_eq!(read.consumed_bytes, 0);
        assert!(!read.application_progress);
        // A storage-ready turn can contain no new QUIC bytes. It must still
        // collect the sink completion that makes retained ordered bytes
        // eligible on the following turn.
        assert_eq!(receiver.sink_mut().polls, 1);
    }

    #[test]
    fn pending_storage_leaves_the_ordered_reader_unread_until_the_same_next_turn() {
        struct SliceReader {
            bytes: Vec<u8>,
            offset: usize,
        }

        impl OrderedStreamRead for SliceReader {
            fn read(&mut self, out: &mut [u8]) -> usize {
                let count = out.len().min(self.bytes.len().saturating_sub(self.offset));
                out[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
                self.offset += count;
                count
            }
        }

        type Receiver = SignedObjectReceiver<DelayedStreamSink, NoSignatureVerifier, 256, 64>;
        let mut receiver = Receiver::new(DelayedStreamSink {
            bytes: 0,
            polls: 0,
            // The first manifest is always admissible so it can start work.
            // The first following record observes Pending, then Ready.
            release_every: 3,
            done: false,
        });
        let mut bytes = test_image_manifest(None);
        bytes.extend_from_slice(b"1234");
        let mut reader = SliceReader { bytes, offset: 0 };

        assert!(
            receiver
                .consume_stream_body(&mut reader)
                .unwrap()
                .application_progress
        );
        let offset_after_manifest = reader.offset;
        let resumed = receiver.consume_stream_body(&mut reader).unwrap();
        assert!(resumed.application_progress);
        assert_eq!(reader.offset, offset_after_manifest);
        assert_eq!(receiver.received_body_bytes(), 4);
    }

    #[test]
    fn image_receiver_rejects_corrupt_block_before_writing() {
        let manifest = test_image_manifest(None);
        let mut receiver = ImageReceiver::new(ImageTestSink {
            blocks: 0,
            bytes: 0,
            done: false,
        });
        receiver.on_manifest(&manifest).unwrap();
        let mut block = [0u8; 16];
        block[8..12].copy_from_slice(&4u32.to_be_bytes());
        block[12..16].copy_from_slice(b"1235");
        assert_eq!(receiver.on_block(&block), Err(ImageError::InvalidBlock));
        assert_eq!(receiver.sink_mut().blocks, 0);
    }

    #[test]
    fn image_receiver_accepts_done_from_verified_block_digests() {
        let mut manifest = test_image_manifest(None);
        let image = Sha256::digest(b"12345678");
        let image_offset = manifest
            .windows(image.len())
            .position(|window| window == image.as_slice())
            .unwrap();
        manifest[image_offset] ^= 1;
        let mut receiver = ImageReceiver::new(ImageTestSink {
            blocks: 0,
            bytes: 0,
            done: false,
        });
        receiver.on_manifest(&manifest).unwrap();
        let mut block = [0u8; 16];
        block[8..12].copy_from_slice(&4u32.to_be_bytes());
        block[12..16].copy_from_slice(b"1234");
        receiver.on_block(&block).unwrap();
        block[4..8].copy_from_slice(&1u32.to_be_bytes());
        block[12..16].copy_from_slice(b"5678");
        receiver.on_block(&block).unwrap();
        assert_eq!(receiver.on_done(), Ok(ImageEvent::Complete));
        assert!(receiver.sink_mut().done);
    }

    struct AcceptTestSignature;

    impl SignatureVerifier for AcceptTestSignature {
        fn verify(&self, _manifest_bytes: &[u8], signature: &[u8]) -> bool {
            signature == b"valid"
        }
    }

    #[test]
    fn image_receiver_requires_and_checks_optional_signature() {
        let manifest = test_image_manifest(Some(b"invalid"));
        let mut default_receiver = ImageReceiver::new(ImageTestSink {
            blocks: 0,
            bytes: 0,
            done: false,
        });
        assert_eq!(
            default_receiver.on_manifest(&manifest),
            Err(ImageError::InvalidSignature)
        );

        let valid_manifest = test_image_manifest(Some(b"valid"));
        let mut verified_receiver = ImageReceiver::new_with_verifier(
            ImageTestSink {
                blocks: 0,
                bytes: 0,
                done: false,
            },
            AcceptTestSignature,
        );
        assert_eq!(
            verified_receiver.on_manifest(&valid_manifest),
            Ok(ImageEvent::ManifestAccepted)
        );
    }

    #[test]
    fn get_request_round_trips_as_binary_cbor() {
        let mut bytes = [0u8; 64];
        let len = encode_get(&mut bytes, Some(b"main"), 13, 6).unwrap();
        let request = decode_get(&bytes[..len]).unwrap();
        assert_eq!(request.name, Some(&b"main"[..]));
        assert_eq!(request.cpu, 13);
        assert_eq!(request.target, 6);
    }

    #[test]
    fn object_handlers_use_correlated_tagged_stream_requests() {
        let mut get = [0u8; 128];
        let get_len = encode_get_request(&mut get, 41, Some(b"main"), 13, 6).unwrap();
        assert_eq!(
            decode_get_request(&get[..get_len]),
            Some((
                41,
                GetRequest {
                    name: Some(b"main"),
                    cpu: 13,
                    target: 6,
                }
            ))
        );

        let flash = FlashRequest {
            object: GetRequest {
                name: None,
                cpu: 13,
                target: 6,
            },
            address: None,
            transport: 0,
            dry_run: true,
        };
        let mut wire = [0u8; 160];
        let used = encode_flash_handler_request(flash, 42, &mut wire).unwrap();
        assert_eq!(
            decode_flash_handler_request(&wire[..used]),
            Some((42, flash))
        );

        let used = crate::tagged::encode_numeric_error(
            OBJECT_COMPONENT,
            OBJECT_FLASH_METHOD,
            42,
            FLASH_BUSY_ERROR,
            &mut wire,
        )
        .unwrap();
        assert_eq!(
            decode_flash_handler_error(&wire[..used]),
            Some(FLASH_BUSY_ERROR)
        );

        // A raw fields map is no longer a callable stream request.
        assert!(decode_get_request(&[0xa2, 0x01, 0x0d, 0x02, 0x06]).is_none());
    }

    #[test]
    fn flash_request_uses_default_transport_and_durable_mode_when_omitted() {
        // { cpu: 13, target: 6 }; normal operators should not need to carry
        // implementation/debug defaults in every invocation.
        assert_eq!(
            decode_flash_request(&[0xa2, 0x01, 0x0d, 0x02, 0x06]),
            Some(FlashRequest {
                object: GetRequest {
                    name: None,
                    cpu: 13,
                    target: 6,
                },
                address: None,
                transport: 0,
                dry_run: false,
            })
        );
    }

    #[test]
    fn get_request_rejects_duplicate_and_trailing_fields() {
        // {2: 6, 2: 6}
        assert!(decode_get(&[0xa2, 0x02, 0x06, 0x02, 0x06]).is_none());

        let mut bytes = [0u8; 64];
        let len = encode_get(&mut bytes, None, 13, 6).unwrap();
        let mut with_trailing = bytes[..len].to_vec();
        with_trailing.push(0);
        assert!(decode_get(&with_trailing).is_none());
    }

    #[test]
    fn get_request_encoding_is_canonical_for_main() {
        let mut bytes = [0u8; 64];
        let len = encode_get(&mut bytes, None, 13, 6).unwrap();
        assert_eq!(&bytes[..len], &[0xa2, 0x01, 0x0d, 0x02, 0x06]);
    }

    #[test]
    fn flash_request_reuses_signed_object_identity_and_preserves_execution_policy() {
        let request = FlashRequest {
            object: GetRequest {
                name: Some(b"stage2"),
                cpu: 13,
                target: 2,
            },
            address: Some(0x20_000),
            transport: 3,
            dry_run: true,
        };
        let mut bytes = [0u8; 96];
        let used = encode_flash_request(request, &mut bytes).unwrap();
        assert_eq!(decode_flash_request(&bytes[..used]), Some(request));
        // Duplicate transport field and trailing bytes are not safe to pass
        // through to an erase/write implementation.
        assert!(
            decode_flash_request(&[0xa5, 0x01, 13, 0x02, 2, 0x04, 0, 0x04, 1, 0x05, 0xf4])
                .is_none()
        );
        let mut trailing = bytes[..used].to_vec();
        trailing.push(0);
        assert!(decode_flash_request(&trailing).is_none());
    }

    #[cfg(feature = "std")]
    #[test]
    fn signed_object_body_uses_the_same_file_sink_as_firmware() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("main.bin");
        let manifest = test_image_manifest(None);
        let mut receiver =
            SignedObjectReceiver::<_, _, 1024, 4096>::new(FileImageSink::new(&destination, false));
        receiver.push_ordered(&manifest).unwrap();
        let mut body = b"12345678".as_slice();
        while !body.is_empty() {
            let used = receiver.push_ordered(body).unwrap();
            body = &body[used..];
        }
        assert_eq!(receiver.received_body_bytes(), 8);
        assert_eq!(receiver.buffered_body_bytes(), 0);
        receiver.finish_ordered().unwrap();
        assert_eq!(std::fs::read(destination).unwrap(), b"12345678");
    }

    #[cfg(feature = "std")]
    #[test]
    fn signed_object_receiver_accepts_fragmented_ordered_stream_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("stage2.bin");
        let manifest = test_image_manifest(None);
        let mut stream = ObjectRecordStream::from_object(manifest, b"12345678".to_vec());
        let mut receiver =
            SignedObjectReceiver::<_, _, 1024, 4096>::new(FileImageSink::new(&destination, false));
        let mut encoded = [0u8; 7];
        while let Some(chunk) = stream.next_chunk(&mut encoded) {
            let mut bytes = &encoded[..chunk.len];
            while !bytes.is_empty() {
                let used = receiver.push_ordered(bytes).unwrap();
                bytes = &bytes[used..];
            }
            if chunk.fin {
                while !receiver.body_is_fully_consumed() {
                    receiver.push_ordered(&[]).unwrap();
                }
                receiver.finish_ordered().unwrap();
            }
        }
        assert!(receiver.is_complete());
        assert_eq!(std::fs::read(destination).unwrap(), b"12345678");
    }

    #[test]
    fn flash_session_encodes_the_object_get_without_transport_state() {
        let request = FlashRequest {
            object: GetRequest {
                name: Some(b"stage2"),
                cpu: 13,
                target: 2,
            },
            address: None,
            transport: 0,
            dry_run: true,
        };
        let session = SignedObjectFlashSession::<_, _, 64, 4096>::new(
            request,
            ImageTestSink {
                blocks: 0,
                bytes: 0,
                done: false,
            },
        );
        let mut out = [0u8; 64];
        let used = session.get_request(&mut out).unwrap();
        assert_eq!(decode_get(&out[..used]), Some(request.object));
    }

    #[test]
    fn object_record_stream_keeps_records_ordered_and_finishes_only_on_done() {
        let mut stream = ObjectRecordStream::new(vec![
            (RECORD_MANIFEST, b"meta".to_vec()),
            (RECORD_BLOB, b"abcdef".to_vec()),
            (RECORD_DONE, Vec::new()),
        ]);
        let mut output = [0u8; 4];
        let mut bytes = Vec::new();
        let mut chunks = Vec::new();
        while let Some(chunk) = stream.next_chunk(&mut output) {
            bytes.extend_from_slice(&output[..chunk.len]);
            chunks.push(chunk);
        }
        assert_eq!(
            bytes,
            [
                RECORD_MANIFEST,
                0,
                0,
                0,
                4,
                b'm',
                b'e',
                b't',
                b'a',
                RECORD_BLOB,
                0,
                0,
                0,
                6,
                b'a',
                b'b',
                b'c',
                b'd',
                b'e',
                b'f',
                RECORD_DONE,
                0,
                0,
                0,
                0,
            ]
        );
        assert_eq!(chunks[0].offset, 0);
        assert_eq!(chunks[1].offset, 4);
        assert_eq!(chunks.last().unwrap().offset, 24);
        assert!(!chunks.iter().take(chunks.len() - 1).any(|chunk| chunk.fin));
        assert!(chunks.last().unwrap().fin);
        assert_eq!(stream.sent_bytes(), bytes.len());
        assert!(stream.is_complete());
    }

    #[test]
    fn flat_object_stream_is_manifest_then_raw_body_with_fin_only_at_end() {
        let manifest = test_image_manifest(None);
        let body = b"12345678".to_vec();
        let mut expected = manifest.clone();
        expected.extend_from_slice(&body);
        let mut stream = ObjectRecordStream::from_object(manifest.clone(), body);
        let mut actual = Vec::new();
        let mut scratch = [0u8; 3];
        let mut saw_fin = false;
        while let Some(chunk) = stream.next_chunk(&mut scratch) {
            actual.extend_from_slice(&scratch[..chunk.len]);
            assert!(!saw_fin);
            saw_fin = chunk.fin;
        }
        assert_eq!(actual, expected);
        assert!(saw_fin);
        let (decoded, used) = ImageManifest::decode_prefix(&actual).unwrap();
        assert_eq!(used, manifest.len());
        assert_eq!(&actual[used..], b"12345678");
        assert_eq!(decoded.image_size, 8);
    }

    #[test]
    fn flat_receiver_accepts_fragmented_manifest_and_unframed_body() {
        type Receiver = SignedObjectReceiver<DelayedStreamSink, NoSignatureVerifier, 256, 64>;
        let manifest = test_image_manifest(None);
        let mut wire = manifest.clone();
        wire.extend_from_slice(b"12345678");
        let mut receiver = Receiver::new(DelayedStreamSink {
            bytes: 0,
            polls: 0,
            release_every: 1,
            done: false,
        });
        for chunk in wire.chunks(7) {
            let mut remaining = chunk;
            while !remaining.is_empty() {
                let used = receiver.push_ordered(remaining).unwrap();
                assert!(used > 0);
                remaining = &remaining[used..];
            }
        }
        while !receiver.body_is_fully_consumed() {
            receiver.push_ordered(&[]).unwrap();
        }
        assert_eq!(receiver.received_body_bytes(), 8);
        assert_eq!(receiver.buffered_body_bytes(), 0);
        receiver.finish_ordered().unwrap();
        assert!(receiver.is_complete());
        assert_eq!(receiver.sink_mut().bytes, 8);
        assert!(receiver.sink_mut().done);
    }

    #[test]
    fn flat_receiver_accepts_a_large_manifest_and_mtu_fragmented_body() {
        const BODY_LEN: usize = 2 * 1024 * 1024 + 17;
        let body = (0..BODY_LEN)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let blocks = body.chunks(BLOCK_SIZE).collect::<Vec<_>>();
        let mut manifest = Vec::new();
        crate::cbor::encode::map(8, &mut manifest);
        for (key, value) in [
            (0, 6_u64),
            (1, u64::from(VERIFIED_OBJECT_VERSION)),
            (2, BLOCK_SIZE as u64),
            (3, blocks.len() as u64),
            (4, BODY_LEN as u64),
        ] {
            crate::cbor::encode::uint(key, &mut manifest);
            crate::cbor::encode::uint(value, &mut manifest);
        }
        crate::cbor::encode::uint(5, &mut manifest);
        crate::cbor::encode::bytes(&Sha256::digest(&body), &mut manifest);
        crate::cbor::encode::uint(6, &mut manifest);
        let mut digests = Vec::with_capacity(blocks.len() * BLOCK_DIGEST_BYTES);
        for block in &blocks {
            digests.extend_from_slice(&Sha256::digest(block)[..BLOCK_DIGEST_BYTES]);
        }
        crate::cbor::encode::bytes(&digests, &mut manifest);
        crate::cbor::encode::uint(8, &mut manifest);
        crate::cbor::encode::uint(13, &mut manifest);
        assert!(manifest.len() < 10_240);
        let mut wire = manifest;
        wire.extend_from_slice(&body);
        type Receiver =
            SignedObjectReceiver<DelayedStreamSink, NoSignatureVerifier, 10_240, BLOCK_SIZE>;
        let mut receiver = Receiver::new(DelayedStreamSink {
            bytes: 0,
            polls: 0,
            release_every: 1,
            done: false,
        });
        for chunk in wire.chunks(1036) {
            // A ready synchronous sink must consume the whole ordered
            // callback, even when this fragment crosses a verified 4 KiB
            // block boundary. Returning only the prefix leaves a duplicate
            // suffix under the stream reassembler after parser state has
            // advanced, which corrupts the next block on loss recovery.
            assert_eq!(receiver.push_ordered(chunk).unwrap(), chunk.len());
        }
        assert!(receiver.body_is_fully_consumed());
        receiver.finish_ordered().unwrap();
        assert!(receiver.is_complete());
        assert_eq!(receiver.sink_mut().bytes, BODY_LEN);
    }

    #[test]
    fn delayed_receiver_preserves_a_large_manifest_body_boundary_across_mtu_turns() {
        // Exercise the device shape exactly: the CBOR manifest crosses two
        // MTU-sized reads, carries a prefetched raw-body suffix, then the
        // sink withholds the same ordered bytes while its initial erase is
        // pending.  A later consumer-ready turn must resume the identical
        // byte boundary, never duplicate or skip it.
        const BODY_LEN: usize = 512 * 1024 + 17;
        let body = (0..BODY_LEN)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let blocks = body.chunks(BLOCK_SIZE).collect::<Vec<_>>();
        let mut manifest = Vec::new();
        crate::cbor::encode::map(8, &mut manifest);
        for (key, value) in [
            (0, 3_u64),
            (1, u64::from(VERIFIED_OBJECT_VERSION)),
            (2, BLOCK_SIZE as u64),
            (3, blocks.len() as u64),
            (4, BODY_LEN as u64),
        ] {
            crate::cbor::encode::uint(key, &mut manifest);
            crate::cbor::encode::uint(value, &mut manifest);
        }
        crate::cbor::encode::uint(5, &mut manifest);
        crate::cbor::encode::bytes(&Sha256::digest(&body), &mut manifest);
        crate::cbor::encode::uint(6, &mut manifest);
        let mut digests = Vec::with_capacity(blocks.len() * BLOCK_DIGEST_BYTES);
        for block in &blocks {
            digests.extend_from_slice(&Sha256::digest(block)[..BLOCK_DIGEST_BYTES]);
        }
        crate::cbor::encode::bytes(&digests, &mut manifest);
        crate::cbor::encode::uint(8, &mut manifest);
        crate::cbor::encode::uint(13, &mut manifest);
        assert!(manifest.len() > 1024);

        struct SliceReader<'a> {
            bytes: &'a [u8],
            offset: usize,
        }
        impl OrderedStreamRead for SliceReader<'_> {
            fn read(&mut self, out: &mut [u8]) -> usize {
                let count = out.len().min(self.bytes.len().saturating_sub(self.offset));
                out[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
                self.offset += count;
                count
            }
        }

        let mut wire = manifest;
        wire.extend_from_slice(&body);
        type Receiver =
            SignedObjectReceiver<DelayedStreamSink, NoSignatureVerifier, 10_240, BLOCK_SIZE>;
        let mut receiver = Receiver::new(DelayedStreamSink {
            bytes: 0,
            polls: 0,
            // Simulate an erase/write completion becoming available only on
            // a later consumer-ready turn.
            release_every: 3,
            done: false,
        });
        for packet in wire.chunks(1024) {
            let mut reader = SliceReader {
                bytes: packet,
                offset: 0,
            };
            for _ in 0..16 {
                let before = reader.offset;
                let read = receiver.consume_stream_body(&mut reader).unwrap();
                if reader.offset == packet.len() {
                    break;
                }
                // A body block may consume a prefix before deferred storage
                // stalls the suffix. A ready edge may instead consume zero;
                // only a nonzero report without reader progress is invalid.
                assert!(read.consumed_bytes == 0 || reader.offset > before);
            }
            assert_eq!(reader.offset, packet.len());
        }
        while !receiver.body_is_fully_consumed() {
            let mut reader = SliceReader {
                bytes: &[],
                offset: 0,
            };
            receiver.consume_stream_body(&mut reader).unwrap();
        }
        receiver.finish_ordered().unwrap();
        assert!(receiver.is_complete());
        assert_eq!(receiver.sink_mut().bytes, BODY_LEN);
    }
}
