// Bounded object-store records and the binary GET request.
//
// Transport supplies ordered stream bytes. This module does not parse packets,
// create sockets, or implement flow control.

extern crate alloc;
use super::cbor::Decoder;
use alloc::vec::Vec;
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

/// Credit return after one verified object record. This policy is independent
/// of UDP/UART/radio: a persistent sink returns blob credit only when it has
/// reclaimed storage, while a benchmark/fake sink can reuse it immediately.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectRecordCredit {
    Immediate(usize),
    Deferred,
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
pub struct ObjectRecordStream {
    records: Vec<(u8, Vec<u8>)>,
    record_index: usize,
    record_offset: usize,
    stream_offset: u64,
    sent_bytes: usize,
}

impl ObjectRecordStream {
    pub fn new(records: Vec<(u8, Vec<u8>)>) -> Self {
        Self {
            records,
            record_index: 0,
            record_offset: 0,
            stream_offset: 0,
            sent_bytes: 0,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.record_index == self.records.len()
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
    fn record(&mut self, kind: u8, payload: &[u8]) -> Result<(), Self::Error>;
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

    pub fn push<E: RecordEvents>(
        &mut self,
        mut input: &[u8],
        events: &mut E,
    ) -> Result<(), FixedRecordError<E::Error>> {
        while !input.is_empty() {
            if self.header_len < self.header.len() {
                let copied = (self.header.len() - self.header_len).min(input.len());
                self.header[self.header_len..self.header_len + copied]
                    .copy_from_slice(&input[..copied]);
                self.header_len += copied;
                input = &input[copied..];
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
                if self.expected == 0 {
                    if self.kind != RECORD_DONE {
                        return Err(FixedRecordError::Invalid);
                    }
                    events
                        .record(self.kind, &[])
                        .map_err(FixedRecordError::Callback)?;
                    self.header_len = 0;
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
            }
        }
        Ok(())
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
    let fields = 4 + usize::from(request.object.name.is_some()) + usize::from(request.address.is_some());
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

/// Decode a complete canonical `flash` handler body. Duplicate, unknown, or
/// trailing fields are rejected before a platform sink can erase anything.
pub fn decode_flash_request(input: &[u8]) -> Option<FlashRequest<'_>> {
    let mut d = Decoder::new(input);
    let (major, count) = d.head()?;
    if major != 5 || !(4..=6).contains(&count) {
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
            0 => name = Some(d.bytes_ref()?),
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
        transport: transport?,
        dry_run: dry_run?,
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
                request.name = Some(d.bytes_ref()?);
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
    pub version: u8,
    pub block_size: u32,
    pub block_count: u32,
    pub image_size: u32,
    pub image_sha256: [u8; 32],
    pub block_sha256: Vec<[u8; 32]>,
    pub signature: Option<Vec<u8>>,
}

impl ImageManifest {
    pub const HEADER_LEN: usize = 20;

    pub fn decode(input: &[u8]) -> Result<Self, ImageError> {
        let mut decoder = Decoder::new(input);
        let (major, count) = decoder.head().ok_or(ImageError::Truncated)?;
        if major != 5 {
            return Err(ImageError::InvalidManifest);
        }
        let mut target = None;
        let mut version = None;
        let mut block_size = 0u32;
        let mut block_count = 0u32;
        let mut image_size = 0u32;
        let mut image_sha256 = None;
        let mut block_sha256 = None;
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
                    let (major, length) = decoder.head().ok_or(ImageError::Truncated)?;
                    if major != 4 || length > 4096 {
                        return Err(ImageError::InvalidManifest);
                    }
                    // Embedded Recovery must reject a manifest it cannot
                    // retain rather than invoking Rust's allocation-failure
                    // abort after a valid transport delivery.
                    let mut hashes = Vec::new();
                    hashes
                        .try_reserve_exact(length as usize)
                        .map_err(|_| ImageError::InvalidManifest)?;
                    for _ in 0..length {
                        let bytes = decoder.bytes_ref().ok_or(ImageError::Truncated)?;
                        if bytes.len() != 32 {
                            return Err(ImageError::InvalidManifest);
                        }
                        let mut digest = [0u8; 32];
                        digest.copy_from_slice(bytes);
                        hashes.push(digest);
                    }
                    block_sha256 = Some(hashes);
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
        if !decoder.is_finished() {
            return Err(ImageError::InvalidManifest);
        }
        let manifest = Self {
            target: target.ok_or(ImageError::InvalidManifest)?,
            version: version.ok_or(ImageError::InvalidManifest)?,
            block_size,
            block_count,
            image_size,
            image_sha256: image_sha256.ok_or(ImageError::InvalidManifest)?,
            block_sha256: block_sha256.ok_or(ImageError::InvalidManifest)?,
            signature,
        };
        if manifest.version != 1
            || manifest.block_size == 0
            || manifest.block_count == 0
            || manifest.block_count as u64
                != (manifest.image_size as u64 + manifest.block_size as u64 - 1)
                    / manifest.block_size as u64
            || manifest.block_sha256.len() != manifest.block_count as usize
        {
            return Err(ImageError::InvalidManifest);
        }
        Ok(manifest)
    }
}

pub trait ImageSink {
    type Error;
    fn begin(&mut self, manifest: &ImageManifest) -> Result<(), Self::Error>;
    fn write_block(&mut self, index: u32, data: &[u8]) -> Result<(), Self::Error>;
    fn finish(&mut self, manifest: &ImageManifest) -> Result<(), Self::Error>;
    fn abort(&mut self);
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
    records: FixedRecordDecoder<MAX_MANIFEST, MAX_BLOB>,
    image: ImageReceiver<S, V>,
    complete: bool,
}


struct SignedObjectEvents<'a, S, V> {
    image: &'a mut ImageReceiver<S, V>,
    complete: &'a mut bool,
}

impl<S, V> RecordEvents for SignedObjectEvents<'_, S, V>
where
    S: ImageSink,
    V: SignatureVerifier,
{
    type Error = ImageError;

    fn record(&mut self, kind: u8, payload: &[u8]) -> Result<(), Self::Error> {
        if *self.complete {
            return Err(ImageError::InvalidBlock);
        }
        let event = match kind {
            RECORD_MANIFEST => self.image.on_manifest(payload)?,
            RECORD_BLOB => self.image.on_block(payload)?,
            RECORD_DONE => self.image.on_done()?,
            _ => return Err(ImageError::InvalidBlock),
        };
        *self.complete = matches!(event, ImageEvent::Complete);
        Ok(())
    }
}

impl<S, const MAX_MANIFEST: usize, const MAX_BLOB: usize>
    SignedObjectReceiver<S, NoSignatureVerifier, MAX_MANIFEST, MAX_BLOB>
{
    pub const fn new(sink: S) -> Self {
        Self {
            records: FixedRecordDecoder::new(),
            image: ImageReceiver::new(sink),
            complete: false,
        }
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
            records: FixedRecordDecoder::new(),
            image: ImageReceiver::new_with_verifier(sink, verifier),
            complete: false,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn sink_mut(&mut self) -> &mut S {
        self.image.sink_mut()
    }

    /// Feed any ordered response fragment. A fragment may split either the
    /// five-byte record header or a blob body.
    pub fn push_ordered(&mut self, bytes: &[u8]) -> Result<(), ImageError> {
        let mut events = SignedObjectEvents {
            image: &mut self.image,
            complete: &mut self.complete,
        };
        self.records.push(bytes, &mut events).map_err(|error| match error {
            FixedRecordError::Invalid => ImageError::InvalidBlock,
            FixedRecordError::Callback(error) => error,
        })
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
        self.receiver.push_ordered(bytes)
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
        if actual != manifest.block_sha256[index as usize] {
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
    fn image_receiver_accepts_main_wire_records() {
        let first = Sha256::digest(b"1234");
        let second = Sha256::digest(b"5678");
        let image = Sha256::digest(b"12345678");
        let mut manifest = Vec::new();
        crate::cbor::encode::map(7, &mut manifest);
        for (key, value) in [(0, 6), (1, 1), (2, 4), (3, 2), (4, 8)] {
            crate::cbor::encode::uint(key, &mut manifest);
            crate::cbor::encode::uint(value, &mut manifest);
        }
        crate::cbor::encode::uint(5, &mut manifest);
        crate::cbor::encode::bytes(&image, &mut manifest);
        crate::cbor::encode::uint(6, &mut manifest);
        crate::cbor::encode::array(2, &mut manifest);
        crate::cbor::encode::bytes(&first, &mut manifest);
        crate::cbor::encode::bytes(&second, &mut manifest);
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
        decoder
            .push(&[3, b'a', b'b', b'c', RECORD_DONE, 0, 0, 0, 0], &mut sink)
            .unwrap();
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
        crate::cbor::encode::map(if signature.is_some() { 8 } else { 7 }, &mut manifest);
        for (key, value) in [(0, 6), (1, 1), (2, 4), (3, 2), (4, 8)] {
            crate::cbor::encode::uint(key, &mut manifest);
            crate::cbor::encode::uint(value, &mut manifest);
        }
        crate::cbor::encode::uint(5, &mut manifest);
        crate::cbor::encode::bytes(&image, &mut manifest);
        crate::cbor::encode::uint(6, &mut manifest);
        crate::cbor::encode::array(2, &mut manifest);
        crate::cbor::encode::bytes(&first, &mut manifest);
        crate::cbor::encode::bytes(&second, &mut manifest);
        if let Some(signature) = signature {
            crate::cbor::encode::uint(7, &mut manifest);
            crate::cbor::encode::bytes(signature, &mut manifest);
        }
        manifest
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
        assert!(decode_flash_request(&[0xa5, 0x01, 13, 0x02, 2, 0x04, 0, 0x04, 1, 0x05, 0xf4]).is_none());
        let mut trailing = bytes[..used].to_vec();
        trailing.push(0);
        assert!(decode_flash_request(&trailing).is_none());
    }

    #[cfg(feature = "std")]
    #[test]
    fn signed_object_records_use_the_same_file_sink_as_firmware() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("main.bin");
        let manifest = test_image_manifest(None);
        let block = |index: u32, bytes: &[u8]| {
            let mut payload = vec![0; 12];
            payload[4..8].copy_from_slice(&index.to_be_bytes());
            payload[8..12].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
            payload.extend_from_slice(bytes);
            payload
        };
        let records = vec![
            (RECORD_MANIFEST, manifest),
            (RECORD_BLOB, block(0, b"1234")),
            (RECORD_BLOB, block(1, b"5678")),
            (RECORD_DONE, Vec::new()),
        ];
        let mut receiver = ImageReceiver::new(FileImageSink::new(&destination, false));
        assert_eq!(
            apply_signed_object_records(&mut receiver, &records),
            Ok(ImageEvent::Complete)
        );
        assert_eq!(std::fs::read(destination).unwrap(), b"12345678");
    }

    #[cfg(feature = "std")]
    #[test]
    fn signed_object_receiver_accepts_fragmented_ordered_stream_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("stage2.bin");
        let manifest = test_image_manifest(None);
        let block = |index: u32, bytes: &[u8]| {
            let mut payload = vec![0; 12];
            payload[4..8].copy_from_slice(&index.to_be_bytes());
            payload[8..12].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
            payload.extend_from_slice(bytes);
            payload
        };
        let mut stream = ObjectRecordStream::new(vec![
            (RECORD_MANIFEST, manifest),
            (RECORD_BLOB, block(0, b"1234")),
            (RECORD_BLOB, block(1, b"5678")),
            (RECORD_DONE, Vec::new()),
        ]);
        let mut receiver = SignedObjectReceiver::<_, _, 1024, 4096>::new(
            FileImageSink::new(&destination, false),
        );
        let mut encoded = [0u8; 7];
        while let Some(chunk) = stream.next_chunk(&mut encoded) {
            receiver.push_ordered(&encoded[..chunk.len]).unwrap();
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
}
