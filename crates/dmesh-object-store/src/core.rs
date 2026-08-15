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

impl<const MAX_MANIFEST: usize, const MAX_BLOB: usize>
    FixedRecordDecoder<MAX_MANIFEST, MAX_BLOB>
{
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
                    let mut hashes = Vec::with_capacity(length as usize);
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
        decoder.push(&[RECORD_MANIFEST, 0, 0, 0], &mut sink).unwrap();
        decoder
            .push(&[3, b'a', b'b', b'c', RECORD_DONE, 0, 0, 0, 0], &mut sink)
            .unwrap();
        assert_eq!(sink.0, vec![(RECORD_MANIFEST, b"abc".to_vec()), (RECORD_DONE, Vec::new())]);
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
}
