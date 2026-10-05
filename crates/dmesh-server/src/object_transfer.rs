// `POST /flash`: an image pushed to a device as one request.
//
// The request is the generic REST form of the tagged-CBOR envelope (`crate::http`: component 2002,
// verb POST, path `/flash`) whose headers are `name`, `cpu`, `target`, `address`, `transport`,
// `dry_run` and `content-length`. The image follows on the same stream as raw bytes and ends with
// FIN; the response is a terminal header sent only after the sink has made the image durable. There
// is no manifest, block table, digest or signature: the transport carries integrity and the sink
// knows its own block size (see `notes/design/object-transfer-integrity.md`).
//
// `object.flash` (component 10, method 2) is only the CLI's name for this request: a command built
// from the schema carries the same headers as its fields, and the sender turns it into the POST.
//
// Transport supplies ordered stream bytes. This module does not parse packets, create sockets, or
// implement flow control.

extern crate alloc;
use alloc::vec::Vec;

/// The CLI/schema identity of the command (`object.flash`); the wire request is `http.post`.
pub const OBJECT_COMPONENT: u64 = 10;
pub const OBJECT_FLASH_METHOD: u64 = 2;
/// The path of `POST /flash`: the dispatch key is `[http, post, FLASH]`.
pub const FLASH_PATH: &[crate::http::Seg] = &[crate::http::Seg::Num(OBJECT_COMPONENT)];

// Flash request headers (application range of `crate::http`).
use crate::http::{CONTENT_LENGTH, Header};
const H_NAME: Header = Header { number: 64, name: "name" };
const H_CPU: Header = Header { number: 65, name: "cpu" };
const H_TARGET: Header = Header { number: 66, name: "target" };
const H_ADDRESS: Header = Header { number: 67, name: "address" };
const H_TRANSPORT: Header = Header { number: 68, name: "transport" };
const H_DRY_RUN: Header = Header { number: 69, name: "dry_run" };
pub const FLASH_BUSY_ERROR: &[u8] = b"flash already in progress";
pub const FLASH_TOO_LARGE_ERROR: &[u8] = b"image too large";
pub const REQUEST_MAX: usize = 1024;

/// Exactly `/flash`: the registry routes by prefix, so the handler refuses a longer path.
fn is_flash_path(params: Option<&[u8]>) -> bool {
    crate::http::path_starts_with(params, FLASH_PATH)
        && params.and_then(crate::http::path_len) == Some(FLASH_PATH.len())
}

/// Which image: the part of a request that names the object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectId<'a> {
    pub name: Option<&'a [u8]>,
    pub cpu: u8,
    pub target: u8,
}

/// The headers of `POST /flash`. The sender sets `len`; `0` means absent, which a device refuses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlashRequest<'a> {
    pub object: ObjectId<'a>,
    pub address: Option<u32>,
    /// `0` lets the active connection select a path. Other values are a
    /// handler-defined path preference, never a bearer-specific wire format.
    pub transport: u8,
    pub dry_run: bool,
    /// Content length: the number of image bytes that follow the header.
    pub len: u32,
}

/// Platform effects required by the common `object.flash` handler.
///
/// `start` validates the request (including `len` against the destination) and, when the platform
/// can write it, returns the sink that receives the request body and produces the terminal
/// response. The platform owns partition selection, erase/write calls and reboot integration; it
/// never decodes tagged CBOR or inspects QUIC/bearer state. Implementations copy any borrowed
/// request fields they retain.
pub trait FlashPlatform: Send + Sync + 'static {
    fn start(
        &self,
        request: FlashRequest<'_>,
        id: u64,
        context: crate::registry::CallContext,
    ) -> Result<alloc::boxed::Box<dyn crate::stream::BodySink>, FlashStartError>;
}

/// Stable application errors returned by the common flash handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlashStartError {
    Busy,
    Unsupported,
    InvalidTarget,
    /// `len` is zero, missing, or larger than the destination.
    TooLarge,
}

/// The `object.flash` handler: a request header, then the image as the request body, then FIN,
/// answered with a terminal response header. It is registered like every other method; the platform
/// supplies the sink.
///
/// The response to the header is not an acknowledgement of durable completion: the terminal
/// response comes only after the body has been written, and reboot remains a separate platform
/// event.
pub struct FlashHandler<P: FlashPlatform>(pub P);

impl<P: FlashPlatform> crate::stream::StreamHandler for FlashHandler<P> {
    fn open<'a>(&'a self, request: crate::stream::Request<'a>) -> crate::stream::OpenFuture<'a> {
        use crate::stream::{Outcome, Response};
        let outcome = (|| {
            let record = request.record;
            if record.component != Some(crate::tagged::Name::Tag(crate::http::COMPONENT))
                || record.method != Some(crate::tagged::Name::Tag(crate::http::verb::POST))
                || !is_flash_path(record.params)
                || record.to.is_some()
                || record.data.is_some()
                || record.result.is_some()
                || record.error.is_some()
            {
                return None;
            }
            let id = record.id?;
            let flash = decode_flash_request(record.fields?)?;
            Some(match self.0.start(flash, id, request.context) {
                Ok(sink) => Outcome::Receive(sink),
                Err(error) => {
                    let (status, message): (u16, &[u8]) = match error {
                        FlashStartError::Busy => (503, FLASH_BUSY_ERROR),
                        FlashStartError::Unsupported => (501, b"flash unavailable"),
                        FlashStartError::InvalidTarget => (400, b"invalid flash target"),
                        FlashStartError::TooLarge => (413, FLASH_TOO_LARGE_ERROR),
                    };
                    let mut response = [0u8; REQUEST_MAX];
                    let used = crate::http::encode_response(
                        crate::http::verb::POST,
                        id,
                        status,
                        message,
                        &mut response,
                    )?;
                    Outcome::Respond(Response::header(alloc::vec::Vec::from(&response[..used])))
                }
            })
        })();
        alloc::boxed::Box::pin(core::future::ready(outcome))
    }
}

/// Canonically encode the flash headers as a map: 64=name, 65=cpu, 66=target, 67=address,
/// 68=transport, 69=dry_run and 1=content-length (omitted when 0). A schema-built `object.flash`
/// command carries exactly these as its fields.
pub fn encode_flash_request(request: FlashRequest<'_>, out: &mut [u8]) -> Option<usize> {
    if request.object.target == 0 {
        return None;
    }
    let mut encoder = super::cbor::Encoder::new(out);
    let fields = 4
        + usize::from(request.object.name.is_some())
        + usize::from(request.address.is_some())
        + usize::from(request.len != 0);
    encoder.map(fields as u64)?;
    if request.len != 0 {
        encoder.uint(CONTENT_LENGTH.number)?;
        encoder.uint(u64::from(request.len))?;
    }
    if let Some(name) = request.object.name {
        encoder.uint(H_NAME.number)?;
        encoder.bytes_value(name)?;
    }
    encoder.uint(H_CPU.number)?;
    encoder.uint(u64::from(request.object.cpu))?;
    encoder.uint(H_TARGET.number)?;
    encoder.uint(u64::from(request.object.target))?;
    if let Some(address) = request.address {
        encoder.uint(H_ADDRESS.number)?;
        encoder.uint(u64::from(address))?;
    }
    encoder.uint(H_TRANSPORT.number)?;
    encoder.uint(u64::from(request.transport))?;
    encoder.uint(H_DRY_RUN.number)?;
    encoder.boolean(request.dry_run)?;
    Some(encoder.len())
}

/// Encode `POST /flash` on the normal QUIC stream plane: the REST envelope with path `[10]` and the
/// flash headers.
pub fn encode_flash_handler_request(
    request: FlashRequest<'_>,
    id: u64,
    out: &mut [u8],
) -> Option<usize> {
    let mut headers = [0u8; REQUEST_MAX];
    let headers_len = encode_flash_request(request, &mut headers)?;
    let mut path = [0u8; 8];
    let mut encoder = super::cbor::Encoder::new(&mut path);
    encoder.array(1)?;
    encoder.uint(OBJECT_COMPONENT)?;
    let path_len = encoder.len();
    crate::http::encode_request(
        crate::http::verb::POST,
        id,
        &path[..path_len],
        &headers[..headers_len],
        out,
    )
}

/// Decode a `POST /flash` request header.
pub fn decode_flash_handler_request(input: &[u8]) -> Option<(u64, FlashRequest<'_>)> {
    let record = super::tagged::decode(input)?;
    if record.component != Some(super::tagged::Name::Tag(crate::http::COMPONENT))
        || record.method != Some(super::tagged::Name::Tag(crate::http::verb::POST))
        || !is_flash_path(record.params)
        || record.to.is_some()
        || record.data.is_some()
        || record.result.is_some()
        || record.error.is_some()
    {
        return None;
    }
    Some((record.id?, decode_flash_request(record.fields?)?))
}

/// Encode the CLI's `object.flash` command (component 10, method 2, the headers as fields): what a
/// schema-built request looks like before the sender turns it into the POST.
pub fn encode_flash_command(request: FlashRequest<'_>, id: u64, out: &mut [u8]) -> Option<usize> {
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

/// Decode the CLI's `object.flash` command (component 10, method 2, the headers as fields).
pub fn decode_flash_command(input: &[u8]) -> Option<(u64, FlashRequest<'_>)> {
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

/// Decode a correlated flash error response: its status and message.
pub fn decode_flash_handler_error(input: &[u8]) -> Option<(u16, &[u8])> {
    let record = super::tagged::decode(input)?;
    if record.component != Some(super::tagged::Name::Tag(crate::http::COMPONENT))
        || record.result.is_some()
    {
        return None;
    }
    let status = crate::http::response_status(&record)?;
    let mut decoder = super::cbor::Decoder::new(record.error?);
    let error = decoder.text_ref()?;
    decoder.is_finished().then_some((status, error))
}

/// Decode the flash headers. Duplicate, unknown, or trailing entries are rejected before a
/// platform sink can erase anything. A header may be spelled by number or by name.
/// `transport=0` (default bearer selection) and `dry_run=false` may be omitted, and a request
/// without `content-length` decodes with `len=0` (the sender that holds the image sets it; the
/// device refuses 0).
pub fn decode_flash_request(input: &[u8]) -> Option<FlashRequest<'_>> {
    let mut name = None;
    let mut cpu = None;
    let mut target = None;
    let mut address = None;
    let mut transport = None;
    let mut dry_run = None;
    let mut len = None;
    fn once<T>(slot: &mut Option<T>, value: T) -> Option<()> {
        slot.is_none().then(|| *slot = Some(value))
    }
    crate::http::for_each_header(input, |key, d| {
        if key.is(H_NAME) {
            once(&mut name, d.bytes_or_text_ref()?)
        } else if key.is(H_CPU) {
            once(&mut cpu, d.uint()?.try_into().ok()?)
        } else if key.is(H_TARGET) {
            once(&mut target, d.uint()?.try_into().ok()?)
        } else if key.is(H_ADDRESS) {
            once(&mut address, d.uint()?.try_into().ok()?)
        } else if key.is(H_TRANSPORT) {
            once(&mut transport, d.uint()?.try_into().ok()?)
        } else if key.is(H_DRY_RUN) {
            once(&mut dry_run, d.boolean()?)
        } else if key.is(CONTENT_LENGTH) {
            once(&mut len, d.uint()?.try_into().ok()?)
        } else {
            None
        }
    })?;
    Some(FlashRequest {
        object: ObjectId {
            name,
            cpu: cpu?,
            target: target.filter(|target| *target != 0)?,
        },
        address,
        transport: transport.unwrap_or(0),
        dry_run: dry_run.unwrap_or(false),
        len: len.unwrap_or(0),
    })
}

/// Plan one sector-aligned erase without crossing a hardware block boundary.
/// A leading partial block aligns subsequent calls for large-block erase;
/// a final partial block never erases beyond the image's rounded extent.
pub fn next_erase_chunk_len(
    address: usize,
    remaining: usize,
    sector_size: usize,
    block_size: usize,
) -> Option<usize> {
    if sector_size == 0 || block_size == 0 || block_size % sector_size != 0
        || address % sector_size != 0 || remaining % sector_size != 0 {
        return None;
    }
    address.checked_add(remaining)?;
    Some(remaining.min(block_size - address % block_size))
}

#[cfg(test)]
mod erase_chunk_tests {
    use super::next_erase_chunk_len;

    #[test]
    fn aligned_unaligned_and_tail_erases_cover_only_the_requested_extent() {
        for base in [0, 4096, 60 * 1024, 64 * 1024] {
            for length in [0, 4096, 64 * 1024, 68 * 1024, 460 * 4096] {
                let mut erased = 0;
                while erased < length {
                    let count = next_erase_chunk_len(base + erased, length - erased, 4096, 65536).unwrap();
                    assert!(count > 0 && count <= 65536 && count % 4096 == 0);
                    assert_eq!((base + erased) / 65536, (base + erased + count - 1) / 65536);
                    erased += count;
                }
                assert_eq!(erased, length);
            }
        }
    }

    #[test]
    fn rejects_bad_geometry_and_overflow() {
        assert_eq!(next_erase_chunk_len(0, 4096, 0, 65536), None);
        assert_eq!(next_erase_chunk_len(0, 4096, 4096, 0), None);
        assert_eq!(next_erase_chunk_len(0, 4096, 4096, 5000), None);
        assert_eq!(next_erase_chunk_len(1, 4096, 4096, 65536), None);
        assert_eq!(next_erase_chunk_len(0, 4097, 4096, 65536), None);
        assert_eq!(next_erase_chunk_len(usize::MAX - 4095, 4096, 4096, 65536), None);
    }
}

/// Where an image goes. Flash, disk and RAM sinks implement this one interface; QUIC is absent:
/// ordered bytes have been copied out of its receive buffers before the sink is called.
pub trait ImageSink {
    type Error;

    /// The write unit. [`ImageWriter`] offers whole blocks of this size, in order; only the last
    /// may be shorter. The sink owns this choice (flash page or erase granularity), not the sender.
    fn block_size(&self) -> usize {
        4096
    }
    /// An image of `len` bytes is about to be written. Refuse here when it cannot fit.
    fn begin(&mut self, len: u32) -> Result<(), Self::Error>;
    fn write_block(&mut self, index: u32, data: &[u8]) -> Result<(), Self::Error>;
    /// Every byte was written: make the image durable.
    fn finish(&mut self) -> Result<(), Self::Error>;
    fn abort(&mut self);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageError {
    /// The block buffer could not be allocated (local resource exhaustion, not the sender's fault).
    Allocation,
    /// The body is shorter or longer than the declared `len`, or `len` is zero.
    Length,
    Sink,
}

/// Feeds an ordered byte stream to an [`ImageSink`] in the sink's block size and checks the total
/// against the declared content length. It is synchronous: a block is written before `write`
/// returns, so the caller may release the stream bytes immediately.
pub struct ImageWriter<S: ImageSink> {
    sink: S,
    len: u32,
    received: u32,
    next_index: u32,
    block_size: usize,
    block: Vec<u8>,
    complete: bool,
}

impl<S: ImageSink> ImageWriter<S> {
    /// Allocate the block buffer (fallibly) and begin the sink. The sink is aborted on failure.
    pub fn try_new(mut sink: S, len: u32) -> Result<Self, ImageError> {
        let block_size = sink.block_size();
        if len == 0 || block_size == 0 {
            sink.abort();
            return Err(ImageError::Length);
        }
        let mut block = Vec::new();
        if block.try_reserve_exact(block_size).is_err() {
            sink.abort();
            return Err(ImageError::Allocation);
        }
        if sink.begin(len).is_err() {
            sink.abort();
            return Err(ImageError::Sink);
        }
        Ok(Self { sink, len, received: 0, next_index: 0, block_size, block, complete: false })
    }

    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }
    pub fn received(&self) -> u32 {
        self.received
    }
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Take the next ordered body bytes; all are consumed.
    pub fn write(&mut self, mut bytes: &[u8]) -> Result<(), ImageError> {
        let total = (self.received as u64).checked_add(bytes.len() as u64);
        if self.complete || total.is_none_or(|total| total > u64::from(self.len)) {
            return Err(ImageError::Length);
        }
        self.received += bytes.len() as u32;
        while !bytes.is_empty() {
            if self.block.is_empty() && bytes.len() >= self.block_size {
                let (block, rest) = bytes.split_at(self.block_size);
                self.sink
                    .write_block(self.next_index, block)
                    .map_err(|_| ImageError::Sink)?;
                self.next_index += 1;
                bytes = rest;
                continue;
            }
            let take = (self.block_size - self.block.len()).min(bytes.len());
            self.block.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.block.len() == self.block_size {
                self.sink
                    .write_block(self.next_index, &self.block)
                    .map_err(|_| ImageError::Sink)?;
                self.next_index += 1;
                self.block.clear();
            }
        }
        Ok(())
    }

    /// The body ended (FIN): the declared length must have arrived. Writes the last partial block
    /// and finishes the sink.
    pub fn finish(&mut self) -> Result<(), ImageError> {
        if self.complete || self.received != self.len {
            return Err(ImageError::Length);
        }
        if !self.block.is_empty() {
            self.sink
                .write_block(self.next_index, &self.block)
                .map_err(|_| ImageError::Sink)?;
            self.next_index += 1;
            self.block.clear();
        }
        self.sink.finish().map_err(|_| ImageError::Sink)?;
        self.complete = true;
        Ok(())
    }

    /// The stream ended early or failed: release the sink's partial work.
    pub fn abort(&mut self) {
        if !self.complete {
            self.sink.abort();
        }
    }
}

/// Host-only durable sink used by object handler tests and by local
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

    fn begin(&mut self, _: u32) -> Result<(), Self::Error> {
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

    fn finish(&mut self) -> Result<(), Self::Error> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recording {
        blocks: Vec<(u32, Vec<u8>)>,
        begun: Option<u32>,
        done: bool,
        aborted: bool,
        block_size: usize,
        refuse_begin: bool,
    }

    impl ImageSink for Recording {
        type Error = ();
        fn block_size(&self) -> usize {
            if self.block_size == 0 { 4 } else { self.block_size }
        }
        fn begin(&mut self, len: u32) -> Result<(), ()> {
            if self.refuse_begin {
                return Err(());
            }
            self.begun = Some(len);
            Ok(())
        }
        fn write_block(&mut self, index: u32, data: &[u8]) -> Result<(), ()> {
            self.blocks.push((index, data.to_vec()));
            Ok(())
        }
        fn finish(&mut self) -> Result<(), ()> {
            self.done = true;
            Ok(())
        }
        fn abort(&mut self) {
            self.aborted = true;
        }
    }

    fn writer(len: u32) -> ImageWriter<Recording> {
        ImageWriter::try_new(Recording::default(), len).unwrap()
    }

    #[test]
    fn the_writer_offers_whole_sink_blocks_however_the_stream_is_split() {
        let image: Vec<u8> = (0..10).collect();
        for step in [1, 3, 4, 5, 10] {
            let mut writer = writer(10);
            for chunk in image.chunks(step) {
                writer.write(chunk).unwrap();
            }
            writer.finish().unwrap();
            let sink = writer.sink_mut();
            assert_eq!(sink.begun, Some(10));
            assert!(sink.done);
            assert_eq!(
                sink.blocks,
                vec![(0, image[0..4].to_vec()), (1, image[4..8].to_vec()), (2, image[8..].to_vec())],
                "step {step}"
            );
        }
    }

    #[test]
    fn a_body_shorter_or_longer_than_len_is_rejected_and_never_finishes_the_sink() {
        let mut short = writer(8);
        short.write(b"1234").unwrap();
        assert_eq!(short.finish(), Err(ImageError::Length));
        assert!(!short.sink_mut().done);
        short.abort();
        assert!(short.sink_mut().aborted);

        let mut long = writer(4);
        long.write(b"1234").unwrap();
        assert_eq!(long.write(b"5"), Err(ImageError::Length));
        long.finish().unwrap();
        assert_eq!(long.write(b"x"), Err(ImageError::Length));
    }

    #[test]
    fn a_zero_length_or_refused_image_never_starts_the_sink() {
        assert_eq!(ImageWriter::try_new(Recording::default(), 0).err(), Some(ImageError::Length));
        let refusing = Recording { refuse_begin: true, ..Default::default() };
        assert_eq!(ImageWriter::try_new(refusing, 4).err(), Some(ImageError::Sink));
    }

    #[test]
    fn flash_request_headers_round_trip_with_the_content_length() {
        let request = FlashRequest {
            object: ObjectId { name: Some(b"stage2"), cpu: 13, target: 2 },
            address: Some(0x20_000),
            transport: 3,
            dry_run: true,
            len: 1_048_576,
        };
        let mut bytes = [0u8; 96];
        let used = encode_flash_request(request, &mut bytes).unwrap();
        assert_eq!(decode_flash_request(&bytes[..used]), Some(request));

        // The wire request is `POST /flash`: REST envelope, path [10], headers, no body inside.
        let mut wire = [0u8; 160];
        let used = encode_flash_handler_request(request, 42, &mut wire).unwrap();
        assert_eq!(decode_flash_handler_request(&wire[..used]), Some((42, request)));
        let record = crate::tagged::decode(&wire[..used]).unwrap();
        assert_eq!(record.component, Some(crate::tagged::Name::Tag(crate::http::COMPONENT)));
        assert_eq!(record.method, Some(crate::tagged::Name::Tag(crate::http::verb::POST)));
        assert!(record.data.is_none());
        // The CLI command form is not the wire form.
        assert!(decode_flash_command(&wire[..used]).is_none());

        // Duplicate headers (also by number and name), unknown ones and trailing bytes are refused.
        assert!(decode_flash_request(&[0xa4, 65, 13, 66, 2, 68, 0, 68, 1]).is_none());
        let mut trailing = bytes[..used.min(bytes.len())].to_vec();
        let used_fields = encode_flash_request(request, &mut bytes).unwrap();
        trailing.truncate(used_fields);
        trailing.push(0);
        assert!(decode_flash_request(&trailing).is_none());
        // Header 70 is not a flash header.
        assert!(decode_flash_request(&[0xa3, 65, 13, 66, 2, 0x18, 70, 1]).is_none());
    }

    #[test]
    fn headers_may_be_spelled_by_name_and_defaults_may_be_omitted() {
        // {"cpu": 13, 66: 6}: a name and a number mix; transport, dry_run, content-length default.
        let mut bytes = [0u8; 32];
        let mut encoder = crate::cbor::Encoder::new(&mut bytes);
        encoder.map(2).unwrap();
        encoder.text_value(b"cpu").unwrap();
        encoder.uint(13).unwrap();
        encoder.uint(66).unwrap();
        encoder.uint(6).unwrap();
        let used = encoder.len();
        assert_eq!(
            decode_flash_request(&bytes[..used]),
            Some(FlashRequest {
                object: ObjectId { name: None, cpu: 13, target: 6 },
                address: None,
                transport: 0,
                dry_run: false,
                len: 0,
            })
        );
        // The same header by number and by name is a duplicate.
        let mut encoder = crate::cbor::Encoder::new(&mut bytes);
        encoder.map(3).unwrap();
        encoder.text_value(b"cpu").unwrap();
        encoder.uint(13).unwrap();
        encoder.uint(65).unwrap();
        encoder.uint(13).unwrap();
        encoder.uint(66).unwrap();
        encoder.uint(6).unwrap();
        let used = encoder.len();
        assert!(decode_flash_request(&bytes[..used]).is_none());
    }

    #[test]
    fn a_refusal_is_a_correlated_response_with_a_status() {
        let mut wire = [0u8; 96];
        let used = crate::http::encode_response(
            crate::http::verb::POST,
            42,
            503,
            FLASH_BUSY_ERROR,
            &mut wire,
        )
        .unwrap();
        assert_eq!(decode_flash_handler_error(&wire[..used]), Some((503, FLASH_BUSY_ERROR)));
    }

    #[cfg(feature = "std")]
    #[test]
    fn the_file_sink_publishes_the_image_only_when_complete() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("main.bin");
        let image: Vec<u8> = (0..10_000u32).map(|v| (v % 251) as u8).collect();
        let mut writer =
            ImageWriter::try_new(FileImageSink::new(&destination, false), image.len() as u32).unwrap();
        for chunk in image.chunks(1036) {
            writer.write(chunk).unwrap();
        }
        assert!(!destination.exists());
        writer.finish().unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), image);
        assert!(!destination.with_extension("part").exists());
    }
}
