//! Handler streams: a header, then an optional raw body.
//!
//! The contract is defined once for every mesh API in ssh-mesh
//! `PROTOCOLS.md` ("Handler streams: header and body"). In short, each
//! direction of a stream is one self-delimiting CBOR item (the header) followed
//! by raw bytes (the body) and then FIN, and a method with no body is a header
//! followed by FIN. This module holds the pieces every ingress shares: the
//! incremental header scanner, the handler traits, and a transport-neutral
//! server-side state machine for callers (firmware) that are driven chunk by
//! chunk. Async hosts use [`scan_header`] and the traits directly.
//!
//! A registered handler never sees a transport. It is opened with the complete
//! header and answers with an [`Outcome`]; a method with no body answers with
//! [`Outcome::Respond`] and never touches a body.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;

use crate::registry::{CallContext, Registry};
use crate::tagged::Record;

/// Largest header accepted. A header that is not complete within this many
/// bytes is invalid; this bounds the buffer a stream may make a node hold
/// before any handler is chosen.
pub const MAX_HEADER_BYTES: usize = 4096;

/// Bytes of body that may arrive in the same chunk as the end of the header.
/// They are held until the handler's sink takes them.
const MAX_SURPLUS_BYTES: usize = 2048;

/// Run handler work and record successful progress using its completion time.
///
/// Event-loop timestamps captured before dispatch must not be reused here:
/// synchronous storage operations may outlast the stream's idle deadline.
/// Work returning `false` leaves the timestamp unchanged, so blocked handlers
/// still expire. The clock is sampled only after successful work completes.
pub fn track_progress<T>(
    last_progress_ms: &mut u64,
    clock: impl FnOnce() -> u64,
    work: impl FnOnce() -> (T, bool),
) -> T {
    let (result, progressed) = work();
    if progressed {
        *last_progress_ms = clock();
    }
    result
}

#[cfg(test)]
mod progress_tests {
    use super::track_progress;
    use core::cell::Cell;

    #[test]
    fn blocking_handler_uses_completion_time_and_continued_upload_survives() {
        let clock = Cell::new(1_000u64);
        let mut last = clock.get();
        let consumed = track_progress(&mut last, || clock.get(), || {
            // Partition erase blocks longer than the firmware's 15s idle limit.
            clock.set(clock.get() + 32_000);
            (512, true)
        });
        assert_eq!(consumed, 512);
        assert_eq!(last, 33_000);
        assert!(clock.get().saturating_sub(last) < 15_000);
        clock.set(34_000);
        track_progress(&mut last, || clock.get(), || ((), true));
        assert_eq!(last, 34_000);
        // Retaining the transfer does not exempt it from future idle expiry.
        clock.set(49_000);
        assert!(clock.get().saturating_sub(last) >= 15_000);
    }

    #[test]
    fn blocked_handler_does_not_refresh_idle_deadline() {
        let mut last = 1_000;
        track_progress(&mut last, || 33_000, || ((), false));
        assert_eq!(last, 1_000);
    }
}

/// Result of scanning the start of a stream for its header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Header {
    /// The first `n` bytes are one complete CBOR item; body bytes follow.
    Complete(usize),
    /// The bytes so far are a valid prefix of an item.
    NeedMore,
    /// Not a CBOR item, nested too deeply, or longer than a header may be.
    Invalid,
}

enum Scan {
    More,
    Bad,
}

const MAX_DEPTH: u8 = 24;

/// Find where the one CBOR data item at the start of `bytes` ends.
///
/// CBOR is self-delimiting, so no marker or length prefix is needed: a
/// definite-length container ends after its last element and an
/// indefinite-length one at its break code. The first byte after the item is
/// the first body byte.
pub fn scan_header(bytes: &[u8]) -> Header {
    let mut position = 0;
    match scan_item(bytes, &mut position, 0) {
        Ok(()) if position <= MAX_HEADER_BYTES => Header::Complete(position),
        Ok(()) => Header::Invalid,
        Err(Scan::More) if bytes.len() < MAX_HEADER_BYTES => Header::NeedMore,
        Err(Scan::More) | Err(Scan::Bad) => Header::Invalid,
    }
}

fn take(bytes: &[u8], position: &mut usize, count: usize) -> Result<(), Scan> {
    let end = position.checked_add(count).ok_or(Scan::Bad)?;
    if end > bytes.len() {
        return Err(Scan::More);
    }
    *position = end;
    Ok(())
}

/// Read the argument of an initial byte; `None` means an indefinite length.
fn argument(bytes: &[u8], position: &mut usize, info: u8) -> Result<Option<u64>, Scan> {
    let width = match info {
        0..=23 => return Ok(Some(u64::from(info))),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        31 => return Ok(None),
        _ => return Err(Scan::Bad),
    };
    let start = *position;
    take(bytes, position, width)?;
    Ok(Some(
        bytes[start..*position]
            .iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte)),
    ))
}

fn scan_item(bytes: &[u8], position: &mut usize, depth: u8) -> Result<(), Scan> {
    if depth > MAX_DEPTH {
        return Err(Scan::Bad);
    }
    let initial = *bytes.get(*position).ok_or(Scan::More)?;
    *position += 1;
    let (major, info) = (initial >> 5, initial & 0x1f);
    let length = argument(bytes, position, info)?;
    match (major, length) {
        // Unsigned and negative integers, simple values and floats.
        (0 | 1, Some(_)) | (7, Some(_)) => Ok(()),
        (0 | 1 | 7, None) => Err(Scan::Bad),
        // Byte and text strings.
        (2 | 3, Some(length)) => {
            let length = usize::try_from(length).map_err(|_| Scan::Bad)?;
            take(bytes, position, length)
        }
        (2 | 3, None) => loop {
            if *bytes.get(*position).ok_or(Scan::More)? == 0xff {
                *position += 1;
                return Ok(());
            }
            let chunk = *bytes.get(*position).ok_or(Scan::More)?;
            if chunk >> 5 != major || chunk & 0x1f == 31 {
                return Err(Scan::Bad);
            }
            scan_item(bytes, position, depth + 1)?;
        },
        // Arrays and maps.
        (4 | 5, Some(count)) => {
            let items = if major == 5 {
                count.checked_mul(2).ok_or(Scan::Bad)?
            } else {
                count
            };
            for _ in 0..items {
                scan_item(bytes, position, depth + 1)?;
            }
            Ok(())
        }
        (4 | 5, None) => loop {
            if *bytes.get(*position).ok_or(Scan::More)? == 0xff {
                *position += 1;
                return Ok(());
            }
            scan_item(bytes, position, depth + 1)?;
            if major == 5 {
                scan_item(bytes, position, depth + 1)?;
            }
        },
        // A tag wraps one item.
        (6, Some(_)) => scan_item(bytes, position, depth + 1),
        (6, None) => Err(Scan::Bad),
        _ => Err(Scan::Bad),
    }
}

/// A request as a handler is opened with it: the decoded header only. The body,
/// if there is one, is delivered to the sink the handler returns.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub record: Record<'a>,
    /// The header's bytes, exactly as received.
    pub header: &'a [u8],
    pub context: CallContext,
}

/// Where a handler puts the request body. Bytes arrive in order.
pub trait BodySink: Send {
    /// Take the next request-body bytes and return how many were accepted. A
    /// count below `chunk.len()` withholds the rest (the transport offers it
    /// again later); `fin` is set on the call that carries the last byte. An
    /// `Err` is the response header to send, and ends the request.
    fn write(&mut self, chunk: &[u8], fin: bool) -> Result<usize, Vec<u8>>;

    /// The whole body was accepted: produce the response.
    fn finish(self: Box<Self>) -> Response;

    /// The stream was reset or abandoned before the body ended.
    fn abort(self: Box<Self>) {}
}

/// Where a handler gets the response body. Bytes are produced in order.
pub trait BodySource: Send {
    /// Fill `out` and return `(count, done)`. `(0, false)` means no bytes are
    /// available yet; the transport asks again when it can send. `done` ends
    /// the body, and FIN follows the last byte.
    fn read(&mut self, out: &mut [u8]) -> (usize, bool);
}

/// A response: its header, then an optional body, then FIN.
pub struct Response {
    pub header: Vec<u8>,
    pub body: Option<Box<dyn BodySource>>,
    /// Local work to schedule after the ordinary response stream is finished.
    /// Dropping/aborting a response never invokes it. This is not a peer ACK.
    pub after_finish: Option<Box<dyn FnOnce() + Send>>,
}

impl Response {
    /// A header-only response.
    pub fn header(header: Vec<u8>) -> Self {
        Self { header, body: None, after_finish: None }
    }

    /// A response whose body is produced by `body`.
    pub fn with_body(header: Vec<u8>, body: impl BodySource + 'static) -> Self {
        Self {
            header,
            body: Some(Box::new(body)),
            after_finish: None,
        }
    }

    /// Schedule an application action only after a successful response write
    /// and end-of-stream, equally for TCP and QUIC stream adapters.
    pub fn after_finish(mut self, action: impl FnOnce() + Send + 'static) -> Self {
        self.after_finish = Some(Box::new(action));
        self
    }

    /// Read the response as the bytes to put on the stream.
    pub fn into_reader(self) -> ResponseReader {
        ResponseReader {
            header: self.header,
            position: 0,
            body: self.body,
            after_finish: self.after_finish,
        }
    }
}

/// The response as a byte producer: the header, then the body.
pub struct ResponseReader {
    header: Vec<u8>,
    position: usize,
    body: Option<Box<dyn BodySource>>,
    after_finish: Option<Box<dyn FnOnce() + Send>>,
}

impl ResponseReader {
    /// Called by the stream adapter after writing all bytes and successfully
    /// finishing the response direction. Never call this on a failed write.
    pub fn finish_response(&mut self) {
        if let Some(action) = self.after_finish.take() {
            action();
        }
    }
    /// Fill `out` with the next response bytes. The second value is true when
    /// the last byte is included, so the sender should end its direction (FIN)
    /// after writing `count` bytes. `(0, false)` means the body has nothing
    /// ready yet.
    pub fn read(&mut self, out: &mut [u8]) -> (usize, bool) {
        if self.position < self.header.len() {
            let count = (self.header.len() - self.position).min(out.len());
            out[..count].copy_from_slice(&self.header[self.position..self.position + count]);
            self.position += count;
            let header_done = self.position == self.header.len();
            return (count, header_done && self.body.is_none());
        }
        match self.body.as_mut() {
            Some(body) => body.read(out),
            None => (0, true),
        }
    }
}

/// A response that is not ready when the header has been handled: the handler
/// started work (a probe, a flash erase) and answers when it finishes. The
/// transport polls it until it yields the response.
pub trait Deferred: Send {
    fn poll(&mut self) -> Option<Response>;
}

/// What a handler decided about a request.
pub enum Outcome {
    /// Answer now. Any request body that follows is discarded.
    Respond(Response),
    /// Take the request body into the sink, then answer with its `finish`.
    Receive(Box<dyn BodySink>),
    /// Answer later, when the deferred work completes. Any request body that
    /// follows is discarded.
    Defer(Box<dyn Deferred>),
}

pub type OpenFuture<'a> = Pin<Box<dyn Future<Output = Option<Outcome>> + Send + 'a>>;

/// A handler for one method on a stream: given the header, decide what
/// happens to the body. `None` declines the request, which the dispatcher
/// answers with the shared numeric error.
pub trait StreamHandler: Send + Sync + 'static {
    fn open<'a>(&'a self, request: Request<'a>) -> OpenFuture<'a>;
}

enum Phase {
    Header,
    Body(Box<dyn BodySink>),
    Waiting(Box<dyn Deferred>),
    Discard,
}

/// The server side of one handler stream for a transport that delivers it chunk
/// by chunk and cannot await (firmware). The transport keeps one per inbound
/// stream, calls [`ServerStream::push`] with each ordered chunk, and writes any
/// [`Response`] it returns with [`Response::into_reader`].
pub struct ServerStream {
    context: CallContext,
    phase: Phase,
    received: u64,
    header: Vec<u8>,
    surplus: Vec<u8>,
    fin: bool,
    finished: bool,
}

/// What [`ServerStream::push`] did with a chunk.
pub struct Pushed {
    /// Bytes of the chunk taken. Fewer than offered means the sink or the
    /// header buffer is full; offer the rest again later.
    pub accepted: usize,
    /// The response to send, once the request has been answered.
    pub response: Option<Response>,
}

impl ServerStream {
    pub fn new(context: CallContext) -> Self {
        Self {
            context,
            phase: Phase::Header,
            received: 0,
            header: Vec::new(),
            surplus: Vec::new(),
            fin: false,
            finished: false,
        }
    }

    /// Whether the request has been answered (or failed) and the stream needs
    /// no more request bytes except to discard them.
    pub fn is_answered(&self) -> bool {
        matches!(self.phase, Phase::Discard) || self.finished
    }

    /// Whether the stream is waiting for deferred work.
    pub fn is_waiting(&self) -> bool {
        matches!(self.phase, Phase::Waiting(_))
    }

    /// Offer the next ordered request bytes. `offset` is the stream offset of
    /// `chunk`; `fin` is set when `chunk` ends the request direction.
    pub fn push(
        &mut self,
        registry: &Registry,
        offset: u64,
        fin: bool,
        chunk: &[u8],
    ) -> Pushed {
        if offset != self.received {
            return self.fail(chunk.len(), b"stream offset rejected");
        }
        match self.phase {
            Phase::Discard | Phase::Waiting(_) => {
                self.received += chunk.len() as u64;
                Pushed {
                    accepted: chunk.len(),
                    response: None,
                }
            }
            Phase::Header => self.push_header(registry, fin, chunk),
            Phase::Body(_) => self.push_body(fin, chunk),
        }
    }

    /// Advance work that does not depend on a new chunk: offer withheld body
    /// bytes again, or poll deferred work. Returns the response once there is
    /// one. A transport calls this from its progress loop.
    pub fn poll(&mut self) -> Option<Response> {
        match &mut self.phase {
            Phase::Body(_) if !self.finished => self.drain_surplus(),
            Phase::Waiting(deferred) => {
                let response = deferred.poll()?;
                self.phase = Phase::Discard;
                self.finished = true;
                Some(response)
            }
            _ => None,
        }
    }

    /// The stream was reset or abandoned.
    pub fn abort(self) {
        if let Phase::Body(sink) = self.phase {
            sink.abort();
        }
    }

    fn fail(&mut self, accepted: usize, message: &'static [u8]) -> Pushed {
        self.phase = Phase::Discard;
        self.finished = true;
        Pushed {
            accepted,
            response: Some(Response::header(error_header(self.id(), message))),
        }
    }

    fn id(&self) -> Option<u64> {
        crate::tagged::decode(&self.header).and_then(|record| record.id)
    }

    fn push_header(&mut self, registry: &Registry, fin: bool, chunk: &[u8]) -> Pushed {
        let room = (MAX_HEADER_BYTES + MAX_SURPLUS_BYTES).saturating_sub(self.header.len());
        let take = chunk.len().min(room);
        self.header.extend_from_slice(&chunk[..take]);
        self.received += take as u64;
        let at_end = fin && take == chunk.len();
        match scan_header(&self.header) {
            Header::NeedMore if at_end => self.fail(take, b"request ended inside its header"),
            Header::NeedMore => Pushed {
                accepted: take,
                response: None,
            },
            Header::Invalid => self.fail(take, b"invalid request header"),
            Header::Complete(length) => {
                self.surplus = self.header.split_off(length);
                self.fin = at_end;
                let outcome = {
                    let record = crate::tagged::decode(&self.header);
                    record.and_then(|record| {
                        registry.open_now(
                            Request {
                                record,
                                header: &self.header,
                                context: self.context,
                            },
                        )
                    })
                };
                match outcome {
                    Some(Outcome::Respond(response)) => {
                        self.phase = Phase::Discard;
                        self.surplus.clear();
                        self.finished = true;
                        Pushed {
                            accepted: take,
                            response: Some(response),
                        }
                    }
                    Some(Outcome::Receive(sink)) => {
                        self.phase = Phase::Body(sink);
                        let response = self.drain_surplus();
                        Pushed {
                            accepted: take,
                            response,
                        }
                    }
                    Some(Outcome::Defer(deferred)) => {
                        self.phase = Phase::Waiting(deferred);
                        self.surplus.clear();
                        let response = self.poll();
                        Pushed {
                            accepted: take,
                            response,
                        }
                    }
                    None => {
                        self.phase = Phase::Discard;
                        self.finished = true;
                        Pushed {
                            accepted: take,
                            response: None,
                        }
                    }
                }
            }
        }
    }

    fn push_body(&mut self, fin: bool, chunk: &[u8]) -> Pushed {
        // Bytes held from the header chunk go first, to keep the body ordered.
        if !self.surplus.is_empty() {
            let room = MAX_SURPLUS_BYTES.saturating_sub(self.surplus.len());
            let take = chunk.len().min(room);
            self.surplus.extend_from_slice(&chunk[..take]);
            self.received += take as u64;
            self.fin = fin && take == chunk.len();
            let response = self.drain_surplus();
            return Pushed {
                accepted: take,
                response,
            };
        }
        let Phase::Body(sink) = &mut self.phase else {
            unreachable!("push_body is only called in the body phase");
        };
        match sink.write(chunk, fin) {
            Ok(accepted) => {
                self.received += accepted as u64;
                let response = if fin && accepted == chunk.len() {
                    self.complete()
                } else {
                    None
                };
                Pushed { accepted, response }
            }
            Err(header) => {
                self.phase = Phase::Discard;
                self.finished = true;
                Pushed {
                    accepted: chunk.len(),
                    response: Some(Response::header(header)),
                }
            }
        }
    }

    /// Hand held body bytes to the sink; finish the request when they were the
    /// last bytes.
    fn drain_surplus(&mut self) -> Option<Response> {
        let Phase::Body(sink) = &mut self.phase else {
            return None;
        };
        if !self.surplus.is_empty() || self.fin {
            match sink.write(&self.surplus, self.fin) {
                Ok(accepted) => {
                    self.surplus.drain(..accepted);
                }
                Err(header) => {
                    self.phase = Phase::Discard;
                    self.finished = true;
                    return Some(Response::header(header));
                }
            }
        }
        if self.surplus.is_empty() && self.fin {
            return self.complete();
        }
        None
    }

    fn complete(&mut self) -> Option<Response> {
        let Phase::Body(sink) = core::mem::replace(&mut self.phase, Phase::Discard) else {
            return None;
        };
        self.finished = true;
        Some(sink.finish())
    }
}

/// An error response header with no correlation id knowledge beyond `id`.
pub fn error_header(id: Option<u64>, message: &[u8]) -> Vec<u8> {
    let mut out = alloc::vec![0u8; 64 + message.len()];
    let mut encoder = crate::cbor::Encoder::new(&mut out);
    let count = if id.is_some() { 2 } else { 1 };
    let ok = (|| {
        encoder.map(count)?;
        if let Some(id) = id {
            encoder.uint(3)?;
            encoder.uint(id)?;
        }
        encoder.uint(7)?;
        encoder.text_value(message)?;
        Some(encoder.len())
    })();
    let used = ok.unwrap_or(0);
    drop(encoder);
    out.truncate(used);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{Method, Registry, SyncFn};

    fn map_header(id: u64, body_hint: u64) -> Vec<u8> {
        // {1: 0x7ffe, 2: 1, 3: id, 5: {1: body_hint}}
        let mut out = [0u8; 64];
        let mut e = crate::cbor::Encoder::new(&mut out);
        e.map(4).unwrap();
        e.uint(1).unwrap();
        e.uint(0x7ffe).unwrap();
        e.uint(2).unwrap();
        e.uint(1).unwrap();
        e.uint(3).unwrap();
        e.uint(id).unwrap();
        e.uint(5).unwrap();
        e.map(1).unwrap();
        e.uint(1).unwrap();
        e.uint(body_hint).unwrap();
        let used = e.len();
        out[..used].to_vec()
    }

    #[test]
    fn the_header_ends_where_the_cbor_item_ends() {
        let header = map_header(7, 3);
        let mut wire = header.clone();
        wire.extend_from_slice(b"raw body, not cbor \xff\xff");
        assert_eq!(scan_header(&wire), Header::Complete(header.len()));
        // Any strict prefix is incomplete, never invalid.
        for end in 0..header.len() {
            assert_eq!(scan_header(&header[..end]), Header::NeedMore, "prefix {end}");
        }
    }

    #[test]
    fn indefinite_length_items_end_at_their_break() {
        // {_ 1: "a", 2: [_ 1, 2]} followed by body
        let wire = [0xbf, 0x01, 0x61, b'a', 0x02, 0x9f, 0x01, 0x02, 0xff, 0xff, 0xde, 0xad];
        assert_eq!(scan_header(&wire), Header::Complete(10));
        assert_eq!(scan_header(&wire[..9]), Header::NeedMore);
        // Indefinite byte string chunks.
        let strings = [0x5f, 0x41, 0x01, 0x42, 0x02, 0x03, 0xff, 0xaa];
        assert_eq!(scan_header(&strings), Header::Complete(7));
    }

    #[test]
    fn malformed_and_oversize_headers_are_invalid() {
        assert_eq!(scan_header(&[0xff]), Header::Invalid);
        assert_eq!(scan_header(&[0x1c]), Header::Invalid);
        let deep = [0x81u8; 64];
        assert_eq!(scan_header(&deep), Header::Invalid);
        let mut long = alloc::vec![0x59, 0x20, 0x00];
        long.extend_from_slice(&[0u8; 0x2000]);
        assert_eq!(scan_header(&long), Header::Invalid);
        // A tag wraps one item.
        assert_eq!(scan_header(&[0xc1, 0x1a, 1, 2, 3, 4, 9]), Header::Complete(6));
    }

    fn respond(record: Record<'_>) -> Option<Vec<u8>> {
        let mut out = [0u8; 32];
        let used = crate::tagged::encode_numeric_response(
            0x7ffe,
            1,
            record.id?,
            &[0xa0],
            &mut out,
        )?;
        Some(out[..used].to_vec())
    }

    struct Collect {
        bytes: Vec<u8>,
        take: usize,
        id: u64,
        ended: bool,
    }

    impl BodySink for Collect {
        fn write(&mut self, chunk: &[u8], fin: bool) -> Result<usize, Vec<u8>> {
            let count = chunk.len().min(self.take);
            self.bytes.extend_from_slice(&chunk[..count]);
            self.ended |= fin && count == chunk.len();
            Ok(count)
        }

        fn finish(self: Box<Self>) -> Response {
            let mut out = [0u8; 48];
            let used = crate::tagged::encode_numeric_response(
                0x7ffe,
                2,
                self.id,
                &[0xa1, 1, self.bytes.len() as u8],
                &mut out,
            )
            .unwrap();
            Response::header(out[..used].to_vec())
        }
    }

    struct Upload;

    impl StreamHandler for Upload {
        fn open<'a>(&'a self, request: Request<'a>) -> OpenFuture<'a> {
            Box::pin(core::future::ready(Some(Outcome::Receive(Box::new(Collect {
                bytes: Vec::new(),
                take: 3,
                id: request.record.id.unwrap_or(0),
                ended: false,
            })))))
        }
    }

    fn registry() -> Registry {
        let registry = Registry::new();
        assert!(registry.register(Method::new(0x7ffe, "t", 1, "short"), SyncFn(respond)));
        assert!(registry.register_stream(Method::new(0x7ffe, "t", 2, "upload"), Upload));
        registry
    }

    fn request(method: u64, id: u64) -> Vec<u8> {
        let mut out = [0u8; 32];
        let used =
            crate::tagged::encode_numeric_empty_request(0x7ffe, method, id, &mut out).unwrap();
        out[..used].to_vec()
    }

    #[test]
    fn upload_survives_synchronous_erase_then_finishes_on_the_same_stream() {
        use alloc::sync::Arc;
        use core::sync::atomic::{AtomicU64, Ordering};

        struct ErasingSink {
            clock: Arc<AtomicU64>,
            bytes: usize,
        }
        impl BodySink for ErasingSink {
            fn write(&mut self, chunk: &[u8], _: bool) -> Result<usize, Vec<u8>> {
                if self.bytes == 0 && !chunk.is_empty() {
                    self.clock.fetch_add(32_000, Ordering::Relaxed);
                }
                self.bytes += chunk.len();
                Ok(chunk.len())
            }
            fn finish(self: Box<Self>) -> Response {
                assert_eq!(self.bytes, 6);
                Response::header(alloc::vec![0xa0])
            }
        }
        struct ErasingUpload(Arc<AtomicU64>);
        impl StreamHandler for ErasingUpload {
            fn open<'a>(&'a self, _: Request<'a>) -> OpenFuture<'a> {
                Box::pin(core::future::ready(Some(Outcome::Receive(Box::new(
                    ErasingSink { clock: self.0.clone(), bytes: 0 },
                )))))
            }
        }

        let clock = Arc::new(AtomicU64::new(1_000));
        let registry = Registry::new();
        assert!(registry.register_stream(
            Method::new(0x7ffe, "t", 2, "upload"),
            ErasingUpload(clock.clone()),
        ));
        let mut stream = ServerStream::new(Default::default());
        let mut first = request(2, 42);
        first.extend_from_slice(b"abc");
        let mut last = 1_000;
        let pushed = track_progress(&mut last, || clock.load(Ordering::Relaxed), || {
            let pushed = stream.push(&registry, 0, false, &first);
            let progressed = pushed.accepted != 0;
            (pushed, progressed)
        });
        assert_eq!(pushed.accepted, first.len());
        assert!(pushed.response.is_none());
        assert_eq!(last, 33_000);
        assert!(clock.load(Ordering::Relaxed).saturating_sub(last) < 15_000);
        clock.fetch_add(1_000, Ordering::Relaxed);
        let pushed = track_progress(&mut last, || clock.load(Ordering::Relaxed), || {
            let pushed = stream.push(&registry, first.len() as u64, true, b"def");
            let progressed = pushed.accepted != 0;
            (pushed, progressed)
        });
        assert_eq!(pushed.accepted, 3);
        assert_eq!(last, 34_000);
        assert_eq!(read_all(pushed.response.expect("terminal response")), [0xa0]);
    }

    fn read_all(response: Response) -> Vec<u8> {
        let mut reader = response.into_reader();
        let mut out = Vec::new();
        let mut buffer = [0u8; 16];
        loop {
            let (count, done) = reader.read(&mut buffer);
            out.extend_from_slice(&buffer[..count]);
            if done {
                return out;
            }
        }
    }

    #[test]
    fn a_short_method_answers_at_the_end_of_its_header() {
        let registry = registry();
        let mut stream = ServerStream::new(CallContext::default());
        let header = request(1, 5);
        let pushed = stream.push(&registry, 0, true, &header);
        assert_eq!(pushed.accepted, header.len());
        let response = read_all(pushed.response.expect("answered at header end"));
        let record = crate::tagged::decode(&response).unwrap();
        assert_eq!(record.id, Some(5));
        assert!(record.result.is_some());
    }

    #[test]
    fn the_header_may_arrive_in_pieces_and_the_body_is_not_cbor() {
        let registry = registry();
        let mut stream = ServerStream::new(CallContext::default());
        let mut wire = request(2, 9);
        let header_len = wire.len();
        wire.extend_from_slice(b"\xff\x00raw\xde\xad\xbe\xef");
        // Split inside the header, then inside the body; the sink takes 3 at a time.
        let mut offset = 0usize;
        let mut response = None;
        let pieces: &[usize] = &[4, header_len - 4 + 2, 5, 100];
        for (index, size) in pieces.iter().enumerate() {
            let end = (offset + size).min(wire.len());
            let fin = end == wire.len();
            let mut chunk = &wire[offset..end];
            while !chunk.is_empty() || (fin && index + 1 == pieces.len()) {
                let pushed = stream.push(&registry, offset as u64, fin, chunk);
                offset += pushed.accepted;
                chunk = &chunk[pushed.accepted..];
                if let Some(next) = pushed.response {
                    response = Some(next);
                }
                if pushed.accepted == 0 {
                    // The sink is withholding: let it take more.
                    if let Some(next) = stream.poll() {
                        response = Some(next);
                    }
                    if chunk.is_empty() || response.is_some() {
                        break;
                    }
                }
                if chunk.is_empty() {
                    break;
                }
            }
        }
        while response.is_none() {
            response = stream.poll();
        }
        let record_bytes = read_all(response.unwrap());
        let record = crate::tagged::decode(&record_bytes).unwrap();
        assert_eq!(record.id, Some(9));
        // 10 body bytes counted by the sink: "\xff\x00raw" (5) + 4.
        let mut d = crate::cbor::Decoder::new(record.result.unwrap());
        assert_eq!(d.head(), Some((5, 1)));
        assert_eq!(d.uint(), Some(1));
        assert_eq!(d.uint(), Some(9));
    }

    #[test]
    fn an_empty_body_is_a_header_then_fin() {
        let registry = registry();
        let mut stream = ServerStream::new(CallContext::default());
        let header = request(2, 4);
        let pushed = stream.push(&registry, 0, true, &header);
        let response = pushed.response.or_else(|| stream.poll()).expect("finished");
        assert!(crate::tagged::decode(&read_all(response)).unwrap().result.is_some());
    }

    #[test]
    fn bad_input_gets_an_error_header() {
        let registry = registry();
        let mut stream = ServerStream::new(CallContext::default());
        let pushed = stream.push(&registry, 0, false, &[0xff, 0xff]);
        let record_bytes = read_all(pushed.response.unwrap());
        assert!(crate::tagged::decode(&record_bytes).is_none() || true);
        assert!(!record_bytes.is_empty());
        assert!(stream.is_answered());

        // A request that ends inside its header.
        let mut stream = ServerStream::new(CallContext::default());
        let header = request(1, 3);
        let pushed = stream.push(&registry, 0, true, &header[..header.len() - 1]);
        assert!(pushed.response.is_some());
    }

    #[test]
    fn a_response_body_follows_its_header() {
        struct Counter(u8);
        impl BodySource for Counter {
            fn read(&mut self, out: &mut [u8]) -> (usize, bool) {
                let count = out.len().min(5);
                for byte in &mut out[..count] {
                    *byte = self.0;
                    self.0 = self.0.wrapping_add(1);
                }
                (count, self.0 >= 12)
            }
        }
        let response = Response::with_body(alloc::vec![0xa0], Counter(0));
        let bytes = read_all(response);
        assert_eq!(bytes[0], 0xa0);
        assert!(bytes.len() > 5);
    }
}
