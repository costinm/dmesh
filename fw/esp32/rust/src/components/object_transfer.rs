//! Bearer-independent object-transfer receiver.
//!
//! UDP, BLE, FSK, and future bearers only provide datagram boundaries and an
//! output callback.  Stream reassembly, object framing, ACK ranges, flow
//! credit, and optional block verification live here.

use anyhow::{anyhow, bail, Result};
use dmesh_transport::{
    decode_frame, ConnectionLimits, EndpointState, Frame, RecoveryEndpoint, Role, ShortHeader,
    INITIAL_MAX_DATA, INITIAL_MAX_STREAM_DATA,
};
use sha2::{Digest, Sha256};

pub const DRS2_MAGIC: u32 = 0x4452_5332;
pub const DRS2_FRAME_MANIFEST: u16 = 6;
pub const DRS2_FRAME_BLOCK: u16 = 8;
pub const DRS2_FRAME_DONE: u16 = 10;
pub const DRS2_FRAME_MANIFEST_OK: u16 = 13;
pub const MANIFEST_STREAM: u64 = 3;
pub const BLOCK_STREAM: u64 = 7;
pub const MAX_STREAM_BUFFER: usize = 17 * 1024;
pub const MAX_PENDING_SEGMENTS: usize = 64;

#[derive(Clone, Debug)]
struct PendingSegment { offset: u64, fin: bool, data: Vec<u8> }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveEvent {
    pub header: ShortHeader,
    pub stream_id: u64,
    pub stream_end: u64,
    pub connection_end: u64,
    pub duplicate: bool,
    pub manifest_complete: bool,
    pub complete: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub image_bytes: u64,
    pub image_size: u64,
    pub stream_received: u64,
    pub block_count: u32,
    pub sha_blocks: u32,
    pub packets: u32,
    pub duplicate_packets: u32,
    pub pending_segments: usize,
}

pub trait ObjectSink {
    fn begin(&mut self, image_size: u64, block_count: u32) -> Result<()>;
    fn write_block(&mut self, index: u32, data: &[u8]) -> Result<()>;
    fn finish(&mut self) -> Result<()>;
}

pub struct NullSink;

impl ObjectSink for NullSink {
    fn begin(&mut self, _image_size: u64, _block_count: u32) -> Result<()> { Ok(()) }
    fn write_block(&mut self, _index: u32, _data: &[u8]) -> Result<()> { Ok(()) }
    fn finish(&mut self) -> Result<()> { Ok(()) }
}

/// Main's module slot sink.  It is deliberately kept beside the generic
/// receiver rather than in the Wi-Fi adapter so the same sink can be used by
/// BLE, FSK, or another bearer later.
pub struct ModuleFlashSink {
    offset: u32,
    limit: u32,
    image_size: u64,
    next_block: u32,
}

/// Main application sink. Recovery owns the update in production; this sink
/// is also available to the bearer-neutral receiver for controlled lab
/// transfers and keeps erase/write behavior identical to Recovery.
pub struct MainFlashSink {
    image_size: u64,
    next_block: u32,
}

extern "C" {
    fn dmesh_module_loader_offset() -> u32;
    fn dmesh_module_loader_partition_size() -> u32;
    fn dmesh_module_loader_flash_erase(address: u32, length: u32) -> i32;
    fn dmesh_module_loader_flash_write(address: u32, data: *const u8, length: usize) -> i32;
    fn dmesh_module_loader_refresh_header() -> bool;
    fn dmesh_main_flash_erase(length: u32) -> i32;
    fn dmesh_main_flash_write(offset: u32, data: *const u8, length: usize) -> i32;
}

impl MainFlashSink {
    pub fn new() -> Self { Self { image_size: 0, next_block: 0 } }
}

impl ObjectSink for MainFlashSink {
    fn begin(&mut self, image_size: u64, _block_count: u32) -> Result<()> {
        if image_size == 0 || image_size > 0x2e0000 {
            bail!("main image size out of range: {image_size}");
        }
        let result = unsafe { dmesh_main_flash_erase(image_size as u32) };
        if result != 0 { bail!("main bulk erase failed result={result}"); }
        self.image_size = image_size;
        self.next_block = 0;
        Ok(())
    }

    fn write_block(&mut self, index: u32, data: &[u8]) -> Result<()> {
        if index != self.next_block { bail!("main block order index={index} expected={}", self.next_block); }
        if data.len() > 4096 { bail!("main block too large bytes={}", data.len()); }
        let offset = index.checked_mul(4096).ok_or_else(|| anyhow!("main block offset overflow"))?;
        if u64::from(offset) + data.len() as u64 > self.image_size {
            bail!("main block exceeds image index={index}");
        }
        let result = unsafe { dmesh_main_flash_write(offset, data.as_ptr(), data.len()) };
        if result != 0 { bail!("main block write failed index={index} result={result}"); }
        self.next_block = self.next_block.saturating_add(1);
        Ok(())
    }

    fn finish(&mut self) -> Result<()> { Ok(()) }
}

impl ModuleFlashSink {
    pub fn new() -> Self {
        let offset = unsafe { dmesh_module_loader_offset() };
        let limit = unsafe { dmesh_module_loader_partition_size() };
        Self { offset, limit, image_size: 0, next_block: 0 }
    }
}

impl ObjectSink for ModuleFlashSink {
    fn begin(&mut self, image_size: u64, _block_count: u32) -> Result<()> {
        if image_size == 0 || image_size > u64::from(self.limit.saturating_sub(self.offset)) {
            bail!("module image size {} exceeds slot limit offset=0x{:x} size=0x{:x}", image_size, self.offset, self.limit);
        }
        let erase_len = ((image_size as u32).saturating_add(0xfff)) & !0xfff;
        let result = unsafe { dmesh_module_loader_flash_erase(self.offset, erase_len) };
        if result != 0 { bail!("module erase failed result={result}"); }
        self.image_size = image_size;
        self.next_block = 0;
        Ok(())
    }

    fn write_block(&mut self, index: u32, data: &[u8]) -> Result<()> {
        if index != self.next_block { bail!("module block order index={} expected={}", index, self.next_block); }
        if data.len() > 4096 { bail!("module block too large bytes={}", data.len()); }
        let address = self.offset.checked_add(index.checked_mul(4096).ok_or_else(|| anyhow!("module block offset overflow"))?)
            .ok_or_else(|| anyhow!("module flash address overflow"))?;
        let end = u64::from(address.saturating_sub(self.offset)) + data.len() as u64;
        if end > self.image_size { bail!("module block exceeds image index={} end={} image_size={}", index, end, self.image_size); }
        let result = unsafe { dmesh_module_loader_flash_write(address, data.as_ptr(), data.len()) };
        if result != 0 { bail!("module write failed index={} result={result}", index); }
        self.next_block = self.next_block.saturating_add(1);
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        if !unsafe { dmesh_module_loader_refresh_header() } { bail!("module header refresh failed after UDP flash"); }
        Ok(())
    }
}

pub enum TransferSink {
    Null(NullSink),
    Module(ModuleFlashSink),
    Main(MainFlashSink),
}

impl ObjectSink for TransferSink {
    fn begin(&mut self, image_size: u64, block_count: u32) -> Result<()> {
        match self { Self::Null(s) => s.begin(image_size, block_count), Self::Module(s) => s.begin(image_size, block_count), Self::Main(s) => s.begin(image_size, block_count) }
    }
    fn write_block(&mut self, index: u32, data: &[u8]) -> Result<()> {
        match self { Self::Null(s) => s.write_block(index, data), Self::Module(s) => s.write_block(index, data), Self::Main(s) => s.write_block(index, data) }
    }
    fn finish(&mut self) -> Result<()> {
        match self { Self::Null(s) => s.finish(), Self::Module(s) => s.finish(), Self::Main(s) => s.finish() }
    }
}

pub struct ObjectReceiver<S = NullSink> {
    sink: S,
    pub endpoint: RecoveryEndpoint<2>,
    verify_sha: bool,
    phase: u8,
    wire: Vec<u8>,
    stream_received: u64,
    image_bytes: u64,
    image_size: u64,
    block_count: u32,
    block_hashes: Vec<[u8; 4]>,
    sha_blocks: u32,
    packets: u32,
    duplicate_packets: u32,
    finished: bool,
    done_received: bool,
    pending: Vec<PendingSegment>,
}

impl ObjectReceiver<NullSink> {
    pub fn new(verify_sha: bool, max_datagram_size: u64) -> Self {
        Self::new_with_sink(verify_sha, max_datagram_size, NullSink)
    }
}

impl<S: ObjectSink> ObjectReceiver<S> {
    pub fn new_with_sink(verify_sha: bool, max_datagram_size: u64, sink: S) -> Self {
        Self {
            sink,
            endpoint: EndpointState::new(Role::Client, ConnectionLimits::default(), max_datagram_size),
            verify_sha,
            phase: 1,
            wire: Vec::new(),
            stream_received: 0,
            image_bytes: 0,
            image_size: 0,
            block_count: 0,
            block_hashes: Vec::new(),
            sha_blocks: 0,
            packets: 0,
            duplicate_packets: 0,
            finished: false,
            done_received: false,
            pending: Vec::new(),
        }
    }

    pub fn stats(&self) -> Stats {
        Stats {
            image_bytes: self.image_bytes,
            image_size: self.image_size,
            stream_received: self.stream_received,
            block_count: self.block_count,
            sha_blocks: self.sha_blocks,
            packets: self.packets,
            duplicate_packets: self.duplicate_packets,
            pending_segments: self.pending.len(),
        }
    }

    pub fn verify_sha(&self) -> bool { self.verify_sha }

    pub fn receive(&mut self, packet: &[u8]) -> Result<ReceiveEvent> {
        let (header, header_len) = ShortHeader::decode(packet).map_err(|error| anyhow!("UDP header: {error:?}"))?;
        let (frame, _) = decode_frame(&packet[header_len..]).map_err(|error| anyhow!("transport frame: {error:?}"))?;
        let Frame::Stream(stream) = frame else { bail!("object packet did not contain a stream") };
        if stream.id != MANIFEST_STREAM && stream.id != BLOCK_STREAM { bail!("unexpected object stream={}", stream.id); }
        let stream_end = stream.offset.saturating_add(stream.data.len() as u64);
        self.endpoint.receive.accept(stream.id, stream.offset, stream.data.len(), stream.fin)
            .map_err(|error| anyhow!("receive flow credit stream={} offset={} len={}: {error:?}", stream.id, stream.offset, stream.data.len()))?;
        self.endpoint.observe_packet(header.packet_number);
        self.packets = self.packets.saturating_add(1);

        // HELLO is intentionally retransmitted by the UDP sender.  A lost
        // MANIFEST_OK can therefore cause the manifest to be sent again after
        // the receiver has already entered block phase.  It is a duplicate
        // control frame, not a new object and must not be rejected as an
        // out-of-phase manifest.
        if stream.id == MANIFEST_STREAM && self.phase >= 2 {
            self.duplicate_packets = self.duplicate_packets.saturating_add(1);
            return Ok(self.event(header, stream.id, stream_end, true, false, false));
        }

        if stream.offset < self.stream_received {
            self.duplicate_packets = self.duplicate_packets.saturating_add(1);
            return Ok(self.event(header, stream.id, stream_end, true, false, false));
        }
        if stream.offset > self.stream_received {
            if !self.pending.iter().any(|segment| segment.offset == stream.offset) {
                if self.pending.len() >= MAX_PENDING_SEGMENTS {
                    bail!("object receive pending segment limit reached");
                }
                self.pending.push(PendingSegment { offset: stream.offset, fin: stream.fin, data: stream.data.to_vec() });
            }
            self.duplicate_packets = self.duplicate_packets.saturating_add(1);
            return Ok(self.event(header, stream.id, stream_end, false, false, false));
        }

        let mut fin = stream.fin;
        self.consume_contiguous(stream.id, stream.data)?;
        while let Some(index) = self.pending.iter().position(|segment| segment.offset == self.stream_received) {
            let segment = self.pending.remove(index);
            fin |= segment.fin;
            self.consume_contiguous(stream.id, &segment.data)?;
        }
        let manifest_complete = self.phase == 2 && stream.id == MANIFEST_STREAM && fin;
        // DRS2 terminates the block stream with FIN and then sends an explicit
        // DONE object frame.  Completion is reported only after DONE, so the
        // caller does not close the UDP session before the server's final
        // protocol frame has been consumed.
        let complete = self.done_received && stream.id == BLOCK_STREAM;
        if stream.id == MANIFEST_STREAM && fin && self.phase == 2 { self.phase = 2; }
        if stream.id == BLOCK_STREAM && fin && self.image_bytes == self.image_size { self.phase = 3; }
        self.endpoint.receive.extend_connection_credit(INITIAL_MAX_DATA);
        self.endpoint.receive.extend_stream_credit(stream.id, INITIAL_MAX_STREAM_DATA)
            .map_err(|error| anyhow!("stream credit extension: {error:?}"))?;
        Ok(self.event(header, stream.id, stream_end, false, manifest_complete, complete))
    }

    fn event(&self, header: ShortHeader, stream_id: u64, stream_end: u64, duplicate: bool, manifest_complete: bool, complete: bool) -> ReceiveEvent {
        ReceiveEvent { header, stream_id, stream_end, connection_end: self.endpoint.receive.connection.consumed, duplicate, manifest_complete, complete }
    }

    fn consume_contiguous(&mut self, stream_id: u64, data: &[u8]) -> Result<()> {
        if data.len() > MAX_STREAM_BUFFER.saturating_sub(self.wire.len()) { bail!("object stream buffer full"); }
        self.wire.extend_from_slice(data);
        self.stream_received = self.stream_received.saturating_add(data.len() as u64);
        self.endpoint.receive.consume(stream_id, data.len() as u64)
            .map_err(|error| anyhow!("receive consume: {error:?}"))?;
        loop {
            if self.wire.len() < 8 { return Ok(()); }
            let magic = u32::from_be_bytes(self.wire[0..4].try_into()?);
            let kind = u16::from_be_bytes(self.wire[4..6].try_into()?);
            let length = u16::from_be_bytes(self.wire[6..8].try_into()?) as usize;
            let frame_len = 8usize.saturating_add(length);
            if magic != DRS2_MAGIC { bail!("invalid object magic"); }
            if self.wire.len() < frame_len { return Ok(()); }
            let body = self.wire[8..frame_len].to_vec();
            self.wire.drain(..frame_len);
            match kind {
                DRS2_FRAME_MANIFEST if self.phase == 1 => self.accept_manifest(&body)?,
                DRS2_FRAME_BLOCK if self.phase == 2 && stream_id == BLOCK_STREAM => self.accept_block(&body)?,
                DRS2_FRAME_DONE if (self.phase == 2 || self.phase == 3) && stream_id == BLOCK_STREAM => {
                    if self.image_bytes != self.image_size { bail!("image bytes {} != {}", self.image_bytes, self.image_size); }
                    if !self.finished {
                        self.sink.finish()?;
                        self.finished = true;
                    }
                    self.phase = 3;
                    self.done_received = true;
                    return Ok(());
                }
                _ => bail!("unexpected object frame kind={} phase={} stream={}", kind, self.phase, stream_id),
            }
        }
    }

    fn accept_manifest(&mut self, body: &[u8]) -> Result<()> {
        if body.len() < 149 { bail!("truncated object manifest"); }
        let count = u32::from_be_bytes(body[12..16].try_into()?) as usize;
        self.image_size = u32::from_be_bytes(body[16..20].try_into()?) as u64;
        let hashes_start = 149usize;
        let hashes_len = count.checked_mul(4).ok_or_else(|| anyhow!("manifest hash table overflow"))?;
        if body.len() < hashes_start + hashes_len { bail!("truncated object hash table"); }
        self.block_count = count as u32;
        self.sink.begin(self.image_size, self.block_count)?;
        self.block_hashes.clear();
        if self.verify_sha {
            self.block_hashes.extend(body[hashes_start..hashes_start + hashes_len].chunks_exact(4).map(|chunk| [chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
        self.wire.clear();
        self.stream_received = 0;
        self.phase = 2;
        Ok(())
    }

    fn accept_block(&mut self, body: &[u8]) -> Result<()> {
        if body.len() < 12 { bail!("truncated object block"); }
        let index = u32::from_be_bytes(body[4..8].try_into()?) as usize;
        let length = u32::from_be_bytes(body[8..12].try_into()?) as usize;
        if length > body.len().saturating_sub(12) { bail!("object block length exceeds frame"); }
        if self.verify_sha {
            let expected = self.block_hashes.get(index).ok_or_else(|| anyhow!("block hash index out of range"))?;
            let digest = Sha256::digest(&body[12..12 + length]);
            if digest[..4] != expected[..] { bail!("object block SHA prefix mismatch index={index}"); }
            self.sha_blocks = self.sha_blocks.saturating_add(1);
        }
        self.image_bytes = self.image_bytes.saturating_add(length as u64);
        self.sink.write_block(index as u32, &body[12..12 + length])?;
        Ok(())
    }

    pub fn encode_ack(&self, out: &mut [u8], event: ReceiveEvent) -> Result<usize> {
        let largest = self.endpoint.largest_received().ok_or_else(|| anyhow!("ACK range empty"))?;
        let mut p = event.header.encode(out).map_err(|error| anyhow!("ACK header: {error:?}"))?;
        p += Frame::AckRanges { largest, delay: 0, ranges: self.endpoint.received_packets }
            .encode(&mut out[p..]).map_err(|error| anyhow!("ACK frame: {error:?}"))?;
        p += Frame::MaxData(event.connection_end.saturating_add(INITIAL_MAX_DATA))
            .encode(&mut out[p..]).map_err(|error| anyhow!("MAX_DATA frame: {error:?}"))?;
        if let Some(max_data) = self.endpoint.receive.stream_max_data(event.stream_id) {
            p += Frame::MaxStreamData { id: event.stream_id, max: max_data }
                .encode(&mut out[p..]).map_err(|error| anyhow!("MAX_STREAM_DATA frame: {error:?}"))?;
        }
        Ok(p)
    }
}
