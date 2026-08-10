// Bounded object-store protocol for embedded receivers.
//
// This module intentionally does not allocate, perform I/O, or know anything
// about NAN. A bearer passes DRS2 envelopes to Receiver and implements
// ObjectSink for the target storage. The same envelope can be carried in an
// action frame while data-frame transport is being validated.

#[allow(clippy::result_unit_err)]

use dmesh_transport::{decode_frame, ConnectionId, Frame, ShortHeader, StreamFrame, FLAG_FIXED};

pub const MAGIC: u32 = 0x4452_5332;
pub const ENVELOPE_VERSION: u8 = 1;
pub const ENVELOPE_LEN: usize = 16;
pub const BLOCK_SIZE: usize = 4096;
pub const FRAME_HELLO: u16 = 1;
pub const FRAME_MANIFEST: u16 = 6;
pub const FRAME_BLOCK: u16 = 8;
pub const FRAME_ACK: u16 = 9;
pub const FRAME_DONE: u16 = 10;
pub const FRAME_ERROR: u16 = 255;
pub const UDP_HELLO_LEN: usize = 90;
pub const UDP_HELLO_STREAM: u64 = 0;
pub const UDP_MANIFEST_STREAM: u64 = 3;
pub const UDP_DCID: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerKey {
    pub wifi_mac: [u8; 6],
    pub dcid: ConnectionId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectTarget {
    Module,
}

impl ObjectTarget {
    fn from_wire(v: u8) -> Result<Self, Error> {
        if v == 7 { Ok(Self::Module) } else { Err(Error::UnsupportedTarget) }
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
        if input.len() < Self::WIRE_LEN { return Err(Error::Truncated); }
        if u32::from_be_bytes(input[0..4].try_into().unwrap()) != MAGIC {
            return Err(Error::BadMagic);
        }
        let target = ObjectTarget::from_wire(input[4])?;
        let block_size = u16::from_be_bytes(input[5..7].try_into().unwrap());
        if block_size == 0 || block_size as usize > BLOCK_SIZE { return Err(Error::InvalidManifest); }
        let size = u64::from_be_bytes(input[7..15].try_into().unwrap());
        let block_count = u32::from_be_bytes(input[15..19].try_into().unwrap());
        if block_count == 0 || block_count as u64 > (size + block_size as u64 - 1) / block_size as u64 {
            return Err(Error::InvalidManifest);
        }
        let mut sha256 = [0u8; 32]; sha256.copy_from_slice(&input[19..51]);
        let name_len = input[51];
        if name_len > 32 { return Err(Error::InvalidManifest); }
        let mut name = [0u8; 32]; name.copy_from_slice(&input[52..84]);
        Ok(Self { target, size, block_size, block_count, sha256, name, name_len })
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
pub enum DatagramError {
    BufferTooSmall,
    Truncated,
    Invalid,
}

/// Metadata returned by the read-only UDP HELLO exchange. The payload points
/// into the caller's receive buffer; no allocation or I/O is performed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpManifest<'a> {
    pub dcid: ConnectionId,
    pub packet_number: u32,
    pub payload: &'a [u8],
}

/// Encode the DRS2 HELLO used by both the TCP and UDP object-store bearers.
/// The caller owns the datagram buffer and supplies the device model/target.
pub fn encode_udp_hello(model: u8, target: u8, dry_run: bool, out: &mut [u8]) -> Result<usize, DatagramError> {
    let mut hello = [0u8; UDP_HELLO_LEN];
    hello[0] = model;
    hello[71] = target;
    hello[89] = 0x07 | if dry_run { 0x08 } else { 0 }; // fixed layout, fast hashes, direct manifest
    let mut drs = [0u8; 8 + UDP_HELLO_LEN];
    drs[..4].copy_from_slice(&MAGIC.to_be_bytes());
    drs[4..6].copy_from_slice(&FRAME_HELLO.to_be_bytes());
    drs[6..8].copy_from_slice(&(UDP_HELLO_LEN as u16).to_be_bytes());
    drs[8..].copy_from_slice(&hello);
    let header = ShortHeader {
        flags: FLAG_FIXED,
        dcid: ConnectionId::new(UDP_DCID).unwrap(),
        packet_number: 0,
        packet_number_len: 2,
    };
    let header_len = header.encode(out).map_err(|_| DatagramError::BufferTooSmall)?;
    let frame_len = Frame::Stream(StreamFrame {
        id: UDP_HELLO_STREAM,
        offset: 0,
        fin: true,
        data: &drs,
    })
    .encode(&mut out[header_len..])
    .map_err(|_| DatagramError::BufferTooSmall)?;
    Ok(header_len + frame_len)
}

/// Parse the first lmesh UDP response to a HELLO. This validates the shared
/// QUIC-shaped header, stream identity, and DRS2 manifest frame only; it does
/// not accept blocks or perform any flash operation.
pub fn decode_udp_manifest<'a>(input: &'a [u8]) -> Result<UdpManifest<'a>, DatagramError> {
    let (header, header_len) = ShortHeader::decode(input).map_err(|_| DatagramError::Truncated)?;
    let (frame, _) = decode_frame(&input[header_len..]).map_err(|_| DatagramError::Truncated)?;
    let Frame::Stream(stream) = frame else { return Err(DatagramError::Invalid); };
    if stream.id != UDP_MANIFEST_STREAM || stream.offset != 0 || stream.data.len() < 8 {
        return Err(DatagramError::Invalid);
    }
    if u32::from_be_bytes(stream.data[..4].try_into().unwrap()) != MAGIC
        || u16::from_be_bytes(stream.data[4..6].try_into().unwrap()) != FRAME_MANIFEST
    {
        return Err(DatagramError::Invalid);
    }
    let length = u16::from_be_bytes(stream.data[6..8].try_into().unwrap()) as usize;
    // A manifest may span multiple UDP stream packets.  The first HELLO
    // response is only a transport probe, so accept a validated prefix and
    // let the stream layer reassemble the declared total length later.
    if stream.data.len() > 8 + length { return Err(DatagramError::Invalid); }
    Ok(UdpManifest { dcid: header.dcid, packet_number: header.packet_number, payload: &stream.data[8..] })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event { ManifestAccepted, BlockAccepted { index: u32, bytes: usize }, Complete, Rejected(Error) }

pub struct Receiver<S> {
    sink: S,
    manifest: Option<Manifest>,
    next_block: u32,
    bytes: u64,
    complete: bool,
}

impl<S> Receiver<S> {
    pub const fn new(sink: S) -> Self { Self { sink, manifest: None, next_block: 0, bytes: 0, complete: false } }
    pub fn sink_mut(&mut self) -> &mut S { &mut self.sink }
    pub fn manifest(&self) -> Option<Manifest> { self.manifest }
    pub fn is_complete(&self) -> bool { self.complete }

    pub fn on_manifest(&mut self, bytes: &[u8]) -> Result<Event, Error>
    where S: ObjectSink {
        if self.manifest.is_some() { return Err(Error::InvalidManifest); }
        let manifest = Manifest::decode(bytes)?;
        self.sink.begin(&manifest).map_err(|_| Error::Sink)?;
        self.manifest = Some(manifest);
        Ok(Event::ManifestAccepted)
    }

    pub fn on_block(&mut self, index: u32, offset: u64, data: &[u8]) -> Result<Event, Error>
    where S: ObjectSink {
        let manifest = self.manifest.ok_or(Error::InvalidManifest)?;
        if self.complete || index != self.next_block || offset != self.bytes || data.is_empty()
            || data.len() > manifest.block_size as usize
            || offset + data.len() as u64 > manifest.size { return Err(Error::InvalidBlock); }
        self.sink.write_block(index, offset, data).map_err(|_| Error::Sink)?;
        self.next_block += 1; self.bytes += data.len() as u64;
        Ok(Event::BlockAccepted { index, bytes: data.len() })
    }

    pub fn on_done(&mut self) -> Result<Event, Error>
    where S: ObjectSink {
        let manifest = self.manifest.ok_or(Error::InvalidManifest)?;
        if self.bytes != manifest.size || self.next_block != manifest.block_count { return Err(Error::InvalidBlock); }
        self.sink.finish(&manifest).map_err(|_| Error::Sink)?;
        self.complete = true; Ok(Event::Complete)
    }

    pub fn abort(&mut self)
    where S: ObjectSink {
        self.sink.abort(); self.manifest = None; self.next_block = 0; self.bytes = 0; self.complete = false;
    }
}

/// Prefix used by both NAN data and action frames. The remaining bytes are a
/// dmesh-transport packet or a DRS2 control frame.
pub fn encode_envelope(key: PeerKey, kind: u8, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let mut cid = [0u8; 8]; let cid_len = key.dcid.encode(&mut cid).map_err(|_| Error::InvalidBlock)?;
    let need = 4 + 1 + 1 + 6 + 1 + cid_len + payload.len();
    if out.len() < need { return Err(Error::Truncated); }
    out[0..4].copy_from_slice(&MAGIC.to_be_bytes()); out[4] = ENVELOPE_VERSION; out[5] = kind;
    out[6..12].copy_from_slice(&key.wifi_mac); out[12] = cid_len as u8; out[13..13 + cid_len].copy_from_slice(&cid[..cid_len]);
    out[13 + cid_len..need].copy_from_slice(payload); Ok(need)
}

pub fn decode_envelope(input: &[u8]) -> Result<(PeerKey, u8, &[u8]), Error> {
    if input.len() < 14 || u32::from_be_bytes(input[0..4].try_into().unwrap()) != MAGIC || input[4] != ENVELOPE_VERSION { return Err(Error::BadMagic); }
    let cid_len = input[12] as usize; if !matches!(cid_len, 1 | 2 | 4 | 8) || input.len() < 13 + cid_len { return Err(Error::Truncated); }
    let (dcid, _) = ConnectionId::decode(&input[13..]) .map_err(|_| Error::InvalidBlock)?;
    let mut mac = [0u8; 6]; mac.copy_from_slice(&input[6..12]);
    Ok((PeerKey { wifi_mac: mac, dcid }, input[5], &input[13 + cid_len..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Sink { blocks: u32, bytes: usize, done: bool }
    impl ObjectSink for Sink {
        type Error = ();
        fn begin(&mut self, _: &Manifest) -> Result<(), Self::Error> { Ok(()) }
        fn write_block(&mut self, _: u32, _: u64, data: &[u8]) -> Result<(), Self::Error> { self.blocks += 1; self.bytes += data.len(); Ok(()) }
        fn finish(&mut self, _: &Manifest) -> Result<(), Self::Error> { self.done = true; Ok(()) }
        fn abort(&mut self) {}
    }

    #[test]
    fn envelope_round_trip_uses_mac_and_dcid() {
        let key = PeerKey { wifi_mac: [1, 2, 3, 4, 5, 6], dcid: ConnectionId::new(0x1234).unwrap() };
        let mut out = [0u8; 64];
        let n = encode_envelope(key, 9, b"payload", &mut out).unwrap();
        let (got, kind, payload) = decode_envelope(&out[..n]).unwrap();
        assert_eq!(got, key); assert_eq!(kind, 9); assert_eq!(payload, b"payload");
    }

    #[test]
    fn receiver_accepts_ordered_module_blocks() {
        let mut bytes = [0u8; Manifest::WIRE_LEN];
        bytes[0..4].copy_from_slice(&MAGIC.to_be_bytes()); bytes[4] = 7;
        bytes[5..7].copy_from_slice(&(4u16).to_be_bytes()); bytes[7..15].copy_from_slice(&(8u64).to_be_bytes());
        bytes[15..19].copy_from_slice(&(2u32).to_be_bytes()); bytes[51] = 4; bytes[52..56].copy_from_slice(b"test");
        let mut receiver = Receiver::new(Sink { blocks: 0, bytes: 0, done: false });
        receiver.on_manifest(&bytes).unwrap(); receiver.on_block(0, 0, b"1234").unwrap(); receiver.on_block(1, 4, b"5678").unwrap();
        assert_eq!(receiver.on_done().unwrap(), Event::Complete); assert!(receiver.sink_mut().done);
    }

    #[test]
    fn udp_hello_is_shared_drs2_stream() {
        let mut packet = [0u8; 256];
        let len = encode_udp_hello(1, 6, true, &mut packet).unwrap();
        let (header, header_len) = ShortHeader::decode(&packet[..len]).unwrap();
        assert_eq!(header.dcid.value(), UDP_DCID);
        let (frame, _) = decode_frame(&packet[header_len..len]).unwrap();
        let Frame::Stream(stream) = frame else { panic!("expected HELLO stream") };
        assert_eq!(stream.id, UDP_HELLO_STREAM);
        assert_eq!(&stream.data[..4], &MAGIC.to_be_bytes());
        assert_eq!(&stream.data[4..6], &FRAME_HELLO.to_be_bytes());
        assert_eq!(stream.data.len(), 8 + UDP_HELLO_LEN);
    }
}
