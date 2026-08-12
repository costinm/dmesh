// Bounded object-store protocol for embedded receivers.
//
// This module intentionally does not allocate, perform I/O, or know anything
// about NAN. A bearer passes DRS2 envelopes to Receiver and implements
// ObjectSink for the target storage. The same envelope can be carried in an
// action frame while data-frame transport is being validated.

#[allow(clippy::result_unit_err)]

pub const MAGIC: u32 = 0x4452_5332;
pub const BLOCK_SIZE: usize = 4096;
pub const FRAME_MANIFEST: u16 = 6;
pub const FRAME_BLOCK: u16 = 8;
pub const FRAME_DONE: u16 = 10;

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
    fn receiver_accepts_ordered_module_blocks() {
        let mut bytes = [0u8; Manifest::WIRE_LEN];
        bytes[0..4].copy_from_slice(&MAGIC.to_be_bytes()); bytes[4] = 7;
        bytes[5..7].copy_from_slice(&(4u16).to_be_bytes()); bytes[7..15].copy_from_slice(&(8u64).to_be_bytes());
        bytes[15..19].copy_from_slice(&(2u32).to_be_bytes()); bytes[51] = 4; bytes[52..56].copy_from_slice(b"test");
        let mut receiver = Receiver::new(Sink { blocks: 0, bytes: 0, done: false });
        receiver.on_manifest(&bytes).unwrap(); receiver.on_block(0, 0, b"1234").unwrap(); receiver.on_block(1, 4, b"5678").unwrap();
        assert_eq!(receiver.on_done().unwrap(), Event::Complete); assert!(receiver.sink_mut().done);
    }

}
