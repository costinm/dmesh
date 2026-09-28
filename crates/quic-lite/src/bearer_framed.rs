//! Length-delimited reliable-stream implementation of the bearer contract.
//!
//! This is low-level L2 packet transport code. It must not inspect QUIC
//! headers or expose application streams, stream IDs, stream offsets, or FIN.
//! Each frame is one opaque QUIC packet encoded as a two-byte big-endian
//! length followed by exactly that many bytes. The format is suitable for TCP,
//! BLE CoC, and other reliable ordered byte transports.
//!
//! `TokioFramedBearer` is the host TCP initialization of that format. Other
//! reliable byte transports should reuse the framing rules and implement the
//! same [`crate::bearer`] interfaces; they must not implement a QUIC stream API.

#[cfg(feature = "tokio")]
use core::fmt;
#[cfg(feature = "tokio")]
use std::io;
#[cfg(feature = "tokio")]
use std::sync::{Arc, Mutex};

#[cfg(feature = "tokio")]
use tokio::io::AsyncReadExt;

#[cfg(feature = "tokio")]
use crate::bearer::{
    BearerContext, BearerInfo, BearerName, EgressSubmission, PacketBearer, PacketEgress,
    PacketMeta, PacketPool, PacketSendOutcome, PacketSubmitError, PacketWriter, PeerL2Address,
};

/// Bytes in the big-endian length prefix used by reliable-stream bearers.
pub const LENGTH_HEADER_BYTES: usize = 2;
/// Largest packet representable by the two-byte framing format.
pub const MAX_FRAMED_PACKET_BYTES: usize = u16::MAX as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Invalid packet length at the reusable reliable-stream framing boundary.
pub enum FramedPacketError {
    /// Zero is reserved and cannot represent a QUIC packet.
    Empty,
    /// Packet length exceeds the framing or caller-selected maximum.
    TooLarge(usize),
}

/// Encode the carrier header for one complete opaque packet.
///
/// This helper is runtime-independent and may be used by BLE CoC, firmware
/// drivers, or host reliable-stream bearers.
pub fn encode_packet_length(length: usize) -> Result<[u8; 2], FramedPacketError> {
    if length == 0 {
        return Err(FramedPacketError::Empty);
    }
    let length = u16::try_from(length).map_err(|_| FramedPacketError::TooLarge(length))?;
    Ok(length.to_be_bytes())
}

/// Decode and validate one carrier header.
pub fn decode_packet_length(header: [u8; 2], maximum: usize) -> Result<usize, FramedPacketError> {
    let length = usize::from(u16::from_be_bytes(header));
    if length == 0 {
        Err(FramedPacketError::Empty)
    } else if length > maximum {
        Err(FramedPacketError::TooLarge(length))
    } else {
        Ok(length)
    }
}

#[cfg(feature = "tokio")]
#[derive(Debug)]
/// Failure while attaching a [`TokioFramedBearer`] to a node.
///
/// Background stream I/O and framing failures are private bearer state and are
/// reported through packet completion or by ending the bearer task.
pub enum FramedBearerError {
    /// The receive half was already attached to a node.
    AlreadyAttached,
}

#[cfg(feature = "tokio")]
impl fmt::Display for FramedBearerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyAttached => formatter.write_str("framed bearer is already attached"),
        }
    }
}

#[cfg(feature = "tokio")]
impl std::error::Error for FramedBearerError {}

#[cfg(feature = "tokio")]
enum FramedIoError {
    Io(io::Error),
    InvalidFrameLength(usize),
    WriteClosed,
}

#[cfg(feature = "tokio")]
impl From<io::Error> for FramedIoError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(feature = "tokio")]
struct ActiveWrite<B: AsRef<[u8]>> {
    submission: EgressSubmission<B>,
    header: [u8; 2],
    written: usize,
}

/// Point-to-point host bearer for two-byte length-delimited packets.
///
/// `submit` never waits. It may retain the single frame whose write has
/// started; its private writer task completes that frame and returns the packet
/// lease through the submission's normal completion callback. No later packet
/// is queued by this bearer.
#[cfg(feature = "tokio")]
pub struct TokioFramedBearer<P>
where
    P: PacketPool + 'static,
{
    info: BearerInfo,
    reader: Option<tokio::net::tcp::OwnedReadHalf>,
    shared: Arc<FramedWriteState<P::Buffer>>,
}

#[cfg(feature = "tokio")]
struct FramedWriteState<B: AsRef<[u8]>> {
    writer: tokio::net::tcp::OwnedWriteHalf,
    active: Mutex<Option<ActiveWrite<B>>>,
    progress: tokio::sync::Notify,
}

#[cfg(feature = "tokio")]
impl<P> TokioFramedBearer<P>
where
    P: PacketPool + 'static,
{
    /// Connect TCP and wrap it as an opaque length-delimited packet bearer.
    ///
    /// TCP is only one carrier for this format; applications still register
    /// the result through [`crate::QuicNode::add_bearer`].
    pub async fn connect_tcp(address: std::net::SocketAddr, name: BearerName) -> io::Result<Self> {
        let stream = tokio::net::TcpStream::connect(address).await?;
        Ok(Self::from_tcp(stream, name))
    }

    /// Adopt an established TCP stream as a length-delimited packet bearer.
    pub fn from_tcp(stream: tokio::net::TcpStream, name: BearerName) -> Self {
        let (reader, writer) = stream.into_split();
        Self {
            info: BearerInfo {
                name,
                max_packet_size: crate::DEFAULT_MAX_PACKET_SIZE,
                prefix_required: 0,
                suffix_required: 0,
                requires_packet_encryption: true,
                secure_link: false,
                nominal_bitrate_bps: 0,
                local_mac: None,
            },
            reader: Some(reader),
            shared: Arc::new(FramedWriteState {
                writer,
                active: Mutex::new(None),
                progress: tokio::sync::Notify::new(),
            }),
        }
    }
}

#[cfg(feature = "tokio")]
fn progress_active_write<B: AsRef<[u8]>>(
    shared: &FramedWriteState<B>,
) -> Result<bool, FramedIoError> {
    let mut guard = shared.active.lock().unwrap();
    let Some(active) = guard.as_mut() else {
        // A previous zero-byte WouldBlock did not transfer a submission.
        // Socket writability is therefore the capacity-return event which
        // lets the node retry its retained packet.
        return Ok(true);
    };
    let packet = active.submission.packet().bytes();
    let total = 2 + packet.len();
    let result = if active.written < 2 {
        let header = &active.header[active.written..];
        let slices = [io::IoSlice::new(header), io::IoSlice::new(packet)];
        shared.writer.try_write_vectored(&slices)
    } else {
        shared.writer.try_write(&packet[active.written - 2..])
    };
    match result {
        Ok(0) => {
            let active = guard.take().unwrap();
            active.submission.complete(PacketSendOutcome::Failed, 0);
            Err(FramedIoError::WriteClosed)
        }
        Ok(written) => {
            active.written += written;
            if active.written == total {
                let active = guard.take().unwrap();
                active.submission.complete(PacketSendOutcome::Sent, 0);
                return Ok(true);
            }
            Ok(false)
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => {
            let active = guard.take().unwrap();
            active.submission.complete(PacketSendOutcome::Failed, 0);
            Err(FramedIoError::Io(error))
        }
    }
}

#[cfg(feature = "tokio")]
async fn receive_framed<P>(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    context: BearerContext<P>,
) -> Result<(), FramedIoError>
where
    P: PacketPool + Sync + 'static,
    P::Writer: Send,
{
    let peer_l2_address = PeerL2Address::new(1).expect("one is a valid L2 address");
    loop {
        let mut header = [0; 2];
        let mut header_len = 0;
        while header_len < 2 {
            let read = reader.read(&mut header[header_len..]).await?;
            if read == 0 {
                return Err(FramedIoError::WriteClosed);
            }
            header_len += read;
        }
        let declared = usize::from(u16::from_be_bytes(header));
        let receive_len = decode_packet_length(header, crate::DEFAULT_MAX_PACKET_SIZE)
            .map_err(|_| FramedIoError::InvalidFrameLength(declared))?;
        let Some(mut writer) = context
            .pool()
            .acquire_writer(crate::PACKET_PREFIX_RESERVE, 0)
        else {
            // A reliable carrier cannot abandon a frame after consuming its
            // length header without desynchronizing every later packet. Drain
            // only this frame into fixed scratch storage; do not wait for the
            // pool or allocate fallback packet storage.
            let mut remaining = receive_len;
            let mut discard = [0u8; 256];
            while remaining != 0 {
                let take = remaining.min(discard.len());
                let read = reader.read(&mut discard[..take]).await?;
                if read == 0 {
                    return Err(FramedIoError::WriteClosed);
                }
                remaining -= read;
            }
            continue;
        };
        let mut body_len = 0;
        while body_len < receive_len {
            let read = reader
                .read(&mut writer.payload_mut()[body_len..receive_len])
                .await?;
            if read == 0 {
                return Err(FramedIoError::WriteClosed);
            }
            body_len += read;
        }
        let packet = writer
            .commit(receive_len)
            .ok_or(FramedIoError::InvalidFrameLength(receive_len))?;
        context.enqueue_packet(
            PacketMeta {
                bearer: context.bearer(),
                peer_l2_address,
                received_at_us: 0,
            },
            packet,
        );
    }
}

#[cfg(feature = "tokio")]
impl<P> PacketEgress<P::Buffer> for TokioFramedBearer<P>
where
    P: PacketPool + 'static,
{
    fn submit(
        &mut self,
        _peer_l2_address: PeerL2Address,
        submission: EgressSubmission<P::Buffer>,
    ) -> Result<(), PacketSubmitError<P::Buffer>> {
        let mut active_write = self.shared.active.lock().unwrap();
        if active_write.is_some() {
            return Err(PacketSubmitError::WouldBlock(submission));
        }
        let length = submission.packet().bytes().len();
        let header = match encode_packet_length(length) {
            Ok(header) => header,
            Err(FramedPacketError::Empty) => {
                submission.complete(PacketSendOutcome::Failed, 0);
                return Ok(());
            }
            Err(FramedPacketError::TooLarge(_length)) => {
                submission.complete(PacketSendOutcome::Failed, 0);
                return Ok(());
            }
        };
        let slices = [
            io::IoSlice::new(&header),
            io::IoSlice::new(submission.packet().bytes()),
        ];
        match self.shared.writer.try_write_vectored(&slices) {
            Ok(0) => {
                submission.complete(PacketSendOutcome::Failed, 0);
                Ok(())
            }
            Ok(written) if written == length + 2 => {
                submission.complete(PacketSendOutcome::Sent, 0);
                Ok(())
            }
            Ok(written) => {
                // Ownership transfers once any byte of the frame is written.
                // The exact submission remains here until completion.
                *active_write = Some(ActiveWrite {
                    submission,
                    header,
                    written,
                });
                self.shared.progress.notify_one();
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                self.shared.progress.notify_one();
                Err(PacketSubmitError::WouldBlock(submission))
            }
            Err(_error) => {
                submission.complete(PacketSendOutcome::Failed, 0);
                Ok(())
            }
        }
    }
}

#[cfg(feature = "tokio")]
impl<P> PacketBearer<P> for TokioFramedBearer<P>
where
    P: PacketPool + Sync + 'static,
    P::Buffer: Send + 'static,
    P::Writer: Send + 'static,
{
    type AttachError = FramedBearerError;

    fn info(&self) -> BearerInfo {
        self.info
    }

    fn attach(&mut self, context: BearerContext<P>) -> Result<(), Self::AttachError> {
        let reader = self
            .reader
            .take()
            .ok_or(FramedBearerError::AlreadyAttached)?;
        let receive_context = context.clone();
        tokio::spawn(async move {
            let _ = receive_framed(reader, receive_context).await;
        });

        let shared = self.shared.clone();
        tokio::spawn(async move {
            loop {
                shared.progress.notified().await;
                if shared.writer.writable().await.is_err() {
                    break;
                }
                match progress_active_write(&shared) {
                    Ok(true) => context.send_ready(),
                    Ok(false) => shared.progress.notify_one(),
                    Err(_) => break,
                }
            }
        });
        Ok(())
    }
}

#[cfg(all(test, feature = "tokio"))]
mod tests {
    use super::*;

    #[test]
    fn length_codec_uses_only_packet_framing() {
        assert_eq!(encode_packet_length(0), Err(FramedPacketError::Empty));
        assert_eq!(encode_packet_length(258).unwrap(), [1, 2]);
        assert_eq!(decode_packet_length([1, 2], 512).unwrap(), 258);
        assert_eq!(
            decode_packet_length([1, 2], 128),
            Err(FramedPacketError::TooLarge(258))
        );
    }
}
