//! Tokio trait implementations for the runtime-independent QUIC-lite API.
//!
//! This module intentionally defines no node, association, protocol stream,
//! bearer, or packet-storage type. [`crate::QuicAssociation`] and the common
//! [`crate::QuicStream`] own application-facing protocol state. Tokio support
//! connects bearer ingress to async waits and defines only the borrowed
//! Tokio ownership adapters required to implement `AsyncRead` and `AsyncWrite`.

use alloc::{boxed::Box, format, sync::Arc, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use std::{
    fs::File,
    io::{self, Write},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use ::tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use ::tokio::sync::{mpsc, oneshot};

use crate::bearer::{AddBearerError, PacketBearer};
use crate::{
    BearerId, PacketPool, QuicAssociation, QuicNode, QuicNodeEgressError, QuicStream,
    ReceivedStreamChunk,
};

const PACKET_CAPTURE_ENV: &str = "QUIC_LITE_PCAP";
const LINKTYPE_LINUX_SLL2: u32 = 276;
const SLL2_HEADER_LEN: usize = 20;
const ETH_P_QUIC_LITE: u16 = 0x88b5;

enum DriverCommand {
    Wake,
    RemoveBearer {
        bearer: BearerId,
        reply: oneshot::Sender<bool>,
    },
    Associate {
        meta: crate::PacketMeta,
        now_us: u64,
        reply: oneshot::Sender<Result<QuicAssociation, QuicNodeEgressError>>,
    },
    WaitEstablished {
        association: QuicAssociation,
        reply: oneshot::Sender<Result<(), QuicNodeEgressError>>,
    },
    OpenStream {
        association: QuicAssociation,
        reply: oneshot::Sender<Result<TokioStream, QuicNodeEgressError>>,
    },
    Write {
        stream: Arc<Mutex<QuicStream>>,
        bytes: Vec<u8>,
        fin: bool,
        partial: bool,
        reply: oneshot::Sender<Result<usize, QuicNodeEgressError>>,
    },
    Finish {
        association: QuicAssociation,
        reply: oneshot::Sender<Result<(), QuicNodeEgressError>>,
    },
}

/// Cloneable command handle for a Tokio-owned QUIC node driver.
#[derive(Clone)]
pub struct TokioNode {
    commands: mpsc::UnboundedSender<DriverCommand>,
    incoming: Arc<::tokio::sync::Mutex<mpsc::Receiver<TokioStream>>>,
    events: Arc<::tokio::sync::Mutex<mpsc::UnboundedReceiver<crate::AssociationEvent>>>,
}

/// Independently owned application stream routed by [`TokioNodeDriver`].
pub struct TokioStream {
    commands: mpsc::UnboundedSender<DriverCommand>,
    stream: Arc<Mutex<QuicStream>>,
    incoming: mpsc::Receiver<ReceivedStreamChunkData>,
    read_bytes: Vec<u8>,
    read_cursor: usize,
    read_finished: bool,
    pending_write: Option<Pin<Box<dyn Future<Output = Result<usize, QuicNodeEgressError>> + Send>>>,
    write_buffer: Vec<u8>,
    shutdown_started: bool,
}

struct ReceivedStreamChunkData {
    offset: u64,
    fin: bool,
    bytes: Vec<u8>,
}

/// Cloneable client association handle backed by one [`TokioNodeDriver`].
#[derive(Clone)]
pub struct TokioAssociation {
    node: TokioNode,
    association: QuicAssociation,
}

impl TokioNode {
    /// Accept the next independently owned peer stream.
    pub async fn accept_stream(&self) -> Option<TokioStream> {
        self.incoming.lock().await.recv().await
    }

    /// Receive the next terminal association lifecycle event.
    pub async fn next_event(&self) -> Option<crate::AssociationEvent> {
        self.events.lock().await.recv().await
    }

    /// Remove a registered bearer without stopping streams on other links.
    pub async fn remove_bearer(&self, bearer: BearerId) -> bool {
        let (reply, receive) = oneshot::channel();
        if self
            .commands
            .send(DriverCommand::RemoveBearer { bearer, reply })
            .is_err()
        {
            return false;
        }
        receive.await.unwrap_or(false)
    }
    /// Create a client association through the node-owning driver.
    pub async fn associate(
        &self,
        meta: crate::PacketMeta,
        now_us: u64,
    ) -> Result<TokioAssociation, QuicNodeEgressError> {
        let (reply, receive) = oneshot::channel();
        self.commands
            .send(DriverCommand::Associate {
                meta,
                now_us,
                reply,
            })
            .map_err(|_| QuicNodeEgressError::AssociationTimedOut)?;
        let association = receive
            .await
            .map_err(|_| QuicNodeEgressError::AssociationTimedOut)??;
        Ok(TokioAssociation {
            node: self.clone(),
            association,
        })
    }
}

impl TokioAssociation {
    /// Wait until the peer has completed this association's handshake.
    pub async fn wait_established(&self) -> Result<(), QuicNodeEgressError> {
        let (reply, receive) = oneshot::channel();
        self.node
            .commands
            .send(DriverCommand::WaitEstablished {
                association: self.association,
                reply,
            })
            .map_err(|_| QuicNodeEgressError::AssociationTimedOut)?;
        receive
            .await
            .map_err(|_| QuicNodeEgressError::AssociationTimedOut)?
    }

    /// Open another bidirectional stream without borrowing the node.
    pub async fn open_stream(&self) -> Result<TokioStream, QuicNodeEgressError> {
        let (reply, receive) = oneshot::channel();
        self.node
            .commands
            .send(DriverCommand::OpenStream {
                association: self.association,
                reply,
            })
            .map_err(|_| QuicNodeEgressError::AssociationTimedOut)?;
        receive
            .await
            .map_err(|_| QuicNodeEgressError::AssociationTimedOut)?
    }

    /// Gracefully close and retire this association.
    pub async fn finish(&self) -> Result<(), QuicNodeEgressError> {
        let (reply, receive) = oneshot::channel();
        self.node
            .commands
            .send(DriverCommand::Finish {
                association: self.association,
                reply,
            })
            .map_err(|_| QuicNodeEgressError::AssociationTimedOut)?;
        receive
            .await
            .map_err(|_| QuicNodeEgressError::AssociationTimedOut)?
    }
}

impl TokioStream {
    /// Receive the next ordered application chunk.
    pub async fn read_chunk(&mut self) -> Option<(u64, bool, Vec<u8>)> {
        let chunk = self
            .incoming
            .recv()
            .await
            .map(|chunk| (chunk.offset, chunk.fin, chunk.bytes));
        let _ = self.commands.send(DriverCommand::Wake);
        chunk
    }

    /// Accept as many bytes as fit the next packet and current flow window.
    pub async fn write(&mut self, bytes: Vec<u8>) -> Result<usize, QuicNodeEgressError> {
        let available = crate::DEFAULT_MAX_STREAM_PAYLOAD.saturating_sub(self.write_buffer.len());
        let accepted = available.min(bytes.len());
        self.write_buffer.extend_from_slice(&bytes[..accepted]);
        Ok(accepted)
    }

    /// Close this stream's sending half after all accepted bytes.
    pub async fn finish(&mut self) -> Result<(), QuicNodeEgressError> {
        let (reply, receive) = oneshot::channel();
        let bytes = core::mem::take(&mut self.write_buffer);
        self.commands
            .send(DriverCommand::Write {
                stream: self.stream.clone(),
                bytes,
                fin: true,
                partial: false,
                reply,
            })
            .map_err(|_| QuicNodeEgressError::AssociationTimedOut)?;
        receive
            .await
            .map_err(|_| QuicNodeEgressError::AssociationTimedOut)??;
        Ok(())
    }

    fn begin_write(&mut self, bytes: Vec<u8>, fin: bool) {
        let commands = self.commands.clone();
        let stream = self.stream.clone();
        self.pending_write = Some(Box::pin(async move {
            let (reply, receive) = oneshot::channel();
            commands
                .send(DriverCommand::Write {
                    stream,
                    bytes,
                    fin,
                    partial: false,
                    reply,
                })
                .map_err(|_| QuicNodeEgressError::AssociationTimedOut)?;
            receive
                .await
                .map_err(|_| QuicNodeEgressError::AssociationTimedOut)?
        }));
    }

    fn poll_pending_write(&mut self, context: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let Some(pending) = self.pending_write.as_mut() else {
            return Poll::Ready(Ok(0));
        };
        match pending.as_mut().poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending_write = None;
                Poll::Ready(result.map_err(|error| {
                    io::Error::other(format!("QUIC stream write failed: {error:?}"))
                }))
            }
        }
    }
}

impl AsyncRead for TokioStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.read_cursor < self.read_bytes.len() {
                let count = output
                    .remaining()
                    .min(self.read_bytes.len() - self.read_cursor);
                output.put_slice(&self.read_bytes[self.read_cursor..self.read_cursor + count]);
                self.read_cursor += count;
                return Poll::Ready(Ok(()));
            }
            if self.read_finished {
                return Poll::Ready(Ok(()));
            }
            match self.incoming.poll_recv(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    self.read_finished = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(chunk)) => {
                    self.read_bytes = chunk.bytes;
                    self.read_cursor = 0;
                    self.read_finished = chunk.fin;
                    let _ = self.commands.send(DriverCommand::Wake);
                }
            }
        }
    }
}

impl AsyncWrite for TokioStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending_write.is_some() {
            return match self.poll_pending_write(context) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(_)) => {
                    context.waker().wake_by_ref();
                    Poll::Pending
                }
            };
        }
        if self.shutdown_started {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "QUIC stream send half is closed",
            )));
        }
        let available = crate::DEFAULT_MAX_STREAM_PAYLOAD.saturating_sub(self.write_buffer.len());
        if available == 0 {
            let pending = core::mem::take(&mut self.write_buffer);
            self.begin_write(pending, false);
            context.waker().wake_by_ref();
            return Poll::Pending;
        }
        let count = bytes.len().min(available);
        self.write_buffer.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_write.is_none() && !self.write_buffer.is_empty() {
            let pending = core::mem::take(&mut self.write_buffer);
            self.begin_write(pending, false);
        }
        match self.poll_pending_write(context) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shutdown_started && self.pending_write.is_some() {
            match self.poll_pending_write(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(_)) => {}
            }
        }
        if !self.shutdown_started {
            if !self.write_buffer.is_empty() {
                let pending = core::mem::take(&mut self.write_buffer);
                self.begin_write(pending, false);
                return match self.poll_pending_write(context) {
                    Poll::Ready(Ok(_)) => {
                        context.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                    Poll::Pending => Poll::Pending,
                };
            }
            self.shutdown_started = true;
            self.begin_write(Vec::new(), true);
        }
        match self.poll_pending_write(context) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

struct StreamRoute {
    owner: crate::node::StreamOwner,
    stream_id: u64,
    incoming: mpsc::Sender<ReceivedStreamChunkData>,
}

struct PendingWrite {
    stream: Arc<Mutex<QuicStream>>,
    bytes: Vec<u8>,
    fin: bool,
    partial: bool,
    reply: oneshot::Sender<Result<usize, QuicNodeEgressError>>,
}

struct PendingOpen {
    association: QuicAssociation,
    reply: oneshot::Sender<Result<TokioStream, QuicNodeEgressError>>,
}

/// The single Tokio task which owns and advances one [`QuicNode`].
pub struct TokioNodeDriver<
    NextHop,
    const ASSOCIATIONS: usize,
    const ROUTES: usize,
    P: PacketPool + 'static,
    const CLIENT_HISTORY: usize = 8,
    const SERVER_STREAMS: usize = 8,
    const SERVER_HISTORY: usize = 8,
    const PACKET: usize = { crate::DEFAULT_MAX_PACKET_SIZE },
> {
    node: QuicNode<
        NextHop,
        ASSOCIATIONS,
        ROUTES,
        P,
        CLIENT_HISTORY,
        SERVER_STREAMS,
        SERVER_HISTORY,
        PACKET,
    >,
    limits: crate::ConnectionLimits,
    commands: mpsc::UnboundedReceiver<DriverCommand>,
    command_sender: mpsc::UnboundedSender<DriverCommand>,
    accepted: mpsc::Sender<TokioStream>,
    event_sender: mpsc::UnboundedSender<crate::AssociationEvent>,
    routes: Vec<StreamRoute>,
    establishment_waiters: Vec<(
        QuicAssociation,
        oneshot::Sender<Result<(), QuicNodeEgressError>>,
    )>,
    pending_writes: Vec<PendingWrite>,
    pending_opens: Vec<PendingOpen>,
    finish_waiters: Vec<(
        QuicAssociation,
        oneshot::Sender<Result<(), QuicNodeEgressError>>,
    )>,
}

impl<
    NextHop,
    const ASSOCIATIONS: usize,
    const ROUTES: usize,
    P,
    const CLIENT_HISTORY: usize,
    const SERVER_STREAMS: usize,
    const SERVER_HISTORY: usize,
    const PACKET: usize,
>
    TokioNodeDriver<
        NextHop,
        ASSOCIATIONS,
        ROUTES,
        P,
        CLIENT_HISTORY,
        SERVER_STREAMS,
        SERVER_HISTORY,
        PACKET,
    >
where
    NextHop: Copy,
    P: PacketPool + 'static,
    P::Buffer: Send,
{
    /// Transfer a fully configured node to its sole Tokio driver.
    pub fn new(
        node: QuicNode<
            NextHop,
            ASSOCIATIONS,
            ROUTES,
            P,
            CLIENT_HISTORY,
            SERVER_STREAMS,
            SERVER_HISTORY,
            PACKET,
        >,
        limits: crate::ConnectionLimits,
    ) -> (TokioNode, Self) {
        let (commands, receiver) = mpsc::unbounded_channel();
        let (accepted, incoming) = mpsc::channel(SERVER_STREAMS.max(1));
        let (event_sender, events) = mpsc::unbounded_channel();
        let handle = TokioNode {
            commands: commands.clone(),
            incoming: Arc::new(::tokio::sync::Mutex::new(incoming)),
            events: Arc::new(::tokio::sync::Mutex::new(events)),
        };
        (
            handle,
            Self {
                node,
                limits,
                commands: receiver,
                command_sender: commands,
                accepted,
                event_sender,
                routes: Vec::new(),
                establishment_waiters: Vec::new(),
                pending_writes: Vec::new(),
                pending_opens: Vec::new(),
                finish_waiters: Vec::new(),
            },
        )
    }

    /// Run until every command handle has been dropped or the node fails.
    pub async fn run(mut self) -> Result<(), QuicNodeEgressError> {
        loop {
            while let Some(event) = self.node.next_association_event() {
                let _ = self.event_sender.send(event);
            }
            let blocked = self.dispatch_stream_chunks();
            self.resolve_establishment_waiters();
            self.retry_pending_opens();
            self.retry_pending_writes();
            self.retry_finishes();
            if blocked {
                let Some(command) = self.commands.recv().await else {
                    return Ok(());
                };
                self.handle_command(command)?;
                continue;
            }
            ::tokio::select! {
                command = self.commands.recv() => {
                    let Some(command) = command else { return Ok(()); };
                    self.handle_command(command)?;
                }
                event = core::future::poll_fn(|context| {
                    self.node.poll_one_event(context, Some(self.limits))
                }) => {
                    event?;
                }
            }
        }
    }

    fn handle_command(&mut self, command: DriverCommand) -> Result<(), QuicNodeEgressError> {
        match command {
            DriverCommand::Wake => {}
            DriverCommand::RemoveBearer { bearer, reply } => {
                let _ = reply.send(self.node.remove_bearer(bearer));
            }
            DriverCommand::Associate {
                meta,
                now_us,
                reply,
            } => {
                let _ = reply.send(self.node.associate(meta, now_us));
            }
            DriverCommand::WaitEstablished { association, reply } => {
                if self.node.association_is_established(association) {
                    let _ = reply.send(Ok(()));
                } else {
                    self.establishment_waiters.push((association, reply));
                }
            }
            DriverCommand::OpenStream { association, reply } => {
                self.try_open(PendingOpen { association, reply });
            }
            DriverCommand::Write {
                stream,
                bytes,
                fin,
                partial,
                reply,
            } => {
                self.try_write(PendingWrite {
                    stream,
                    bytes,
                    fin,
                    partial,
                    reply,
                });
            }
            DriverCommand::Finish { association, reply } => {
                self.finish_waiters.push((association, reply));
            }
        }
        Ok(())
    }

    fn resolve_establishment_waiters(&mut self) {
        let mut pending = Vec::new();
        for (association, reply) in self.establishment_waiters.drain(..) {
            if self.node.association_is_established(association) {
                let _ = reply.send(Ok(()));
            } else {
                pending.push((association, reply));
            }
        }
        self.establishment_waiters = pending;
    }

    fn try_write(&mut self, pending: PendingWrite) {
        let result = {
            let mut stream = pending
                .stream
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if pending.fin && !pending.bytes.is_empty() {
                if stream.is_direct() {
                    self.node
                        .write_stream(&mut stream, &pending.bytes)
                        .and_then(|accepted| {
                            if accepted != pending.bytes.len() {
                                return Err(QuicNodeEgressError::Transport(crate::Error::Blocked));
                            }
                            self.node.finish_stream(&mut stream)?;
                            Ok(accepted)
                        })
                } else {
                    self.node
                        .write_stream_packet(&mut stream, &pending.bytes, true)
                        .map(|()| pending.bytes.len())
                }
            } else if pending.fin {
                self.node.finish_stream(&mut stream).map(|()| 0)
            } else if pending.partial {
                self.node.write_stream(&mut stream, &pending.bytes)
            } else {
                self.node
                    .write_stream_packet(&mut stream, &pending.bytes, false)
                    .map(|()| pending.bytes.len())
            }
        };
        if matches!(&result, Err(error) if error.is_stream_retryable()) {
            self.pending_writes.push(pending);
        } else {
            let _ = pending.reply.send(result);
        }
    }

    fn try_open(&mut self, pending: PendingOpen) {
        match self.node.open_stream(pending.association) {
            Ok(stream) => {
                let stream = self.register_stream(stream);
                let _ = pending.reply.send(Ok(stream));
            }
            Err(QuicNodeEgressError::Transport(crate::Error::StreamLimit)) => {
                self.pending_opens.push(pending);
            }
            Err(error) => {
                let _ = pending.reply.send(Err(error));
            }
        }
    }

    fn retry_pending_opens(&mut self) {
        for pending in core::mem::take(&mut self.pending_opens) {
            self.try_open(pending);
        }
    }

    fn retry_pending_writes(&mut self) {
        for pending in core::mem::take(&mut self.pending_writes) {
            self.try_write(pending);
        }
    }

    fn retry_finishes(&mut self) {
        for (association, reply) in core::mem::take(&mut self.finish_waiters) {
            match self.node.close_association(association, 0) {
                Ok(crate::node::NodeClose::Control(packet)) => {
                    match self.node.submit_node_packet(packet) {
                        Ok(()) => self.finish_waiters.push((association, reply)),
                        Err(error) if error.is_stream_retryable() => {
                            self.finish_waiters.push((association, reply));
                        }
                        Err(error) => {
                            let _ = reply.send(Err(error));
                        }
                    }
                }
                Ok(crate::node::NodeClose::Closed(packet)) => {
                    let _ = reply.send(self.node.submit_node_packet(packet));
                }
                Err(error) if error.is_stream_retryable() => {
                    self.finish_waiters.push((association, reply));
                }
                Err(error) => {
                    let _ = reply.send(Err(error));
                }
            }
        }
    }

    fn register_stream(&mut self, stream: QuicStream) -> TokioStream {
        let owner = stream.owner();
        let stream_id = stream.id();
        let stream = Arc::new(Mutex::new(stream));
        let (incoming, receiver) = mpsc::channel(self.node.stream_chunk_limit.max(1));
        self.routes.push(StreamRoute {
            owner,
            stream_id,
            incoming,
        });
        TokioStream {
            commands: self.command_sender.clone(),
            stream,
            incoming: receiver,
            read_bytes: Vec::new(),
            read_cursor: 0,
            read_finished: false,
            pending_write: None,
            write_buffer: Vec::new(),
            shutdown_started: false,
        }
    }

    fn dispatch_stream_chunks(&mut self) -> bool {
        while let Some(chunk) = self.node.stream_chunks.pop_front() {
            let route = self
                .routes
                .iter()
                .position(|route| route.owner == chunk.owner && route.stream_id == chunk.stream);
            let index = if let Some(index) = route {
                index
            } else {
                let stream = match chunk.owner {
                    crate::node::StreamOwner::Association(association) => {
                        QuicStream::incoming(association, chunk.stream)
                    }
                    crate::node::StreamOwner::Direct(reply) => {
                        QuicStream::direct(reply, chunk.stream)
                    }
                };
                let handle = self.register_stream(stream);
                let index = self.routes.len() - 1;
                if self.accepted.try_send(handle).is_err() {
                    self.routes.remove(index);
                    self.node.stream_chunks.push_front(chunk);
                    return true;
                }
                index
            };
            match self.routes[index]
                .incoming
                .try_send(ReceivedStreamChunkData {
                    offset: chunk.offset,
                    fin: chunk.fin,
                    bytes: chunk.bytes,
                }) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(data)) => {
                    self.node
                        .stream_chunks
                        .push_front(crate::node::QueuedStreamChunk {
                            owner: self.routes[index].owner,
                            stream: self.routes[index].stream_id,
                            offset: data.offset,
                            fin: data.fin,
                            bytes: data.bytes,
                        });
                    return true;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.routes.remove(index);
                }
            }
        }
        false
    }
}

/// Tokio-only packet capture enabled by `QUIC_LITE_PCAP=/path/to/file.pcap`.
///
/// The file uses classic pcap with the standard Linux cooked-v2 link type.
/// Its small cooked header records ingress/egress direction and the bearer ID;
/// bytes following that header are the exact opaque QUIC packet passed across
/// the bearer boundary. Capture failures never alter packet delivery.
pub(crate) struct PacketCapture {
    file: Mutex<File>,
}

impl PacketCapture {
    pub(crate) fn from_env() -> Option<Self> {
        let path = std::env::var_os(PACKET_CAPTURE_ENV)?;
        match File::create(&path).and_then(|mut file| {
            file.write_all(&0xa1b2_c3d4_u32.to_le_bytes())?;
            file.write_all(&2_u16.to_le_bytes())?;
            file.write_all(&4_u16.to_le_bytes())?;
            file.write_all(&0_i32.to_le_bytes())?;
            file.write_all(&0_u32.to_le_bytes())?;
            file.write_all(&u32::MAX.to_le_bytes())?;
            file.write_all(&LINKTYPE_LINUX_SLL2.to_le_bytes())?;
            Ok(file)
        }) {
            Ok(file) => Some(Self {
                file: Mutex::new(file),
            }),
            Err(error) => {
                std::eprintln!(
                    "quic-lite: cannot create packet capture {}: {error}",
                    path.to_string_lossy()
                );
                None
            }
        }
    }

    pub(crate) fn record(&self, ingress: bool, bearer: BearerId, packet: &[u8]) {
        if let Err(error) = self.write_record(ingress, bearer, packet) {
            std::eprintln!("quic-lite: packet capture write failed: {error}");
        }
    }

    fn write_record(&self, ingress: bool, bearer: BearerId, packet: &[u8]) -> io::Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let packet_len = SLL2_HEADER_LEN
            .checked_add(packet.len())
            .and_then(|len| u32::try_from(len).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "packet too large"))?;
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        file.write_all(&(timestamp.as_secs() as u32).to_le_bytes())?;
        file.write_all(&timestamp.subsec_micros().to_le_bytes())?;
        file.write_all(&packet_len.to_le_bytes())?;
        file.write_all(&packet_len.to_le_bytes())?;
        file.write_all(&ETH_P_QUIC_LITE.to_be_bytes())?;
        file.write_all(&0_u16.to_be_bytes())?;
        file.write_all(&u32::from(bearer.value()).to_be_bytes())?;
        file.write_all(&0_u16.to_be_bytes())?;
        file.write_all(&[if ingress { 0 } else { 4 }, 0])?;
        file.write_all(&[0; 8])?;
        file.write_all(packet)
    }
}

/// Deprecated exclusive-borrow adapter retained while callers migrate to
/// [`TokioNodeDriver`] and the owned [`TokioStream`].
///
/// This adapter exists only because Tokio's `AsyncRead` and `AsyncWrite`
/// traits require an object which retains unread bytes and a task waker. It
/// borrows the [`QuicNode`] that owns all protocol, bearer, and packet-pool
/// state; it does not create another driver, task, queue, association, or
/// packet pool. Dropping it releases the node borrow and does not close the
/// association.
pub struct BorrowedTokioStream<
    'a,
    NextHop,
    const ASSOCIATIONS: usize,
    const ROUTES: usize,
    P: PacketPool + 'static,
    const CLIENT_HISTORY: usize = 8,
    const SERVER_STREAMS: usize = 8,
    const SERVER_HISTORY: usize = 8,
    const PACKET: usize = { crate::DEFAULT_MAX_PACKET_SIZE },
> {
    node: &'a mut QuicNode<
        NextHop,
        ASSOCIATIONS,
        ROUTES,
        P,
        CLIENT_HISTORY,
        SERVER_STREAMS,
        SERVER_HISTORY,
        PACKET,
    >,
    stream: QuicStream,
    read_bytes: Vec<u8>,
    read_cursor: usize,
    next_read_offset: u64,
    read_finished: bool,
    direct_write: Option<Vec<u8>>,
    pending_write: Vec<u8>,
    clock_started: ::tokio::time::Instant,
    clock_base_us: u64,
    timer: Option<Pin<Box<::tokio::time::Sleep>>>,
    timer_deadline_us: Option<u64>,
}

impl<
    NextHop,
    const ASSOCIATIONS: usize,
    const ROUTES: usize,
    P,
    const CLIENT_HISTORY: usize,
    const SERVER_STREAMS: usize,
    const SERVER_HISTORY: usize,
    const PACKET: usize,
> QuicNode<NextHop, ASSOCIATIONS, ROUTES, P, CLIENT_HISTORY, SERVER_STREAMS, SERVER_HISTORY, PACKET>
where
    P: PacketPool + 'static,
    P::Buffer: Send,
{
    fn retain_admitted_stream_chunks(&mut self, chunks: Vec<crate::node::QueuedStreamChunk>) {
        // Admission is atomic at the packet boundary. Once receive state has
        // committed, every application chunk from that packet must remain
        // available even if the batch crosses the normal queue limit.
        self.stream_chunks.extend(chunks);
    }

    /// Add one physical packet bearer using Tokio ingress delivery.
    ///
    /// This Tokio-specific operation installs the node's asynchronous ingress
    /// sender in the bearer. Bearer callbacks and read tasks enqueue complete
    /// packets there without driving QUIC protocol state themselves. A
    /// no-std/RTOS owner uses [`crate::nostd::NoStdRuntime::add_bearer`] to
    /// install the corresponding fixed-capacity synchronous queue.
    ///
    /// In both cases the node owns the registered send callback, readiness
    /// state, send accounting, completion delivery, and packet pool. The
    /// bearer must return the same packet lease on completion and must not
    /// create a private ingress queue or packet pool.
    pub fn add_bearer<T>(
        &mut self,
        bearer: T,
    ) -> Result<crate::BearerId, AddBearerError<T::AttachError>>
    where
        T: PacketBearer<P> + 'static,
    {
        self.register_bearer_with_ingress(bearer, Arc::new(self.ingress_sender.clone()))
    }

    /// Borrow this node as a Tokio byte stream for a locally opened stream.
    ///
    /// This is analogous to retaining a connected `TcpStream`: callers use
    /// standard Tokio read, write, and shutdown operations while `QuicNode`
    /// continues to own packet routing, flow control, retransmission state,
    /// bearers, and storage. The exclusive borrow prevents an application from
    /// running a second competing node driver while this stream is active.
    pub fn stream<'a>(
        &'a mut self,
        stream: QuicStream,
    ) -> BorrowedTokioStream<
        'a,
        NextHop,
        ASSOCIATIONS,
        ROUTES,
        P,
        CLIENT_HISTORY,
        SERVER_STREAMS,
        SERVER_HISTORY,
        PACKET,
    >
    where
        NextHop: Copy,
    {
        BorrowedTokioStream::new(self, stream, Vec::new(), 0, false)
    }

    /// Borrow this node as a Tokio byte stream beginning with an accepted chunk.
    ///
    /// [`QuicNode::accept_stream`] returns the first available ordered chunk so
    /// a server can select a handler before committing to a Tokio task model.
    /// This method preserves that chunk as the first `AsyncRead` result and
    /// then continues the same stream through the node's normal receive path.
    pub fn accepted_stream<'a>(
        &'a mut self,
        accepted: ReceivedStreamChunk,
    ) -> BorrowedTokioStream<
        'a,
        NextHop,
        ASSOCIATIONS,
        ROUTES,
        P,
        CLIENT_HISTORY,
        SERVER_STREAMS,
        SERVER_HISTORY,
        PACKET,
    >
    where
        NextHop: Copy,
    {
        let next_read_offset = accepted.offset.saturating_add(accepted.bytes.len() as u64);
        BorrowedTokioStream::new(
            self,
            accepted.stream,
            accepted.bytes,
            next_read_offset,
            accepted.fin,
        )
    }

    fn take_stream_chunk(
        &mut self,
        owner: crate::node::StreamOwner,
        stream_id: u64,
    ) -> Option<ReceivedStreamChunk> {
        let index = self.stream_chunks.iter().position(|chunk| {
            let probe = match owner {
                crate::node::StreamOwner::Association(association) => {
                    QuicStream::incoming(association, stream_id)
                }
                crate::node::StreamOwner::Direct(reply) => QuicStream::direct(reply, stream_id),
            };
            probe.matches(chunk.owner, chunk.stream)
        })?;
        let chunk = self
            .stream_chunks
            .remove(index)
            .expect("position names an existing queued stream chunk");
        Some(ReceivedStreamChunk {
            stream: match chunk.owner {
                crate::node::StreamOwner::Association(association) => {
                    QuicStream::incoming(association, chunk.stream)
                }
                crate::node::StreamOwner::Direct(reply) => QuicStream::direct(reply, chunk.stream),
            },
            offset: chunk.offset,
            fin: chunk.fin,
            bytes: chunk.bytes,
        })
    }

    pub(crate) fn poll_one_event(
        &mut self,
        context: &mut Context<'_>,
        local_limits: Option<crate::ConnectionLimits>,
    ) -> Poll<Result<(), QuicNodeEgressError>>
    where
        NextHop: Copy,
    {
        if self.drain_bearer_events() {
            return Poll::Ready(Ok(()));
        }
        match self.retry_one_pending_control() {
            Ok(true) => return Poll::Ready(Ok(())),
            Ok(false) => {}
            Err(error) => return Poll::Ready(Err(error)),
        }
        if self.stream_chunks.len() >= self.stream_chunk_limit {
            return Poll::Ready(Err(QuicNodeEgressError::StreamEventsFull));
        }
        let received = match self.ingress.poll_receive(context) {
            Poll::Ready(received) => received,
            Poll::Pending => {
                self.completions.register_waker(context.waker());
                if self.drain_bearer_events() {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Pending;
            }
        };
        if let Some(capture) = &self.packet_capture {
            capture.record(true, received.meta.bearer, received.packet.bytes());
        }
        let first_server_cid = local_limits
            .map(|_| self.allocate_local_cid())
            .transpose()?;
        let second_server_cid = local_limits
            .map(|_| self.allocate_local_cid())
            .transpose()?;
        let mut chunks = Vec::new();
        let mut direct_chunk = None;
        let ingress = self
            .receive_packet(
                received.meta,
                received.packet,
                |open| {
                    let local_limits = local_limits?;
                    let first_server_cid = first_server_cid?;
                    let second_server_cid = second_server_cid?;
                    Some(crate::node::InitialAdmission {
                        server_cid: if first_server_cid == open.client_receive_cid {
                            second_server_cid
                        } else {
                            first_server_cid
                        },
                        local_limits,
                    })
                },
                |source, stream, offset, fin, bytes| {
                    match source {
                        crate::node::ApplicationStreamSource::Association(association) => {
                            chunks.push(crate::node::QueuedStreamChunk {
                                owner: crate::node::StreamOwner::Association(association),
                                stream,
                                offset,
                                fin,
                                bytes: bytes.to_vec(),
                            });
                        }
                        crate::node::ApplicationStreamSource::Direct => {
                            direct_chunk = Some((stream, offset, fin, bytes.to_vec()));
                        }
                    }
                    Ok(bytes.len())
                },
            )
            .map_err(|rejected| match rejected.reason {
                crate::node::QuicNodePacketRejection::Egress(error) => error,
                crate::node::QuicNodePacketRejection::Packet(error)
                | crate::node::QuicNodePacketRejection::Application(error) => {
                    QuicNodeEgressError::Transport(error)
                }
                crate::node::QuicNodePacketRejection::PeerClosed(_) => {
                    unreachable!("peer close is converted to NodeIngress::PeerClosed")
                }
            })?;
        match ingress {
            crate::node::NodeIngress::Initial { response, .. }
            | crate::node::NodeIngress::StatelessReset { response } => {
                self.submit_unassociated_packet(response)?;
            }
            crate::node::NodeIngress::Association { association, .. } => {
                self.submit_or_defer_control(association.association())?;
            }
            crate::node::NodeIngress::Direct(request) => {
                if let Some((stream, offset, fin, bytes)) = direct_chunk {
                    chunks.push(crate::node::QueuedStreamChunk {
                        owner: crate::node::StreamOwner::Direct(request.reply()),
                        stream,
                        offset,
                        fin,
                        bytes,
                    });
                }
            }
            crate::node::NodeIngress::Forward { .. } => {
                return Poll::Ready(Err(QuicNodeEgressError::RelayUnavailable));
            }
            _ => {}
        }
        // The packet has now committed receive state. Retain every application
        // chunk it admitted, even when this one packet crosses the queue's
        // normal high-water mark. A later packet is held at the preflight
        // check above until the application drains these chunks.
        self.retain_admitted_stream_chunks(chunks);
        Poll::Ready(Ok(()))
    }

    /// Take one packet from the node-owned ingress queue and run the common
    /// bearer-independent QUIC receive state machine.
    ///
    /// This is crate-only so applications cannot recreate a competing packet
    /// driver. The Tokio stream/service surface calls it while waiting for
    /// accepted streams. The no-std/RTOS surface reaches the same common state
    /// transition through one queued [`crate::nostd::NoStdRuntime::progress`]
    /// event instead.
    pub(crate) async fn receive_next<Admit, StreamEvent>(
        &mut self,
        admit_initial: Admit,
        on_stream: StreamEvent,
    ) -> Result<crate::node::NodeIngress<P::Buffer, P::Buffer, NextHop>, QuicNodeEgressError>
    where
        NextHop: Copy,
        Admit: FnMut(crate::BootstrapOpen) -> Option<crate::node::InitialAdmission>,
        StreamEvent: FnMut(
            crate::node::ApplicationStreamSource,
            u64,
            u64,
            bool,
            &[u8],
        ) -> Result<usize, crate::Error>,
    {
        let mut admit_initial = admit_initial;
        let mut on_stream = on_stream;
        let clock_started = ::tokio::time::Instant::now();
        let clock_base_us = self.clock_us();
        loop {
            self.drain_bearer_events();
            let now = clock_base_us.saturating_add(
                u64::try_from(clock_started.elapsed().as_micros()).unwrap_or(u64::MAX),
            );
            self.advance_clock(now);
            let deadline = self.next_deadline(crate::node::DEFAULT_INITIAL_PTO_US);
            let timer = async move {
                match deadline {
                    Some(deadline) => {
                        ::tokio::time::sleep(std::time::Duration::from_micros(
                            deadline.saturating_sub(now),
                        ))
                        .await;
                    }
                    None => core::future::pending::<()>().await,
                }
            };
            tokio::pin!(timer);
            tokio::select! {
                received = self.ingress.receive() => {
                    if let Some(capture) = &self.packet_capture {
                        capture.record(true, received.meta.bearer, received.packet.bytes());
                    }
                    return self.receive_packet(
                        received.meta,
                        received.packet,
                        &mut admit_initial,
                        &mut on_stream,
                    ).map_err(|rejected| match rejected.reason {
                        crate::node::QuicNodePacketRejection::Egress(error) => error,
                        crate::node::QuicNodePacketRejection::Packet(error)
                        | crate::node::QuicNodePacketRejection::Application(error) => {
                            QuicNodeEgressError::Transport(error)
                        }
                        crate::node::QuicNodePacketRejection::PeerClosed(_) => {
                            unreachable!("peer close is converted to NodeIngress::PeerClosed")
                        }
                    });
                }
                () = self.completions.changed() => {}
                () = &mut timer => {
                    let now = deadline.unwrap_or(now);
                    self.advance_clock(now);
                    match self.timer_expired(now, crate::node::DEFAULT_INITIAL_PTO_US)? {
                        Some(crate::node::NodeTimer::Egress(packet)) => {
                            self.submit_node_packet(packet)?;
                        }
                        Some(crate::node::NodeTimer::BootstrapTimedOut { .. }) => {
                            return Err(QuicNodeEgressError::AssociationTimedOut);
                        }
                        Some(crate::node::NodeTimer::IdleTimedOut { .. }) | None => {}
                    }
                }
            }
        }
    }

    /// Process at most one already-queued ingress event. Public operations use
    /// this to consume ACK/credit progress without introducing a polling loop.
    fn drive_one_queued_packet(&mut self) -> Result<bool, QuicNodeEgressError>
    where
        NextHop: Copy,
    {
        self.drain_bearer_events();
        if self.stream_chunks.len() >= self.stream_chunk_limit {
            return Err(QuicNodeEgressError::StreamEventsFull);
        }
        let Some(received) = self.ingress.try_receive() else {
            return Ok(false);
        };
        if let Some(capture) = &self.packet_capture {
            capture.record(true, received.meta.bearer, received.packet.bytes());
        }
        let mut chunks = alloc::vec::Vec::new();
        let mut direct_chunk = None;
        let ingress = self
            .receive_packet(
                received.meta,
                received.packet,
                |_| None,
                |source, stream, offset, fin, bytes| {
                    match source {
                        crate::node::ApplicationStreamSource::Association(association) => {
                            chunks.push(crate::node::QueuedStreamChunk {
                                owner: crate::node::StreamOwner::Association(association),
                                stream,
                                offset,
                                fin,
                                bytes: bytes.to_vec(),
                            });
                        }
                        crate::node::ApplicationStreamSource::Direct => {
                            direct_chunk = Some((stream, offset, fin, bytes.to_vec()));
                        }
                    }
                    Ok(bytes.len())
                },
            )
            .map_err(|rejected| match rejected.reason {
                crate::node::QuicNodePacketRejection::Egress(error) => error,
                crate::node::QuicNodePacketRejection::Packet(error)
                | crate::node::QuicNodePacketRejection::Application(error) => {
                    QuicNodeEgressError::Transport(error)
                }
                crate::node::QuicNodePacketRejection::PeerClosed(_) => {
                    unreachable!("peer close is converted to NodeIngress::PeerClosed")
                }
            })?;
        match ingress {
            crate::node::NodeIngress::StatelessReset { response } => {
                self.submit_unassociated_packet(response)?;
            }
            crate::node::NodeIngress::Association { association, .. } => {
                self.submit_or_defer_control(association.association())?;
            }
            crate::node::NodeIngress::Direct(request) => {
                if let Some((stream, offset, fin, bytes)) = direct_chunk {
                    chunks.push(crate::node::QueuedStreamChunk {
                        owner: crate::node::StreamOwner::Direct(request.reply()),
                        stream,
                        offset,
                        fin,
                        bytes,
                    });
                }
            }
            crate::node::NodeIngress::Forward { .. } => {
                return Err(QuicNodeEgressError::RelayUnavailable);
            }
            _ => {}
        }
        // Receive state has committed; this batch must remain durable. The
        // next packet observes the full queue before entering the state
        // machine and supplies backpressure while this batch is drained.
        self.retain_admitted_stream_chunks(chunks);
        Ok(true)
    }

    /// Wait for the first or next ordered application chunk from any peer.
    ///
    /// This is the server-side equivalent of accepting and reading a TCP or
    /// HTTP stream. The node admits new associations, handles duplicate
    /// Initial packets, routes established packets, and normalizes a
    /// connectionless long-message request into the same [`QuicStream`] type.
    /// A service therefore reads `offset`, bytes, and FIN and writes its reply
    /// through the returned stream without inspecting packet form or CIDs.
    pub async fn accept_stream(
        &mut self,
        local_limits: crate::ConnectionLimits,
    ) -> Result<ReceivedStreamChunk, QuicNodeEgressError>
    where
        NextHop: Copy,
    {
        loop {
            if let Some(chunk) = self.stream_chunks.pop_front() {
                let stream = match chunk.owner {
                    crate::node::StreamOwner::Association(association) => {
                        QuicStream::incoming(association, chunk.stream)
                    }
                    crate::node::StreamOwner::Direct(reply) => {
                        QuicStream::direct(reply, chunk.stream)
                    }
                };
                return Ok(ReceivedStreamChunk {
                    stream,
                    offset: chunk.offset,
                    fin: chunk.fin,
                    bytes: chunk.bytes,
                });
            }
            if self.stream_chunks.len() >= self.stream_chunk_limit {
                return Err(QuicNodeEgressError::StreamEventsFull);
            }
            let first_server_cid = self.allocate_local_cid()?;
            let second_server_cid = self.allocate_local_cid()?;
            let mut chunks = alloc::vec::Vec::new();
            let mut direct_chunk = None;
            let ingress = self
                .receive_next(
                    |open| {
                        let server_cid = if first_server_cid == open.client_receive_cid {
                            second_server_cid
                        } else {
                            first_server_cid
                        };
                        Some(crate::node::InitialAdmission {
                            server_cid,
                            local_limits,
                        })
                    },
                    |source, stream, offset, fin, bytes| {
                        match source {
                            crate::node::ApplicationStreamSource::Association(association) => {
                                chunks.push(crate::node::QueuedStreamChunk {
                                    owner: crate::node::StreamOwner::Association(association),
                                    stream,
                                    offset,
                                    fin,
                                    bytes: bytes.to_vec(),
                                });
                            }
                            crate::node::ApplicationStreamSource::Direct => {
                                direct_chunk = Some((stream, offset, fin, bytes.to_vec()));
                            }
                        }
                        Ok(bytes.len())
                    },
                )
                .await?;
            match ingress {
                crate::node::NodeIngress::Initial { response, .. }
                | crate::node::NodeIngress::StatelessReset { response } => {
                    self.submit_unassociated_packet(response)?;
                }
                crate::node::NodeIngress::Association { association, .. } => {
                    self.submit_or_defer_control(association.association())?;
                }
                crate::node::NodeIngress::Direct(request) => {
                    if let Some((stream, offset, fin, bytes)) = direct_chunk {
                        chunks.push(crate::node::QueuedStreamChunk {
                            owner: crate::node::StreamOwner::Direct(request.reply()),
                            stream,
                            offset,
                            fin,
                            bytes,
                        });
                    }
                }
                crate::node::NodeIngress::Forward { .. } => {
                    return Err(QuicNodeEgressError::RelayUnavailable);
                }
                _ => {}
            }
            // Do not discard an already-admitted batch. One packet may cross
            // the queue's normal high-water mark; subsequent packets wait for
            // the application to drain it.
            self.retain_admitted_stream_chunks(chunks);
        }
    }

    /// Wait until a client association has processed its server Initial
    /// response. This is the asynchronous equivalent of TCP connect finishing.
    pub async fn wait_established(
        &mut self,
        association: QuicAssociation,
    ) -> Result<(), QuicNodeEgressError>
    where
        NextHop: Copy,
    {
        while !self.association_is_established(association) {
            if self.stream_chunks.len() >= self.stream_chunk_limit {
                return Err(QuicNodeEgressError::StreamEventsFull);
            }
            let mut chunks = Vec::new();
            let mut direct_chunk = None;
            let ingress = self
                .receive_next(
                    |_| None,
                    |source, stream, offset, fin, bytes| {
                        match source {
                            crate::node::ApplicationStreamSource::Association(association) => {
                                chunks.push(crate::node::QueuedStreamChunk {
                                    owner: crate::node::StreamOwner::Association(association),
                                    stream,
                                    offset,
                                    fin,
                                    bytes: bytes.to_vec(),
                                });
                            }
                            crate::node::ApplicationStreamSource::Direct => {
                                direct_chunk = Some((stream, offset, fin, bytes.to_vec()));
                            }
                        }
                        Ok(bytes.len())
                    },
                )
                .await?;
            if let crate::node::NodeIngress::StatelessReset { response } = ingress {
                self.submit_unassociated_packet(response)?;
            } else if let crate::node::NodeIngress::Association { association, .. } = ingress {
                self.submit_or_defer_control(association.association())?;
            } else if let crate::node::NodeIngress::Direct(request) = ingress
                && let Some((stream, offset, fin, bytes)) = direct_chunk
            {
                chunks.push(crate::node::QueuedStreamChunk {
                    owner: crate::node::StreamOwner::Direct(request.reply()),
                    stream,
                    offset,
                    fin,
                    bytes,
                });
            }
            self.retain_admitted_stream_chunks(chunks);
        }
        Ok(())
    }

    /// Gracefully finish an association and retire all of its node state.
    ///
    /// This is the connection-level counterpart to
    /// [`AsyncWrite::shutdown`](::tokio::io::AsyncWrite::poll_shutdown), which
    /// finishes only one stream's sending half. The operation sends pending
    /// acknowledgements and flow-control updates before the final connection
    /// close, waits for bearer readiness or completion when required, and
    /// removes the association and its private routing entry. Applications do
    /// not handle connection IDs, close packets, or retry sequencing.
    ///
    /// A one-request client should call this after it has read the response to
    /// stream FIN. Long-lived clients retain the association and open more
    /// streams instead.
    pub async fn finish_association(
        &mut self,
        association: QuicAssociation,
    ) -> Result<(), QuicNodeEgressError>
    where
        NextHop: Copy,
    {
        loop {
            self.drain_bearer_events();
            match self.close_association(association, 0) {
                Ok(crate::node::NodeClose::Control(packet)) => {
                    self.submit_node_packet(packet)?;
                }
                Ok(crate::node::NodeClose::Closed(packet)) => {
                    self.submit_node_packet(packet)?;
                    return Ok(());
                }
                Err(error) if error.is_stream_retryable() => {
                    core::future::poll_fn(|context| self.poll_one_event(context, None)).await?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn write_stream_after_queued_progress(
        &mut self,
        stream: &mut QuicStream,
        bytes: &[u8],
        fin: bool,
    ) -> Result<(), QuicNodeEgressError>
    where
        NextHop: Copy,
    {
        let _ = self.drive_one_queued_packet()?;
        self.write_stream_packet(stream, bytes, fin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BearerName, PacketMeta, PacketWriter, PeerL2Address,
        fake::FakePacketBearer,
        node::{QueuedStreamChunk, StreamOwner},
        packet_pool::PacketPool,
    };
    use alloc::vec;

    type Pool = PacketPool<4, { crate::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
    type Node = QuicNode<(), 1, 1, Pool, 8, 1>;

    #[test]
    fn committed_packet_batch_is_retained_when_it_crosses_the_queue_limit() {
        static POOL: Pool = Pool::new();
        let (bearer, _peer) = FakePacketBearer::<Pool>::pair(
            BearerName::new("batch-node").unwrap(),
            BearerName::new("batch-peer").unwrap(),
        );
        let mut node = Node::new(None, &POOL);
        let bearer = node.add_bearer(bearer).unwrap();
        let association = node
            .associate(
                PacketMeta {
                    bearer,
                    peer_l2_address: PeerL2Address::new(1).unwrap(),
                    received_at_us: 0,
                },
                0,
            )
            .unwrap();
        node.drain_bearer_events();
        assert_eq!(node.stream_chunk_limit, 1);

        node.retain_admitted_stream_chunks(vec![
            QueuedStreamChunk {
                owner: StreamOwner::Association(association),
                stream: 0,
                offset: 0,
                fin: false,
                bytes: b"first".to_vec(),
            },
            QueuedStreamChunk {
                owner: StreamOwner::Association(association),
                stream: 4,
                offset: 0,
                fin: true,
                bytes: b"second".to_vec(),
            },
        ]);

        assert_eq!(node.stream_chunks.len(), 2);
        assert_eq!(node.stream_chunks.pop_front().unwrap().bytes, b"first");
        assert_eq!(node.stream_chunks.pop_front().unwrap().bytes, b"second");

        node.retain_admitted_stream_chunks(vec![QueuedStreamChunk {
            owner: StreamOwner::Association(association),
            stream: 8,
            offset: 0,
            fin: true,
            bytes: b"queued".to_vec(),
        }]);
        let mut writer = node
            .acquire_packet_writer(crate::PACKET_PREFIX_RESERVE)
            .unwrap();
        writer.payload_mut()[0] = 0;
        let packet = PacketWriter::commit(writer, 1).unwrap();
        node.ingress_sender.enqueue_packet(
            PacketMeta {
                bearer,
                peer_l2_address: PeerL2Address::new(1).unwrap(),
                received_at_us: 1,
            },
            packet,
        );

        let waker = std::task::Waker::noop();
        let mut context = Context::from_waker(waker);
        assert!(matches!(
            node.poll_one_event(&mut context, None),
            Poll::Ready(Err(QuicNodeEgressError::StreamEventsFull))
        ));
        assert!(
            node.ingress.try_receive().is_some(),
            "queue pressure must not dequeue and discard the next ingress packet"
        );
    }
}

impl<
    'a,
    NextHop,
    const ASSOCIATIONS: usize,
    const ROUTES: usize,
    P,
    const CLIENT_HISTORY: usize,
    const SERVER_STREAMS: usize,
    const SERVER_HISTORY: usize,
    const PACKET: usize,
>
    BorrowedTokioStream<
        'a,
        NextHop,
        ASSOCIATIONS,
        ROUTES,
        P,
        CLIENT_HISTORY,
        SERVER_STREAMS,
        SERVER_HISTORY,
        PACKET,
    >
where
    NextHop: Copy,
    P: PacketPool + 'static,
    P::Buffer: Send,
{
    fn new(
        node: &'a mut QuicNode<
            NextHop,
            ASSOCIATIONS,
            ROUTES,
            P,
            CLIENT_HISTORY,
            SERVER_STREAMS,
            SERVER_HISTORY,
            PACKET,
        >,
        stream: QuicStream,
        read_bytes: Vec<u8>,
        next_read_offset: u64,
        read_finished: bool,
    ) -> Self {
        let direct_write = stream.is_direct().then(Vec::new);
        let clock_base_us = node.clock_us();
        Self {
            node,
            stream,
            read_bytes,
            read_cursor: 0,
            next_read_offset,
            read_finished,
            direct_write,
            pending_write: Vec::new(),
            clock_started: ::tokio::time::Instant::now(),
            clock_base_us,
            timer: None,
            timer_deadline_us: None,
        }
    }

    fn now_us(&self) -> u64 {
        self.clock_base_us.saturating_add(
            u64::try_from(self.clock_started.elapsed().as_micros()).unwrap_or(u64::MAX),
        )
    }

    fn poll_progress(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.node.poll_one_event(context, None) {
            Poll::Ready(Ok(())) => {
                self.timer = None;
                self.timer_deadline_us = None;
                return Poll::Ready(Ok(()));
            }
            Poll::Ready(Err(error)) => return Poll::Ready(Err(Self::transport_error(error))),
            Poll::Pending => {}
        }
        let now = self.now_us();
        self.node.advance_clock(now);
        let Some(deadline) = self.node.next_deadline(crate::node::DEFAULT_INITIAL_PTO_US) else {
            self.timer = None;
            self.timer_deadline_us = None;
            return Poll::Pending;
        };
        let duration = std::time::Duration::from_micros(deadline.saturating_sub(now));
        let reset_timer = self.timer_deadline_us != Some(deadline);
        if reset_timer {
            self.timer = Some(Box::pin(::tokio::time::sleep(duration)));
            self.timer_deadline_us = Some(deadline);
        }
        let Some(timer) = self.timer.as_mut() else {
            return Poll::Pending;
        };
        if timer.as_mut().poll(context).is_pending() {
            return Poll::Pending;
        }
        self.timer = None;
        self.timer_deadline_us = None;
        let now = self.now_us().max(deadline);
        self.node.advance_clock(now);
        match self
            .node
            .timer_expired(now, crate::node::DEFAULT_INITIAL_PTO_US)
        {
            Ok(Some(crate::node::NodeTimer::Egress(packet))) => {
                match self.node.submit_node_packet(packet) {
                    Ok(()) => Poll::Ready(Ok(())),
                    Err(QuicNodeEgressError::PoolUnavailable | QuicNodeEgressError::BearerBusy) => {
                        context.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Err(error) => Poll::Ready(Err(Self::transport_error(error))),
                }
            }
            Ok(Some(crate::node::NodeTimer::BootstrapTimedOut { association })) => {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("QUIC association {association:?} timed out"),
                )))
            }
            Ok(Some(crate::node::NodeTimer::IdleTimedOut { association })) => {
                let _ = association;
                Poll::Ready(Ok(()))
            }
            Ok(None) => {
                context.waker().wake_by_ref();
                Poll::Pending
            }
            Err(QuicNodeEgressError::PoolUnavailable | QuicNodeEgressError::BearerBusy) => {
                context.waker().wake_by_ref();
                Poll::Pending
            }
            Err(error) => Poll::Ready(Err(Self::transport_error(error))),
        }
    }

    fn copy_read_bytes(&mut self, output: &mut ReadBuf<'_>) -> bool {
        let remaining = &self.read_bytes[self.read_cursor..];
        if remaining.is_empty() || output.remaining() == 0 {
            return false;
        }
        let count = remaining.len().min(output.remaining());
        output.put_slice(&remaining[..count]);
        self.read_cursor += count;
        if self.read_cursor == self.read_bytes.len() {
            self.read_bytes.clear();
            self.read_cursor = 0;
        }
        true
    }

    fn install_chunk(&mut self, chunk: ReceivedStreamChunk) -> io::Result<()> {
        if chunk.offset != self.next_read_offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "QUIC stream delivered a noncontiguous ordered chunk",
            ));
        }
        self.next_read_offset = self
            .next_read_offset
            .checked_add(chunk.bytes.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stream offset overflow"))?;
        self.read_bytes = chunk.bytes;
        self.read_cursor = 0;
        self.read_finished = chunk.fin;
        Ok(())
    }

    fn transport_error(error: QuicNodeEgressError) -> io::Error {
        io::Error::other(format!("QUIC stream operation failed: {error:?}"))
    }
}

impl<
    NextHop,
    const ASSOCIATIONS: usize,
    const ROUTES: usize,
    P,
    const CLIENT_HISTORY: usize,
    const SERVER_STREAMS: usize,
    const SERVER_HISTORY: usize,
    const PACKET: usize,
> AsyncRead
    for BorrowedTokioStream<
        '_,
        NextHop,
        ASSOCIATIONS,
        ROUTES,
        P,
        CLIENT_HISTORY,
        SERVER_STREAMS,
        SERVER_HISTORY,
        PACKET,
    >
where
    NextHop: Copy + Unpin,
    P: PacketPool + Unpin + 'static,
    P::Buffer: Send,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.copy_read_bytes(output) {
            return Poll::Ready(Ok(()));
        }
        if self.read_finished {
            return Poll::Ready(Ok(()));
        }
        let owner = self.stream.owner();
        let stream_id = self.stream.id();
        if let Some(chunk) = self.node.take_stream_chunk(owner, stream_id) {
            if let Err(error) = self.install_chunk(chunk) {
                return Poll::Ready(Err(error));
            }
            let _ = self.copy_read_bytes(output);
            return Poll::Ready(Ok(()));
        }
        match self.poll_progress(context) {
            Poll::Ready(Ok(())) => {
                let owner = self.stream.owner();
                let stream_id = self.stream.id();
                if let Some(chunk) = self.node.take_stream_chunk(owner, stream_id) {
                    if let Err(error) = self.install_chunk(chunk) {
                        return Poll::Ready(Err(error));
                    }
                    let _ = self.copy_read_bytes(output);
                    Poll::Ready(Ok(()))
                } else {
                    context.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<
    NextHop,
    const ASSOCIATIONS: usize,
    const ROUTES: usize,
    P,
    const CLIENT_HISTORY: usize,
    const SERVER_STREAMS: usize,
    const SERVER_HISTORY: usize,
    const PACKET: usize,
> AsyncWrite
    for BorrowedTokioStream<
        '_,
        NextHop,
        ASSOCIATIONS,
        ROUTES,
        P,
        CLIENT_HISTORY,
        SERVER_STREAMS,
        SERVER_HISTORY,
        PACKET,
    >
where
    NextHop: Copy + Unpin,
    P: PacketPool + Unpin + 'static,
    P::Buffer: Send,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.stream.send_finished() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "QUIC stream write half is closed",
            )));
        }
        if let Some(buffer) = self.direct_write.as_mut() {
            let remaining = crate::DEFAULT_MAX_STREAM_PAYLOAD.saturating_sub(buffer.len());
            if remaining == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "direct message exceeds one QUIC packet",
                )));
            }
            let count = remaining.min(bytes.len());
            buffer.extend_from_slice(&bytes[..count]);
            return Poll::Ready(Ok(count));
        }
        if !self.pending_write.is_empty() {
            let pending = core::mem::take(&mut self.pending_write);
            let result = {
                let this = &mut *self;
                this.node
                    .write_stream_after_queued_progress(&mut this.stream, &pending, false)
            };
            match result {
                Ok(()) => {
                    context.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Err(error) if error.is_stream_retryable() => {
                    self.pending_write = pending;
                    return match self.poll_progress(context) {
                        Poll::Ready(Ok(())) => {
                            context.waker().wake_by_ref();
                            Poll::Pending
                        }
                        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                        Poll::Pending => Poll::Pending,
                    };
                }
                Err(error) => return Poll::Ready(Err(Self::transport_error(error))),
            }
        }
        let window = match self.node.stream_send_window(&self.stream) {
            Ok(window) => window,
            Err(error) => return Poll::Ready(Err(Self::transport_error(error))),
        };
        let count = bytes
            .len()
            .min(crate::DEFAULT_MAX_STREAM_PAYLOAD)
            .min(usize::try_from(window).unwrap_or(usize::MAX));
        if count == 0 {
            return match self.poll_progress(context) {
                Poll::Ready(Ok(())) => {
                    context.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            };
        }
        self.pending_write.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.direct_write.is_some() || self.pending_write.is_empty() {
            return Poll::Ready(Ok(()));
        }
        let pending = core::mem::take(&mut self.pending_write);
        let result = {
            let this = &mut *self;
            this.node
                .write_stream_after_queued_progress(&mut this.stream, &pending, false)
        };
        match result {
            Ok(()) => Poll::Ready(Ok(())),
            Err(error) if error.is_stream_retryable() => {
                self.pending_write = pending;
                match self.poll_progress(context) {
                    Poll::Ready(Ok(())) => {
                        context.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                    Poll::Pending => Poll::Pending,
                }
            }
            Err(error) => Poll::Ready(Err(Self::transport_error(error))),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.stream.send_finished() {
            return Poll::Ready(Ok(()));
        }
        let direct = self.direct_write.take();
        let associated = core::mem::take(&mut self.pending_write);
        let result = {
            let this = &mut *self;
            let bytes = direct.as_deref().unwrap_or(&associated);
            this.node
                .write_stream_after_queued_progress(&mut this.stream, bytes, true)
        };
        match result {
            Ok(()) => Poll::Ready(Ok(())),
            Err(error) if error.is_stream_retryable() => {
                self.direct_write = direct;
                self.pending_write = associated;
                match self.poll_progress(context) {
                    Poll::Ready(Ok(())) => {
                        context.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                    Poll::Pending => Poll::Pending,
                }
            }
            Err(error) => Poll::Ready(Err(Self::transport_error(error))),
        }
    }
}
