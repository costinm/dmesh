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

use crate::bearer::{AddBearerError, PacketBearer, ReceivedPacket};
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
    P: PacketPool + 'static,
    const PACKET: usize = { crate::DEFAULT_MAX_PACKET_SIZE },
> {
    node: QuicNode<P, PACKET>,
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
    closing_associations: Vec<QuicAssociation>,
}

impl<P, const PACKET: usize> TokioNodeDriver<P, PACKET>
where
    P: PacketPool + 'static,
    P::Buffer: Send,
{
    /// Transfer a fully configured node to its sole Tokio driver.
    pub fn new(node: QuicNode<P, PACKET>, limits: crate::ConnectionLimits) -> (TokioNode, Self) {
        let (commands, receiver) = mpsc::unbounded_channel();
        let (accepted, incoming) =
            mpsc::channel(node.default_association_limits().max_pending_streams.max(1));
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
                closing_associations: Vec::new(),
            },
        )
    }

    /// Run until every command handle has been dropped or the node fails.
    pub async fn run(mut self) -> Result<(), QuicNodeEgressError> {
        loop {
            self.dispatch_stream_chunks();
            self.dispatch_association_events();
            self.resolve_establishment_waiters();
            self.retry_pending_opens();
            self.retry_pending_writes();
            self.retry_finishes();
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

    fn dispatch_association_events(&mut self) {
        while let Some(event) = self.node.next_association_event() {
            if matches!(event, crate::AssociationEvent::EventsDropped { .. }) {
                self.routes.retain(|route| match route.owner {
                    crate::node::StreamOwner::Association(association) => {
                        self.node.contains_association(association)
                    }
                });
                let _ = self.event_sender.send(event);
                continue;
            }
            let association = match event {
                crate::AssociationEvent::Closed { association, .. }
                | crate::AssociationEvent::Reset { association }
                | crate::AssociationEvent::IdleTimeout { association }
                | crate::AssociationEvent::SetupTimeout { association } => association,
                crate::AssociationEvent::EventsDropped { .. } => unreachable!(),
            };
            if matches!(event, crate::AssociationEvent::Closed { .. }) {
                if !self.closing_associations.contains(&association) {
                    self.closing_associations.push(association);
                }
                self.node
                    .deferred_streams
                    .retain(|(owner, _)| *owner != association);
                let _ = self.event_sender.send(event);
                continue;
            }
            self.routes
                .retain(|route| route.owner != crate::node::StreamOwner::Association(association));
            self.node
                .stream_chunks
                .retain(|chunk| chunk.owner != crate::node::StreamOwner::Association(association));
            self.node
                .deferred_streams
                .retain(|(owner, _)| *owner != association);
            if matches!(event, crate::AssociationEvent::SetupTimeout { .. }) {
                let mut pending = Vec::new();
                for (waiting, reply) in self.establishment_waiters.drain(..) {
                    if waiting == association {
                        let _ = reply.send(Err(QuicNodeEgressError::AssociationTimedOut));
                    } else {
                        pending.push((waiting, reply));
                    }
                }
                self.establishment_waiters = pending;
            }
            let _ = self.event_sender.send(event);
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
                self.node
                    .write_stream_packet(&mut stream, &pending.bytes, true)
                    .map(|()| pending.bytes.len())
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
        if matches!(&result, Err(error) if error.is_retryable()) {
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
                        Err(error) if error.is_retryable() => {
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
                Err(error) if error.is_retryable() => {
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

    /// Move queued chunks to their stream readers.
    ///
    /// A stream whose reader channel is full keeps its remaining chunks, in
    /// order, in the node queue; other streams continue. A full accept
    /// channel holds back only new streams. Nothing here stops the driver
    /// from polling the node: per-stream backpressure reaches the peer
    /// through withheld receive credit (see `ChunkAdmission`).
    fn dispatch_stream_chunks(&mut self) {
        if self.node.stream_chunks.is_empty() {
            self.finish_graceful_closes();
            return;
        }
        let mut kept = std::collections::VecDeque::new();
        let mut held: Vec<(crate::node::StreamOwner, u64)> = Vec::new();
        let mut accept_full = false;
        while let Some(chunk) = self.node.stream_chunks.pop_front() {
            let key = (chunk.owner, chunk.stream);
            if held.contains(&key) {
                kept.push_back(chunk);
                continue;
            }
            let route = self
                .routes
                .iter()
                .position(|route| route.owner == chunk.owner && route.stream_id == chunk.stream);
            let index = if let Some(index) = route {
                index
            } else {
                if accept_full {
                    held.push(key);
                    kept.push_back(chunk);
                    continue;
                }
                let crate::node::StreamOwner::Association(association) = chunk.owner;
                let stream = QuicStream::incoming(association, chunk.stream);
                let handle = self.register_stream(stream);
                let index = self.routes.len() - 1;
                if self.accepted.try_send(handle).is_err() {
                    self.routes.remove(index);
                    accept_full = true;
                    held.push(key);
                    kept.push_back(chunk);
                    continue;
                }
                index
            };
            let fin = chunk.fin;
            match self.routes[index]
                .incoming
                .try_send(ReceivedStreamChunkData {
                    offset: chunk.offset,
                    fin: chunk.fin,
                    bytes: chunk.bytes,
                }) {
                Ok(()) => {
                    if fin {
                        self.routes.remove(index);
                    }
                }
                Err(mpsc::error::TrySendError::Full(data)) => {
                    held.push(key);
                    kept.push_back(crate::node::QueuedStreamChunk {
                        owner: key.0,
                        stream: key.1,
                        offset: data.offset,
                        fin: data.fin,
                        bytes: data.bytes,
                    });
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    // The reader was dropped. Keep the route until FIN so later
                    // chunks are discarded rather than accepted as a new stream.
                    if fin {
                        self.routes.remove(index);
                    }
                }
            }
        }
        self.node.stream_chunks = kept;
        self.finish_graceful_closes();
    }

    fn finish_graceful_closes(&mut self) {
        let mut pending = Vec::new();
        for association in self.closing_associations.drain(..) {
            let owner = crate::node::StreamOwner::Association(association);
            if self
                .node
                .stream_chunks
                .iter()
                .any(|chunk| chunk.owner == owner)
            {
                pending.push(association);
                continue;
            }
            self.routes.retain(|route| route.owner != owner);
        }
        self.closing_associations = pending;
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
    P: PacketPool + 'static,
    const PACKET: usize = { crate::DEFAULT_MAX_PACKET_SIZE },
> {
    node: &'a mut QuicNode<P, PACKET>,
    stream: QuicStream,
    read_bytes: Vec<u8>,
    read_cursor: usize,
    next_read_offset: u64,
    read_finished: bool,
    pending_write: Vec<u8>,
    clock_started: ::tokio::time::Instant,
    clock_base_us: u64,
    timer: Option<Pin<Box<::tokio::time::Sleep>>>,
    timer_deadline_us: Option<u64>,
}

impl<P, const PACKET: usize> QuicNode<P, PACKET>
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

    /// Queue the chunks one packet admitted and remember streams whose
    /// remaining bytes were left retained at the per-stream limit.
    fn admit_stream_chunks(&mut self, admission: crate::node::ChunkAdmission) {
        self.retain_admitted_stream_chunks(admission.chunks);
        for deferred in admission.deferred {
            if !self.deferred_streams.contains(&deferred) {
                self.deferred_streams.push(deferred);
            }
        }
    }

    /// Queue retained bytes for deferred streams whose per-stream queue has
    /// room again, and publish the receive credit they release. Returns
    /// whether any chunk was queued.
    pub(crate) fn resume_deferred_streams(&mut self) -> Result<bool, QuicNodeEgressError> {
        let mut progressed = false;
        let mut pending = core::mem::take(&mut self.deferred_streams).into_iter();
        while let Some((association, stream)) = pending.next() {
            let mut admission = crate::node::ChunkAdmission::new(
                &self.stream_chunks,
                self.stream_chunk_limit,
                self.association_chunk_limits(),
            );
            let resumed = self.resume_stream_delivery(
                association,
                stream,
                &mut |source, stream, offset, fin, bytes| {
                    admission.offer(source, stream, offset, fin, bytes)
                },
            );
            let Ok(consumed) = resumed else {
                // The association is gone; its retained bytes went with it.
                continue;
            };
            progressed |= !admission.chunks.is_empty();
            self.admit_stream_chunks(admission);
            if consumed != 0 {
                if let Err(error) = self.submit_or_defer_control(association) {
                    self.deferred_streams.extend(pending);
                    return Err(error);
                }
            }
        }
        Ok(progressed)
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
    pub fn stream<'a>(&'a mut self, stream: QuicStream) -> BorrowedTokioStream<'a, P, PACKET> {
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
    ) -> BorrowedTokioStream<'a, P, PACKET> {
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
            let crate::node::StreamOwner::Association(association) = owner;
            let probe = QuicStream::incoming(association, stream_id);
            probe.matches(chunk.owner, chunk.stream)
        })?;
        let chunk = self
            .stream_chunks
            .remove(index)
            .expect("position names an existing queued stream chunk");
        Some(ReceivedStreamChunk {
            stream: {
                let crate::node::StreamOwner::Association(association) = chunk.owner;
                QuicStream::incoming(association, chunk.stream)
            },
            offset: chunk.offset,
            fin: chunk.fin,
            bytes: chunk.bytes,
        })
    }

    fn process_received_packet(
        &mut self,
        received: ReceivedPacket<P::Buffer>,
        local_limits: Option<crate::ConnectionLimits>,
    ) -> Result<(), QuicNodeEgressError> {
        if let Some(capture) = &self.packet_capture {
            capture.record(true, received.meta.bearer, received.packet.bytes());
        }
        let mut admission = crate::node::ChunkAdmission::new(
            &self.stream_chunks,
            self.stream_chunk_limit,
            self.association_chunk_limits(),
        );
        let ingress = self
            .receive_packet(
                received.meta,
                received.packet,
                |_| {
                    let local_limits = local_limits?;
                    Some(crate::node::InitialAdmission { local_limits })
                },
                |source, stream, offset, fin, bytes| {
                    admission.offer(source, stream, offset, fin, bytes)
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
            crate::node::NodeIngress::Forward { .. } => {
                return Err(QuicNodeEgressError::RelayUnavailable);
            }
            _ => {}
        }
        self.admit_stream_chunks(admission);
        Ok(())
    }

    pub(crate) fn poll_one_event(
        &mut self,
        context: &mut Context<'_>,
        local_limits: Option<crate::ConnectionLimits>,
    ) -> Poll<Result<(), QuicNodeEgressError>> {
        if self.drain_bearer_events() {
            return Poll::Ready(Ok(()));
        }
        match self.resume_deferred_streams() {
            Ok(true) => return Poll::Ready(Ok(())),
            Ok(false) => {}
            Err(error) => return Poll::Ready(Err(error)),
        }
        match self.retry_one_pending_control() {
            Ok(true) => return Poll::Ready(Ok(())),
            Ok(false) => {}
            Err(error) => return Poll::Ready(Err(error)),
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
        Poll::Ready(self.process_received_packet(received, local_limits))
    }

    /// Take one packet from the node-owned ingress queue and run the common
    /// bearer-independent QUIC receive state machine.
    ///
    /// This is crate-only so applications cannot recreate a competing packet
    /// driver. The Tokio stream/service surface calls it while waiting for
    /// accepted streams. The no-std/RTOS surface reaches the same common state
    /// transition through one queued [`crate::nostd::NoStdRuntime::progress`]
    /// event instead.
    async fn receive_one(
        &mut self,
        local_limits: Option<crate::ConnectionLimits>,
    ) -> Result<(), QuicNodeEgressError> {
        let clock_started = ::tokio::time::Instant::now();
        let clock_base_us = self.clock_us();
        loop {
            self.drain_bearer_events();
            let now = clock_base_us.saturating_add(
                u64::try_from(clock_started.elapsed().as_micros()).unwrap_or(u64::MAX),
            );
            self.advance_clock(now);
            let deadline = self.next_deadline();
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
                    return self.process_received_packet(received, local_limits);
                }
                () = self.completions.changed() => {}
                () = &mut timer => {
                    let now = deadline.unwrap_or(now);
                    self.advance_clock(now);
                    match self.timer_expired(now)? {
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
    fn drive_one_queued_packet(&mut self) -> Result<bool, QuicNodeEgressError> {
        self.drain_bearer_events();
        if self.resume_deferred_streams()? {
            return Ok(true);
        }
        let Some(received) = self.ingress.try_receive() else {
            return Ok(false);
        };
        self.process_received_packet(received, None)?;
        Ok(true)
    }

    /// Wait for the first or next ordered application chunk from any peer.
    ///
    /// This is the server-side equivalent of accepting and reading a TCP or
    /// HTTP stream. The node admits new associations, handles duplicate
    /// Initial packets and routes established packets.
    /// A service therefore reads `offset`, bytes, and FIN and writes its reply
    /// through the returned stream without inspecting packet form or CIDs.
    pub async fn accept_stream(
        &mut self,
        local_limits: crate::ConnectionLimits,
    ) -> Result<ReceivedStreamChunk, QuicNodeEgressError> {
        loop {
            self.resume_deferred_streams()?;
            if let Some(chunk) = self.stream_chunks.pop_front() {
                let crate::node::StreamOwner::Association(association) = chunk.owner;
                let stream = QuicStream::incoming(association, chunk.stream);
                return Ok(ReceivedStreamChunk {
                    stream,
                    offset: chunk.offset,
                    fin: chunk.fin,
                    bytes: chunk.bytes,
                });
            }
            self.receive_one(Some(local_limits)).await?;
        }
    }

    /// Wait until a client association has processed its server Initial
    /// response. This is the asynchronous equivalent of TCP connect finishing.
    pub async fn wait_established(
        &mut self,
        association: QuicAssociation,
    ) -> Result<(), QuicNodeEgressError> {
        while !self.association_is_established(association) {
            self.receive_one(None).await?;
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
    ) -> Result<(), QuicNodeEgressError> {
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
                Err(error) if error.is_retryable() => {
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
    ) -> Result<(), QuicNodeEgressError> {
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
    type Node = QuicNode<Pool>;

    #[test]
    fn per_stream_chunk_limit_does_not_scale_with_node_size() {
        static POOL: Pool = Pool::new();
        let mut node = Node::new(None, &POOL);
        node.set_limits(crate::NodeLimits {
            max_associations: 1_000_000,
            max_routes: 1_000_000,
        })
        .unwrap();
        assert_eq!(
            node.stream_chunk_limit,
            crate::AssociationLimits::host().max_queued_chunks_per_stream
        );
    }

    #[test]
    fn committed_packet_batch_is_retained_and_ingress_continues_at_the_queue_limit() {
        static POOL: Pool = Pool::new();
        let (bearer, _peer) = FakePacketBearer::<Pool>::pair(
            BearerName::new("batch-node").unwrap(),
            BearerName::new("batch-peer").unwrap(),
        );
        let mut node = Node::new(None, &POOL);
        node.set_limits(crate::NodeLimits {
            max_associations: 1,
            max_routes: 1,
        })
        .unwrap();
        node.set_default_association_limits(crate::AssociationLimits {
            max_pending_streams: 1,
            max_queued_chunks_per_stream: 1,
            ..crate::AssociationLimits::host()
        })
        .unwrap();
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

        // A full queue for one stream must not stop node ingress: the limit
        // is per stream and enforced through withheld receive credit, so the
        // next packet is still processed (here it is not QUIC and is ignored).
        let waker = std::task::Waker::noop();
        let mut context = Context::from_waker(waker);
        assert!(matches!(
            node.poll_one_event(&mut context, None),
            Poll::Ready(Ok(()))
        ));
        assert!(node.ingress.try_receive().is_none());
        assert_eq!(node.stream_chunks.len(), 1, "queued chunk stays queued");
    }
}

impl<'a, P, const PACKET: usize> BorrowedTokioStream<'a, P, PACKET>
where
    P: PacketPool + 'static,
    P::Buffer: Send,
{
    fn new(
        node: &'a mut QuicNode<P, PACKET>,
        stream: QuicStream,
        read_bytes: Vec<u8>,
        next_read_offset: u64,
        read_finished: bool,
    ) -> Self {
        let clock_base_us = node.clock_us();
        Self {
            node,
            stream,
            read_bytes,
            read_cursor: 0,
            next_read_offset,
            read_finished,
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
        let Some(deadline) = self.node.next_deadline() else {
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
        match self.node.timer_expired(now) {
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

impl<P, const PACKET: usize> AsyncRead for BorrowedTokioStream<'_, P, PACKET>
where
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

impl<P, const PACKET: usize> AsyncWrite for BorrowedTokioStream<'_, P, PACKET>
where
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
                Err(error) if error.is_retryable() => {
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
        if self.pending_write.is_empty() {
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
            Err(error) if error.is_retryable() => {
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
        let associated = core::mem::take(&mut self.pending_write);
        let result = {
            let this = &mut *self;
            this.node
                .write_stream_after_queued_progress(&mut this.stream, &associated, true)
        };
        match result {
            Ok(()) => Poll::Ready(Ok(())),
            Err(error) if error.is_retryable() => {
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
