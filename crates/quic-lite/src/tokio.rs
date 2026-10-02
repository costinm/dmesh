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
    collections::hash_map::RandomState,
    fs::File,
    hash::BuildHasher,
    io::{self, Write},
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
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
static PROCESS_CID_BASE: OnceLock<u64> = OnceLock::new();
static NODE_CID_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Allocate a host node's first local CID from a process-random namespace.
/// Firmware without OS entropy keeps its compact local counter; Tokio hosts
/// create short-lived nodes in separate processes and must not all restart at
/// CID 1 while a peer still retains their previous associations.
pub(crate) fn initial_local_cid_seed() -> u64 {
    let range = crate::ConnectionId::MAX_VALUE;
    let base = *PROCESS_CID_BASE.get_or_init(|| {
        RandomState::new().hash_one((SystemTime::now(), std::process::id())) % range
    });
    let sequence = NODE_CID_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    base.wrapping_add(sequence) % range + 1
}

enum DriverCommand {
    Wake,
    Telemetry {
        reply: oneshot::Sender<crate::NodeTelemetry>,
    },
    RemoveBearer {
        bearer: BearerId,
        reply: oneshot::Sender<bool>,
    },
    Associate {
        meta: crate::PacketMeta,
        now_us: u64,
        reply: oneshot::Sender<Result<QuicAssociation, QuicNodeEgressError>>,
    },
    AssociateRelayed {
        meta: crate::PacketMeta,
        destination_vip: Option<u64>,
        hops: Vec<crate::RelayHop>,
        return_hints: crate::NearbyRelayHints,
        now_us: u64,
        reply: oneshot::Sender<Result<QuicAssociation, QuicNodeEgressError>>,
    },
    AddRelayedCircuit {
        association: QuicAssociation,
        meta: crate::PacketMeta,
        hops: Vec<crate::RelayHop>,
        now_us: u64,
        reply: oneshot::Sender<Result<crate::CircuitId, QuicNodeEgressError>>,
    },
    AddDirectCircuit {
        association: QuicAssociation,
        next_hop: crate::CircuitNextHop,
        now_us: u64,
        reply: oneshot::Sender<Result<crate::CircuitId, QuicNodeEgressError>>,
    },
    RetryDirectCircuit {
        circuit: crate::CircuitId,
        reply: oneshot::Sender<Result<(), QuicNodeEgressError>>,
    },
    SuspendCircuit {
        circuit: crate::CircuitId,
        reply: oneshot::Sender<Result<(), QuicNodeEgressError>>,
    },
    ResumeCircuit {
        circuit: crate::CircuitId,
        next_hop: crate::CircuitNextHop,
        now_us: u64,
        reply: oneshot::Sender<Result<(), QuicNodeEgressError>>,
    },
    CloseCircuit {
        circuit: crate::CircuitId,
        reply: oneshot::Sender<Result<(), QuicNodeEgressError>>,
    },
    Circuits {
        association: QuicAssociation,
        reply: oneshot::Sender<Result<Vec<crate::CircuitInfo>, QuicNodeEgressError>>,
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
    /// Return a snapshot of QUIC counters from the node-owning driver.
    pub async fn telemetry(&self) -> Option<crate::NodeTelemetry> {
        let (reply, receive) = oneshot::channel();
        self.commands
            .send(DriverCommand::Telemetry { reply })
            .ok()?;
        receive.await.ok()
    }

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

    /// Create an association through a client-selected layered relay circuit.
    pub async fn associate_relayed(
        &self,
        meta: crate::PacketMeta,
        destination_vip: Option<u64>,
        hops: Vec<crate::RelayHop>,
        now_us: u64,
    ) -> Result<TokioAssociation, QuicNodeEgressError> {
        self.associate_relayed_with_return_hints(
            meta,
            destination_vip,
            hops,
            crate::NearbyRelayHints::EMPTY,
            now_us,
        )
        .await
    }

    /// Create a relayed association and offer nearby relays for a peer-built
    /// return circuit.
    pub async fn associate_relayed_with_return_hints(
        &self,
        meta: crate::PacketMeta,
        destination_vip: Option<u64>,
        hops: Vec<crate::RelayHop>,
        return_hints: crate::NearbyRelayHints,
        now_us: u64,
    ) -> Result<TokioAssociation, QuicNodeEgressError> {
        let (reply, receive) = oneshot::channel();
        self.commands
            .send(DriverCommand::AssociateRelayed {
                meta,
                destination_vip,
                hops,
                return_hints,
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

    /// Add a directly reachable circuit using a registered bearer.
    pub async fn add_direct_circuit(
        &self,
        next_hop: crate::CircuitNextHop,
        now_us: u64,
    ) -> Result<crate::CircuitId, QuicNodeEgressError> {
        let (reply, receive) = oneshot::channel();
        self.node
            .commands
            .send(DriverCommand::AddDirectCircuit {
                association: self.association,
                next_hop,
                now_us,
                reply,
            })
            .map_err(|_| QuicNodeEgressError::AssociationTimedOut)?;
        receive
            .await
            .map_err(|_| QuicNodeEgressError::AssociationTimedOut)?
    }

    /// Add a client-selected layered relay circuit to this association.
    pub async fn add_relayed_circuit(
        &self,
        first_hop: crate::PacketMeta,
        hops: Vec<crate::RelayHop>,
        now_us: u64,
    ) -> Result<crate::CircuitId, QuicNodeEgressError> {
        let (reply, receive) = oneshot::channel();
        self.node
            .commands
            .send(DriverCommand::AddRelayedCircuit {
                association: self.association,
                meta: first_hop,
                hops,
                now_us,
                reply,
            })
            .map_err(|_| QuicNodeEgressError::AssociationTimedOut)?;
        receive
            .await
            .map_err(|_| QuicNodeEgressError::AssociationTimedOut)?
    }

    /// Retry a direct circuit join that is still opening.
    pub async fn retry_direct_circuit(
        &self,
        circuit: crate::CircuitId,
    ) -> Result<(), QuicNodeEgressError> {
        if circuit.association() != self.association {
            return Err(QuicNodeEgressError::Transport(crate::Error::Invalid));
        }
        let (reply, receive) = oneshot::channel();
        self.node
            .commands
            .send(DriverCommand::RetryDirectCircuit { circuit, reply })
            .map_err(|_| QuicNodeEgressError::AssociationTimedOut)?;
        receive
            .await
            .map_err(|_| QuicNodeEgressError::AssociationTimedOut)?
    }

    /// Mark a circuit unavailable after its neighbour-down notification.
    pub async fn suspend_circuit(
        &self,
        circuit: crate::CircuitId,
    ) -> Result<(), QuicNodeEgressError> {
        if circuit.association() != self.association {
            return Err(QuicNodeEgressError::Transport(crate::Error::Invalid));
        }
        let (reply, receive) = oneshot::channel();
        self.node
            .commands
            .send(DriverCommand::SuspendCircuit { circuit, reply })
            .map_err(|_| QuicNodeEgressError::AssociationTimedOut)?;
        receive
            .await
            .map_err(|_| QuicNodeEgressError::AssociationTimedOut)?
    }

    /// Probe a suspended circuit through its newly available next hop.
    pub async fn resume_circuit(
        &self,
        circuit: crate::CircuitId,
        next_hop: crate::CircuitNextHop,
        now_us: u64,
    ) -> Result<(), QuicNodeEgressError> {
        if circuit.association() != self.association {
            return Err(QuicNodeEgressError::Transport(crate::Error::Invalid));
        }
        let (reply, receive) = oneshot::channel();
        self.node
            .commands
            .send(DriverCommand::ResumeCircuit {
                circuit,
                next_hop,
                now_us,
                reply,
            })
            .map_err(|_| QuicNodeEgressError::AssociationTimedOut)?;
        receive
            .await
            .map_err(|_| QuicNodeEgressError::AssociationTimedOut)?
    }

    /// Close an idle circuit after PATH_STATUS abandon has been acknowledged.
    /// The first call queues the status and returns `CircuitBusy`; retry after
    /// the peer's ACK arrives.
    pub async fn close_circuit(
        &self,
        circuit: crate::CircuitId,
    ) -> Result<(), QuicNodeEgressError> {
        if circuit.association() != self.association {
            return Err(QuicNodeEgressError::Transport(crate::Error::Invalid));
        }
        let (reply, receive) = oneshot::channel();
        self.node
            .commands
            .send(DriverCommand::CloseCircuit { circuit, reply })
            .map_err(|_| QuicNodeEgressError::AssociationTimedOut)?;
        receive
            .await
            .map_err(|_| QuicNodeEgressError::AssociationTimedOut)?
    }

    /// Return read-only telemetry for this association's direct circuits.
    pub async fn circuits(&self) -> Result<Vec<crate::CircuitInfo>, QuicNodeEgressError> {
        let (reply, receive) = oneshot::channel();
        self.node
            .commands
            .send(DriverCommand::Circuits {
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
    /// Mark this stream as latency-sensitive control traffic. Accepted data
    /// packets may be duplicated over an alternate circuit when budget allows.
    pub fn set_priority(&mut self, priority: bool) {
        self.stream
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .set_priority(priority);
    }

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
        let clock_started = ::tokio::time::Instant::now();
        let clock_base_us = self.node.clock_us();
        loop {
            self.dispatch_stream_chunks();
            self.dispatch_association_events();
            self.resolve_establishment_waiters();
            self.retry_pending_opens();
            self.retry_pending_writes();
            self.retry_finishes();
            // The driver owns every node timer (pacing, loss, ACK delay, PTO,
            // idle). Without one, a send that pacing defers after the initial
            // burst would never be retried while the driver waits for packets
            // or commands.
            let now = clock_base_us.saturating_add(
                u64::try_from(clock_started.elapsed().as_micros()).unwrap_or(u64::MAX),
            );
            self.node.advance_clock(now);
            let deadline = self.node.next_deadline();
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
            ::tokio::pin!(timer);
            ::tokio::select! {
                command = self.commands.recv() => {
                    let Some(command) = command else { return Ok(()); };
                    self.handle_command(command)?;
                }
                event = core::future::poll_fn(|context| {
                    self.node.poll_one_event(context, Some(self.limits))
                }) => {
                    if let Err(error) = event {
                        // A socket or pool that is momentarily full is not a
                        // reason to stop the node: loss recovery resends, and
                        // the short pause stops this loop from spinning.
                        if !error.is_retryable() {
                            return Err(error);
                        }
                        ::tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    }
                }
                () = &mut timer => {
                    let now = deadline.unwrap_or(now);
                    self.node.advance_clock(now);
                    match self.node.timer_expired(now) {
                        Ok(Some(crate::node::NodeTimer::Egress(packet))) => {
                            match self.node.submit_node_packet(packet) {
                                Ok(()) => {}
                                Err(error) if error.is_retryable() => {}
                                Err(error) => return Err(error),
                            }
                        }
                        Ok(Some(crate::node::NodeTimer::BootstrapTimedOut { .. })) => {
                            return Err(QuicNodeEgressError::AssociationTimedOut);
                        }
                        Ok(Some(crate::node::NodeTimer::IdleTimedOut { .. }))
                        | Ok(Some(crate::node::NodeTimer::CircuitSetupTimedOut { .. }))
                        | Ok(None) => {}
                        Err(error) if error.is_retryable() => {}
                        Err(error) => return Err(error),
                    }
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
                crate::AssociationEvent::CircuitOpened { association, .. }
                | crate::AssociationEvent::CircuitStatusChanged { association, .. }
                | crate::AssociationEvent::CircuitClosed { association, .. }
                | crate::AssociationEvent::Closed { association, .. }
                | crate::AssociationEvent::Reset { association }
                | crate::AssociationEvent::IdleTimeout { association }
                | crate::AssociationEvent::SetupTimeout { association }
                | crate::AssociationEvent::SetupRejected { association, .. }
                | crate::AssociationEvent::PeerReturnPathHints { association, .. } => association,
                crate::AssociationEvent::EventsDropped { .. } => unreachable!(),
            };
            if matches!(
                event,
                crate::AssociationEvent::CircuitOpened { .. }
                    | crate::AssociationEvent::CircuitStatusChanged { .. }
                    | crate::AssociationEvent::CircuitClosed { .. }
                    | crate::AssociationEvent::PeerReturnPathHints { .. }
            ) {
                let _ = self.event_sender.send(event);
                continue;
            }
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
            if matches!(
                event,
                crate::AssociationEvent::SetupTimeout { .. }
                    | crate::AssociationEvent::SetupRejected { .. }
            ) {
                let mut pending = Vec::new();
                for (waiting, reply) in self.establishment_waiters.drain(..) {
                    if waiting == association {
                        let result = match event {
                            crate::AssociationEvent::SetupTimeout { .. } => {
                                QuicNodeEgressError::AssociationTimedOut
                            }
                            crate::AssociationEvent::SetupRejected { code, .. } => {
                                QuicNodeEgressError::SetupRejected(code)
                            }
                            _ => unreachable!(),
                        };
                        let _ = reply.send(Err(result));
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
            DriverCommand::Telemetry { reply } => {
                let _ = reply.send(self.node.telemetry());
            }
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
            DriverCommand::AssociateRelayed {
                meta,
                destination_vip,
                hops,
                return_hints,
                now_us,
                reply,
            } => {
                let _ = reply.send(self.node.associate_relayed_with_return_hints(
                    meta,
                    destination_vip,
                    &hops,
                    return_hints,
                    now_us,
                ));
            }
            DriverCommand::AddRelayedCircuit {
                association,
                meta,
                hops,
                now_us,
                reply,
            } => {
                let _ = reply.send(
                    self.node
                        .join_relayed_path(association, meta, &hops, now_us),
                );
            }
            DriverCommand::AddDirectCircuit {
                association,
                next_hop,
                now_us,
                reply,
            } => {
                let _ = reply.send(self.node.add_direct_circuit(association, next_hop, now_us));
            }
            DriverCommand::RetryDirectCircuit { circuit, reply } => {
                let _ = reply.send(self.node.retry_direct_circuit(circuit));
            }
            DriverCommand::SuspendCircuit { circuit, reply } => {
                let _ = reply.send(self.node.suspend_circuit(circuit));
            }
            DriverCommand::ResumeCircuit {
                circuit,
                next_hop,
                now_us,
                reply,
            } => {
                let _ = reply.send(self.node.resume_circuit(circuit, next_hop, now_us));
            }
            DriverCommand::CloseCircuit { circuit, reply } => {
                let _ = reply.send(self.node.close_circuit(circuit));
            }
            DriverCommand::Circuits { association, reply } => {
                let _ = reply.send(Ok(self.node.circuits_vec(association)));
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
            | crate::node::NodeIngress::SetupReply { response }
            | crate::node::NodeIngress::SetupAccepted { response, .. }
            | crate::node::NodeIngress::StatelessReset { response } => {
                self.submit_unassociated_packet(response)?;
            }
            crate::node::NodeIngress::PathControl { response, .. } => {
                self.submit_node_packet(response)?;
            }
            crate::node::NodeIngress::Association { association, .. } => {
                self.submit_or_defer_control(association.association())?;
            }
            crate::node::NodeIngress::Forward { next_hop, packet } => {
                self.submit_egress(next_hop.bearer, next_hop.peer_l2_address, packet)?;
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
                        Some(crate::node::NodeTimer::IdleTimedOut { .. })
                        | Some(crate::node::NodeTimer::CircuitSetupTimedOut { .. })
                        | None => {}
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
        let mut node = Node::new(&POOL);
        node.set_limits(crate::NodeLimits {
            max_associations: 1_000_000,
            max_routes: 1_000_000,
            ..crate::NodeLimits::host()
        })
        .unwrap();
        assert_eq!(
            node.stream_chunk_limit,
            crate::AssociationLimits::host().max_queued_chunks_per_stream
        );
    }

    #[test]
    fn relayed_association_starts_with_replayable_layered_path_open() {
        static POOL: Pool = Pool::new();
        let mut node = Node::new(&POOL);
        let bearer = FakePacketBearer::<Pool>::new(BearerName::new("relay-origin").unwrap());
        let sent = bearer.sent_packets();
        let bearer = node.add_bearer(bearer).unwrap();
        let address = PacketMeta {
            bearer,
            peer_l2_address: PeerL2Address::new(9).unwrap(),
            received_at_us: 100,
        };
        let hop = crate::RelayHop::new(2, &[1, 2, 3], 5_000_000, 128).unwrap();
        let association = node
            .associate_relayed(address, Some(0x1020), &[hop], 100)
            .unwrap();
        let first = sent.lock().unwrap()[0].clone();
        let request = crate::relay::decode_setup_request_packet(&first).unwrap();
        assert_eq!(request.transaction_id, 1);
        assert_eq!(request.destination_vip, Some(0x1020));
        assert_eq!(request.blocks.count(), 2);
        assert_eq!(
            request.current_hop_instruction().unwrap(),
            crate::relay::SetupHopInstruction {
                address_kind: 2,
                address_len: 3,
                address: [1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                lease_us: 5_000_000,
                packet_quota: 128,
            }
        );

        let Some(crate::node::NodeTimer::Egress(retry)) = node
            .timer_expired(100 + crate::node::DEFAULT_INITIAL_PTO_US)
            .unwrap()
        else {
            panic!("relay setup should retry on its bootstrap deadline");
        };
        assert_eq!(retry.association, association);
        assert_eq!(retry.packet.bytes(), first);
        drop(retry);

        let client_cid = node.receive_cid(association).unwrap();
        let endpoint_cid = crate::ConnectionId::new(0x902).unwrap();
        let mut bootstrap_ack = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        let ack_len = crate::encode_bootstrap_open_ack_packet(
            client_cid,
            endpoint_cid,
            0,
            &mut bootstrap_ack,
        )
        .unwrap();
        let mut relay_cids = crate::relay::SetupRelayCids::empty();
        relay_cids
            .prepend(crate::ConnectionId::new(0x901).unwrap())
            .unwrap();
        let reply = crate::relay::SetupReply {
            transaction_id: request.transaction_id,
            circuit: request.circuit,
            result: crate::relay::SetupResult::Accepted {
                endpoint_cid,
                lease_us: 5_000_000,
            },
            bootstrap_ack: Some(
                crate::relay::SetupBootstrapAck::from_slice(&bootstrap_ack[..ack_len]).unwrap(),
            ),
            relay_cids,
        };
        let mut reply_bytes = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        let reply_len = reply.encode_packet(&mut reply_bytes).unwrap();
        let mut writer = POOL.acquire_writer(0).unwrap();
        writer.payload_mut()[..reply_len].copy_from_slice(&reply_bytes[..reply_len]);
        let ingress_lease = writer.commit(reply_len).unwrap();
        let ingress_packet = match crate::OwnedPacket::new(ingress_lease, 0..reply_len) {
            Ok(packet) => packet,
            Err(_) => panic!("valid pooled packet range should be accepted"),
        };
        let ingress =
            match node.receive_packet(address, ingress_packet, |_| None, |_, _, _, _, _| Ok(0)) {
                Ok(ingress) => ingress,
                Err(_) => panic!("valid PATH_OPEN_ACK should not reject its packet lease"),
            };
        assert!(matches!(
            ingress,
            crate::node::NodeIngress::Association {
                association: crate::node::AssociationIngress::Client(opened),
                ..
            } if opened == association
        ));
        let mut circuits = [crate::CircuitInfo::default(); 1];
        assert_eq!(node.circuits(association, &mut circuits), 1);
        assert_eq!(circuits[0].status, crate::CircuitStatus::Active);
        assert_eq!(
            circuits[0].first_hop.peer_l2_address,
            address.peer_l2_address
        );
    }

    #[test]
    fn create_through_three_relays_then_join_a_second_three_relay_chain() {
        use crate::node::InitialAdmission;
        use crate::node::NodeIngress;
        use crate::{CircuitNextHop, RelayHop};

        type MultiPool = PacketPool<32, { crate::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
        type RelayNode = QuicNode<MultiPool>;
        type TestPacket = [u8; crate::DEFAULT_MAX_PACKET_SIZE];
        static CLIENT_POOL: MultiPool = MultiPool::new();
        static R1_POOL: MultiPool = MultiPool::new();
        static R2_POOL: MultiPool = MultiPool::new();
        static R3_POOL: MultiPool = MultiPool::new();
        static R4_POOL: MultiPool = MultiPool::new();
        static R5_POOL: MultiPool = MultiPool::new();
        static R6_POOL: MultiPool = MultiPool::new();
        static ENDPOINT_POOL: MultiPool = MultiPool::new();

        let packet = |bytes: &[u8]| {
            let mut storage = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
            storage[..bytes.len()].copy_from_slice(bytes);
            crate::OwnedPacket::<TestPacket>::new(storage, 0..bytes.len()).unwrap()
        };
        let admission = || {
            Some(InitialAdmission {
                local_limits: crate::ConnectionLimits::default(),
            })
        };
        let on_stream = |_, _, _, _, bytes: &[u8]| Ok(bytes.len());
        macro_rules! forward {
            ($relay:expr, $meta:expr, $packet:expr) => {{
                match $relay
                    .receive_packet($meta, $packet, |_| admission(), on_stream)
                    .unwrap()
                {
                    NodeIngress::Forward { packet, .. } => packet,
                    _ => panic!("relay must forward the next setup block"),
                }
            }};
        }
        macro_rules! reply {
            ($relay:expr, $meta:expr, $packet:expr) => {{
                match $relay
                    .receive_packet($meta, $packet, |_| None, on_stream)
                    .unwrap()
                {
                    NodeIngress::SetupReply { response } => response.packet,
                    NodeIngress::NonQuic { error, .. } => {
                        panic!("{} rejected the setup reply: {error:?}", stringify!($relay));
                    }
                    _ => panic!("{} must return the setup reply", stringify!($relay)),
                }
            }};
        }

        let bearer_impl = FakePacketBearer::<MultiPool>::new(BearerName::new("mp-client").unwrap());
        let sent = bearer_impl.sent_packets();
        let node = RelayNode::new(&CLIENT_POOL);
        let mut client = TokioNodeDriver::new(node, crate::ConnectionLimits::default()).1;
        let bearer = client.node.add_bearer(bearer_impl).unwrap();
        let create_meta = PacketMeta {
            bearer,
            peer_l2_address: PeerL2Address::new(11).unwrap(),
            received_at_us: 10,
        };

        let links1 = [
            CircuitNextHop {
                bearer: BearerId::new(2).unwrap(),
                peer_l2_address: PeerL2Address::new(22).unwrap(),
            },
            CircuitNextHop {
                bearer: BearerId::new(3).unwrap(),
                peer_l2_address: PeerL2Address::new(33).unwrap(),
            },
            CircuitNextHop {
                bearer: BearerId::new(4).unwrap(),
                peer_l2_address: PeerL2Address::new(44).unwrap(),
            },
        ];
        let links2 = [
            CircuitNextHop {
                bearer: BearerId::new(5).unwrap(),
                peer_l2_address: PeerL2Address::new(55).unwrap(),
            },
            CircuitNextHop {
                bearer: BearerId::new(6).unwrap(),
                peer_l2_address: PeerL2Address::new(66).unwrap(),
            },
            CircuitNextHop {
                bearer: BearerId::new(7).unwrap(),
                peer_l2_address: PeerL2Address::new(77).unwrap(),
            },
        ];
        let mut r1 = RelayNode::new(&R1_POOL);
        let mut r2 = RelayNode::new(&R2_POOL);
        let mut r3 = RelayNode::new(&R3_POOL);
        let mut r4 = RelayNode::new(&R4_POOL);
        let mut r5 = RelayNode::new(&R5_POOL);
        let mut r6 = RelayNode::new(&R6_POOL);
        let mut endpoint = RelayNode::new(&ENDPOINT_POOL);
        r1.set_path_open_resolver(move |kind, addr| {
            (kind == 2 && addr == [2]).then_some(links1[0])
        });
        r2.set_path_open_resolver(move |kind, addr| {
            (kind == 2 && addr == [3]).then_some(links1[1])
        });
        r3.set_path_open_resolver(move |kind, addr| {
            (kind == 3 && addr == [4]).then_some(links1[2])
        });
        r4.set_path_open_resolver(move |kind, addr| {
            (kind == 2 && addr == [5]).then_some(links2[0])
        });
        r5.set_path_open_resolver(move |kind, addr| {
            (kind == 2 && addr == [6]).then_some(links2[1])
        });
        r6.set_path_open_resolver(move |kind, addr| {
            (kind == 3 && addr == [7]).then_some(links2[2])
        });

        let hops1 = [
            RelayHop::new(2, &[2], 60_000_000, 4096).unwrap(),
            RelayHop::new(2, &[3], 50_000_000, 4096).unwrap(),
            RelayHop::new(3, &[4], 40_000_000, 4096).unwrap(),
        ];
        let association = client
            .node
            .associate_relayed(create_meta, Some(0x0102_0304_0506_0708), &hops1, 10)
            .unwrap();
        let create_bytes = sent.lock().unwrap()[0].clone();
        let p12 = forward!(r1, create_meta, packet(&create_bytes));
        let meta12 = PacketMeta {
            bearer: links1[0].bearer,
            peer_l2_address: links1[0].peer_l2_address,
            received_at_us: 20,
        };
        let p23 = forward!(r2, meta12, p12);
        let meta23 = PacketMeta {
            bearer: links1[1].bearer,
            peer_l2_address: links1[1].peer_l2_address,
            received_at_us: 30,
        };
        let p3e = forward!(r3, meta23, p23);
        let created = endpoint
            .receive_packet(
                PacketMeta {
                    bearer: links1[2].bearer,
                    peer_l2_address: links1[2].peer_l2_address,
                    received_at_us: 40,
                },
                p3e,
                |_| admission(),
                on_stream,
            )
            .unwrap();
        let NodeIngress::SetupAccepted {
            response: endpoint_reply,
            ..
        } = created
        else {
            panic!("the endpoint admits Create through three relays");
        };
        let p3r = reply!(
            r3,
            PacketMeta {
                bearer: links1[2].bearer,
                peer_l2_address: links1[2].peer_l2_address,
                received_at_us: 50,
            },
            endpoint_reply.packet
        );
        let p2r = reply!(
            r2,
            PacketMeta {
                received_at_us: 60,
                ..meta23
            },
            p3r
        );
        let p1r = reply!(
            r1,
            PacketMeta {
                received_at_us: 70,
                ..meta12
            },
            p2r
        );
        let create_reply = crate::relay::decode_setup_reply_packet(p1r.bytes()).unwrap();
        assert!(matches!(
            create_reply.result,
            crate::relay::SetupResult::Accepted { .. }
        ));
        assert_eq!(create_reply.relay_cids.count(), 3);
        client
            .node
            .receive_packet(
                PacketMeta {
                    received_at_us: 70,
                    ..create_meta
                },
                p1r,
                |_| None,
                on_stream,
            )
            .unwrap();
        assert_eq!(client.node.association_count(), 1);
        assert_eq!(endpoint.association_count(), 1);
        assert!(client.node.association_is_established(association));

        let join_meta = PacketMeta {
            peer_l2_address: PeerL2Address::new(12).unwrap(),
            received_at_us: 100,
            ..create_meta
        };
        let hops2 = [
            RelayHop::new(2, &[5], 60_000_000, 4096).unwrap(),
            RelayHop::new(2, &[6], 50_000_000, 4096).unwrap(),
            RelayHop::new(3, &[7], 40_000_000, 4096).unwrap(),
        ];
        let join_circuit = client
            .node
            .join_relayed_path(association, join_meta, &hops2, 100)
            .unwrap();
        let join_bytes = sent.lock().unwrap()[1].clone();
        let p45 = forward!(r4, join_meta, packet(&join_bytes));
        let meta45 = PacketMeta {
            bearer: links2[0].bearer,
            peer_l2_address: links2[0].peer_l2_address,
            received_at_us: 110,
        };
        let p56 = forward!(r5, meta45, p45);
        let meta56 = PacketMeta {
            bearer: links2[1].bearer,
            peer_l2_address: links2[1].peer_l2_address,
            received_at_us: 120,
        };
        let p6e = forward!(r6, meta56, p56);
        let joined = endpoint
            .receive_packet(
                PacketMeta {
                    bearer: links2[2].bearer,
                    peer_l2_address: links2[2].peer_l2_address,
                    received_at_us: 130,
                },
                p6e,
                |_| None,
                on_stream,
            )
            .unwrap();
        let NodeIngress::SetupReply {
            response: join_endpoint_reply,
        } = joined
        else {
            panic!("the existing endpoint accepts the second chain JOIN");
        };
        let p6r = reply!(
            r6,
            PacketMeta {
                bearer: links2[2].bearer,
                peer_l2_address: links2[2].peer_l2_address,
                received_at_us: 140,
            },
            join_endpoint_reply.packet
        );
        let p5r = reply!(
            r5,
            PacketMeta {
                received_at_us: 150,
                ..meta56
            },
            p6r
        );
        let p4r = reply!(
            r4,
            PacketMeta {
                received_at_us: 160,
                ..meta45
            },
            p5r
        );
        let join_reply = crate::relay::decode_setup_reply_packet(p4r.bytes()).unwrap();
        assert!(matches!(
            join_reply.result,
            crate::relay::SetupResult::Accepted { .. }
        ));
        assert_eq!(join_reply.relay_cids.count(), 3);
        client
            .node
            .receive_packet(
                PacketMeta {
                    received_at_us: 160,
                    ..join_meta
                },
                p4r,
                |_| None,
                on_stream,
            )
            .unwrap();
        assert_eq!(client.node.association_count(), 1);
        assert_eq!(endpoint.association_count(), 1);
        let mut circuits = [crate::CircuitInfo::default(); crate::MAX_PATH_STATES];
        assert_eq!(client.node.circuits(association, &mut circuits), 2);
        assert_eq!(circuits[1].id, join_circuit);
        assert_eq!(circuits[1].status, crate::CircuitStatus::Probing);
    }

    #[test]
    fn committed_packet_batch_is_retained_and_ingress_continues_at_the_queue_limit() {
        static POOL: Pool = Pool::new();
        let (bearer, _peer) = FakePacketBearer::<Pool>::pair(
            BearerName::new("batch-node").unwrap(),
            BearerName::new("batch-peer").unwrap(),
        );
        let mut node = Node::new(&POOL);
        node.set_limits(crate::NodeLimits {
            max_associations: 1,
            max_routes: 1,
            ..crate::NodeLimits::host()
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
    /// Mark this stream as latency-sensitive control traffic. Accepted data
    /// packets may be duplicated over an alternate circuit when budget allows.
    pub fn set_priority(&mut self, priority: bool) {
        self.stream.set_priority(priority);
    }

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
            Ok(Some(crate::node::NodeTimer::CircuitSetupTimedOut { .. })) => Poll::Ready(Ok(())),
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
