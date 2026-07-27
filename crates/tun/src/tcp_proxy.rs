use crate::control::{TapInject, TapInjectSender};
use crate::packet::{TunTcpPacket, build_ipv4_tcp_packet_with_options};
use crate::policy::{FlowContext, FlowProtocol, MeshTunPolicy, TcpRouteDecision};
use bytes::{Bytes, BytesMut};
use mesh::config::DEFAULT_MESH_TUN_MTU;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex as StdMutex, MutexGuard as StdMutexGuard};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

const TCP_REORDER_BUFFER_MAX_BYTES: usize = 256 * 1024;
const IPV4_TCP_HEADER_BYTES: u32 = 40;
const TCP_WINDOW_SCALE_SHIFT: u8 = 7;
// This is a conservative host-to-guest burst cap, not the guest-visible TCP
// receive window. The TAP worker drains 16 near-MTU frames per pass, so cap
// synthetic flight to roughly one drain worth of data. Larger 4-8 MiB bursts
// can leave Linux in the guest silent after the initial reverse-iperf burst.
const TCP_SYNTHETIC_WINDOW_BYTES: u32 = 1 * 1024 * 1024;
const FLOW_TABLE_SHARDS: usize = 64;
const DELAYED_ACK_EVERY_SEGMENTS: u8 = 2;
const DELAYED_ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(1);

fn default_tcp_mss() -> u16 {
    // Keep synthetic TCP segments below the jumbo TAP MTU. 64 KiB packets are
    // fast when accepted, but reverse iperf can randomly stop ACKing after a
    // jumbo burst. 16 KiB still amortizes per-packet cost while staying stable.
    DEFAULT_MESH_TUN_MTU
        .saturating_sub(IPV4_TCP_HEADER_BYTES)
        .min(16 * 1024)
        .min(u16::MAX as u32) as u16
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TcpProxyConfig {
    pub max_flows: usize,
    pub per_flow_queue_capacity: usize,
    pub handshake_timeout: std::time::Duration,
    pub connect_timeout: std::time::Duration,
}

impl Default for TcpProxyConfig {
    fn default() -> Self {
        Self {
            max_flows: 4096,
            per_flow_queue_capacity: 256,
            handshake_timeout: std::time::Duration::from_secs(10),
            connect_timeout: std::time::Duration::from_secs(10),
        }
    }
}

#[derive(Clone)]
pub struct TcpProxyManager {
    config: TcpProxyConfig,
    flows: Arc<FlowTable>,
    outgoing_tx: mpsc::Sender<Vec<u8>>,
    policy: Arc<dyn MeshTunPolicy>,
    vm_id: String,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct TcpFlowKey {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

struct FlowTable {
    shards: Vec<StdMutex<HashMap<TcpFlowKey, mpsc::Sender<TunTcpPacket>>>>,
}

impl FlowTable {
    fn new() -> Self {
        let mut shards = Vec::with_capacity(FLOW_TABLE_SHARDS);
        for _ in 0..FLOW_TABLE_SHARDS {
            shards.push(StdMutex::new(HashMap::new()));
        }
        Self { shards }
    }

    fn shard_index(key: &TcpFlowKey) -> usize {
        // Ports are well distributed for the common iperf and container case,
        // and using them avoids hashing the whole 4-tuple on every packet.
        ((usize::from(key.src.port())) ^ (usize::from(key.dst.port()) << 1))
            & (FLOW_TABLE_SHARDS - 1)
    }

    fn shard(
        &self,
        key: &TcpFlowKey,
    ) -> StdMutexGuard<'_, HashMap<TcpFlowKey, mpsc::Sender<TunTcpPacket>>> {
        self.shards[Self::shard_index(key)]
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| {
                shard
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .len()
            })
            .sum()
    }

    fn remove(&self, key: &TcpFlowKey) {
        self.shard(key).remove(key);
    }
}

fn tcp_seq_after(seq: u32, other: u32) -> bool {
    (seq.wrapping_sub(other) as i32) > 0
}

fn tcp_seq_before_or_equal(seq: u32, other: u32) -> bool {
    (seq.wrapping_sub(other) as i32) <= 0
}

fn advance_tcp_seq(atomic: &AtomicU32, seq: u32) -> u32 {
    let mut current = atomic.load(Ordering::Acquire);
    while tcp_seq_after(seq, current) {
        match atomic.compare_exchange_weak(current, seq, Ordering::Release, Ordering::Acquire) {
            Ok(_) => return seq,
            Err(actual) => current = actual,
        }
    }
    current
}

fn record_atomic_max(counter: &AtomicU64, value: u64) {
    let mut current = counter.load(Ordering::Relaxed);
    while value > current {
        match counter.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

impl TcpProxyManager {
    pub fn new(
        vm_id: String,
        outgoing_tx: mpsc::Sender<Vec<u8>>,
        policy: Arc<dyn MeshTunPolicy>,
        config: TcpProxyConfig,
    ) -> Self {
        Self {
            config,
            flows: Arc::new(FlowTable::new()),
            outgoing_tx,
            policy,
            vm_id,
        }
    }

    pub async fn handle_packet(&self, pkt: TunTcpPacket) {
        crate::stats::record_tcp_packet(pkt.payload.len());
        let key = TcpFlowKey {
            src: SocketAddr::new(pkt.src_addr, pkt.src_port),
            dst: SocketAddr::new(pkt.dst_addr, pkt.dst_port),
        };

        // Existing-flow dispatch is the packet hot path. Use a small sharded
        // synchronous table to avoid yielding on a tokio mutex for every ACK or
        // data segment.
        let existing_tx = {
            let flows_guard = self.flows.shard(&key);
            flows_guard.get(&key).cloned()
        };
        if let Some(tx) = existing_tx {
            crate::stats::record_tcp_flow_packet();
            match tx.try_send(pkt) {
                Ok(()) => return,
                Err(mpsc::error::TrySendError::Full(pkt)) => {
                    crate::stats::stats()
                        .tcp_flow_queue_full
                        .fetch_add(1, Ordering::Relaxed);
                    // ACKs are cumulative but the newest ACK can be the one
                    // that opens the synthetic send window. Dropping it can
                    // stall reverse iperf until timeout, so yield and apply
                    // backpressure instead.
                    if tx.send(pkt).await.is_err() {
                        crate::stats::stats()
                            .tcp_flow_error
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    return;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    crate::stats::stats()
                        .tcp_flow_error
                        .fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        } else if pkt.syn && !pkt.ack {
            if self.flows.len() >= self.config.max_flows {
                crate::stats::stats()
                    .tcp_flow_rejected
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            crate::stats::stats()
                .tcp_syn
                .fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = mpsc::channel(self.config.per_flow_queue_capacity);
            let mut flows_guard = self.flows.shard(&key);
            if flows_guard.contains_key(&key) {
                return;
            }
            flows_guard.insert(key.clone(), tx.clone());
            drop(flows_guard);

            let flows_clone = self.flows.clone();
            let outgoing_tx = self.outgoing_tx.clone();
            let policy = self.policy.clone();
            let config = self.config.clone();
            let vm_id = self.vm_id.clone();

            tokio::spawn(async move {
                if tx.try_send(pkt).is_err() {
                    crate::stats::stats()
                        .tcp_flow_queue_full
                        .fetch_add(1, Ordering::Relaxed);
                }
                handle_tcp_flow(key.src, key.dst, rx, outgoing_tx, policy, config, vm_id).await;
                flows_clone.remove(&key);
            });
        }
    }

    pub async fn connect_inbound(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Result<DuplexStream, anyhow::Error> {
        // Inbound streams may originate from a local listener, SSH, HBONE, or
        // another mesh transport. The original source/destination tuple is
        // preserved here and used both for policy and for the guest-visible
        // synthetic TCP handshake.
        let context = FlowContext {
            vm_id: self.vm_id.clone(),
            protocol: FlowProtocol::Tcp,
            src,
            dst,
        };
        if let crate::policy::PolicyDecision::Deny { reason } = self.policy.check(&context).await {
            crate::stats::stats()
                .tcp_inbound_rejected
                .fetch_add(1, Ordering::Relaxed);
            anyhow::bail!("inbound TCP flow denied: {reason}");
        }

        let key = TcpFlowKey { src: dst, dst: src };
        if self.flows.len() >= self.config.max_flows {
            crate::stats::stats()
                .tcp_inbound_rejected
                .fetch_add(1, Ordering::Relaxed);
            anyhow::bail!("too many TCP flows");
        }
        let (tx, rx) = mpsc::channel(self.config.per_flow_queue_capacity);
        {
            let mut flows_guard = self.flows.shard(&key);
            if flows_guard.contains_key(&key) {
                crate::stats::stats()
                    .tcp_flow_rejected
                    .fetch_add(1, Ordering::Relaxed);
                anyhow::bail!("inbound TCP flow already exists");
            }
            flows_guard.insert(key.clone(), tx);
        }

        let (caller_stream, mesh_stream) = tokio::io::duplex(usize::from(default_tcp_mss()) * 4);
        let outgoing_tx = self.outgoing_tx.clone();
        let flows = self.flows.clone();
        let config = self.config.clone();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            if let Err(error) =
                handle_inbound_tcp_flow(src, dst, rx, outgoing_tx, mesh_stream, config, ready_tx)
                    .await
            {
                tracing::debug!(?src, ?dst, %error, "inbound TCP flow stopped");
                crate::stats::stats()
                    .tcp_flow_error
                    .fetch_add(1, Ordering::Relaxed);
            }
            flows.remove(&key);
        });

        match ready_rx.await {
            Ok(Ok(())) => Ok(caller_stream),
            Ok(Err(error)) => anyhow::bail!(error),
            Err(_) => anyhow::bail!("inbound TCP flow task stopped before handshake"),
        }
    }
}

async fn handle_inbound_tcp_flow(
    src: SocketAddr,
    dst: SocketAddr,
    mut rx: mpsc::Receiver<TunTcpPacket>,
    outgoing_tx: mpsc::Sender<Vec<u8>>,
    mesh_stream: DuplexStream,
    config: TcpProxyConfig,
    ready_tx: tokio::sync::oneshot::Sender<Result<(), String>>,
) -> Result<(), anyhow::Error> {
    let src_ip_v4 = match src.ip() {
        IpAddr::V4(ip) => ip,
        _ => anyhow::bail!("IPv6 inbound TCP is not implemented yet"),
    };
    let dst_ip_v4 = match dst.ip() {
        IpAddr::V4(ip) => ip,
        _ => anyhow::bail!("IPv6 inbound TCP is not implemented yet"),
    };
    let direct_guest_tx = crate::control::destination_sender(&dst.ip());
    let initial_remote_seq = initial_tcp_sequence();
    let remote_seq_shared = Arc::new(AtomicU32::new(initial_remote_seq.wrapping_add(1)));
    let guest_seq_shared = Arc::new(AtomicU32::new(0));
    let remote_acked_shared = Arc::new(AtomicU32::new(initial_remote_seq));

    if !send_tcp4_output(
        Tcp4Output {
            src_addr: src_ip_v4,
            src_port: src.port(),
            dst_addr: dst_ip_v4,
            dst_port: dst.port(),
            flags: 0x02,
            seq: initial_remote_seq,
            ack: 0,
            options: tcp_syn_options().to_vec(),
            payload: Bytes::new(),
        },
        &outgoing_tx,
        direct_guest_tx.as_ref(),
    )
    .await
    {
        crate::stats::stats()
            .tcp_flow_error
            .fetch_add(1, Ordering::Relaxed);
        let message = "failed to send inbound TCP SYN".to_string();
        let _ = ready_tx.send(Err(message.clone()));
        anyhow::bail!(message);
    }
    crate::stats::stats()
        .tcp_inbound_syn_sent
        .fetch_add(1, Ordering::Relaxed);

    let expected_ack = initial_remote_seq.wrapping_add(1);
    let syn_ack = loop {
        let recv = tokio::time::timeout(config.handshake_timeout, rx.recv()).await;
        let Some(pkt) = (match recv {
            Ok(pkt) => pkt,
            Err(_) => {
                crate::stats::stats()
                    .tcp_handshake_timeout
                    .fetch_add(1, Ordering::Relaxed);
                let message = "inbound TCP handshake timed out".to_string();
                let _ = ready_tx.send(Err(message.clone()));
                anyhow::bail!(message);
            }
        }) else {
            let message = "inbound TCP flow closed during handshake".to_string();
            let _ = ready_tx.send(Err(message.clone()));
            anyhow::bail!(message);
        };

        if pkt.syn && pkt.ack && pkt.ack_num == expected_ack {
            break pkt;
        }
        if pkt.rst || pkt.fin {
            let message = "inbound TCP flow rejected by guest".to_string();
            let _ = ready_tx.send(Err(message.clone()));
            anyhow::bail!(message);
        }
        crate::stats::stats()
            .tcp_handshake_skip
            .fetch_add(1, Ordering::Relaxed);
    };

    let guest_seq = syn_ack.seq.wrapping_add(1);
    guest_seq_shared.store(guest_seq, Ordering::Release);
    advance_tcp_seq(&remote_acked_shared, syn_ack.ack_num);

    if !send_tcp4_output(
        Tcp4Output {
            src_addr: src_ip_v4,
            src_port: src.port(),
            dst_addr: dst_ip_v4,
            dst_port: dst.port(),
            flags: 0x10,
            seq: expected_ack,
            ack: guest_seq,
            options: Vec::new(),
            payload: Bytes::new(),
        },
        &outgoing_tx,
        direct_guest_tx.as_ref(),
    )
    .await
    {
        crate::stats::stats()
            .tcp_flow_error
            .fetch_add(1, Ordering::Relaxed);
        let message = "failed to send inbound TCP handshake ACK".to_string();
        let _ = ready_tx.send(Err(message.clone()));
        anyhow::bail!(message);
    }
    crate::stats::stats()
        .tcp_inbound_ack_sent
        .fetch_add(1, Ordering::Relaxed);
    crate::stats::stats()
        .tcp_inbound_open
        .fetch_add(1, Ordering::Relaxed);
    let _ = ready_tx.send(Ok(()));

    let (mut reader, mut writer) = tokio::io::split(mesh_stream);
    let remote_seq_a = remote_seq_shared.clone();
    let guest_seq_a = guest_seq_shared.clone();
    let remote_acked_a = remote_acked_shared.clone();
    let outgoing_tx_a = outgoing_tx.clone();
    let direct_guest_tx_a = direct_guest_tx.clone();
    let ack_notify = Arc::new(tokio::sync::Notify::new());
    let ack_notify_rx = ack_notify.clone();
    let ack_notify_tx = ack_notify.clone();

    let mut rx_task = tokio::spawn(async move {
        let mut guest_seq = guest_seq_a.load(Ordering::Acquire);
        while let Some(pkt) = rx.recv().await {
            if pkt.rst {
                break;
            }
            if pkt.ack {
                advance_tcp_seq(&remote_acked_a, pkt.ack_num);
                ack_notify_tx.notify_one();
            }
            if !pkt.payload.is_empty() {
                let segment_end = pkt.seq.wrapping_add(pkt.payload.len() as u32);
                if tcp_seq_after(segment_end, guest_seq)
                    && tcp_seq_before_or_equal(pkt.seq, guest_seq)
                {
                    let offset = guest_seq.wrapping_sub(pkt.seq) as usize;
                    let new_data = &pkt.payload[offset..];
                    if !new_data.is_empty() {
                        if writer.write_all(new_data).await.is_err() {
                            crate::stats::stats()
                                .tcp_flow_error
                                .fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                        crate::stats::record_tcp_guest_to_host(new_data.len());
                        crate::stats::stats()
                            .tcp_guest_write_calls
                            .fetch_add(1, Ordering::Relaxed);
                        guest_seq = guest_seq.wrapping_add(new_data.len() as u32);
                        guest_seq_a.store(guest_seq, Ordering::Release);
                    }
                }
                let r_seq = remote_seq_a.load(Ordering::Relaxed);
                let _ = send_tcp4_output(
                    Tcp4Output {
                        src_addr: src_ip_v4,
                        src_port: src.port(),
                        dst_addr: dst_ip_v4,
                        dst_port: dst.port(),
                        flags: 0x10,
                        seq: r_seq,
                        ack: guest_seq,
                        options: Vec::new(),
                        payload: Bytes::new(),
                    },
                    &outgoing_tx_a,
                    direct_guest_tx_a.as_ref(),
                )
                .await;
                crate::stats::record_tcp_ack_sent();
            }
            if pkt.fin {
                let r_seq = remote_seq_a.load(Ordering::Relaxed);
                let final_guest_seq = guest_seq.wrapping_add(1);
                guest_seq_a.store(final_guest_seq, Ordering::Release);
                let _ = send_tcp4_output(
                    Tcp4Output {
                        src_addr: src_ip_v4,
                        src_port: src.port(),
                        dst_addr: dst_ip_v4,
                        dst_port: dst.port(),
                        flags: 0x11,
                        seq: r_seq,
                        ack: final_guest_seq,
                        options: Vec::new(),
                        payload: Bytes::new(),
                    },
                    &outgoing_tx_a,
                    direct_guest_tx_a.as_ref(),
                )
                .await;
                let _ = writer.shutdown().await;
                break;
            }
        }
    });

    let mut tx_task = tokio::spawn(async move {
        loop {
            let mut payload = BytesMut::with_capacity(usize::from(default_tcp_mss()));
            match reader.read_buf(&mut payload).await {
                Ok(0) => {
                    let r_seq = remote_seq_shared.fetch_add(1, Ordering::Relaxed);
                    let g_seq = guest_seq_shared.load(Ordering::Relaxed);
                    let _ = send_tcp4_output(
                        Tcp4Output {
                            src_addr: src_ip_v4,
                            src_port: src.port(),
                            dst_addr: dst_ip_v4,
                            dst_port: dst.port(),
                            flags: 0x11,
                            seq: r_seq,
                            ack: g_seq,
                            options: Vec::new(),
                            payload: Bytes::new(),
                        },
                        &outgoing_tx,
                        direct_guest_tx.as_ref(),
                    )
                    .await;
                    crate::stats::stats()
                        .tcp_fin_sent
                        .fetch_add(1, Ordering::Relaxed);
                    break;
                }
                Ok(n) => {
                    crate::stats::record_tcp_host_to_guest(n);
                    crate::stats::stats()
                        .tcp_host_read_calls
                        .fetch_add(1, Ordering::Relaxed);
                    let r_seq = remote_seq_shared.load(Ordering::Relaxed);
                    let window = TCP_SYNTHETIC_WINDOW_BYTES;
                    let deadline =
                        tokio::time::Instant::now() + tokio::time::Duration::from_secs(60);
                    loop {
                        let acked = remote_acked_shared.load(Ordering::Acquire);
                        let in_flight = r_seq.wrapping_add(n as u32).wrapping_sub(acked);
                        if in_flight <= window {
                            break;
                        }
                        let timeout = tokio::time::sleep_until(deadline);
                        tokio::pin!(timeout);
                        tokio::select! {
                            _ = ack_notify_rx.notified() => {}
                            _ = &mut timeout => {
                                crate::stats::stats()
                                    .tcp_flow_error
                                    .fetch_add(1, Ordering::Relaxed);
                                return;
                            }
                        }
                    }

                    let g_seq = guest_seq_shared.load(Ordering::Relaxed);
                    let payload = payload.freeze();
                    if !send_tcp4_output(
                        Tcp4Output {
                            src_addr: src_ip_v4,
                            src_port: src.port(),
                            dst_addr: dst_ip_v4,
                            dst_port: dst.port(),
                            flags: 0x10,
                            seq: r_seq,
                            ack: g_seq,
                            options: Vec::new(),
                            payload,
                        },
                        &outgoing_tx,
                        direct_guest_tx.as_ref(),
                    )
                    .await
                    {
                        crate::stats::stats()
                            .tun_output_queue_full
                            .fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    // Keep the published seq aligned with frames already
                    // accepted for output; otherwise close/control frames can
                    // race ahead of data in the guest-visible TCP stream.
                    remote_seq_shared.fetch_add(n as u32, Ordering::Release);
                    crate::stats::record_tcp_data_sent();
                }
                Err(_) => {
                    crate::stats::stats()
                        .tcp_flow_error
                        .fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }
        }
    });

    let _ = tokio::select! {
        res = &mut rx_task => {
            tx_task.abort();
            res
        }
        res = &mut tx_task => {
            rx_task.abort();
            res
        }
    };
    crate::stats::stats()
        .tcp_flow_close
        .fetch_add(1, Ordering::Relaxed);
    crate::stats::flush_hot_counters();
    Ok(())
}

async fn handle_tcp_flow(
    src: SocketAddr,
    dst: SocketAddr,
    mut rx: mpsc::Receiver<TunTcpPacket>,
    outgoing_tx: mpsc::Sender<Vec<u8>>,
    policy: Arc<dyn MeshTunPolicy>,
    config: TcpProxyConfig,
    vm_id: String,
) {
    let syn_pkt = match rx.recv().await {
        Some(pkt) if pkt.syn && !pkt.ack => pkt,
        _ => return,
    };
    crate::stats::stats()
        .tcp_flow_open
        .fetch_add(1, Ordering::Relaxed);

    let src_ip_v4 = match src.ip() {
        IpAddr::V4(ip) => ip,
        _ => return,
    };
    let direct_guest_tx = crate::control::destination_sender(&src.ip());
    let dst_ip_v4 = match dst.ip() {
        IpAddr::V4(ip) => ip,
        _ => return,
    };

    let context = FlowContext {
        vm_id,
        protocol: FlowProtocol::Tcp,
        src,
        dst,
    };

    let connect_result = match policy.route_tcp(&context).await {
        TcpRouteDecision::Connect { connector } => {
            tokio::time::timeout(config.connect_timeout, connector.connect(&context)).await
        }
        TcpRouteDecision::Deny { reason } => {
            tracing::debug!(?src, ?dst, %reason, "TCP flow denied before SYN-ACK");
            crate::stats::stats()
                .tcp_flow_rejected
                .fetch_add(1, Ordering::Relaxed);
            send_tcp_reset(
                src_ip_v4,
                src.port(),
                dst_ip_v4,
                dst.port(),
                &syn_pkt,
                &outgoing_tx,
                direct_guest_tx.as_ref(),
            )
            .await;
            return;
        }
    };

    let backend_stream = match connect_result {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            tracing::debug!(?src, ?dst, %error, "TCP backend connect failed before SYN-ACK");
            crate::stats::stats()
                .tcp_flow_error
                .fetch_add(1, Ordering::Relaxed);
            send_tcp_reset(
                src_ip_v4,
                src.port(),
                dst_ip_v4,
                dst.port(),
                &syn_pkt,
                &outgoing_tx,
                direct_guest_tx.as_ref(),
            )
            .await;
            return;
        }
        Err(_) => {
            tracing::debug!(?src, ?dst, "TCP backend connect timed out before SYN-ACK");
            crate::stats::stats()
                .tcp_flow_error
                .fetch_add(1, Ordering::Relaxed);
            send_tcp_reset(
                src_ip_v4,
                src.port(),
                dst_ip_v4,
                dst.port(),
                &syn_pkt,
                &outgoing_tx,
                direct_guest_tx.as_ref(),
            )
            .await;
            return;
        }
    };

    let backend_flow_control = backend_stream.flow_control.clone();
    if let Some(flow_control) = &backend_flow_control {
        crate::stats::stats()
            .tcp_backend_flow_control
            .fetch_add(1, Ordering::Relaxed);
        if let Some(snapshot) = flow_control.snapshot() {
            tracing::trace!(
                send_capacity_bytes = snapshot.send_capacity_bytes,
                unacked_packets = snapshot.unacked_packets,
                notsent_bytes = snapshot.notsent_bytes,
                send_cwnd_packets = snapshot.send_cwnd_packets,
                send_mss = snapshot.send_mss,
                "native TCP backend flow-control metadata available"
            );
        }
    }
    let (mut reader, mut writer) = tokio::io::split(backend_stream.stream);

    let initial_server_seq = initial_tcp_sequence();
    let server_seq_shared = Arc::new(AtomicU32::new(initial_server_seq.wrapping_add(1)));
    let client_seq_shared = Arc::new(AtomicU32::new(syn_pkt.seq.wrapping_add(1)));
    let client_acked_shared = Arc::new(AtomicU32::new(initial_server_seq));

    // Send SYN-ACK
    let syn_ack_options = tcp_syn_ack_options().to_vec();
    if !send_tcp4_output(
        Tcp4Output {
            src_addr: dst_ip_v4,
            src_port: dst.port(),
            dst_addr: src_ip_v4,
            dst_port: src.port(),
            flags: 0x12,
            seq: initial_server_seq,
            ack: syn_pkt.seq.wrapping_add(1),
            options: syn_ack_options.clone(),
            payload: Bytes::new(),
        },
        &outgoing_tx,
        direct_guest_tx.as_ref(),
    )
    .await
    {
        crate::stats::stats()
            .tcp_flow_error
            .fetch_add(1, Ordering::Relaxed);
        return;
    }
    crate::stats::stats()
        .tcp_syn_ack_sent
        .fetch_add(1, Ordering::Relaxed);

    let expected_ack = initial_server_seq.wrapping_add(1);
    let ack_pkt = loop {
        let recv = tokio::time::timeout(config.handshake_timeout, rx.recv()).await;
        let Some(pkt) = (match recv {
            Ok(pkt) => pkt,
            Err(_) => {
                crate::stats::stats()
                    .tcp_handshake_timeout
                    .fetch_add(1, Ordering::Relaxed);
                crate::stats::stats()
                    .tcp_flow_error
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
        }) else {
            crate::stats::stats()
                .tcp_flow_error
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        if pkt.ack && pkt.ack_num == expected_ack {
            break pkt;
        }
        if pkt.rst || pkt.fin {
            crate::stats::stats()
                .tcp_flow_error
                .fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                ?src,
                ?dst,
                rst = pkt.rst,
                fin = pkt.fin,
                "TCP flow closed during handshake"
            );
            return;
        }
        if pkt.syn && !pkt.ack {
            if !send_tcp4_output(
                Tcp4Output {
                    src_addr: dst_ip_v4,
                    src_port: dst.port(),
                    dst_addr: src_ip_v4,
                    dst_port: src.port(),
                    flags: 0x12,
                    seq: initial_server_seq,
                    ack: syn_pkt.seq.wrapping_add(1),
                    options: syn_ack_options.clone(),
                    payload: Bytes::new(),
                },
                &outgoing_tx,
                direct_guest_tx.as_ref(),
            )
            .await
            {
                crate::stats::stats()
                    .tcp_flow_error
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            crate::stats::stats()
                .tcp_syn_ack_sent
                .fetch_add(1, Ordering::Relaxed);
        }
        crate::stats::stats()
            .tcp_handshake_skip
            .fetch_add(1, Ordering::Relaxed);
        crate::stats::stats()
            .tcp_last_handshake_flags
            .store(tcp_flags(&pkt) as u64, Ordering::Relaxed);
        crate::stats::stats()
            .tcp_last_handshake_seq
            .store(pkt.seq as u64, Ordering::Relaxed);
        crate::stats::stats()
            .tcp_last_handshake_ack
            .store(pkt.ack_num as u64, Ordering::Relaxed);
        crate::stats::stats()
            .tcp_last_handshake_expected_ack
            .store(expected_ack as u64, Ordering::Relaxed);
        crate::stats::stats()
            .tcp_last_handshake_payload_len
            .store(pkt.payload.len() as u64, Ordering::Relaxed);
        tracing::debug!(
            ?src,
            ?dst,
            syn = pkt.syn,
            ack = pkt.ack,
            seq = pkt.seq,
            ack_num = pkt.ack_num,
            expected_ack,
            payload_len = pkt.payload.len(),
            "skipping TCP packet while waiting for handshake ACK"
        );
    };

    advance_tcp_seq(&client_acked_shared, ack_pkt.ack_num);
    crate::stats::stats()
        .tcp_ack_after_syn
        .fetch_add(1, Ordering::Relaxed);

    let server_seq_a = server_seq_shared.clone();
    let client_seq_a = client_seq_shared.clone();
    let client_acked_a = client_acked_shared.clone();
    let outgoing_tx_a = outgoing_tx.clone();
    let direct_guest_tx_a = direct_guest_tx.clone();
    let bulk_flow = Arc::new(AtomicBool::new(false));
    let bulk_flow_rx = bulk_flow.clone();
    let bulk_flow_tx = bulk_flow.clone();

    // B2: Notify the tx_task (host→guest) when an ACK advances the window,
    // instead of the old 5ms busy-poll that burned CPU and could deadlock.
    let ack_notify = Arc::new(tokio::sync::Notify::new());
    let ack_notify_rx = ack_notify.clone();
    let ack_notify_tx = ack_notify.clone();

    // Task A: Guest to Host (Read rx -> Write writer)
    let mut rx_task = tokio::spawn(async move {
        let mut client_seq = client_seq_a.load(Ordering::Acquire);
        // B3: Reorder buffer for out-of-order segments, keyed by seq.
        let mut ooo_buf: std::collections::BTreeMap<u32, bytes::Bytes> =
            std::collections::BTreeMap::new();
        let mut ooo_bytes = 0usize;
        let mut pending_ack = false;
        let mut pending_ack_seq = client_seq;
        let mut pending_ack_segments = 0u8;

        loop {
            let pkt = if pending_ack {
                tokio::select! {
                    pkt = rx.recv() => pkt,
                    _ = tokio::time::sleep(DELAYED_ACK_TIMEOUT) => {
                        let s_seq = server_seq_a.load(Ordering::Relaxed);
                        if !send_tcp_ack(
                            dst_ip_v4,
                            dst.port(),
                            src_ip_v4,
                            src.port(),
                            s_seq,
                            pending_ack_seq,
                            &outgoing_tx_a,
                            direct_guest_tx_a.as_ref(),
                        ).await {
                            crate::stats::stats()
                                .tun_output_queue_full
                                .fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                        pending_ack = false;
                        pending_ack_segments = 0;
                        continue;
                    }
                }
            } else {
                rx.recv().await
            };
            let Some(pkt) = pkt else {
                break;
            };
            if pkt.rst {
                break;
            }

            if pkt.ack {
                let advanced_ack = advance_tcp_seq(&client_acked_a, pkt.ack_num);
                crate::stats::stats()
                    .tcp_last_ack_num
                    .store(advanced_ack as u64, Ordering::Relaxed);
                crate::stats::stats()
                    .tcp_last_ack_flags
                    .store(u64::from(tcp_flags(&pkt)), Ordering::Relaxed);
                if bulk_flow_rx.load(Ordering::Relaxed) {
                    crate::stats::stats()
                        .tcp_bulk_last_ack_num
                        .store(advanced_ack as u64, Ordering::Relaxed);
                    crate::stats::stats()
                        .tcp_bulk_last_ack_flags
                        .store(u64::from(tcp_flags(&pkt)), Ordering::Relaxed);
                }
                // B2: Wake the tx_task so it can re-check the window.
                ack_notify_tx.notify_one();
            }

            if !pkt.payload.is_empty() {
                // B3: Handle in-order, out-of-order, and retransmitted data.
                let segment_end = pkt.seq.wrapping_add(pkt.payload.len() as u32);
                if tcp_seq_after(segment_end, client_seq)
                    && tcp_seq_before_or_equal(pkt.seq, client_seq)
                {
                    // In-order or overlapping: extract the new portion.
                    let offset = client_seq.wrapping_sub(pkt.seq) as usize;
                    let new_data = &pkt.payload[offset..];
                    if !new_data.is_empty() {
                        if writer.write_all(new_data).await.is_err() {
                            crate::stats::stats()
                                .tcp_flow_error
                                .fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                        crate::stats::record_tcp_guest_to_host(new_data.len());
                        crate::stats::stats()
                            .tcp_guest_write_calls
                            .fetch_add(1, Ordering::Relaxed);
                        client_seq = client_seq.wrapping_add(new_data.len() as u32);
                        client_seq_a.store(client_seq, Ordering::Release);

                        // Drain the reorder buffer for any now-in-order segments.
                        while let Some(seg) = ooo_buf.remove(&client_seq) {
                            ooo_bytes = ooo_bytes.saturating_sub(seg.len());
                            if writer.write_all(&seg).await.is_err() {
                                crate::stats::stats()
                                    .tcp_flow_error
                                    .fetch_add(1, Ordering::Relaxed);
                                break;
                            }
                            crate::stats::record_tcp_guest_to_host(seg.len());
                            crate::stats::stats()
                                .tcp_guest_write_calls
                                .fetch_add(1, Ordering::Relaxed);
                            client_seq = client_seq.wrapping_add(seg.len() as u32);
                            client_seq_a.store(client_seq, Ordering::Release);
                        }
                    }
                } else if tcp_seq_after(pkt.seq, client_seq) {
                    // B3: Out-of-order — buffer for later delivery.
                    if let Some(previous) = ooo_buf.insert(pkt.seq, pkt.payload.clone()) {
                        ooo_bytes = ooo_bytes.saturating_sub(previous.len());
                    }
                    ooo_bytes = ooo_bytes.saturating_add(pkt.payload.len());
                    // Avoid delivering gaps if the out-of-order queue grows beyond
                    // its bounded budget. Close the flow and reset the guest side.
                    if ooo_bytes > TCP_REORDER_BUFFER_MAX_BYTES {
                        crate::stats::stats()
                            .tcp_flow_error
                            .fetch_add(1, Ordering::Relaxed);
                        let s_seq = server_seq_a.load(Ordering::Relaxed);
                        let _ = send_tcp4_output(
                            Tcp4Output {
                                src_addr: dst_ip_v4,
                                src_port: dst.port(),
                                dst_addr: src_ip_v4,
                                dst_port: src.port(),
                                flags: 0x14,
                                seq: s_seq,
                                ack: client_seq,
                                options: Vec::new(),
                                payload: Bytes::new(),
                            },
                            &outgoing_tx_a,
                            direct_guest_tx_a.as_ref(),
                        )
                        .await;
                        break;
                    }
                }
                // If pkt.seq + len <= client_seq, it's a pure retransmit of
                // already-received data — ack but don't re-deliver.

                pending_ack = true;
                pending_ack_seq = client_seq;
                pending_ack_segments = pending_ack_segments.saturating_add(1);
                // ACK coalescing reduces TAP packet rate during uploads. Flush
                // every second data segment or after a short timer above; the
                // timer keeps request/response flows responsive.
                if pending_ack_segments >= DELAYED_ACK_EVERY_SEGMENTS {
                    let s_seq = server_seq_a.load(Ordering::Relaxed);
                    if !send_tcp_ack(
                        dst_ip_v4,
                        dst.port(),
                        src_ip_v4,
                        src.port(),
                        s_seq,
                        pending_ack_seq,
                        &outgoing_tx_a,
                        direct_guest_tx_a.as_ref(),
                    )
                    .await
                    {
                        crate::stats::stats()
                            .tun_output_queue_full
                            .fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    pending_ack = false;
                    pending_ack_segments = 0;
                }
            }

            if pkt.fin {
                if pending_ack {
                    let s_seq = server_seq_a.load(Ordering::Relaxed);
                    let _ = send_tcp_ack(
                        dst_ip_v4,
                        dst.port(),
                        src_ip_v4,
                        src.port(),
                        s_seq,
                        pending_ack_seq,
                        &outgoing_tx_a,
                        direct_guest_tx_a.as_ref(),
                    )
                    .await;
                }
                let s_seq = server_seq_a.load(Ordering::Relaxed);
                let final_client_seq = client_seq.wrapping_add(1);
                client_seq_a.store(final_client_seq, Ordering::Release);
                // B3: Reply with FIN|ACK (0x11) instead of bare ACK (0x10) for
                // a cleaner close per RFC 793.
                let _ = send_tcp4_output(
                    Tcp4Output {
                        src_addr: dst_ip_v4,
                        src_port: dst.port(),
                        dst_addr: src_ip_v4,
                        dst_port: src.port(),
                        flags: 0x11,
                        seq: s_seq,
                        ack: final_client_seq,
                        options: Vec::new(),
                        payload: Bytes::new(),
                    },
                    &outgoing_tx_a,
                    direct_guest_tx_a.as_ref(),
                )
                .await;
                crate::stats::stats()
                    .tcp_fin_sent
                    .fetch_add(1, Ordering::Relaxed);
                let _ = writer.shutdown().await;
                break;
            }
        }
    });

    // Task B: Host to Guest (Read reader -> Send outgoing_tx)
    let mut tx_task = tokio::spawn(async move {
        // Match the advertised default MSS so host-to-guest traffic also uses
        // near-MTU packets on the default mesh-tun TAP path.
        loop {
            let mut payload = BytesMut::with_capacity(usize::from(default_tcp_mss()));
            let read_started = tokio::time::Instant::now();
            match reader.read_buf(&mut payload).await {
                Ok(0) => {
                    let s_seq = server_seq_shared.fetch_add(1, Ordering::Relaxed);
                    let c_seq = client_seq_shared.load(Ordering::Relaxed);
                    let _ = send_tcp4_output(
                        Tcp4Output {
                            src_addr: dst_ip_v4,
                            src_port: dst.port(),
                            dst_addr: src_ip_v4,
                            dst_port: src.port(),
                            flags: 0x11,
                            seq: s_seq,
                            ack: c_seq,
                            options: Vec::new(),
                            payload: Bytes::new(),
                        },
                        &outgoing_tx,
                        direct_guest_tx.as_ref(),
                    )
                    .await;
                    crate::stats::stats()
                        .tcp_fin_sent
                        .fetch_add(1, Ordering::Relaxed);
                    crate::stats::stats()
                        .tcp_flow_close
                        .fetch_add(1, Ordering::Relaxed);
                    break;
                }
                Ok(n) => {
                    let read_wait = read_started.elapsed();
                    if n > 1024 {
                        bulk_flow_tx.store(true, Ordering::Relaxed);
                        let stats = crate::stats::stats();
                        stats
                            .tcp_bulk_backend_read_wait_ns
                            .fetch_add(read_wait.as_nanos() as u64, Ordering::Relaxed);
                        if read_wait >= tokio::time::Duration::from_millis(1) {
                            stats
                                .tcp_bulk_backend_read_wait_slow
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    crate::stats::record_tcp_host_to_guest(n);
                    crate::stats::stats()
                        .tcp_host_read_calls
                        .fetch_add(1, Ordering::Relaxed);
                    let s_seq = server_seq_shared.load(Ordering::Relaxed);
                    // B2: Wait for send window to open, woken by the rx_task's
                    // notify on ACK. Use a 60s overall timeout to avoid an
                    // unbounded hang if the client never ACKs.
                    let window = TCP_SYNTHETIC_WINDOW_BYTES;
                    let deadline =
                        tokio::time::Instant::now() + tokio::time::Duration::from_secs(60);
                    loop {
                        let acked = client_acked_shared.load(Ordering::Acquire);
                        let in_flight = s_seq.wrapping_add(n as u32).wrapping_sub(acked);
                        let send_end = s_seq.wrapping_add(n as u32);
                        let stats = crate::stats::stats();
                        stats
                            .tcp_last_send_seq
                            .store(s_seq as u64, Ordering::Relaxed);
                        stats
                            .tcp_last_send_end
                            .store(send_end as u64, Ordering::Relaxed);
                        stats.tcp_last_send_len.store(n as u64, Ordering::Relaxed);
                        stats.tcp_last_acked.store(acked as u64, Ordering::Relaxed);
                        stats
                            .tcp_last_in_flight
                            .store(in_flight as u64, Ordering::Relaxed);
                        if bulk_flow_tx.load(Ordering::Relaxed) {
                            stats
                                .tcp_bulk_last_send_seq
                                .store(s_seq as u64, Ordering::Relaxed);
                            stats
                                .tcp_bulk_last_send_end
                                .store(send_end as u64, Ordering::Relaxed);
                            stats
                                .tcp_bulk_last_send_len
                                .store(n as u64, Ordering::Relaxed);
                            stats
                                .tcp_bulk_last_acked
                                .store(acked as u64, Ordering::Relaxed);
                            stats
                                .tcp_bulk_last_in_flight
                                .store(in_flight as u64, Ordering::Relaxed);
                            record_atomic_max(&stats.tcp_bulk_max_in_flight, in_flight as u64);
                        }
                        if in_flight <= window {
                            break;
                        }
                        stats.tcp_window_wait.fetch_add(1, Ordering::Relaxed);
                        if bulk_flow_tx.load(Ordering::Relaxed) {
                            stats.tcp_bulk_window_wait.fetch_add(1, Ordering::Relaxed);
                        }
                        // Window full: wait for an ACK notification.
                        let timeout = tokio::time::sleep_until(deadline);
                        tokio::pin!(timeout);
                        let wait_started = tokio::time::Instant::now();
                        tokio::select! {
                            _ = ack_notify_rx.notified() => {
                                let waited = wait_started.elapsed();
                                crate::stats::stats()
                                    .tcp_window_wake
                                    .fetch_add(1, Ordering::Relaxed);
                                if bulk_flow_tx.load(Ordering::Relaxed) {
                                    crate::stats::stats()
                                        .tcp_bulk_window_wake
                                        .fetch_add(1, Ordering::Relaxed);
                                    crate::stats::stats()
                                        .tcp_bulk_window_wait_ns
                                        .fetch_add(waited.as_nanos() as u64, Ordering::Relaxed);
                                    if waited >= tokio::time::Duration::from_millis(1) {
                                        crate::stats::stats()
                                            .tcp_bulk_window_wait_slow
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                                            _ = &mut timeout => {
                                tracing::warn!(
                                    "TCP flow {:?}->{:?} timed out waiting for ACK window",
                                    src, dst
                                );
                                crate::stats::stats()
                                    .tcp_window_timeout
                                    .fetch_add(1, Ordering::Relaxed);
                                crate::stats::stats()
                                    .tcp_flow_error
                                    .fetch_add(1, Ordering::Relaxed);
                                return;
                            }
                        }
                    }

                    let c_seq = client_seq_shared.load(Ordering::Relaxed);
                    let payload = payload.freeze();
                    let send_started = tokio::time::Instant::now();
                    let sent = send_tcp4_output(
                        Tcp4Output {
                            src_addr: dst_ip_v4,
                            src_port: dst.port(),
                            dst_addr: src_ip_v4,
                            dst_port: src.port(),
                            flags: 0x10,
                            seq: s_seq,
                            ack: c_seq,
                            options: Vec::new(),
                            payload,
                        },
                        &outgoing_tx,
                        direct_guest_tx.as_ref(),
                    )
                    .await;
                    let send_wait = send_started.elapsed();
                    if n > 1024 {
                        let stats = crate::stats::stats();
                        let send_wait_ns = send_wait.as_nanos() as u64;
                        stats
                            .tcp_bulk_output_send_wait_ns
                            .fetch_add(send_wait_ns, Ordering::Relaxed);
                        record_atomic_max(&stats.tcp_bulk_output_send_wait_max_ns, send_wait_ns);
                        if send_wait >= tokio::time::Duration::from_millis(1) {
                            stats
                                .tcp_bulk_output_send_wait_slow
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    if !sent {
                        crate::stats::stats()
                            .tun_output_queue_full
                            .fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    // Advance only after the frame is accepted for output.
                    // This prevents a concurrent FIN/RST response from seeing
                    // a post-data seq before the guest can receive that data.
                    server_seq_shared.fetch_add(n as u32, Ordering::Release);
                    crate::stats::record_tcp_data_sent();
                }
                Err(_) => {
                    crate::stats::stats()
                        .tcp_flow_error
                        .fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }
        }
    });

    // B2: Abort the loser task to prevent task/FD leaks. Previously the select!
    // returned the winner's result and leaked the loser (which could keep
    // touching outgoing_tx and atomics).
    let _ = tokio::select! {
        res = &mut rx_task => {
            tx_task.abort();
            res
        }
        res = &mut tx_task => {
            rx_task.abort();
            res
        }
    };
    crate::stats::flush_hot_counters();
}

fn tcp_syn_ack_options() -> [u8; 8] {
    // Kind=2, Len=4, MSS=default MTU minus IPv4/TCP headers. Kind=3, Len=3,
    // Shift=7 advertises an
    // ~8 MiB receive window instead of the unscaled ~64 KiB TCP header field.
    // Without MSS, Linux falls back to ~536-byte segments; without window
    // scaling, large-MSS uploads keep only one segment in flight.
    let mss = default_tcp_mss().to_be_bytes();
    [2, 4, mss[0], mss[1], 1, 3, 3, TCP_WINDOW_SCALE_SHIFT]
}

fn tcp_syn_options() -> [u8; 8] {
    tcp_syn_ack_options()
}

fn initial_tcp_sequence() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u32)
        .unwrap_or(0)
}

fn tcp_flags(pkt: &TunTcpPacket) -> u8 {
    (if pkt.fin { 0x01 } else { 0 })
        | (if pkt.syn { 0x02 } else { 0 })
        | (if pkt.rst { 0x04 } else { 0 })
        | (if pkt.ack { 0x10 } else { 0 })
}

struct Tcp4Output {
    src_addr: std::net::Ipv4Addr,
    src_port: u16,
    dst_addr: std::net::Ipv4Addr,
    dst_port: u16,
    flags: u8,
    seq: u32,
    ack: u32,
    options: Vec<u8>,
    payload: Bytes,
}

async fn send_tcp4_output(
    output: Tcp4Output,
    outgoing_tx: &mpsc::Sender<Vec<u8>>,
    direct_guest_tx: Option<&TapInjectSender>,
) -> bool {
    if let Some(tx) = direct_guest_tx {
        let direct = TapInject::Tcp4 {
            src_addr: output.src_addr,
            src_port: output.src_port,
            dst_addr: output.dst_addr,
            dst_port: output.dst_port,
            flags: output.flags,
            seq: output.seq,
            ack: output.ack,
            options: output.options,
            payload: output.payload,
        };
        match tx.send(direct).await {
            Ok(()) => {
                crate::stats::stats()
                    .route_hit
                    .fetch_add(1, Ordering::Relaxed);
                return true;
            }
            Err(error) => {
                let TapInject::Tcp4 {
                    src_addr,
                    src_port,
                    dst_addr,
                    dst_port,
                    flags,
                    seq,
                    ack,
                    options,
                    payload,
                } = error.0
                else {
                    unreachable!("direct TCP output returned unexpected inject variant")
                };
                return build_and_send_tcp4(
                    Tcp4Output {
                        src_addr,
                        src_port,
                        dst_addr,
                        dst_port,
                        flags,
                        seq,
                        ack,
                        options,
                        payload,
                    },
                    outgoing_tx,
                )
                .await;
            }
        }
    }

    build_and_send_tcp4(output, outgoing_tx).await
}

async fn build_and_send_tcp4(output: Tcp4Output, outgoing_tx: &mpsc::Sender<Vec<u8>>) -> bool {
    let packet = build_ipv4_tcp_packet_with_options(
        output.src_addr,
        output.src_port,
        output.dst_addr,
        output.dst_port,
        output.flags,
        output.seq,
        output.ack,
        &output.options,
        &output.payload,
    );
    match packet {
        Ok(packet) => outgoing_tx.send(packet).await.is_ok(),
        Err(error) => {
            tracing::error!(%error, "failed to build TCP output packet");
            false
        }
    }
}

async fn send_tcp_ack(
    src_addr: std::net::Ipv4Addr,
    src_port: u16,
    dst_addr: std::net::Ipv4Addr,
    dst_port: u16,
    seq: u32,
    ack: u32,
    outgoing_tx: &mpsc::Sender<Vec<u8>>,
    direct_guest_tx: Option<&TapInjectSender>,
) -> bool {
    let sent = send_tcp4_output(
        Tcp4Output {
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            flags: 0x10,
            seq,
            ack,
            options: Vec::new(),
            payload: Bytes::new(),
        },
        outgoing_tx,
        direct_guest_tx,
    )
    .await;
    if sent {
        crate::stats::record_tcp_ack_sent();
    }
    sent
}

async fn send_tcp_reset(
    src_ip_v4: std::net::Ipv4Addr,
    src_port: u16,
    dst_ip_v4: std::net::Ipv4Addr,
    dst_port: u16,
    syn_pkt: &TunTcpPacket,
    outgoing_tx: &mpsc::Sender<Vec<u8>>,
    direct_guest_tx: Option<&TapInjectSender>,
) {
    let _ = send_tcp4_output(
        Tcp4Output {
            src_addr: dst_ip_v4,
            src_port: dst_port,
            dst_addr: src_ip_v4,
            dst_port: src_port,
            flags: 0x14,
            seq: 0,
            ack: syn_pkt.seq.wrapping_add(1),
            options: Vec::new(),
            payload: Bytes::new(),
        },
        outgoing_tx,
        direct_guest_tx,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{TunPacket, build_ipv4_tcp_packet, parse_ip_packet};
    use crate::policy::{PolicyDecision, TcpRouteDecision};
    use crate::transport::{BoxTunByteStream, ConnectedTcpStream, TcpConnector};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    struct DuplexConnector;

    #[async_trait::async_trait]
    impl TcpConnector for DuplexConnector {
        async fn connect(&self, _ctx: &FlowContext) -> Result<ConnectedTcpStream, anyhow::Error> {
            let (stream, _peer) = tokio::io::duplex(1024);
            let stream: BoxTunByteStream = Box::new(stream);
            Ok(ConnectedTcpStream::generic(stream))
        }
    }

    struct DuplexPolicy;

    #[async_trait::async_trait]
    impl MeshTunPolicy for DuplexPolicy {
        async fn check(&self, _ctx: &FlowContext) -> PolicyDecision {
            PolicyDecision::Allow
        }

        async fn route_tcp(&self, _ctx: &FlowContext) -> TcpRouteDecision {
            TcpRouteDecision::Connect {
                connector: Arc::new(DuplexConnector),
            }
        }
    }

    struct DenyTcpPolicy;

    #[async_trait::async_trait]
    impl MeshTunPolicy for DenyTcpPolicy {
        async fn check(&self, _ctx: &FlowContext) -> PolicyDecision {
            PolicyDecision::Deny {
                reason: "blocked".to_string(),
            }
        }
    }

    struct FailingConnector;

    #[async_trait::async_trait]
    impl TcpConnector for FailingConnector {
        async fn connect(&self, _ctx: &FlowContext) -> Result<ConnectedTcpStream, anyhow::Error> {
            anyhow::bail!("backend unavailable")
        }
    }

    struct FailingTcpPolicy;

    #[async_trait::async_trait]
    impl MeshTunPolicy for FailingTcpPolicy {
        async fn check(&self, _ctx: &FlowContext) -> PolicyDecision {
            PolicyDecision::Allow
        }

        async fn route_tcp(&self, _ctx: &FlowContext) -> TcpRouteDecision {
            TcpRouteDecision::Connect {
                connector: Arc::new(FailingConnector),
            }
        }
    }

    fn tcp_packet(src_port: u16) -> TunTcpPacket {
        let packet = build_ipv4_tcp_packet(
            Ipv4Addr::new(10, 5, 0, 2),
            src_port,
            Ipv4Addr::new(198, 51, 100, 10),
            80,
            0x02,
            1,
            0,
            &[],
        )
        .unwrap();
        let TunPacket::Tcp(tcp) = parse_ip_packet(&packet) else {
            panic!("expected TCP packet");
        };
        tcp
    }

    #[test]
    fn tcp_sequence_order_handles_wraparound() {
        assert!(tcp_seq_after(1, u32::MAX));
        assert!(tcp_seq_after(0, u32::MAX - 1));
        assert!(!tcp_seq_after(u32::MAX, 1));
        assert!(tcp_seq_before_or_equal(u32::MAX, 1));
        assert!(tcp_seq_before_or_equal(7, 7));
        assert!(!tcp_seq_before_or_equal(9, 7));
    }

    #[tokio::test]
    async fn rejects_new_flows_after_limit() {
        crate::stats::stats().reset();
        let (outgoing_tx, _outgoing_rx) = mpsc::channel(16);
        let manager = TcpProxyManager::new(
            "vm-a".to_string(),
            outgoing_tx,
            Arc::new(DuplexPolicy),
            TcpProxyConfig {
                max_flows: 1,
                per_flow_queue_capacity: 4,
                handshake_timeout: Duration::from_secs(30),
                connect_timeout: Duration::from_secs(30),
            },
        );

        manager.handle_packet(tcp_packet(40000)).await;
        manager.handle_packet(tcp_packet(40001)).await;

        assert!(
            crate::stats::stats()
                .tcp_flow_rejected
                .load(Ordering::Relaxed)
                >= 1
        );
    }

    #[tokio::test]
    async fn handshake_timeout_removes_half_open_flow() {
        crate::stats::stats().reset();
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel(16);
        let manager = TcpProxyManager::new(
            "vm-a".to_string(),
            outgoing_tx,
            Arc::new(DuplexPolicy),
            TcpProxyConfig {
                max_flows: 16,
                per_flow_queue_capacity: 4,
                handshake_timeout: Duration::from_millis(20),
                connect_timeout: Duration::from_secs(30),
            },
        );

        manager.handle_packet(tcp_packet(40000)).await;
        let _ = outgoing_rx.recv().await.expect("SYN-ACK");
        tokio::time::sleep(Duration::from_millis(80)).await;

        assert_eq!(
            crate::stats::stats()
                .tcp_handshake_timeout
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(manager.flows.len(), 0);
    }

    #[tokio::test]
    async fn denied_syn_returns_reset_without_syn_ack() {
        crate::stats::stats().reset();
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel(16);
        let manager = TcpProxyManager::new(
            "vm-a".to_string(),
            outgoing_tx,
            Arc::new(DenyTcpPolicy),
            TcpProxyConfig {
                max_flows: 16,
                per_flow_queue_capacity: 4,
                handshake_timeout: Duration::from_secs(30),
                connect_timeout: Duration::from_secs(30),
            },
        );

        manager.handle_packet(tcp_packet(40000)).await;
        let packet = outgoing_rx.recv().await.expect("RST");
        let TunPacket::Tcp(tcp) = parse_ip_packet(&packet) else {
            panic!("expected TCP packet");
        };
        assert!(tcp.rst);
        assert!(tcp.ack);
        assert!(!tcp.syn);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(manager.flows.len(), 0);
    }

    #[tokio::test]
    async fn backend_connect_failure_returns_reset_without_syn_ack() {
        crate::stats::stats().reset();
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel(16);
        let manager = TcpProxyManager::new(
            "vm-a".to_string(),
            outgoing_tx,
            Arc::new(FailingTcpPolicy),
            TcpProxyConfig {
                max_flows: 16,
                per_flow_queue_capacity: 4,
                handshake_timeout: Duration::from_secs(30),
                connect_timeout: Duration::from_secs(30),
            },
        );

        manager.handle_packet(tcp_packet(40000)).await;
        let packet = outgoing_rx.recv().await.expect("RST");
        let TunPacket::Tcp(tcp) = parse_ip_packet(&packet) else {
            panic!("expected TCP packet");
        };
        assert!(tcp.rst);
        assert!(tcp.ack);
        assert!(!tcp.syn);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(manager.flows.len(), 0);
    }

    #[tokio::test]
    async fn inbound_connect_tcp_preserves_tuple_and_streams_bytes() {
        crate::stats::stats().reset();
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel(16);
        let manager = TcpProxyManager::new(
            "vm-a".to_string(),
            outgoing_tx,
            Arc::new(DuplexPolicy),
            TcpProxyConfig {
                max_flows: 16,
                per_flow_queue_capacity: 4,
                handshake_timeout: Duration::from_secs(1),
                connect_timeout: Duration::from_secs(30),
            },
        );
        let src: SocketAddr = "203.0.113.10:50000".parse().unwrap();
        let dst: SocketAddr = "10.5.0.2:5201".parse().unwrap();

        let connect_manager = manager.clone();
        let connect_task =
            tokio::spawn(async move { connect_manager.connect_inbound(src, dst).await });

        let syn = tokio::time::timeout(Duration::from_secs(1), outgoing_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let syn_tcp = match parse_ip_packet(&syn) {
            TunPacket::Tcp(tcp) => tcp,
            _ => panic!("expected inbound SYN"),
        };
        assert_eq!(syn_tcp.src_addr, src.ip());
        assert_eq!(syn_tcp.src_port, src.port());
        assert_eq!(syn_tcp.dst_addr, dst.ip());
        assert_eq!(syn_tcp.dst_port, dst.port());
        assert!(syn_tcp.syn);
        assert!(!syn_tcp.ack);

        let syn_ack = build_ipv4_tcp_packet(
            match dst.ip() {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(_) => unreachable!(),
            },
            dst.port(),
            match src.ip() {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(_) => unreachable!(),
            },
            src.port(),
            0x12,
            1000,
            syn_tcp.seq.wrapping_add(1),
            &[],
        )
        .unwrap();
        match parse_ip_packet(&syn_ack) {
            TunPacket::Tcp(tcp) => manager.handle_packet(tcp).await,
            _ => panic!("expected TCP SYN-ACK"),
        }

        let mut stream = tokio::time::timeout(Duration::from_secs(1), connect_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        let ack = tokio::time::timeout(Duration::from_secs(1), outgoing_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let ack_tcp = match parse_ip_packet(&ack) {
            TunPacket::Tcp(tcp) => tcp,
            _ => panic!("expected inbound ACK"),
        };
        assert_eq!(ack_tcp.src_addr, src.ip());
        assert_eq!(ack_tcp.src_port, src.port());
        assert_eq!(ack_tcp.dst_addr, dst.ip());
        assert_eq!(ack_tcp.dst_port, dst.port());
        assert!(ack_tcp.ack);
        assert!(!ack_tcp.syn);
        assert_eq!(ack_tcp.ack_num, 1001);

        stream.write_all(b"ping").await.unwrap();
        let data = tokio::time::timeout(Duration::from_secs(1), outgoing_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let data_tcp = match parse_ip_packet(&data) {
            TunPacket::Tcp(tcp) => tcp,
            _ => panic!("expected inbound data"),
        };
        assert_eq!(data_tcp.src_addr, src.ip());
        assert_eq!(data_tcp.src_port, src.port());
        assert_eq!(data_tcp.dst_addr, dst.ip());
        assert_eq!(data_tcp.dst_port, dst.port());
        assert_eq!(&data_tcp.payload[..], b"ping");

        let guest_payload = build_ipv4_tcp_packet(
            match dst.ip() {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(_) => unreachable!(),
            },
            dst.port(),
            match src.ip() {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(_) => unreachable!(),
            },
            src.port(),
            0x10,
            1001,
            data_tcp.seq.wrapping_add(data_tcp.payload.len() as u32),
            b"pong",
        )
        .unwrap();
        match parse_ip_packet(&guest_payload) {
            TunPacket::Tcp(tcp) => manager.handle_packet(tcp).await,
            _ => panic!("expected guest payload"),
        }
        let mut buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"pong");
    }
}
