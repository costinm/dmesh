use crate::packet::{ethernet_payload_to_ip, ip_to_ethernet_frame};

use std::io::IoSlice;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum UdsStyle {
    Qemu,
    VirtioUser,
}

impl UdsStyle {
    pub fn from_env_value(value: &str) -> Result<Self, anyhow::Error> {
        match value {
            "qemu" | "qemu-stream" | "stream" => Ok(Self::Qemu),
            "virtio-user" | "vhost-user" | "vhost" => Ok(Self::VirtioUser),
            other => anyhow::bail!("unsupported MESH_TUN_UDS_STYLE={other}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UdsServerConfig {
    pub socket_path: PathBuf,
    pub style: UdsStyle,
    pub host_mac: [u8; 6],
}

impl UdsServerConfig {
    pub fn new(socket_path: impl Into<PathBuf>, style: UdsStyle) -> Self {
        Self {
            socket_path: socket_path.into(),
            style,
            host_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        }
    }
}

pub async fn run_uds_server(
    listener: UnixListener,
    config: UdsServerConfig,
    tun_tx: mpsc::Sender<Vec<u8>>,
    mut stack_rx: mpsc::Receiver<Vec<u8>>,
) -> Result<(), anyhow::Error> {
    if config.style == UdsStyle::VirtioUser {
        anyhow::bail!(
            "virtio-user/vhost-user UDS mode needs vhost-user vring negotiation; use MESH_TUN_UDS_STYLE=qemu for qemu stream sockets"
        );
    }

    tracing::info!(
        socket = ?listener.local_addr(),
        style = ?config.style,
        "mesh-tun UDS listener started"
    );

    // B14: Previously `stack_rx` was wrapped in a `tokio::sync::Mutex` shared
    // across all connected UDS clients, with each per-client writer holding the
    // lock across `recv().await`. This serialized every client on one mutex:
    // if client A's write stalled (slow socket, half-dead peer), client B's
    // writer could not call `recv()` and was fully blocked — head-of-line
    // blocking across guests, no eviction of stuck clients.
    //
    // Now we drain `stack_rx` in a single dedicated reader task and `broadcast`
    // each packet to all subscribers. Each per-client writer holds its own
    // `broadcast::Receiver` and so never contends with other clients. A stuck
    // client falls behind and gets a `Lagged` error (frames dropped for it),
    // leaving other clients unaffected.
    let (tx, _) = tokio::sync::broadcast::channel::<Vec<u8>>(256);
    let tx = Arc::new(tx);

    let tx_clone = tx.clone();
    let _drain = tokio::spawn(async move {
        while let Some(packet) = stack_rx.recv().await {
            match tx_clone.send(packet) {
                Ok(_) => {
                    crate::stats::stats()
                        .uds_broadcast_sent
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    crate::stats::stats()
                        .uds_broadcast_no_subscribers
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        // When stack_rx ends, `tx` is dropped via `tx_clone`, closing the
        // broadcast and propagating EOF to all subscribers.
    });

    loop {
        let (stream, _) = listener.accept().await?;
        let tun_tx = tun_tx.clone();
        let rx = tx.subscribe();
        let host_mac = config.host_mac;
        tokio::spawn(async move {
            if let Err(error) = serve_qemu_stream(stream, host_mac, tun_tx, rx).await {
                tracing::warn!(%error, "mesh-tun UDS client disconnected");
            }
        });
    }
}

async fn serve_qemu_stream(
    stream: UnixStream,
    host_mac: [u8; 6],
    tun_tx: mpsc::Sender<Vec<u8>>,
    stack_rx: tokio::sync::broadcast::Receiver<Vec<u8>>,
) -> Result<(), anyhow::Error> {
    let (mut reader, mut writer) = stream.into_split();
    let guest_mac = Arc::new(Mutex::new(None::<[u8; 6]>));

    let read_guest_mac = guest_mac.clone();
    let read_task = tokio::spawn(async move {
        loop {
            let frame = read_qemu_frame(&mut reader).await?;
            if let Some((packet, src_mac)) = ethernet_payload_to_ip(&frame) {
                *read_guest_mac
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner()) = Some(src_mac);
                tun_tx
                    .send(packet)
                    .await
                    .map_err(|_| anyhow::anyhow!("TUN input queue closed"))?;
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    });

    let write_guest_mac = guest_mac;
    let mut stack_rx = stack_rx;
    let write_task = tokio::spawn(async move {
        loop {
            let packet = match stack_rx.recv().await {
                Ok(pkt) => pkt,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    return Err(anyhow::anyhow!("TUN output queue closed"));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    crate::stats::stats()
                        .uds_client_lagged_frames
                        .fetch_add(n, Ordering::Relaxed);
                    tracing::warn!(n, "mesh-tun UDS client lagged behind; dropped frames");
                    continue;
                }
            };
            let dst_mac = write_guest_mac
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .unwrap_or([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
            let frame = ip_to_ethernet_frame(&packet, host_mac, dst_mac, 0)?;
            if let Err(error) = write_qemu_frame(&mut writer, &frame).await {
                crate::stats::stats()
                    .uds_client_write_error
                    .fetch_add(1, Ordering::Relaxed);
                return Err(error);
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    });

    tokio::select! {
        result = read_task => result??,
        result = write_task => result??,
    }
    Ok(())
}

async fn read_qemu_frame<R>(reader: &mut R) -> Result<Vec<u8>, anyhow::Error>
where
    R: AsyncRead + Unpin,
{
    let len = reader.read_u32().await? as usize;
    if len == 0 || len > 65535 {
        anyhow::bail!("invalid qemu frame length: {len}");
    }
    let mut frame = vec![0u8; len];
    reader.read_exact(&mut frame).await?;
    Ok(frame)
}

async fn write_qemu_frame<W>(writer: &mut W, frame: &[u8]) -> Result<(), anyhow::Error>
where
    W: AsyncWrite + Unpin,
{
    if frame.len() > u32::MAX as usize {
        anyhow::bail!("frame too large: {}", frame.len());
    }
    let header = (frame.len() as u32).to_be_bytes();
    let mut written = 0usize;
    let total = header.len() + frame.len();
    while written < total {
        let n = if written < header.len() {
            let header_slice = &header[written..];
            let frame_slice = frame;
            writer
                .write_vectored(&[IoSlice::new(header_slice), IoSlice::new(frame_slice)])
                .await?
        } else {
            writer.write(&frame[written - header.len()..]).await?
        };
        if n == 0 {
            anyhow::bail!("short write while writing qemu frame");
        }
        written += n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethernet_round_trip_preserves_ip_payload() {
        let packet = vec![
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        let src = [0x02, 0, 0, 0, 0, 1];
        let dst = [0x02, 0, 0, 0, 0, 2];
        let frame = ip_to_ethernet_frame(&packet, src, dst, 0).unwrap();
        let (decoded, observed_src) = ethernet_payload_to_ip(&frame).unwrap();
        assert_eq!(decoded, packet);
        assert_eq!(observed_src, src);
    }
}
