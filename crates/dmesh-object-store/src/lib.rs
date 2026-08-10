//! Signed object transport. The default `std` feature exposes the host server;
//! embedded users get the bounded protocol core from `core`.
//!
//! Milestone 1 deliberately implements the deployed, unkeyed DRS2 TCP data
//! path.  Manifests are generated once and cached beside their source file;
//! the transfer loop only checks the cached `(mtime,size)` tuple and sends.
//! Signature verification and the datagram protocol are separate milestones.

#[cfg(feature = "std")]
mod host {

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{Duration, timeout};
use dmesh_transport::{ConnectionId, Frame, ShortHeader, StreamFrame, decode_frame};

pub const MAGIC: u32 = 0x4452_5332;
pub const BLOCK_SIZE: usize = 4096;
pub const MAX_FRAME: usize = u16::MAX as usize;
pub const FRAME_HELLO: u16 = 1;
pub const FRAME_MANIFEST: u16 = 6;
pub const FRAME_BLOCK: u16 = 8;
pub const FRAME_ACK: u16 = 9;
pub const FRAME_DONE: u16 = 10;
pub const FRAME_FLOW_PULSE: u16 = 11;
pub const FRAME_PROGRESS: u16 = 12;
pub const FRAME_ERROR: u16 = 255;
pub const FRAME_MANIFEST_OK: u16 = 13;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind: String,
    pub port: u16,
    pub artifact_root: PathBuf,
    pub archive_root: Option<PathBuf>,
    pub idle_timeout: Duration,
    pub udp_mtu: usize,
}
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0".into(),
            port: 3337,
            artifact_root: PathBuf::from("target/flash"),
            archive_root: None,
            idle_timeout: Duration::from_secs(900),
            udp_mtu: 1200,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileManifest {
    pub source: String,
    pub source_mtime_ns: u128,
    pub source_size: u64,
    pub block_size: u32,
    pub image_size: u64,
    pub image_sha256: String,
    /// Full per-block digests are retained in the cache.  DRS2 currently
    /// carries the first four bytes on the wire for compatibility.
    pub block_sha256: Vec<String>,
}

impl FileManifest {
    pub fn sidecar_path(source: &Path) -> PathBuf {
        let name = source.file_name().and_then(|s| s.to_str()).unwrap_or("object");
        source.with_file_name(format!("{name}.manifest.json"))
    }

    pub fn generate(source: &Path) -> Result<Self> {
        let metadata = std::fs::metadata(source)
            .with_context(|| format!("stat artifact {}", source.display()))?;
        let mut file = std::fs::File::open(source)
            .with_context(|| format!("open artifact {}", source.display()))?;
        let mut full = Sha256::new();
        let mut blocks = Vec::new();
        let mut buf = vec![0u8; BLOCK_SIZE];
        loop {
            let n = std::io::Read::read(&mut file, &mut buf)?;
            if n == 0 { break; }
            full.update(&buf[..n]);
            blocks.push(hex::encode(Sha256::digest(&buf[..n])));
        }
        Ok(Self {
            source: source.to_string_lossy().into_owned(),
            source_mtime_ns: mtime_ns(&metadata)?,
            source_size: metadata.len(),
            block_size: BLOCK_SIZE as u32,
            image_size: metadata.len(),
            image_sha256: hex::encode(full.finalize()),
            block_sha256: blocks,
        })
    }

    pub fn load_or_generate(source: &Path) -> Result<Self> {
        let sidecar = Self::sidecar_path(source);
        if sidecar.is_file() {
            let bytes = std::fs::read(&sidecar)
                .with_context(|| format!("read manifest {}", sidecar.display()))?;
            let manifest: Self = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse manifest {}", sidecar.display()))?;
            // Builds replace artifacts in place.  Do not take the listener
            // down, or serve a stale manifest, just because the sidecar was
            // generated for the previous build.
            if manifest.ensure_current(source).is_ok() {
                return Ok(manifest);
            }
        }
        let manifest = Self::generate(source)?;
        let temporary = sidecar.with_extension("json.tmp");
        std::fs::write(&temporary, serde_json::to_vec_pretty(&manifest)?)?;
        std::fs::rename(&temporary, &sidecar)?;
        Ok(manifest)
    }

    pub fn ensure_current(&self, source: &Path) -> Result<()> {
        let metadata = std::fs::metadata(source)
            .with_context(|| format!("stat artifact {}", source.display()))?;
        let mtime = mtime_ns(&metadata)?;
        if metadata.len() != self.source_size || mtime != self.source_mtime_ns {
            bail!("stale manifest for {}; rebuild the manifest", source.display());
        }
        Ok(())
    }
}

fn mtime_ns(metadata: &std::fs::Metadata) -> Result<u128> {
    Ok(metadata.modified()?.duration_since(std::time::UNIX_EPOCH)?.as_nanos())
}

#[derive(Clone)]
pub struct ManifestCache {
    entries: Arc<Mutex<HashMap<PathBuf, FileManifest>>>,
}

impl Default for ManifestCache {
    fn default() -> Self { Self { entries: Arc::new(Mutex::new(HashMap::new())) } }
}

impl ManifestCache {
    pub fn get(&self, source: &Path) -> Result<FileManifest> {
        let source = source.to_path_buf();
        if let Some(manifest) = self.entries.lock().expect("manifest cache poisoned").get(&source).cloned() {
            if manifest.ensure_current(&source).is_ok() {
                return Ok(manifest);
            }
            // A firmware build commonly replaces the artifact while lmesh is
            // already running.  Drop the old cache entry and regenerate from
            // the new bytes instead of rejecting the first transfer forever.
            self.entries.lock().expect("manifest cache poisoned").remove(&source);
        }
        let manifest = FileManifest::load_or_generate(&source)?;
        manifest.ensure_current(&source)?;
        self.entries.lock().expect("manifest cache poisoned").insert(source, manifest.clone());
        Ok(manifest)
    }

    /// Ensure every regular artifact below `root` has a sidecar before the
    /// listener accepts a device. This keeps manifest generation out of the
    /// transfer path; builds may pre-generate the same sidecars.
    pub fn prepare_tree(&self, root: &Path) -> Result<usize> {
        fn visit(cache: &ManifestCache, path: &Path, count: &mut usize) -> Result<()> {
            for entry in std::fs::read_dir(path).with_context(|| format!("scan {}", path.display()))? {
                let entry = entry?;
                let child = entry.path();
                if child.is_dir() {
                    visit(cache, &child, count)?;
                } else if child.is_file() && !child.to_string_lossy().ends_with(".manifest.json") {
                    cache.get(&child)?;
                    *count += 1;
                }
            }
            Ok(())
        }
        let mut count = 0;
        visit(self, root, &mut count)?;
        Ok(count)
    }
}

#[derive(Debug, Clone, Copy)]
struct Hello {
    model: u8,
    target: u8,
    name_len: u8,
    dry_run: bool,
}

fn parse_hello(payload: &[u8]) -> Result<Hello> {
    if payload.len() != 90 { bail!("unsupported HELLO length={}", payload.len()); }
    if payload[89] & 1 == 0 { bail!("device does not advertise fixed flash layout"); }
    if payload[71] == 0 { bail!("HELLO did not request a target"); }
    let name_len = payload[72];
    if name_len > 16 || 73 + name_len as usize > payload.len() {
        bail!("invalid requested resource name length={name_len}");
    }
    Ok(Hello { model: payload[0], target: payload[71], name_len, dry_run: payload[89] & 0x08 != 0 })
}

fn target_name(payload: &[u8], hello: Hello) -> Result<Option<String>> {
    if hello.name_len == 0 { return Ok(None); }
    Ok(Some(std::str::from_utf8(&payload[73..73 + hello.name_len as usize])?.to_owned()))
}

fn target_file(root: &Path, hello: Hello, name: Option<&str>) -> Result<PathBuf> {
    let chip = if hello.model == 9 { "esp32s3" } else { "esp32" };
    let file = match hello.target {
        6 => root.join(chip).join("main-app.bin"),
        3 => root.join(chip).join("recovery.bin"),
        2 => root.join(chip).join("partition-table.bin"),
        7 => {
            let name = name.ok_or_else(|| anyhow::anyhow!("module target requires a name"))?;
            if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
                let bytes = name
                    .as_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                bail!("invalid module name name={name:?} hex={bytes}");
            }
            let rust_target = match chip {
                "esp32s3" => "xtensa-esp32s3-espidf",
                "esp32c6" => "riscv32imac-esp-espidf",
                _ => "xtensa-esp32-espidf",
            };
            let module_name = format!("mod_{name}.dmod");
            let plain_name = format!("{name}.dmod");
            let mut candidates = vec![
                root.join("modules").join(&module_name),
                root.join("modules").join(&plain_name),
                root.join(chip).join("modules").join(&module_name),
                root.join(chip).join("modules").join(&plain_name),
            ];
            // lmesh runs with target/flash as its artifact root, while the
            // module build places CPU-specific DMODs under target/modules.
            // Keep this lookup identical to the Python server's layout
            // resolution so port 3337 can replace port 3336 directly.
            if let Some(parent) = root.parent() {
                let module_root = parent.join("modules").join(rust_target);
                candidates.push(module_root.join(&module_name));
                candidates.push(module_root.join(&plain_name));
            }
            candidates.into_iter().find(|p| p.is_file())
                .ok_or_else(|| anyhow::anyhow!("module not found"))?
        }
        _ => bail!("unsupported target id={}", hello.target),
    };
    if !file.is_file() { bail!("artifact not found: {}", file.display()); }
    Ok(file)
}

fn manifest_wire(manifest: &FileManifest, target: u8, dry_run: bool) -> Result<Vec<u8>> {
    if manifest.image_size > u32::MAX as u64 || manifest.block_sha256.len() > u32::MAX as usize {
        bail!("artifact exceeds DRS2 field limits");
    }
    let count = manifest.block_sha256.len() as u32;
    let mut body = Vec::with_capacity(149 + manifest.block_sha256.len() * 4 + 64);
    body.extend_from_slice(&[target, if dry_run { 1 } else { 0 }, 1, 1]);
    body.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(&(manifest.block_size).to_be_bytes());
    body.extend_from_slice(&count.to_be_bytes());
    body.extend_from_slice(&(manifest.image_size as u32).to_be_bytes());
    body.extend_from_slice(&[0u8; 32]); // canonical table digest is optional in host dry-run
    body.extend_from_slice(&hex::decode(&manifest.image_sha256)?);
    body.extend_from_slice(&[0u8; 65]); // signing is intentionally deferred
    for digest in &manifest.block_sha256 {
        let digest = hex::decode(digest)?;
        body.extend_from_slice(&digest[..4]);
    }
    body.extend_from_slice(&[0u8; 64]);
    Ok(body)
}

async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, kind: u16, payload: &[u8]) -> Result<()> {
    if payload.len() > u16::MAX as usize { bail!("DRS2 frame too large: {}", payload.len()); }
    // TcpStream has no user-space write buffer.  Build the compact frame once
    // so each block is handed to the kernel as one write rather than four
    // separate write_all calls (magic, kind, length, payload).
    let mut frame = Vec::with_capacity(8 + payload.len());
    frame.extend_from_slice(&MAGIC.to_be_bytes());
    frame.extend_from_slice(&kind.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    writer.write_all(&frame).await?;
    Ok(())
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R, idle: Duration) -> Result<(u16, Vec<u8>)> {
    let mut header = [0u8; 8];
    timeout(idle, reader.read_exact(&mut header)).await??;
    if u32::from_be_bytes(header[..4].try_into()?) != MAGIC { bail!("invalid DRS2 magic"); }
    let kind = u16::from_be_bytes(header[4..6].try_into()?);
    let len = u16::from_be_bytes(header[6..8].try_into()?) as usize;
    let mut payload = vec![0u8; len];
    timeout(idle, reader.read_exact(&mut payload)).await??;
    Ok((kind, payload))
}

#[derive(Clone)]
pub struct ObjectServer {
    pub config: ServerConfig,
    pub manifests: ManifestCache,
}

impl ObjectServer {
    pub fn new(config: ServerConfig) -> Self { Self { config, manifests: ManifestCache::default() } }

    pub async fn run(self) -> Result<()> {
        // The controller may start lmesh before its build artifacts exist.
        // Keep the object listener available; requested files are resolved
        // when a session arrives after a later build populates this root.
        std::fs::create_dir_all(&self.config.artifact_root)
            .with_context(|| format!("create artifact root {}", self.config.artifact_root.display()))?;
        match self.manifests.prepare_tree(&self.config.artifact_root) {
            Ok(prepared) => tracing::info!(artifacts=prepared, root=%self.config.artifact_root.display(), "object store manifests ready"),
            Err(error) => tracing::warn!(%error, root=%self.config.artifact_root.display(), "object store manifest preflight incomplete; serving requests with lazy refresh"),
        }
        let udp = UdpSocket::bind((&*self.config.bind, self.config.port)).await?;
        let udp_server = self.clone();
        tokio::spawn(async move {
            if let Err(error) = udp_server.run_udp(udp).await {
                tracing::warn!(%error, "object transfer UDP server stopped");
            }
        });
        let listener = TcpListener::bind((&*self.config.bind, self.config.port)).await?;
        tracing::info!(bind=%self.config.bind, port=self.config.port, "object store TCP server listening");
        loop {
            let (stream, peer) = listener.accept().await?;
            tracing::info!(%peer, "object transfer accepted");
            let server = self.clone();
            tokio::spawn(async move {
                if let Err(error) = server.handle(stream).await {
                    tracing::warn!(%peer, %error, "object transfer failed");
                }
            });
        }
    }

    /// Bearer-neutral stream profile over UDP.  The first implementation uses
    /// one outstanding stream packet per peer; the no_std transport crate owns
    /// the framing and can replace this scheduler with a pipelined sender.
    pub async fn run_udp(&self, socket: UdpSocket) -> Result<()> {
        let mut sessions: HashMap<std::net::SocketAddr, UdpSession> = HashMap::new();
        let mut input = [0u8; 2048];
        loop {
            let (n, peer) = socket.recv_from(&mut input).await?;
            let Some(session) = sessions.get_mut(&peer) else {
                let hello = match udp_hello(&input[..n]) {
                    Ok(Some(hello)) => hello,
                    Ok(None) => {
                        tracing::debug!(%peer, bytes=n, "object UDP packet was not a HELLO");
                        continue;
                    }
                    Err(error) => {
                        tracing::warn!(%peer, bytes=n, %error, "object UDP HELLO parse failed");
                        continue;
                    }
                };
                let name = match target_name(&hello.0, hello.1) {
                    Ok(name) => name,
                    Err(error) => {
                        tracing::warn!(%peer, %error, target=hello.1.target, "object UDP HELLO target name failed");
                        continue;
                    }
                };
                let source = match target_file(&self.config.artifact_root, hello.1, name.as_deref()) {
                    Ok(source) => source,
                    Err(error) => {
                        tracing::warn!(%peer, root=%self.config.artifact_root.display(), target=hello.1.target, model=hello.1.model, name=?name, %error, "object UDP artifact lookup failed");
                        continue;
                    }
                };
                let manifest = match self.manifests.get(&source) {
                    Ok(manifest) => manifest,
                    Err(error) => {
                        tracing::warn!(%peer, source=%source.display(), %error, "object UDP manifest generation failed");
                        continue;
                    }
                };
                let manifest_bytes = match manifest_wire(&manifest, hello.1.target, hello.1.dry_run) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        tracing::warn!(%peer, source=%source.display(), %error, "object UDP manifest encoding failed");
                        continue;
                    }
                };
                let mut wire = Vec::new();
                if let Err(error) = write_frame_vec(FRAME_MANIFEST, &manifest_bytes, &mut wire) {
                    tracing::warn!(%peer, %error, "object UDP manifest framing failed");
                    continue;
                }
                let mut state = UdpSession::new(source, wire);
                match state.next_packet(ConnectionId::new(1).unwrap(), self.config.udp_mtu) {
                    Ok(packet) => {
                        let sent = socket.send_to(&packet, peer).await?;
                        // HELLO is intentionally idempotent and has no ACK
                        // yet. Send one bounded duplicate so a single lost
                        // Wi-Fi datagram does not turn a healthy server into
                        // a false transport timeout.
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        let _ = socket.send_to(&packet, peer).await?;
                        tracing::info!(%peer, bytes=sent, target=hello.1.target, "object UDP HELLO accepted");
                        sessions.insert(peer, state);
                    }
                    Err(error) => tracing::warn!(%peer, %error, "object UDP manifest packet encoding failed"),
                }
                continue;
            };
            if let Some(header) = udp_header(&input[..n]) {
                if udp_has_ack(&input[..n], header.1) {
                    tracing::debug!(%peer, phase=?session.phase, packet_bytes=n, "object UDP ACK received");
                    if session.phase == UdpPhase::Manifest {
                        session.offset = session.offset.saturating_add(session.in_flight);
                        session.in_flight = 0;
                        if session.offset >= session.manifest.len() { session.phase = UdpPhase::AwaitManifestOk; }
                    }
                    if session.phase == UdpPhase::Blocks { session.advance_block()?; }
                    if session.phase == UdpPhase::Manifest || session.phase == UdpPhase::Blocks || session.phase == UdpPhase::Done {
                        let packet = session.next_packet(header.0.dcid, self.config.udp_mtu)?;
                        let sent = socket.send_to(&packet, peer).await?;
                        tracing::debug!(%peer, phase=?session.phase, bytes=sent, "object UDP packet sent after ACK");
                    }
                } else if session.phase == UdpPhase::AwaitManifestOk && udp_manifest_ok(&input[..n], header.1) {
                    tracing::debug!(%peer, packet_bytes=n, "object UDP manifest accepted by device");
                    session.phase = UdpPhase::Blocks;
                    session.prepare_block()?;
                    let packet = session.next_packet(header.0.dcid, self.config.udp_mtu)?;
                    let sent = socket.send_to(&packet, peer).await?;
                    tracing::debug!(%peer, bytes=sent, "object UDP first block sent");
                }
            }
        }
    }

    pub async fn handle(&self, stream: TcpStream) -> Result<()> {
        self.handle_stream(stream).await
    }

    pub async fn handle_stream<S>(&self, stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (kind, hello_payload) = read_frame(&mut reader, self.config.idle_timeout).await?;
        if kind != FRAME_HELLO { bail!("device did not start with HELLO"); }
        let hello = parse_hello(&hello_payload)?;
        let name = target_name(&hello_payload, hello)?;
        let source = target_file(&self.config.artifact_root, hello, name.as_deref())?;
        let manifest = self.manifests.get(&source)?;
        let wire = manifest_wire(&manifest, hello.target, hello.dry_run)?;
        write_frame(&mut writer, FRAME_MANIFEST, &wire).await?;

        // The sender never hashes or retains the file.  A bounded block is
        // read, framed, and released for every iteration.
        let mut file = tokio::fs::File::open(&source).await?;
        let mut block = vec![0u8; BLOCK_SIZE];
        let mut index = 0u32;
        let mut progress_reader = tokio::spawn(async move {
            loop {
                let (kind, payload) = read_frame(&mut reader, Duration::from_secs(900)).await?;
                match kind {
                    FRAME_PROGRESS => continue,
                    FRAME_DONE => return Ok::<(), anyhow::Error>(()),
                    FRAME_ERROR => bail!("device transfer error: {}", String::from_utf8_lossy(&payload)),
                    _ => bail!("unexpected device frame kind={kind}"),
                }
            }
        });
        loop {
            let n = file.read(&mut block).await?;
            if n == 0 { break; }
            let mut payload = Vec::with_capacity(12 + n);
            payload.push(hello.target);
            payload.extend_from_slice(&[0, 0, 0]);
            payload.extend_from_slice(&index.to_be_bytes());
            payload.extend_from_slice(&(n as u32).to_be_bytes());
            payload.extend_from_slice(&block[..n]);
            write_frame(&mut writer, FRAME_BLOCK, &payload).await?;
            index = index.checked_add(1).context("block count overflow")?;
        }
        write_frame(&mut writer, FRAME_DONE, &[]).await?;
        (&mut progress_reader).await??;
        write_frame(&mut writer, FRAME_ACK, &[]).await?;
        writer.flush().await?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpPhase { Manifest, AwaitManifestOk, Blocks, Done }

struct UdpSession {
    source: PathBuf,
    manifest: Vec<u8>,
    block: Vec<u8>,
    phase: UdpPhase,
    offset: usize,
    stream_offset: usize,
    in_flight: usize,
    block_index: u32,
    packet_number: u32,
}

impl UdpSession {
    fn new(source: PathBuf, manifest: Vec<u8>) -> Self {
        Self { source, manifest, block: Vec::new(), phase: UdpPhase::Manifest, offset: 0, stream_offset: 0, in_flight: 0, block_index: 0, packet_number: 0 }
    }

    fn prepare_block(&mut self) -> Result<()> {
        if self.block_index as usize * BLOCK_SIZE >= std::fs::metadata(&self.source)?.len() as usize {
            self.block.clear(); write_frame_vec(FRAME_DONE, &[], &mut self.block)?; self.offset = 0; self.phase = UdpPhase::Done; return Ok(())
        }
        let mut file = std::fs::File::open(&self.source)?;
        file.seek(SeekFrom::Start(self.block_index as u64 * BLOCK_SIZE as u64))?;
        let mut bytes = vec![0u8; BLOCK_SIZE]; let n = file.read(&mut bytes)?; bytes.truncate(n);
        let mut payload = Vec::with_capacity(12 + n);
        payload.extend_from_slice(&[0, 0, 0, 0]); payload.extend_from_slice(&self.block_index.to_be_bytes()); payload.extend_from_slice(&(n as u32).to_be_bytes()); payload.extend_from_slice(&bytes);
        self.block.clear(); write_frame_vec(FRAME_BLOCK, &payload, &mut self.block)?; self.offset = 0; Ok(())
    }

    fn advance_block(&mut self) -> Result<()> {
        self.offset = self.offset.saturating_add(self.in_flight); self.in_flight = 0;
        if self.phase == UdpPhase::Manifest { return Ok(()); }
        if self.offset >= self.block.len() { self.stream_offset += self.block.len(); self.block_index = self.block_index.saturating_add(1); self.block.clear(); self.prepare_block()?; }
        Ok(())
    }

    fn next_packet(&mut self, dcid: ConnectionId, mtu: usize) -> Result<Vec<u8>> {
        let stream = if self.phase == UdpPhase::Manifest { 3 } else { 7 };
        let bytes = if self.phase == UdpPhase::Manifest { &self.manifest } else { &self.block };
        let max_payload = mtu.saturating_sub(48).max(1).min(bytes.len().saturating_sub(self.offset).max(1));
        let end = self.offset.saturating_add(max_payload).min(bytes.len());
        let chunk = &bytes[self.offset..end];
        let mut out = vec![0u8; mtu.max(64)];
        let header = ShortHeader { flags: dmesh_transport::FLAG_FIXED, dcid, packet_number: self.packet_number, packet_number_len: 2 };
        let mut p = header.encode(&mut out).map_err(|e| anyhow::anyhow!("encode UDP header: {e:?}"))?;
        p += Frame::Stream(StreamFrame { id: stream, offset: if stream == 3 { self.offset as u64 } else { (self.stream_offset + self.offset) as u64 }, fin: end == bytes.len(), data: chunk }).encode(&mut out[p..]).map_err(|e| anyhow::anyhow!("encode UDP stream frame: {e:?}"))?;
        out.truncate(p); self.packet_number = self.packet_number.wrapping_add(1); self.in_flight = chunk.len(); Ok(out)
    }
}

fn write_frame_vec(kind: u16, payload: &[u8], out: &mut Vec<u8>) -> Result<()> {
    if payload.len() > u16::MAX as usize { bail!("DRS2 frame too large: {}", payload.len()); }
    out.extend_from_slice(&MAGIC.to_be_bytes()); out.extend_from_slice(&kind.to_be_bytes()); out.extend_from_slice(&(payload.len() as u16).to_be_bytes()); out.extend_from_slice(payload); Ok(())
}

fn udp_header(data: &[u8]) -> Option<(ShortHeader, usize)> { ShortHeader::decode(data).ok() }

fn udp_hello(data: &[u8]) -> Result<Option<(Vec<u8>, Hello)>> {
    let Some((_, mut p)) = udp_header(data) else { return Ok(None); };
    while p < data.len() { let (frame, used) = decode_frame(&data[p..]).map_err(|_| anyhow::anyhow!("invalid UDP frame"))?; p += used; if let Frame::Stream(s) = frame { if s.id == 0 && s.offset == 0 && s.data.len() >= 8 && u32::from_be_bytes(s.data[..4].try_into()?) == MAGIC && u16::from_be_bytes(s.data[4..6].try_into()?) == FRAME_HELLO { let len = u16::from_be_bytes(s.data[6..8].try_into()?) as usize; if s.data.len() >= 8 + len { let payload = s.data[8..8 + len].to_vec(); return Ok(Some((payload.clone(), parse_hello(&payload)?))); } } } }
    Ok(None)
}

fn udp_has_ack(data: &[u8], mut p: usize) -> bool {
    while p < data.len() { let Ok((frame, used)) = decode_frame(&data[p..]) else { return false; }; p += used; if matches!(frame, Frame::Ack { .. }) { return true; } } false
}

fn udp_manifest_ok(data: &[u8], mut p: usize) -> bool {
    while p < data.len() { let Ok((frame, used)) = decode_frame(&data[p..]) else { return false; }; p += used; if let Frame::Stream(s) = frame { if s.id == 0 && s.data.len() >= 8 && u32::from_be_bytes(s.data[..4].try_into().unwrap()) == MAGIC && u16::from_be_bytes(s.data[4..6].try_into().unwrap()) == FRAME_MANIFEST_OK { return true; } } } false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn generates_and_reuses_manifest_until_mtime_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob.bin");
        std::fs::write(&path, b"hello world").unwrap();
        let first = FileManifest::load_or_generate(&path).unwrap();
        assert_eq!(first.block_sha256.len(), 1);
        let second = FileManifest::load_or_generate(&path).unwrap();
        assert_eq!(first, second);
        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"!").unwrap();
        assert!(first.ensure_current(&path).is_err());
    }

    #[test]
    fn manifest_wire_contains_legacy_truncated_block_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob.bin");
        std::fs::write(&path, vec![7u8; BLOCK_SIZE + 3]).unwrap();
        let manifest = FileManifest::generate(&path).unwrap();
        let wire = manifest_wire(&manifest, 6, true).unwrap();
        assert_eq!(wire[0], 6);
        assert_eq!(&wire[149..153], &hex::decode(&manifest.block_sha256[0]).unwrap()[..4]);
        assert_eq!(manifest.block_sha256.len(), 2);
    }

    #[test]
    fn resolves_cpu_specific_modules_next_to_flash_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("target").join("flash");
        let module_root = dir.path().join("target").join("modules")
            .join("xtensa-esp32-espidf");
        std::fs::create_dir_all(&module_root).unwrap();
        let module = module_root.join("mod_flash.dmod");
        std::fs::write(&module, b"dmod").unwrap();
        let mut hello = [0u8; 90];
        hello[0] = 1;
        hello[71] = 7;
        hello[72] = 5;
        hello[73..78].copy_from_slice(b"flash");
        hello[89] = 1;
        let parsed = parse_hello(&hello).unwrap();
        assert_eq!(target_file(&root, parsed, Some("flash")).unwrap(), module);
    }

    #[test]
    fn udp_session_uses_stream_offsets_and_variable_cid() {
        let mut manifest = Vec::new();
        write_frame_vec(FRAME_MANIFEST, &vec![9u8; 2400], &mut manifest).unwrap();
        let mut session = UdpSession::new(PathBuf::from("unused"), manifest);
        let packet = session.next_packet(ConnectionId::new(0x1234).unwrap(), 256).unwrap();
        let (header, p) = ShortHeader::decode(&packet).unwrap();
        assert_eq!(header.dcid, ConnectionId::new(0x1234).unwrap());
        let (frame, _) = decode_frame(&packet[p..]).unwrap();
        match frame { Frame::Stream(s) => { assert_eq!(s.id, 3); assert_eq!(s.offset, 0); assert!(!s.fin); assert!(s.data.len() < 2400); }, _ => panic!("expected stream frame") }
    }

    #[test]
    fn udp_manifest_packet_round_trips_through_shared_decoder() {
        let mut manifest = Vec::new();
        write_frame_vec(FRAME_MANIFEST, &vec![9u8; 2400], &mut manifest).unwrap();
        let mut session = UdpSession::new(PathBuf::from("unused"), manifest);
        let packet = session.next_packet(ConnectionId::new(1).unwrap(), 1200).unwrap();
        let decoded = crate::protocol::decode_udp_manifest(&packet);
        assert!(decoded.is_ok(), "decoder rejected server packet: {decoded:?}");
    }

    #[tokio::test]
    async fn dry_run_tcp_session_sends_manifest_and_all_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("flash");
        let chip = root.join("esp32");
        std::fs::create_dir_all(&chip).unwrap();
        let image_len = 10 * 1024 * 1024 + 17;
        let image = (0..image_len).map(|n| (n % 251) as u8).collect::<Vec<_>>();
        std::fs::write(chip.join("main-app.bin"), &image).unwrap();

        let server = ObjectServer::new(ServerConfig {
            artifact_root: root,
            bind: "127.0.0.1".into(),
            port: 0,
            idle_timeout: Duration::from_secs(5),
            ..ServerConfig::default()
        });
        let (mut device, server_stream) = tokio::io::duplex(1 << 20);
        let server_task = tokio::spawn(async move {
            server.handle_stream(server_stream).await.unwrap();
        });
        let mut hello = vec![0u8; 90];
        hello[0] = 1; // classic ESP32
        hello[71] = 6; // Main
        hello[89] = 0x09; // fixed layout plus client-requested dry run
        write_frame(&mut device, FRAME_HELLO, &hello).await.unwrap();

        let (kind, manifest) = read_frame(&mut device, Duration::from_secs(5)).await.unwrap();
        assert_eq!(kind, FRAME_MANIFEST);
        assert_eq!(manifest[0], 6);
        assert_eq!(manifest[1], 1); // client-requested dry run

        let mut blocks = 0;
        loop {
            let (kind, payload) = read_frame(&mut device, Duration::from_secs(5)).await.unwrap();
            match kind {
                FRAME_BLOCK => {
                    assert_eq!(u32::from_be_bytes(payload[4..8].try_into().unwrap()), blocks);
                    blocks += 1;
                }
                FRAME_DONE => break,
                other => panic!("unexpected server frame {other}"),
            }
        }
        assert_eq!(blocks, ((image_len + BLOCK_SIZE - 1) / BLOCK_SIZE) as u32);
        write_frame(&mut device, FRAME_DONE, &[]).await.unwrap();
        let (kind, payload) = read_frame(&mut device, Duration::from_secs(5)).await.unwrap();
        assert_eq!((kind, payload.len()), (FRAME_ACK, 0));
        server_task.await.unwrap();
    }
}

}

#[cfg(feature = "std")]
pub use host::*;

pub mod protocol {
    include!("core.rs");
}

#[cfg(not(feature = "std"))]
pub use protocol::*;
