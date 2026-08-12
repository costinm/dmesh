#![cfg_attr(not(feature = "std"), no_std)]

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
    use dmesh_transport::{
        AckRangeSet, ConnectionId, EndpointState, Frame, INITIAL_MAX_STREAM_DATA,
        ShortHeader, decode_frame,
    };
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::collections::{HashMap, VecDeque};
    use std::io::{Read, Seek, SeekFrom};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio::time::{Duration, timeout};

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
        pub udp_hello_duplicate_delay: Duration,
        pub udp_send_delay: Duration,
        /// Number of stream packets allowed in flight for the UDP benchmark.
        /// One preserves the original stop-and-wait behavior.
        pub udp_window_packets: usize,
        /// Timeout before unacknowledged UDP packets are retransmitted.
        pub udp_retransmit_timeout: Duration,
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
                udp_hello_duplicate_delay: Duration::from_millis(20),
                udp_send_delay: Duration::ZERO,
                udp_window_packets: 1,
                udp_retransmit_timeout: Duration::from_millis(100),
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
            let name = source
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("object");
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
                if n == 0 {
                    break;
                }
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
                bail!(
                    "stale manifest for {}; rebuild the manifest",
                    source.display()
                );
            }
            Ok(())
        }
    }

    fn mtime_ns(metadata: &std::fs::Metadata) -> Result<u128> {
        Ok(metadata
            .modified()?
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos())
    }

    #[derive(Clone)]
    pub struct ManifestCache {
        entries: Arc<Mutex<HashMap<PathBuf, FileManifest>>>,
    }

    impl Default for ManifestCache {
        fn default() -> Self {
            Self {
                entries: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    impl ManifestCache {
        pub fn get(&self, source: &Path) -> Result<FileManifest> {
            let source = source.to_path_buf();
            if let Some(manifest) = self
                .entries
                .lock()
                .expect("manifest cache poisoned")
                .get(&source)
                .cloned()
            {
                if manifest.ensure_current(&source).is_ok() {
                    return Ok(manifest);
                }
                // A firmware build commonly replaces the artifact while lmesh is
                // already running.  Drop the old cache entry and regenerate from
                // the new bytes instead of rejecting the first transfer forever.
                self.entries
                    .lock()
                    .expect("manifest cache poisoned")
                    .remove(&source);
            }
            let manifest = FileManifest::load_or_generate(&source)?;
            manifest.ensure_current(&source)?;
            self.entries
                .lock()
                .expect("manifest cache poisoned")
                .insert(source, manifest.clone());
            Ok(manifest)
        }

        /// Ensure every regular artifact below `root` has a sidecar before the
        /// listener accepts a device. This keeps manifest generation out of the
        /// transfer path; builds may pre-generate the same sidecars.
        pub fn prepare_tree(&self, root: &Path) -> Result<usize> {
            fn visit(cache: &ManifestCache, path: &Path, count: &mut usize) -> Result<()> {
                for entry in
                    std::fs::read_dir(path).with_context(|| format!("scan {}", path.display()))?
                {
                    let entry = entry?;
                    let child = entry.path();
                    if child.is_dir() {
                        visit(cache, &child, count)?;
                    } else if child.is_file()
                        && !child.to_string_lossy().ends_with(".manifest.json")
                    {
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
        if payload.len() != 90 {
            bail!("unsupported HELLO length={}", payload.len());
        }
        if payload[89] & 1 == 0 {
            bail!("device does not advertise fixed flash layout");
        }
        if payload[71] == 0 {
            bail!("HELLO did not request a target");
        }
        let name_len = payload[72];
        if name_len > 16 || 73 + name_len as usize > payload.len() {
            bail!("invalid requested resource name length={name_len}");
        }
        Ok(Hello {
            model: payload[0],
            target: payload[71],
            name_len,
            dry_run: payload[89] & 0x08 != 0,
        })
    }

    fn target_name(payload: &[u8], hello: Hello) -> Result<Option<String>> {
        if hello.name_len == 0 {
            return Ok(None);
        }
        Ok(Some(
            std::str::from_utf8(&payload[73..73 + hello.name_len as usize])?.to_owned(),
        ))
    }

    fn target_file(root: &Path, hello: Hello, name: Option<&str>) -> Result<PathBuf> {
        // ESP image model IDs follow the esptool/ESP-IDF image header:
        // 9=ESP32-S3 and 13=ESP32-C6/RISC-V. Keep C6 separate so lmesh's
        // object server serves the correct Main/Recovery artifacts instead
        // of silently falling back to classic Xtensa images.
        let chip = match hello.model {
            9 => "esp32s3",
            13 => "esp32c6",
            _ => "esp32",
        };
        let file = match hello.target {
            6 => root.join(chip).join("main-app.bin"),
            3 => root.join(chip).join("recovery.bin"),
            2 => root.join(chip).join("partition-table.bin"),
            7 => {
                let name = name.ok_or_else(|| anyhow::anyhow!("module target requires a name"))?;
                if !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                {
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
                candidates
                    .into_iter()
                    .find(|p| p.is_file())
                    .ok_or_else(|| anyhow::anyhow!("module not found"))?
            }
            _ => bail!("unsupported target id={}", hello.target),
        };
        if !file.is_file() {
            bail!("artifact not found: {}", file.display());
        }
        Ok(file)
    }

    fn manifest_wire(manifest: &FileManifest, target: u8, dry_run: bool) -> Result<Vec<u8>> {
        if manifest.image_size > u32::MAX as u64 || manifest.block_sha256.len() > u32::MAX as usize
        {
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

    async fn write_frame<W: AsyncWrite + Unpin>(
        writer: &mut W,
        kind: u16,
        payload: &[u8],
    ) -> Result<()> {
        if payload.len() > u16::MAX as usize {
            bail!("DRS2 frame too large: {}", payload.len());
        }
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

    async fn read_frame<R: AsyncRead + Unpin>(
        reader: &mut R,
        idle: Duration,
    ) -> Result<(u16, Vec<u8>)> {
        let mut header = [0u8; 8];
        timeout(idle, reader.read_exact(&mut header)).await??;
        if u32::from_be_bytes(header[..4].try_into()?) != MAGIC {
            bail!("invalid DRS2 magic");
        }
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
        pub fn new(config: ServerConfig) -> Self {
            Self {
                config,
                manifests: ManifestCache::default(),
            }
        }

        pub async fn run(self) -> Result<()> {
            // The controller may start lmesh before its build artifacts exist.
            // Keep the object listener available; requested files are resolved
            // when a session arrives after a later build populates this root.
            std::fs::create_dir_all(&self.config.artifact_root).with_context(|| {
                format!(
                    "create artifact root {}",
                    self.config.artifact_root.display()
                )
            })?;
            match self.manifests.prepare_tree(&self.config.artifact_root) {
                Ok(prepared) => {
                    tracing::info!(artifacts=prepared, root=%self.config.artifact_root.display(), "object store manifests ready")
                }
                Err(error) => {
                    tracing::warn!(%error, root=%self.config.artifact_root.display(), "object store manifest preflight incomplete; serving requests with lazy refresh")
                }
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

        /// Bearer-neutral stream profile over UDP.  The host scheduler is bounded
        /// by `udp_window_packets`; exact packet ACKs and a retransmission timer
        /// provide reliability without per-block acknowledgements.
        pub async fn run_udp(&self, socket: UdpSocket) -> Result<()> {
            let mut sessions: HashMap<std::net::SocketAddr, UdpSession> = HashMap::new();
            let mut input = [0u8; 2048];
            loop {
                let (n, peer) = match tokio::time::timeout(
                    self.config.udp_retransmit_timeout,
                    socket.recv_from(&mut input),
                )
                .await
                {
                    Ok(result) => result?,
                        Err(_) => {
                            for (peer, session) in sessions.iter_mut() {
                                let mut resent = 0u32;
                            for flight in session.in_flight.iter_mut().filter(|flight| !flight.acked) {
                                socket.send_to(&flight.packet, *peer).await?;
                                resent = resent.saturating_add(1);
                            }
                            let lost_bytes = session.mark_unacked_lost();
                            if resent != 0 {
                                session.endpoint.lost(lost_bytes);
                                session.data_retransmits =
                                    session.data_retransmits.saturating_add(resent);
                                tracing::debug!(%peer, resent, data_retransmits=session.data_retransmits, "object UDP data retransmit");
                            }
                        }
                        continue;
                    }
                };
                // A device may reboot and reuse the same ephemeral UDP source
                // port. Treat a fresh HELLO as a new session even when the old
                // peer entry is still present; otherwise an abandoned transfer
                // silently consumes all later HELLOs from that device.
                if sessions.contains_key(&peer) && matches!(udp_hello(&input[..n]), Ok(Some(_))) {
                    tracing::info!(%peer, "object UDP HELLO replaced stale session");
                    sessions.remove(&peer);
                }
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
                    let source = match target_file(
                        &self.config.artifact_root,
                        hello.1,
                        name.as_deref(),
                    ) {
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
                    let manifest_bytes = match manifest_wire(
                        &manifest,
                        hello.1.target,
                        hello.1.dry_run,
                    ) {
                        Ok(bytes) => bytes,
                        Err(error) => {
                            tracing::warn!(%peer, source=%source.display(), %error, "object UDP manifest encoding failed");
                            continue;
                        }
                    };
                    let mut wire = Vec::new();
                    if let Err(error) = write_frame_vec(FRAME_MANIFEST, &manifest_bytes, &mut wire)
                    {
                        tracing::warn!(%peer, %error, "object UDP manifest framing failed");
                        continue;
                    }
                    let mut state = UdpSession::new(source, wire, self.config.udp_mtu);
                    match state.next_packet(ConnectionId::new(1).unwrap(), self.config.udp_mtu) {
                        Ok(packet) => {
                            let sent = socket.send_to(&packet, peer).await?;
                            // HELLO is intentionally idempotent and has no ACK
                            // yet. Send one bounded duplicate so a single lost
                            // Wi-Fi datagram does not turn a healthy server into
                            // a false transport timeout.
                            tokio::time::sleep(self.config.udp_hello_duplicate_delay).await;
                            let _ = socket.send_to(&packet, peer).await?;
                            while state.in_flight.len() < self.config.udp_window_packets.max(1)
                                && state.can_send(self.config.udp_mtu)
                                && state.has_unsent_data()
                            {
                                tokio::time::sleep(self.config.udp_send_delay).await;
                                let packet = state.next_packet(
                                    ConnectionId::new(1).unwrap(),
                                    self.config.udp_mtu,
                                )?;
                                socket.send_to(&packet, peer).await?;
                            }
                            tracing::info!(%peer, bytes=sent, target=hello.1.target, hello_copies=2, hello_retransmits=1, data_retransmits=0, "object UDP HELLO accepted");
                            sessions.insert(peer, state);
                        }
                        Err(error) => {
                            tracing::warn!(%peer, %error, "object UDP manifest packet encoding failed")
                        }
                    }
                    continue;
                };
                if let Some(header) = udp_header(&input[..n]) {
                    if matches!(session.phase, UdpPhase::Manifest | UdpPhase::AwaitManifestOk)
                        && udp_manifest_ok(&input[..n], header.1)
                    {
                        tracing::debug!(%peer, packet_bytes=n, "object UDP manifest accepted by device");
                        session.manifest_ok = true;
                        if session.phase == UdpPhase::AwaitManifestOk && session.in_flight.is_empty() {
                            session.start_blocks()?;
                            tokio::time::sleep(self.config.udp_send_delay).await;
                            let packet = session.next_packet(header.0.dcid, self.config.udp_mtu)?;
                            let sent = socket.send_to(&packet, peer).await?;
                            tracing::debug!(%peer, bytes=sent, "object UDP first block sent");
                            while session.in_flight.len() < self.config.udp_window_packets.max(1)
                                && session.can_send(self.config.udp_mtu)
                                && session.has_unsent_data()
                            {
                                tokio::time::sleep(self.config.udp_send_delay).await;
                                let packet = session.next_packet(header.0.dcid, self.config.udp_mtu)?;
                                socket.send_to(&packet, peer).await?;
                            }
                        }
                    } else if let Some(controls) = udp_controls(&input[..n], header.1) {
                        if let Some(max_data) = controls.max_data {
                            session.endpoint.send.extend_connection(max_data);
                        }
                        for (id, max_data) in controls.max_stream_data {
                            session.endpoint.send.extend_stream(id, max_data).map_err(|error| {
                                anyhow::anyhow!("invalid stream credit id={id}: {error:?}")
                            })?;
                        }
                        if let Some(ack_ranges) = controls.ack {
                            session.acks_received = session.acks_received.saturating_add(1);
                            if session.phase == UdpPhase::Done {
                                tracing::info!(
                                    %peer,
                                    packets_sent=session.packets_sent,
                                    acks_received=session.acks_received,
                                    hello_retransmits=1,
                                    data_retransmits=session.data_retransmits,
                                    "object UDP transfer complete"
                                );
                                continue;
                            }
                            tracing::debug!(%peer, phase=?session.phase, packet_bytes=n, "object UDP ACK received");
                            if session.acknowledge_ranges(ack_ranges)? {
                                if session.phase == UdpPhase::AwaitManifestOk
                                    && session.manifest_ok
                                    && session.in_flight.is_empty()
                                {
                                    session.start_blocks()?;
                                    tokio::time::sleep(self.config.udp_send_delay).await;
                                    let packet = session.next_packet(header.0.dcid, self.config.udp_mtu)?;
                                    let sent = socket.send_to(&packet, peer).await?;
                                    tracing::debug!(%peer, bytes=sent, "object UDP first block sent after manifest ACK");
                                }
                                // A later packet can be ACKed while an earlier one
                                // is missing.  Do not wait for an idle socket in that
                                // case: ACK traffic itself would otherwise postpone
                                // the retransmission timer indefinitely.
                                if session.has_acked_after_unacked() {
                                    let mut resent = 0u32;
                                    let mut lost_bytes = 0u64;
                                    for flight in session
                                        .in_flight
                                        .iter_mut()
                                    {
                                        // Selective ACKs prove that packets
                                        // after the first hole arrived. Only
                                        // retransmit the missing prefix; doing
                                        // the whole outstanding window here
                                        // destroys throughput on large objects.
                                        if flight.acked {
                                            break;
                                        }
                                        socket.send_to(&flight.packet, peer).await?;
                                        resent = resent.saturating_add(1);
                                        if !flight.lost {
                                            flight.lost = true;
                                            lost_bytes = lost_bytes.saturating_add(flight.packet.len() as u64);
                                        }
                                    }
                                    if resent != 0 {
                                        session.endpoint.lost(lost_bytes);
                                    }
                                    session.data_retransmits =
                                        session.data_retransmits.saturating_add(resent);
                                    if resent != 0 {
                                        tracing::debug!(%peer, resent, data_retransmits=session.data_retransmits, "object UDP gap retransmit");
                                    }
                                }
                                while session.in_flight.len()
                                    < self.config.udp_window_packets.max(1)
                                    && session.can_send(self.config.udp_mtu)
                                    && session.has_unsent_data()
                                    && matches!(
                                        session.phase,
                                        UdpPhase::Manifest | UdpPhase::Blocks | UdpPhase::Done
                                    )
                                {
                                    tokio::time::sleep(self.config.udp_send_delay).await;
                                    let packet =
                                        session.next_packet(header.0.dcid, self.config.udp_mtu)?;
                                    let sent = socket.send_to(&packet, peer).await?;
                                    tracing::debug!(%peer, phase=?session.phase, bytes=sent, packets_sent=session.packets_sent, acks_received=session.acks_received, window=session.in_flight.len(), "object UDP packet sent after ACK");
                                }
                            }
                        }
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
            if kind != FRAME_HELLO {
                bail!("device did not start with HELLO");
            }
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
                        FRAME_ERROR => bail!(
                            "device transfer error: {}",
                            String::from_utf8_lossy(&payload)
                        ),
                        _ => bail!("unexpected device frame kind={kind}"),
                    }
                }
            });
            loop {
                let n = file.read(&mut block).await?;
                if n == 0 {
                    break;
                }
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
    enum UdpPhase {
        Manifest,
        AwaitManifestOk,
        Blocks,
        Done,
    }

    struct UdpSession {
        source: PathBuf,
        manifest: Vec<u8>,
        block: Vec<u8>,
        phase: UdpPhase,
        offset: usize,
        stream_offset: usize,
        sent_offset: usize,
        in_flight: VecDeque<InFlight>,
        block_index: u32,
        packets_sent: u32,
        acks_received: u32,
        data_retransmits: u32,
        manifest_ok: bool,
        endpoint: EndpointState<2>,
    }

    struct InFlight {
        packet_number: u32,
        len: usize,
        packet: Vec<u8>,
        acked: bool,
        lost: bool,
    }

    impl UdpSession {
        fn new(source: PathBuf, manifest: Vec<u8>, mtu: usize) -> Self {
            let mut endpoint = EndpointState::new(
                dmesh_transport::Role::Server,
                dmesh_transport::ConnectionLimits::default(),
                mtu as u64,
            );
            endpoint.open_send_stream(3, INITIAL_MAX_STREAM_DATA)
                .expect("manifest stream slot");
            endpoint.open_send_stream(7, INITIAL_MAX_STREAM_DATA)
                .expect("block stream slot");
            Self {
                source,
                manifest,
                block: Vec::new(),
                phase: UdpPhase::Manifest,
                offset: 0,
                stream_offset: 0,
                sent_offset: 0,
                in_flight: VecDeque::new(),
                block_index: 0,
                packets_sent: 0,
                acks_received: 0,
                data_retransmits: 0,
                manifest_ok: false,
                endpoint,
            }
        }

        fn can_send(&self, mtu: usize) -> bool {
            self.endpoint.congestion.can_send(mtu as u64)
        }

        fn prepare_block(&mut self) -> Result<()> {
            if self.block_index as usize * BLOCK_SIZE
                >= std::fs::metadata(&self.source)?.len() as usize
            {
                self.block.clear();
                write_frame_vec(FRAME_DONE, &[], &mut self.block)?;
                self.offset = 0;
                self.sent_offset = 0;
                self.phase = UdpPhase::Done;
                return Ok(());
            }
            let mut file = std::fs::File::open(&self.source)?;
            file.seek(SeekFrom::Start(self.block_index as u64 * BLOCK_SIZE as u64))?;
            let mut bytes = vec![0u8; BLOCK_SIZE];
            let n = file.read(&mut bytes)?;
            bytes.truncate(n);
            let mut payload = Vec::with_capacity(12 + n);
            payload.extend_from_slice(&[0, 0, 0, 0]);
            payload.extend_from_slice(&self.block_index.to_be_bytes());
            payload.extend_from_slice(&(n as u32).to_be_bytes());
            payload.extend_from_slice(&bytes);
            self.block.clear();
            write_frame_vec(FRAME_BLOCK, &payload, &mut self.block)?;
            self.offset = 0;
            self.sent_offset = 0;
            Ok(())
        }

        fn start_blocks(&mut self) -> Result<()> {
            if self.phase != UdpPhase::AwaitManifestOk || !self.in_flight.is_empty() {
                bail!("cannot start blocks before manifest is fully acknowledged");
            }
            self.phase = UdpPhase::Blocks;
            self.prepare_block()
        }

        fn acknowledge_ranges(&mut self, ranges: AckRangeSet) -> Result<bool> {
            let mut changed = false;
            for flight in &mut self.in_flight {
                if ranges.contains(flight.packet_number) {
                    flight.acked = true;
                    changed = true;
                }
            }
            if !changed {
                return Ok(false);
            }
            while self.in_flight.front().is_some_and(|flight| flight.acked) {
                if let Some(flight) = self.in_flight.pop_front() {
                    self.offset = self.offset.saturating_add(flight.len);
                    self.endpoint.acked(flight.packet.len() as u64);
                }
            }
            if self.in_flight.is_empty() {
                if self.phase == UdpPhase::Manifest && self.offset >= self.manifest.len() {
                    self.phase = UdpPhase::AwaitManifestOk;
                } else if self.phase == UdpPhase::Blocks && self.offset >= self.block.len() {
                    self.stream_offset += self.block.len();
                    self.block_index = self.block_index.saturating_add(1);
                    self.block.clear();
                    self.prepare_block()?;
                }
            }
            Ok(true)
        }

        fn has_acked_after_unacked(&self) -> bool {
            let Some(first) = self.in_flight.front() else {
                return false;
            };
            !first.acked && self.in_flight.iter().skip(1).any(|flight| flight.acked)
        }

        fn mark_unacked_lost(&mut self) -> u64 {
            let mut bytes = 0u64;
            for flight in self.in_flight.iter_mut().filter(|flight| !flight.acked && !flight.lost) {
                flight.lost = true;
                bytes = bytes.saturating_add(flight.packet.len() as u64);
            }
            bytes
        }

        fn has_unsent_data(&self) -> bool {
            match self.phase {
                UdpPhase::Manifest => self.sent_offset < self.manifest.len(),
                UdpPhase::Blocks | UdpPhase::Done => self.sent_offset < self.block.len(),
                UdpPhase::AwaitManifestOk => false,
            }
        }

        fn next_packet(&mut self, dcid: ConnectionId, mtu: usize) -> Result<Vec<u8>> {
            if !self.can_send(mtu) {
                bail!("congestion window exhausted");
            }
            let stream = if self.phase == UdpPhase::Manifest {
                3
            } else {
                7
            };
            let bytes = if self.phase == UdpPhase::Manifest {
                &self.manifest
            } else {
                &self.block
            };
            let max_payload = mtu
                .saturating_sub(48)
                .max(1)
                .min(bytes.len().saturating_sub(self.sent_offset).max(1));
            let end = self
                .sent_offset
                .saturating_add(max_payload)
                .min(bytes.len());
            let chunk = &bytes[self.sent_offset..end];
            let stream_offset = if stream == 3 {
                self.sent_offset as u64
            } else {
                (self.stream_offset + self.sent_offset) as u64
            };
            let mut out = vec![0u8; mtu.max(64)];
            let (p, packet_number) = self.endpoint.encode_stream_packet(
                dcid, stream, stream_offset, end == bytes.len(), chunk, &mut out,
            ).map_err(|error| anyhow::anyhow!("encode UDP stream packet: {error:?}"))?;
            out.truncate(p);
            self.sent_offset = end;
            self.in_flight.push_back(InFlight {
                packet_number,
                len: chunk.len(),
                packet: out.clone(),
                acked: false,
                lost: false,
            });
            self.packets_sent = self.packets_sent.saturating_add(1);
            Ok(out)
        }
    }

    fn write_frame_vec(kind: u16, payload: &[u8], out: &mut Vec<u8>) -> Result<()> {
        if payload.len() > u16::MAX as usize {
            bail!("DRS2 frame too large: {}", payload.len());
        }
        out.extend_from_slice(&MAGIC.to_be_bytes());
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        Ok(())
    }

    fn udp_header(data: &[u8]) -> Option<(ShortHeader, usize)> {
        ShortHeader::decode(data).ok()
    }

    fn udp_hello(data: &[u8]) -> Result<Option<(Vec<u8>, Hello)>> {
        let Some((_, mut p)) = udp_header(data) else {
            return Ok(None);
        };
        while p < data.len() {
            let (frame, used) =
                decode_frame(&data[p..]).map_err(|_| anyhow::anyhow!("invalid UDP frame"))?;
            p += used;
            if let Frame::Stream(s) = frame {
                if s.id == 0
                    && s.offset == 0
                    && s.data.len() >= 8
                    && u32::from_be_bytes(s.data[..4].try_into()?) == MAGIC
                    && u16::from_be_bytes(s.data[4..6].try_into()?) == FRAME_HELLO
                {
                    let len = u16::from_be_bytes(s.data[6..8].try_into()?) as usize;
                    if s.data.len() >= 8 + len {
                        let payload = s.data[8..8 + len].to_vec();
                        return Ok(Some((payload.clone(), parse_hello(&payload)?)));
                    }
                }
            }
        }
        Ok(None)
    }

    struct UdpControls {
        ack: Option<AckRangeSet>,
        max_data: Option<u64>,
        max_stream_data: Vec<(u64, u64)>,
    }

    fn udp_controls(data: &[u8], mut p: usize) -> Option<UdpControls> {
        let mut controls = UdpControls {
            ack: None,
            max_data: None,
            max_stream_data: Vec::new(),
        };
        while p < data.len() {
            let Ok((frame, used)) = decode_frame(&data[p..]) else {
                return None;
            };
            p += used;
            match frame {
                Frame::Ack { largest, .. } => {
                    let mut ranges = AckRangeSet::new();
                    ranges.insert(largest);
                    controls.ack = Some(ranges);
                }
                Frame::AckRanges { ranges, .. } => controls.ack = Some(ranges),
                Frame::MaxData(max) => controls.max_data = Some(max),
                Frame::MaxStreamData { id, max } => controls.max_stream_data.push((id, max)),
                _ => {}
            }
        }
        Some(controls)
    }

    fn udp_manifest_ok(data: &[u8], mut p: usize) -> bool {
        while p < data.len() {
            let Ok((frame, used)) = decode_frame(&data[p..]) else {
                return false;
            };
            p += used;
            if let Frame::Stream(s) = frame {
                if s.id == 0
                    && s.data.len() >= 8
                    && u32::from_be_bytes(s.data[..4].try_into().unwrap()) == MAGIC
                    && u16::from_be_bytes(s.data[4..6].try_into().unwrap()) == FRAME_MANIFEST_OK
                {
                    return true;
                }
            }
        }
        false
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use dmesh_transport::{INITIAL_MAX_DATA, StreamFrame};
        use std::io::Write;
        use std::time::Instant;

        fn loopback_packet(
            header: ShortHeader,
            stream_id: u64,
            offset: u64,
            fin: bool,
            data: &[u8],
        ) -> Vec<u8> {
            let mut packet = vec![0u8; 1200];
            let mut p = header.encode(&mut packet).unwrap();
            p += Frame::Stream(StreamFrame {
                id: stream_id,
                offset,
                fin,
                data,
            })
            .encode(&mut packet[p..])
            .unwrap();
            packet.truncate(p);
            packet
        }

        fn loopback_ack_with_credit(
            header: ShortHeader,
            ranges: Option<AckRangeSet>,
            stream_id: u64,
            stream_end: u64,
            connection_end: u64,
        ) -> Vec<u8> {
            let mut packet = vec![0u8; 512];
            let mut p = header.encode(&mut packet).unwrap();
            if let Some(ranges) = ranges {
                p += Frame::AckRanges {
                    largest: header.packet_number,
                    delay: 0,
                    ranges,
                }
                .encode(&mut packet[p..])
                .unwrap();
            } else {
                p += Frame::Ack {
                    largest: header.packet_number,
                    delay: 0,
                }
                .encode(&mut packet[p..])
                .unwrap();
            }
            p += Frame::MaxData(connection_end.saturating_add(INITIAL_MAX_DATA))
                .encode(&mut packet[p..])
                .unwrap();
            p += Frame::MaxStreamData {
                id: stream_id,
                max: stream_end.saturating_add(INITIAL_MAX_STREAM_DATA),
            }
            .encode(&mut packet[p..])
            .unwrap();
            packet.truncate(p);
            packet
        }

        fn loopback_drs2_frame<'a>(wire: &'a [u8], offset: &mut usize) -> Option<(u16, &'a [u8])> {
            if wire.len().saturating_sub(*offset) < 8 {
                return None;
            }
            let start = *offset;
            let magic = u32::from_be_bytes(wire[start..start + 4].try_into().unwrap());
            assert_eq!(magic, MAGIC, "loopback client received invalid DRS2 magic");
            let kind = u16::from_be_bytes(wire[start + 4..start + 6].try_into().unwrap());
            let len = u16::from_be_bytes(wire[start + 6..start + 8].try_into().unwrap()) as usize;
            let end = start + 8 + len;
            if wire.len() < end {
                return None;
            }
            *offset = end;
            Some((kind, &wire[start + 8..end]))
        }

        #[tokio::test]
        #[ignore = "16 MiB benchmark; run through scripts/build.sh object-store-loopback"]
        async fn loopback_udp_16m_baseline() {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("flash");
            let chip = root.join("esp32");
            std::fs::create_dir_all(&chip).unwrap();
            let image_size = std::env::var("DMESH_LOOPBACK_IMAGE_BYTES")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(16 * 1024 * 1024);
            std::fs::write(chip.join("main-app.bin"), vec![0x5a; image_size]).unwrap();

            let window = std::env::var("DMESH_LOOPBACK_WINDOW")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(16)
                .max(1);
            let ack_delay = std::env::var("DMESH_LOOPBACK_ACK_DELAY_MS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0);
            let selective_ack_packets = std::env::var("DMESH_LOOPBACK_SELECTIVE_ACK_PACKETS")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            let drop_ack_packet = std::env::var("DMESH_LOOPBACK_DROP_ACK_PACKET")
                .ok()
                .and_then(|value| value.parse::<u32>().ok());
            let mut dropped_ack_packet = false;
            let server = ObjectServer::new(ServerConfig {
                artifact_root: root,
                udp_mtu: 1200,
                udp_hello_duplicate_delay: Duration::from_millis(20),
                udp_window_packets: window,
                udp_retransmit_timeout: Duration::from_millis(100),
                ..ServerConfig::default()
            });
            let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server_socket.local_addr().unwrap();
            let server_task = tokio::spawn(async move {
                server.run_udp(server_socket).await.unwrap();
            });
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client.connect(server_addr).await.unwrap();

            let mut hello = [0u8; 90];
            hello[0] = 1; // classic ESP32
            hello[71] = 6; // Main
            hello[89] = 0x09; // fixed layout plus client-requested dry run
            let mut hello_body = Vec::new();
            write_frame_vec(FRAME_HELLO, &hello, &mut hello_body).unwrap();
            let hello_packet = loopback_packet(
                ShortHeader {
                    flags: dmesh_transport::FLAG_FIXED,
                    dcid: ConnectionId::new(1).unwrap(),
                    packet_number: 0,
                    packet_number_len: 2,
                },
                0,
                0,
                true,
                &hello_body,
            );
            client.send(&hello_packet).await.unwrap();

            let started = Instant::now();
            let mut manifest_wire = Vec::new();
            let mut block_wire = Vec::new();
            let mut manifest_offset = 0u64;
            let mut block_offset = 0u64;
            let mut manifest_frame_offset = 0usize;
            let mut block_frame_offset = 0usize;
            let mut image_bytes = 0usize;
            let mut packets = 0usize;
            let mut duplicate_packets = 0usize;
            let mut received_ack_ranges = AckRangeSet::new();
            let mut selective_acks_sent = 0usize;
            let mut manifest_ok_sent = false;
            let mut completed = false;
            let mut packet = vec![0u8; 1500];

            while !completed {
                let receive_timeout = if drop_ack_packet.is_some() { 120 } else { 30 };
                let received = timeout(Duration::from_secs(receive_timeout), client.recv(&mut packet))
                    .await
                    .unwrap()
                    .unwrap();
                let (header, header_len) = ShortHeader::decode(&packet[..received]).unwrap();
                packets += 1;
                let connection_base = manifest_offset.saturating_add(block_offset);
                let (frame, _) = decode_frame(&packet[header_len..]).unwrap();
                let Frame::Stream(stream) = frame else {
                    continue;
                };
                if std::env::var_os("DMESH_LOOPBACK_PROGRESS").is_some() && packets % 16 == 0 {
                    eprintln!("loopback progress packets={} pn={} image_bytes={} stream_id={} offset={}", packets, header.packet_number, image_bytes, stream.id, stream.offset);
                }
                let (wire, stream_offset, frame_offset) = match stream.id {
                    3 => (
                        &mut manifest_wire,
                        &mut manifest_offset,
                        &mut manifest_frame_offset,
                    ),
                    7 => (&mut block_wire, &mut block_offset, &mut block_frame_offset),
                    _ => continue,
                };
                if ack_delay != 0 {
                    tokio::time::sleep(Duration::from_millis(ack_delay)).await;
                }
                received_ack_ranges.insert(header.packet_number);
                let ranges = if selective_acks_sent < selective_ack_packets {
                    selective_acks_sent += 1;
                    Some(received_ack_ranges)
                } else {
                    None
                };
                let connection_end = connection_base.saturating_add(stream.data.len() as u64);
                if drop_ack_packet == Some(header.packet_number) && !dropped_ack_packet {
                    dropped_ack_packet = true;
                } else {
                    client
                        .send(&loopback_ack_with_credit(
                            header,
                            ranges,
                            stream.id,
                            stream.offset.saturating_add(stream.data.len() as u64),
                            connection_end,
                        ))
                        .await
                        .unwrap();
                }
                if stream.offset < *stream_offset {
                    duplicate_packets += 1;
                    continue;
                }
                assert_eq!(
                    stream.offset, *stream_offset,
                    "loopback client observed a gap"
                );
                wire.extend_from_slice(stream.data);
                *stream_offset += stream.data.len() as u64;
                while let Some((kind, body)) = loopback_drs2_frame(wire, frame_offset) {
                    match kind {
                        FRAME_BLOCK => image_bytes += body.len().saturating_sub(12),
                        FRAME_DONE => {
                            assert_eq!(image_bytes, image_size);
                            completed = true;
                        }
                        FRAME_MANIFEST => {
                            assert!(!body.is_empty());
                            if stream.fin && !manifest_ok_sent {
                                let mut body = [0u8; 8];
                                body[..4].copy_from_slice(&MAGIC.to_be_bytes());
                                body[4..6].copy_from_slice(&FRAME_MANIFEST_OK.to_be_bytes());
                                client
                                    .send(&loopback_packet(
                                        ShortHeader {
                                            flags: dmesh_transport::FLAG_FIXED,
                                            dcid: header.dcid,
                                            packet_number: header.packet_number,
                                            packet_number_len: 2,
                                        },
                                        0,
                                        0,
                                        true,
                                        &body,
                                    ))
                                    .await
                                    .unwrap();
                                manifest_ok_sent = true;
                            }
                        }
                        _ => {}
                    }
                }
                if stream.id == 3 && stream.fin && !manifest_ok_sent {
                    panic!("manifest stream ended without a complete manifest");
                }
                if stream.id == 7 && stream.fin && completed {
                    break;
                }
            }
            let elapsed_ms = started.elapsed().as_millis();
            let bitrate_kbps = (image_bytes as u128 * 8_000 / elapsed_ms.max(1)) as u64 / 1000;
            println!(
                "loopback_udp window={} image_bytes={} packets={} duplicate_packets={} selective_acks_sent={} dropped_ack_packet={} elapsed_ms={} bitrate_kbps={} ack_delay_ms={}",
                window,
                image_bytes,
                packets,
                duplicate_packets,
                selective_acks_sent,
                dropped_ack_packet,
                elapsed_ms,
                bitrate_kbps,
                ack_delay,
            );
            if drop_ack_packet.is_some() {
                assert!(dropped_ack_packet, "configured packet was not observed");
                assert!(duplicate_packets > 0, "dropped ACK did not cause retransmission");
            }
            server_task.abort();
        }

        #[test]
        fn generates_and_reuses_manifest_until_mtime_changes() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("blob.bin");
            std::fs::write(&path, b"hello world").unwrap();
            let first = FileManifest::load_or_generate(&path).unwrap();
            assert_eq!(first.block_sha256.len(), 1);
            let second = FileManifest::load_or_generate(&path).unwrap();
            assert_eq!(first, second);
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
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
            assert_eq!(
                &wire[149..153],
                &hex::decode(&manifest.block_sha256[0]).unwrap()[..4]
            );
            assert_eq!(manifest.block_sha256.len(), 2);
        }

        #[test]
        fn resolves_cpu_specific_modules_next_to_flash_root() {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("target").join("flash");
            let module_root = dir
                .path()
                .join("target")
                .join("modules")
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
            let mut session = UdpSession::new(PathBuf::from("unused"), manifest, 256);
            let packet = session
                .next_packet(ConnectionId::new(0x1234).unwrap(), 256)
                .unwrap();
            let (header, p) = ShortHeader::decode(&packet).unwrap();
            assert_eq!(header.dcid, ConnectionId::new(0x1234).unwrap());
            let (frame, _) = decode_frame(&packet[p..]).unwrap();
            match frame {
                Frame::Stream(s) => {
                    assert_eq!(s.id, 3);
                    assert_eq!(s.offset, 0);
                    assert!(!s.fin);
                    assert!(s.data.len() < 2400);
                }
                _ => panic!("expected stream frame"),
            }
        }

        #[test]
        fn udp_manifest_packet_round_trips_through_shared_decoder() {
            let mut manifest = Vec::new();
            write_frame_vec(FRAME_MANIFEST, &vec![9u8; 2400], &mut manifest).unwrap();
            let mut session = UdpSession::new(PathBuf::from("unused"), manifest, 1200);
            let packet = session
                .next_packet(ConnectionId::new(1).unwrap(), 1200)
                .unwrap();
            let (header, header_len) = ShortHeader::decode(&packet).unwrap();
            let (frame, _) = decode_frame(&packet[header_len..]).unwrap();
            let Frame::Stream(stream) = frame else { panic!("expected stream packet") };
            assert_eq!(header.dcid.value(), 1);
            assert_eq!(stream.id, 3);
        }

        #[test]
        fn udp_ack_does_not_retire_an_unacknowledged_earlier_packet() {
            let mut manifest = Vec::new();
            write_frame_vec(FRAME_MANIFEST, &vec![9u8; 2400], &mut manifest).unwrap();
            let mut session = UdpSession::new(PathBuf::from("unused"), manifest, 1200);
            let first = session
                .next_packet(ConnectionId::new(1).unwrap(), 256)
                .unwrap();
            let first_number = ShortHeader::decode(&first).unwrap().0.packet_number;
            let second = session
                .next_packet(ConnectionId::new(1).unwrap(), 256)
                .unwrap();
            let second_number = ShortHeader::decode(&second).unwrap().0.packet_number;
            let mut second_ack = AckRangeSet::new();
            second_ack.insert(second_number);
            assert!(session.acknowledge_ranges(second_ack).unwrap());
            assert_eq!(session.in_flight.len(), 2);
            assert_eq!(session.offset, 0);
            let mut first_ack = AckRangeSet::new();
            first_ack.insert(first_number);
            assert!(session.acknowledge_ranges(first_ack).unwrap());
            assert_eq!(session.in_flight.len(), 0);
            assert!(session.offset > 0);
        }

        #[test]
    fn udp_session_per_packet_selective_ack_grows_cwnd() {
            let mut manifest = Vec::new();
            write_frame_vec(FRAME_MANIFEST, &vec![9u8; 32 * 1200], &mut manifest).unwrap();
            let mut session = UdpSession::new(PathBuf::from("unused"), manifest, 1200);
            let initial = session.endpoint.congestion.congestion_window;
            for _ in 0..8 {
                let packet = session
                    .next_packet(ConnectionId::new(1).unwrap(), 1200)
                    .unwrap();
                let packet_number = ShortHeader::decode(&packet).unwrap().0.packet_number;
                let mut ack = AckRangeSet::new();
                ack.insert(packet_number);
                assert!(session.acknowledge_ranges(ack).unwrap());
            }
            assert!(session.endpoint.congestion.congestion_window > initial);
        assert_eq!(session.endpoint.congestion.bytes_in_flight, 0);
    }

    #[test]
    fn udp_session_stops_at_peer_credit_and_resumes_after_max_stream_data() {
        let mut manifest = Vec::new();
        manifest.resize(128 * 1024, 9);
        let mut session = UdpSession::new(PathBuf::from("unused"), manifest, 1200);
        let mut sent = 0usize;
        loop {
            let packet = match session.next_packet(ConnectionId::new(1).unwrap(), 1200) {
                Ok(packet) => packet,
                Err(_) => break,
            };
            let (header, header_len) = ShortHeader::decode(&packet).unwrap();
            let (Frame::Stream(stream), _) = decode_frame(&packet[header_len..]).unwrap() else { panic!("expected stream") };
            sent += stream.data.len();
            let mut ack = AckRangeSet::new();
            ack.insert(header.packet_number);
            session.acknowledge_ranges(ack).unwrap();
        }
        assert!(sent <= INITIAL_MAX_STREAM_DATA as usize);
        assert!(session.endpoint.send.sent_data > 0);
        session.endpoint.send.extend_stream(3, 128 * 1024).unwrap();
        session.endpoint.send.extend_connection(256 * 1024);
        assert!(session.next_packet(ConnectionId::new(1).unwrap(), 1200).is_ok());
    }

    #[test]
    fn udp_session_large_credit_exercises_cwnd_after_selective_ack_burst() {
        let mut manifest = Vec::new();
        manifest.resize(512 * 1024, 9);
        let mut session = UdpSession::new(PathBuf::from("unused"), manifest, 1200);
        session.endpoint.send.extend_stream(3, 512 * 1024).unwrap();
        session.endpoint.send.extend_connection(1024 * 1024);
        let initial_cwnd = session.endpoint.congestion.congestion_window;
        let mut sent_packets = Vec::new();
        for _ in 0..10 {
            let packet = session.next_packet(ConnectionId::new(1).unwrap(), 1200).unwrap();
            sent_packets.push(ShortHeader::decode(&packet).unwrap().0.packet_number);
        }
        // Simulate a delayed selective ACK with one loss: later packets are
        // acknowledged first, then the missing packet is retransmitted.
        let mut later = AckRangeSet::new();
        for packet_number in sent_packets.iter().copied().skip(3) { later.insert(packet_number); }
        assert!(session.acknowledge_ranges(later).unwrap());
        assert_eq!(session.in_flight.len(), 10);
        session.endpoint.lost(1200);
        let mut missing = AckRangeSet::new();
        missing.insert(sent_packets[0]);
        missing.insert(sent_packets[1]);
        missing.insert(sent_packets[2]);
        assert!(session.acknowledge_ranges(missing).unwrap());
        assert_eq!(session.endpoint.congestion.bytes_in_flight, 0);
        assert!(session.endpoint.congestion.congestion_window < initial_cwnd);
        // A large peer credit means the next limiting factor is congestion,
        // not the sender's flow window.
        for _ in 0..80 {
            let packet = session.next_packet(ConnectionId::new(1).unwrap(), 1200).unwrap();
            let packet_number = ShortHeader::decode(&packet).unwrap().0.packet_number;
            let mut ack = AckRangeSet::new();
            ack.insert(packet_number);
            session.acknowledge_ranges(ack).unwrap();
        }
        assert!(session.endpoint.send.sent_data > INITIAL_MAX_STREAM_DATA);
    }

        #[tokio::test]
        #[ignore = "16 MiB localhost TCP benchmark; run scripts/build.sh object-store-tcp-loopback"]
        async fn tcp_16m_baseline() {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("flash");
            let chip = root.join("esp32");
            std::fs::create_dir_all(&chip).unwrap();
            let image_len = 16 * 1024 * 1024;
            let image = (0..image_len).map(|n| (n % 251) as u8).collect::<Vec<_>>();
            std::fs::write(chip.join("main-app.bin"), &image).unwrap();

            let server = ObjectServer::new(ServerConfig {
                artifact_root: root,
                bind: "127.0.0.1".into(),
                port: 0,
                idle_timeout: Duration::from_secs(5),
                ..ServerConfig::default()
            });
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server_task = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                server.handle(stream).await.unwrap();
            });
            let mut device = TcpStream::connect(address).await.unwrap();
            device.set_nodelay(true).unwrap();
            let started = std::time::Instant::now();
            let mut hello = vec![0u8; 90];
            hello[0] = 1; // classic ESP32
            hello[71] = 6; // Main
            hello[89] = 0x09; // fixed layout plus client-requested dry run
            write_frame(&mut device, FRAME_HELLO, &hello).await.unwrap();

            let (kind, manifest) = read_frame(&mut device, Duration::from_secs(5))
                .await
                .unwrap();
            assert_eq!(kind, FRAME_MANIFEST);
            assert_eq!(manifest[0], 6);
            assert_eq!(manifest[1], 1); // client-requested dry run

            let mut blocks = 0;
            let mut received_bytes = 0usize;
            loop {
                let (kind, payload) = read_frame(&mut device, Duration::from_secs(5))
                    .await
                    .unwrap();
                match kind {
                    FRAME_BLOCK => {
                        assert_eq!(
                            u32::from_be_bytes(payload[4..8].try_into().unwrap()),
                            blocks
                        );
                        received_bytes += payload.len().saturating_sub(12);
                        blocks += 1;
                    }
                    FRAME_DONE => break,
                    other => panic!("unexpected server frame {other}"),
                }
            }
            assert_eq!(blocks, ((image_len + BLOCK_SIZE - 1) / BLOCK_SIZE) as u32);
            write_frame(&mut device, FRAME_DONE, &[]).await.unwrap();
            let (kind, payload) = read_frame(&mut device, Duration::from_secs(5))
                .await
                .unwrap();
            assert_eq!((kind, payload.len()), (FRAME_ACK, 0));
            server_task.await.unwrap();
            let elapsed_ms = started.elapsed().as_millis().max(1);
            let bitrate_kbps = (received_bytes as u128 * 8_000 / elapsed_ms) as u64 / 1000;
            println!(
                "tcp_stream bytes={} blocks={} elapsed_ms={} bitrate_kbps={} tcp_nodelay=true",
                received_bytes, blocks, elapsed_ms, bitrate_kbps,
            );
            assert_eq!(received_bytes, image_len);
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
