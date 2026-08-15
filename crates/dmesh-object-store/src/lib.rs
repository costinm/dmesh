#![cfg_attr(not(feature = "std"), no_std)]

//! Transport-neutral object store.
//!
//! The crate resolves a binary CBOR GET request and produces a manifest plus
//! blob records on a caller-provided stream. It contains no sockets, UDP,
//! QUIC packet handling, retransmission, or radio code. A host may put those
//! records on TCP, SSH, or any other stream; firmware may put them on a
//! `dmesh-transport` stream.

pub mod cbor;

#[cfg(feature = "std")]
mod host {
    use crate::cbor;
    use anyhow::{bail, Context, Result};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{timeout, Duration};

    pub use crate::protocol::{
        GetRequest, MAX_RECORD, RECORD_BLOB, RECORD_DONE, RECORD_MANIFEST, REQUEST_MAX,
    };

    pub const BLOCK_SIZE: usize = 4096;

    #[derive(Debug, Clone)]
    pub struct ServerConfig {
        pub bind: String,
        pub port: u16,
        pub artifact_root: PathBuf,
        pub archive_root: Option<PathBuf>,
        pub idle_timeout: Duration,
    }

    impl Default for ServerConfig {
        fn default() -> Self {
            Self {
                bind: "0.0.0.0".into(),
                port: 3337,
                artifact_root: PathBuf::from("target/flash"),
                archive_root: None,
                idle_timeout: Duration::from_secs(900),
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
                let n = file.read(&mut buf)?;
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
                let bytes = std::fs::read(&sidecar)?;
                if let Ok(manifest) = serde_json::from_slice::<Self>(&bytes) {
                    if manifest.ensure_current(source).is_ok() {
                        return Ok(manifest);
                    }
                }
            }
            let manifest = Self::generate(source)?;
            let temporary = sidecar.with_extension("json.tmp");
            std::fs::write(&temporary, serde_json::to_vec_pretty(&manifest)?)?;
            std::fs::rename(temporary, sidecar)?;
            Ok(manifest)
        }

        pub fn ensure_current(&self, source: &Path) -> Result<()> {
            let metadata = std::fs::metadata(source)?;
            if metadata.len() != self.source_size || mtime_ns(&metadata)? != self.source_mtime_ns {
                bail!("stale manifest for {}", source.display());
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

    #[derive(Clone, Default)]
    pub struct ManifestCache {
        entries: Arc<Mutex<HashMap<PathBuf, FileManifest>>>,
    }

    impl ManifestCache {
        pub fn get(&self, source: &Path) -> Result<FileManifest> {
            if let Some(value) = self.entries.lock().unwrap().get(source).cloned() {
                if value.ensure_current(source).is_ok() {
                    return Ok(value);
                }
            }
            let value = FileManifest::load_or_generate(source)?;
            self.entries
                .lock()
                .unwrap()
                .insert(source.to_path_buf(), value.clone());
            Ok(value)
        }

        pub fn prepare_tree(&self, root: &Path) -> Result<usize> {
            fn visit(cache: &ManifestCache, path: &Path, count: &mut usize) -> Result<()> {
                for entry in std::fs::read_dir(path)? {
                    let child = entry?.path();
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

    fn target_file(root: &Path, request: GetRequest<'_>) -> Result<PathBuf> {
        let chip = match request.cpu {
            9 => "esp32s3",
            13 => "esp32c6",
            _ => "esp32",
        };
        let file = match request.target {
            6 => root.join(chip).join("main-app.bin"),
            3 => root.join(chip).join("recovery.bin"),
            2 => root.join(chip).join("partition-table.bin"),
            7 => {
                let name = request
                    .name
                    .ok_or_else(|| anyhow::anyhow!("object name missing"))?;
                if !name
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
                {
                    bail!("invalid object name");
                }
                let name = String::from_utf8_lossy(name);
                let path = root.join("modules").join(format!("mod_{name}.dmod"));
                if path.is_file() {
                    path
                } else {
                    root.join("modules").join(format!("{name}.dmod"))
                }
            }
            _ => bail!("unsupported target"),
        };
        if file.is_file() {
            Ok(file)
        } else {
            bail!("artifact not found: {}", file.display())
        }
    }

    fn manifest_bytes(manifest: &FileManifest, request: GetRequest<'_>) -> Result<Vec<u8>> {
        if manifest.image_size > u32::MAX as u64 {
            bail!("object too large");
        }
        let mut out = Vec::with_capacity(64 + manifest.block_sha256.len() * 32);
        // CBOR map: target, version, block size, block count, image size,
        // full image digest, and full per-block SHA-256 digests. The receiver
        // must verify these fields before accepting or committing the image.
        cbor::encode::map(7, &mut out);
        cbor::encode::uint(0, &mut out);
        cbor::encode::uint(request.target as u64, &mut out);
        cbor::encode::uint(1, &mut out);
        cbor::encode::uint(1, &mut out);
        cbor::encode::uint(2, &mut out);
        cbor::encode::uint(manifest.block_size as u64, &mut out);
        cbor::encode::uint(3, &mut out);
        cbor::encode::uint(manifest.block_sha256.len() as u64, &mut out);
        cbor::encode::uint(4, &mut out);
        cbor::encode::uint(manifest.image_size, &mut out);
        cbor::encode::uint(5, &mut out);
        cbor::encode::bytes(&hex::decode(&manifest.image_sha256)?, &mut out);
        cbor::encode::uint(6, &mut out);
        cbor::encode::array(manifest.block_sha256.len() as u64, &mut out);
        for digest in &manifest.block_sha256 {
            let bytes = hex::decode(digest)?;
            cbor::encode::bytes(&bytes, &mut out);
        }
        Ok(out)
    }

    async fn read_record<R: AsyncRead + Unpin>(
        reader: &mut R,
        idle: Duration,
    ) -> Result<(u8, Vec<u8>)> {
        let mut header = [0u8; 5];
        timeout(idle, reader.read_exact(&mut header)).await??;
        let len = u32::from_be_bytes(header[1..5].try_into()?) as usize;
        if len > REQUEST_MAX {
            bail!("request record too large");
        }
        let mut body = vec![0u8; len];
        timeout(idle, reader.read_exact(&mut body)).await??;
        Ok((header[0], body))
    }

    async fn write_record<W: AsyncWrite + Unpin>(
        writer: &mut W,
        kind: u8,
        body: &[u8],
    ) -> Result<()> {
        if body.len() > MAX_RECORD {
            bail!("response record too large");
        }
        writer.write_all(&[kind]).await?;
        writer.write_all(&(body.len() as u32).to_be_bytes()).await?;
        writer.write_all(body).await?;
        Ok(())
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

        /// Resolve a GET and materialize the transport-neutral response
        /// records. Bearer adapters may stream these records over TCP, UDP,
        /// QUIC, or a radio without making the object store aware of that
        /// bearer.
        pub fn response_records(&self, request: GetRequest<'_>) -> Result<Vec<(u8, Vec<u8>)>> {
            let source = target_file(&self.config.artifact_root, request)?;
            let manifest = self.manifests.get(&source)?;
            let mut records = vec![(RECORD_MANIFEST, manifest_bytes(&manifest, request)?)];
            let mut file = std::fs::File::open(source)?;
            let mut block = vec![0u8; BLOCK_SIZE];
            let mut index = 0u32;
            loop {
                let n = file.read(&mut block)?;
                if n == 0 {
                    break;
                }
                let mut body = Vec::with_capacity(12 + n);
                body.extend_from_slice(&[0, 0, 0, 0]);
                body.extend_from_slice(&index.to_be_bytes());
                body.extend_from_slice(&(n as u32).to_be_bytes());
                body.extend_from_slice(&block[..n]);
                records.push((RECORD_BLOB, body));
                index = index.checked_add(1).context("block count overflow")?;
            }
            records.push((RECORD_DONE, Vec::new()));
            Ok(records)
        }

        pub async fn run(self) -> Result<()> {
            std::fs::create_dir_all(&self.config.artifact_root)?;
            let _ = self.manifests.prepare_tree(&self.config.artifact_root);
            let listener = TcpListener::bind((&*self.config.bind, self.config.port)).await?;
            loop {
                let (stream, _) = listener.accept().await?;
                let server = self.clone();
                tokio::spawn(async move {
                    let _ = server.handle_stream(stream).await;
                });
            }
        }

        pub async fn handle_stream<S>(&self, stream: S) -> Result<()>
        where
            S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        {
            let (mut reader, mut writer) = tokio::io::split(stream);
            let (kind, request_bytes) = read_record(&mut reader, self.config.idle_timeout).await?;
            if kind != crate::protocol::FRAME_GET {
                bail!("expected GET record");
            }
            let request = crate::protocol::decode_get(&request_bytes)
                .ok_or_else(|| anyhow::anyhow!("invalid GET"))?;
            for (kind, body) in self.response_records(request)? {
                write_record(&mut writer, kind, &body).await?;
            }
            writer.flush().await?;
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tempfile::tempdir;

        #[test]
        fn response_records_preserve_manifest_and_block_digests() {
            let directory = tempdir().unwrap();
            let artifact_root = directory.path().join("flash");
            let artifact = artifact_root.join("esp32c6/main-app.bin");
            std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
            let bytes: Vec<u8> = (0..5000).map(|value| (value % 251) as u8).collect();
            std::fs::write(&artifact, &bytes).unwrap();

            let server = ObjectServer::new(ServerConfig {
                artifact_root,
                ..ServerConfig::default()
            });
            let request = GetRequest {
                name: None,
                cpu: 13,
                target: 6,
            };
            let records = server.response_records(request).unwrap();
            assert_eq!(records.len(), 4);
            assert_eq!(records[0].0, RECORD_MANIFEST);
            assert_eq!(records[1].0, RECORD_BLOB);
            assert_eq!(records[2].0, RECORD_BLOB);
            assert_eq!(records[3], (RECORD_DONE, Vec::new()));

            let full_digest = Sha256::digest(&bytes).to_vec();
            assert!(records[0]
                .1
                .windows(full_digest.len())
                .any(|window| window == &full_digest[..]));
            let first_digest = Sha256::digest(&bytes[..BLOCK_SIZE]).to_vec();
            assert!(records[0]
                .1
                .windows(4)
                .any(|window| window == &first_digest[..4]));
            assert_eq!(&records[1].1[..4], &[0, 0, 0, 0]);
            assert_eq!(
                u32::from_be_bytes(records[1].1[4..8].try_into().unwrap()),
                0
            );
            assert_eq!(
                u32::from_be_bytes(records[1].1[8..12].try_into().unwrap()),
                BLOCK_SIZE as u32
            );
            assert_eq!(&records[1].1[12..], &bytes[..BLOCK_SIZE]);
            assert_eq!(
                u32::from_be_bytes(records[2].1[4..8].try_into().unwrap()),
                1
            );
            assert_eq!(&records[2].1[12..], &bytes[BLOCK_SIZE..]);
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
