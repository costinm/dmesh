//! Linux UART bearer: discovery of device nodes does not claim a port.

use crate::pool::{PooledDecoder, PooledFrame};
use crate::{
    PACKET_MARKER,
    codec::{DEFAULT_RECORD_MAX, Decoder, Encoder, UART_FLAG},
    decode_packet,
};
use quic_lite::{BearerContext, BearerInfo, BearerName, PacketBearer, PacketMeta, PeerL2Address};
use quic_lite::{
    EgressSubmission, PacketEgress, PacketSendOutcome, PacketSubmitError,
    packet_pool::{PacketPool, PoolBufferLease},
};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
    string::{String, ToString},
    sync::{Arc, Mutex},
    time::Duration,
    vec::Vec,
};

const MAX_LOG_LINE: usize = 4096;
const UART_LOG_ENV: &str = "UART_CODEC_LOG";
/// Default line rate used by DMesh physical UART bearers when no override is supplied.
pub const DEFAULT_BAUD: u32 = 115_200;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SidebandState {
    Text,
    AfterFlag,
    MarkedFrame,
}

struct SidebandText {
    state: SidebandState,
    line: Vec<u8>,
    overflow: bool,
}

impl SidebandText {
    fn new() -> Self {
        Self {
            state: SidebandState::Text,
            line: Vec::new(),
            overflow: false,
        }
    }

    fn reset(&mut self) {
        self.state = SidebandState::Text;
        self.line.clear();
        self.overflow = false;
    }

    /// Extract unframed boot/crash text without examining bytes inside a
    /// marked QUIC datagram. After a flag, the first raw byte is authoritative:
    /// `PACKET_MARKER` starts a frame; every other byte resumes sideband text.
    fn push(&mut self, bytes: &[u8], mut line: impl FnMut(String)) {
        for &byte in bytes {
            if byte == UART_FLAG {
                self.state = SidebandState::AfterFlag;
                self.line.clear();
                self.overflow = false;
                continue;
            }
            match self.state {
                SidebandState::AfterFlag if byte == PACKET_MARKER || byte >= 0x80 => {
                    self.state = SidebandState::MarkedFrame;
                    continue;
                }
                SidebandState::AfterFlag => self.state = SidebandState::Text,
                SidebandState::MarkedFrame => continue,
                SidebandState::Text => {}
            }
            match byte {
                b'\r' => {}
                b'\n' if !self.line.is_empty() => {
                    if self.overflow {
                        self.line
                            .extend_from_slice(b" [uart_log_truncated limit=4096]");
                    }
                    if let Ok(text) = String::from_utf8(core::mem::take(&mut self.line)) {
                        line(text);
                    }
                    self.overflow = false;
                }
                b'\n' => {}
                byte if byte.is_ascii_graphic() || byte == b' ' || byte == b'\t' => {
                    if self.overflow {
                        continue;
                    } else if self.line.len() < MAX_LOG_LINE {
                        self.line.push(byte);
                    } else {
                        self.overflow = true;
                    }
                }
                _ => {
                    self.line.clear();
                    self.overflow = false;
                }
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortInfo {
    /// Stable `/dev/serial/by-id` path when available, otherwise a tty path.
    pub path: PathBuf,
    pub device: PathBuf,
}

/// Enumerate candidate USB serial devices without opening or configuring any.
pub fn list_ports() -> io::Result<Vec<PortInfo>> {
    list_ports_under(Path::new("/dev"))
}

fn list_ports_under(dev: &Path) -> io::Result<Vec<PortInfo>> {
    let mut ports = Vec::new();
    let mut seen = BTreeSet::new();
    for directory in [dev.join("serial/by-id"), dev.to_path_buf()] {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if directory == dev && !name.starts_with("ttyUSB") && !name.starts_with("ttyACM") {
                continue;
            }
            let Ok(device) = path.canonicalize() else {
                continue;
            };
            if seen.insert(device.clone()) {
                ports.push(PortInfo { path, device });
            }
        }
    }
    Ok(ports)
}

/// Linux hotplug hint. Call `list_ports` after a change; no port is opened.
pub struct PortWatcher {
    fd: File,
}

impl PortWatcher {
    pub fn new() -> io::Result<Self> {
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) };
        let watcher = Self { fd };
        for path in ["/dev", "/dev/serial/by-id"] {
            let path = std::ffi::CString::new(path).expect("literal path");
            unsafe {
                libc::inotify_add_watch(
                    watcher.fd.as_raw_fd(),
                    path.as_ptr(),
                    libc::IN_CREATE | libc::IN_DELETE | libc::IN_MOVED_TO | libc::IN_MOVED_FROM,
                )
            };
        }
        Ok(watcher)
    }

    pub fn changed(&self) -> io::Result<bool> {
        let mut events = [0u8; 4096];
        let read = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                events.as_mut_ptr().cast(),
                events.len(),
            )
        };
        if read > 0 {
            return Ok(true);
        }
        if read == 0 {
            return Ok(false);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            Ok(false)
        } else {
            Err(error)
        }
    }

    /// Block the current thread until hotplug activity or `timeout`.
    ///
    /// Do not call this from a Tokio task; register the file descriptor with
    /// the runtime or run this method in `spawn_blocking`.
    pub fn wait_blocking(&self, timeout: Duration) -> io::Result<bool> {
        wait_fd(&self.fd, libc::POLLIN, timeout)?;
        self.changed()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UartRecord {
    /// One complete opaque QUIC-lite datagram, without the physical marker.
    Datagram(Vec<u8>),
    /// Boot/crash text observed outside normal service framing.
    Log(String),
}

fn framed_record(payload: &[u8]) -> Option<UartRecord> {
    if let Ok(packet) = decode_packet(payload) {
        Some(UartRecord::Datagram(packet.to_vec()))
    } else if payload.first().is_some_and(|byte| byte >> 5 == 5) {
        Some(UartRecord::Log(render_sideband_record(payload)))
    } else {
        None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModemLines {
    pub dtr: bool,
    pub rts: bool,
    pub cts: bool,
}

/// Explicit owner of one UART. Closing it releases the advisory lock.
pub struct UartPort {
    file: File,
    path: PathBuf,
    decoder: Decoder,
    sideband: SidebandText,
}

impl UartPort {
    pub fn open(path: impl AsRef<Path>, baud: Option<u32>) -> io::Result<Self> {
        let path = path.as_ref();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::TIOCEXCL) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // A tty may retain its previous line coding after the last process
        // closes it. In particular, B0 left by a flasher silently disables a
        // subsequent default-baud session unless we restore the protocol's
        // physical UART default here. Native USB-JTAG ignores this setting.
        configure(&file, Some(baud.unwrap_or(DEFAULT_BAUD)))?;
        let mut port = Self {
            file,
            path: path.to_path_buf(),
            decoder: Decoder::with_max(DEFAULT_RECORD_MAX),
            sideband: SidebandText::new(),
        };
        // Temporary opt-in laboratory handshake; never changes boot/NVS baud.
        if let Some(value) = std::env::var_os("UART_CODEC_NEGOTIATE_BAUD") {
            let rate = value.to_str().and_then(|v| v.parse().ok())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid negotiation baud"))?;
            port.negotiate_baud_blocking(rate)?;
        }
        Ok(port)
    }

    fn negotiate_baud_blocking(&mut self, baud: u32) -> io::Result<()> {
        let request = crate::BaudHandshake { acknowledged: false, baud }.record()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "unsupported negotiation baud"))?;
        let wire = crate::codec::encode_payload(&request, request.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "baud framing"))?;
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut offset = 0;
        while offset < wire.len() {
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "baud request write timeout"));
            }
            match self.file.write(&wire[offset..]) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "UART closed")),
                Ok(n) => offset += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    wait_fd(&self.file, libc::POLLOUT, Duration::from_millis(20))?;
                }
                Err(e) => return Err(e),
            }
        }
        let expected = crate::BaudHandshake { acknowledged: true, baud };
        let mut bytes = [0u8; 1024];
        while std::time::Instant::now() < deadline {
            wait_fd(&self.file, libc::POLLIN, Duration::from_millis(20))?;
            match self.file.read(&mut bytes) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "UART closed")),
                Ok(n) => {
                    let records = self.decoder.push(&bytes[..n])
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "baud ACK framing"))?;
                    if records.iter().any(|r| crate::BaudHandshake::decode(r) == Some(expected)) {
                        configure(&self.file, Some(baud))?;
                        self.decoder = Decoder::with_max(DEFAULT_RECORD_MAX);
                        self.sideband.reset();
                        return Ok(());
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(io::ErrorKind::TimedOut, "baud ACK timeout; peer may have switched, reset before retry"))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Convert the owned port into the Tokio bearer.
    ///
    /// If `UART_CODEC_LOG` names a file, complete console lines observed
    /// outside marker-qualified QUIC frames are appended there. The diagnostic
    /// file is independent from quic-lite's `QUIC_LITE_PCAP` packet capture.
    pub fn into_tokio<const SLOTS: usize, const MTU: usize>(
        self,
        name: BearerName,
    ) -> io::Result<TokioUartBearer<SLOTS, MTU>> {
        TokioUartBearer::new(self.file, name)
    }

    pub fn set_baud(&self, baud: u32) -> io::Result<()> {
        configure(&self.file, Some(baud))
    }

    /// Send the tiny out-of-band wake record understood by sleepy Main. This
    /// does not create a QUIC-lite packet or bypass the shared PPP framing.
    /// Repeat for one second: UART light-sleep wake can lose trigger bytes,
    /// and each fresh framed record lets the decoder resynchronize. This is
    /// not an acknowledgement that the peer woke. Call from a blocking thread.
    pub fn send_wake_blocking(&mut self) -> io::Result<()> {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let repeat_until = std::time::Instant::now() + Duration::from_secs(1);
        loop {
            let mut encoder = crate::encode_wake()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
            let mut bytes = [0u8; 8];
            while !encoder.is_finished() {
                let used = encoder.write(&mut bytes);
                let mut written = 0;
                while written < used {
                    match self.file.write(&bytes[written..used]) {
                        Ok(0) => {
                            return Err(io::Error::new(io::ErrorKind::WriteZero, "UART closed"));
                        }
                        Ok(count) => written += count,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            if std::time::Instant::now() >= deadline {
                                return Err(io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    "UART wake write timed out",
                                ));
                            }
                            wait_fd(&self.file, libc::POLLOUT, Duration::from_millis(100))?;
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
            if std::time::Instant::now() >= repeat_until {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }

    pub fn lines(&self) -> io::Result<ModemLines> {
        let mut bits: libc::c_int = 0;
        if unsafe { libc::ioctl(self.file.as_raw_fd(), libc::TIOCMGET, &mut bits) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ModemLines {
            dtr: bits & libc::TIOCM_DTR != 0,
            rts: bits & libc::TIOCM_RTS != 0,
            cts: bits & libc::TIOCM_CTS != 0,
        })
    }

    /// Set modem lines only on an explicitly owned port.
    pub fn set_lines(&self, dtr: Option<bool>, rts: Option<bool>) -> io::Result<()> {
        for (line, state) in [(libc::TIOCM_DTR, dtr), (libc::TIOCM_RTS, rts)] {
            if let Some(state) = state {
                let mut line = line;
                let command = if state {
                    libc::TIOCMBIS
                } else {
                    libc::TIOCMBIC
                };
                if unsafe { libc::ioctl(self.file.as_raw_fd(), command, &mut line) } < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        Ok(())
    }

    /// Pulse the physical reset line, sleeping the current thread for 120 ms.
    /// Do not call this from a Tokio task; use `spawn_blocking` when required.
    pub fn reset_blocking(&self) -> io::Result<()> {
        self.set_lines(Some(false), Some(false))?;
        self.set_lines(None, Some(true))?;
        std::thread::sleep(Duration::from_millis(120));
        self.set_lines(None, Some(false))
    }

    /// Discard bytes which predate a newly established logical session and
    /// reset all partial PPP and diagnostic-line state at the boundary.
    ///
    /// This never changes modem lines. It is intended for USB serial devices
    /// which may deliver delayed boot output after a previous owner closes.
    /// This method waits with `poll(2)` and blocks the current thread. Do not
    /// call it from a Tokio task; use `spawn_blocking` when required.
    pub fn discard_input_blocking(&mut self, settle: Duration) -> io::Result<()> {
        let deadline = std::time::Instant::now() + settle;
        let mut bytes = [0u8; 1024];
        while std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            wait_fd(
                &self.file,
                libc::POLLIN,
                remaining.min(Duration::from_millis(20)),
            )?;
            loop {
                match self.file.read(&mut bytes) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
        }
        self.decoder = Decoder::with_max(DEFAULT_RECORD_MAX);
        self.sideband.reset();
        Ok(())
    }

    /// Encode and write one complete datagram, blocking for writability for up
    /// to two seconds. Do not call this from a Tokio task. A Tokio integration
    /// must use a nonblocking `PacketEgress` which retains the pool lease
    /// until quic-lite's ownership-bearing completion callback returns it.
    #[deprecated(note = "blocking copying path; register TokioUartBearer with QuicNode")]
    pub fn send_datagram_blocking(&mut self, packet: &[u8]) -> io::Result<()> {
        self.write_record(packet)
    }

    fn write_record(&mut self, packet: &[u8]) -> io::Result<()> {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut encoder = Encoder::new_prefixed(PACKET_MARKER, packet, DEFAULT_RECORD_MAX)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let mut bytes = [0u8; 256];
        while !encoder.is_finished() {
            let used = encoder.write(&mut bytes);
            let mut written = 0;
            while written < used {
                match self.file.write(&bytes[written..used]) {
                    Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "UART closed")),
                    Ok(count) => written += count,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() >= deadline {
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "UART write timed out",
                            ));
                        }
                        wait_fd(&self.file, libc::POLLOUT, Duration::from_millis(100))?;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    /// Read one batch of complete packets and text lines without storing a private queue.
    /// Block the current thread for at most `timeout` and return one read turn.
    /// Do not call this from a Tokio task; use `spawn_blocking` or an async UART
    /// receive adapter.
    #[deprecated(note = "blocking copying path; register TokioUartBearer with QuicNode")]
    pub fn receive_blocking(&mut self, timeout: Duration) -> io::Result<Vec<UartRecord>> {
        wait_fd(&self.file, libc::POLLIN, timeout)?;
        let mut bytes = [0u8; 1024];
        let used = match self.file.read(&mut bytes) {
            Ok(used) => used,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => 0,
            Err(error) => return Err(error),
        };
        let mut records = Vec::new();
        self.sideband
            .push(&bytes[..used], |line| records.push(UartRecord::Log(line)));
        for payload in self
            .decoder
            .push(&bytes[..used])
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?
        {
            // The marker is now the UART bearer contract. Treating an
            // unmarked record as QUIC confuses ordinary ESP-IDF text between
            // two flags with a legacy packet.
            if let Some(record) = framed_record(&payload) {
                records.push(record);
            }
        }
        Ok(records)
    }
}

struct PendingSend<const SLOTS: usize, const MTU: usize> {
    submission: EgressSubmission<PoolBufferLease<'static, SLOTS, MTU>>,
    cursor: crate::codec::EncoderCursor,
}

enum WriteProgress {
    WouldBlock,
    Partial,
    Complete,
}

struct TokioUartTxState<const SLOTS: usize, const MTU: usize> {
    active: Option<PendingSend<SLOTS, MTU>>,
}

struct TokioUartTx<const SLOTS: usize, const MTU: usize> {
    state: Mutex<TokioUartTxState<SLOTS, MTU>>,
    fd: File,
    accepted: tokio::sync::Notify,
}

/// Nonblocking submission handle for the Tokio UART writer task.
///
/// Submission only transfers one packet lease to an idle writer. It performs
/// no system call and never waits for UART writability. While that lease is
/// active, later submissions are returned unchanged as `WouldBlock`.
struct TokioUartEgress<const SLOTS: usize, const MTU: usize> {
    tx: Arc<TokioUartTx<SLOTS, MTU>>,
}

impl<const SLOTS: usize, const MTU: usize> Clone for TokioUartEgress<SLOTS, MTU> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

/// Tokio UART I/O owner backed directly by the shared quic-lite packet pool.
/// It retains exactly one active egress submission and no packet FIFO.
///
/// This implementation currently owns one port. It may evolve into one
/// multi-peer UART bearer whose dynamic link table maps several open ports to
/// distinct `PeerL2Address` values, matching UDP, ESP-NOW, BLE, and Android
/// USB bearer semantics without changing QUIC associations.
pub struct TokioUartBearer<const SLOTS: usize, const MTU: usize> {
    info: BearerInfo,
    reader: Option<tokio::io::unix::AsyncFd<File>>,
    writer: Option<TokioUartWriter<SLOTS, MTU>>,
    tx: Arc<TokioUartTx<SLOTS, MTU>>,
    sideband: Option<Arc<dyn Fn(TokioUartReceive) + Send + Sync>>,
    log_file: Option<Arc<Mutex<File>>>,
    /// Dropped with the bearer (when the node removes it), which ends the
    /// reader and writer tasks so the port is released.
    closed: tokio::sync::watch::Sender<()>,
}

/// Read half of a Tokio UART bearer. It owns incremental framing state and can
/// run independently from the writer task.
struct TokioUartReader<const SLOTS: usize, const MTU: usize> {
    fd: tokio::io::unix::AsyncFd<File>,
    rx_decoder: PooledDecoder<PacketPool<SLOTS, MTU>>,
    sideband: SidebandText,
    log_file: Option<Arc<Mutex<File>>>,
}

/// Write half of a Tokio UART bearer. It waits for an accepted submission and
/// UART writability without preventing the read half from making progress.
struct TokioUartWriter<const SLOTS: usize, const MTU: usize> {
    fd: tokio::io::unix::AsyncFd<File>,
    tx: Arc<TokioUartTx<SLOTS, MTU>>,
}

#[derive(Debug, Default)]
pub struct TokioUartReceive {
    pub logs: Vec<String>,
    /// Raw unmarked PPP sideband retained for callers that need crash bytes
    /// which are not valid UTF-8 lines. These are never QUIC packets.
    pub log_records: Vec<Vec<u8>>,
    pub pool_drops: usize,
}

impl<const SLOTS: usize, const MTU: usize> TokioUartBearer<SLOTS, MTU> {
    fn new(file: File, name: BearerName) -> io::Result<Self> {
        let write_file = file.try_clone()?;
        let continuation_file = write_file.try_clone()?;
        let tx = Arc::new(TokioUartTx {
            state: Mutex::new(TokioUartTxState { active: None }),
            fd: write_file,
            accepted: tokio::sync::Notify::new(),
        });
        let log_file = std::env::var_os(UART_LOG_ENV)
            .map(|path| OpenOptions::new().create(true).append(true).open(path))
            .transpose()?
            .map(|file| Arc::new(Mutex::new(file)));
        Ok(Self {
            info: BearerInfo {
                name,
                max_packet_size: quic_lite::DEFAULT_MAX_PACKET_SIZE,
                // PPP encoding is streamed into the device; it does not use
                // packet-pool headroom or tailroom for its variable expansion.
                prefix_required: 0,
                suffix_required: 0,
                requires_packet_encryption: false,
                secure_link: true,
                nominal_bitrate_bps: 0,
                local_mac: None,
            },
            reader: Some(tokio::io::unix::AsyncFd::new(file)?),
            writer: Some(TokioUartWriter {
                fd: tokio::io::unix::AsyncFd::new(continuation_file)?,
                tx: tx.clone(),
            }),
            tx,
            sideband: None,
            log_file,
            closed: tokio::sync::watch::channel(()).0,
        })
    }

    /// Receive boot/crash text and unmarked PPP records outside QUIC.
    /// The callback runs in the UART reader task and must return promptly.
    pub fn set_sideband_handler(
        &mut self,
        handler: impl Fn(TokioUartReceive) + Send + Sync + 'static,
    ) {
        self.sideband = Some(Arc::new(handler));
    }
}

impl<const SLOTS: usize, const MTU: usize> TokioUartWriter<SLOTS, MTU> {
    fn has_pending_send(&self) -> bool {
        self.tx.state.lock().unwrap().active.is_some()
    }

    fn try_write_pending(
        fd: &File,
        pending: &mut PendingSend<SLOTS, MTU>,
    ) -> io::Result<WriteProgress> {
        let payload = pending.submission.packet().bytes();
        let before = pending.cursor;
        let mut advanced = before;
        let mut wire = [0u8; 256];
        let encoded = advanced.write(payload, &mut wire);
        if encoded == 0 {
            return Ok(WriteProgress::Complete);
        }
        let mut fd = fd;
        match fd.write(&wire[..encoded]) {
            Ok(0) => Err(io::Error::new(io::ErrorKind::WriteZero, "UART closed")),
            Ok(written) => {
                pending.cursor = before;
                let _ = pending.cursor.write(payload, &mut wire[..written]);
                if pending.cursor.is_finished() {
                    Ok(WriteProgress::Complete)
                } else {
                    Ok(WriteProgress::Partial)
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                Ok(WriteProgress::WouldBlock)
            }
            Err(error) => Err(error),
        }
    }

    /// Wait for an accepted packet and one writable readiness event, then
    /// advance the active frame once.
    ///
    /// An idle writer sleeps until `submit` performs the ownership handoff; it
    /// never polls for work. An incomplete frame remains the single active
    /// submission for the next call. `true` means completion returned its lease
    /// to quic-lite.
    async fn write_ready(&self) -> io::Result<bool> {
        if !self.has_pending_send() {
            let accepted = self.tx.accepted.notified();
            tokio::pin!(accepted);
            accepted.as_mut().enable();
            if !self.has_pending_send() {
                accepted.await;
            }
        }
        let mut ready = self.fd.writable().await?;
        let progress = {
            let mut tx = self.tx.state.lock().unwrap();
            let pending = tx
                .active
                .as_mut()
                .expect("UART writer wakes only for an active submission");
            Self::try_write_pending(self.fd.get_ref(), pending)
        };
        match progress {
            Ok(WriteProgress::Complete) => {
                let pending = self
                    .tx
                    .state
                    .lock()
                    .unwrap()
                    .active
                    .take()
                    .expect("completed UART submission remains active");
                pending.submission.complete(PacketSendOutcome::Sent, 0);
                Ok(true)
            }
            Ok(WriteProgress::Partial) => Ok(false),
            Ok(WriteProgress::WouldBlock) => {
                ready.clear_ready();
                Ok(false)
            }
            Err(error) => {
                let pending = self
                    .tx
                    .state
                    .lock()
                    .unwrap()
                    .active
                    .take()
                    .expect("failed UART submission remains active");
                pending.submission.complete(PacketSendOutcome::Failed, 0);
                Err(error)
            }
        }
    }
}

impl<const SLOTS: usize, const MTU: usize> TokioUartReader<SLOTS, MTU> {
    /// Read one Tokio readiness turn and deliver complete marked frames from
    /// pool leases. Unmarked PPP frames and console lines remain sideband.
    async fn receive_into(
        &mut self,
        peer_l2_address: PeerL2Address,
        payload_offset: usize,
        received_at_us: u64,
        context: &BearerContext<PacketPool<SLOTS, MTU>>,
    ) -> io::Result<TokioUartReceive> {
        let mut ready = self.fd.readable().await?;
        let mut bytes = [0u8; 1024];
        let mut fd = self.fd.get_ref();
        let used = match fd.read(&mut bytes) {
            Ok(used) => used,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                ready.clear_ready();
                0
            }
            Err(error) => return Err(error),
        };
        drop(ready);
        let mut result = TokioUartReceive::default();
        self.scan_async_text(&bytes[..used], &mut result.logs);
        self.rx_decoder
            .push(&bytes[..used], payload_offset, |frame| match frame {
                PooledFrame::Packet(packet) => context.enqueue_packet(
                    PacketMeta {
                        bearer: context.bearer(),
                        peer_l2_address,
                        received_at_us,
                    },
                    packet,
                ),
                PooledFrame::Log(bytes) => result.log_records.push(bytes),
                PooledFrame::PoolUnavailable => result.pool_drops += 1,
                PooledFrame::Wake => {}
            });
        if let Some(log_file) = &self.log_file {
            let mut log_file = log_file
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for line in &result.logs {
                log_file.write_all(line.as_bytes())?;
                log_file.write_all(b"\n")?;
            }
            for record in &result.log_records {
                log_file.write_all(render_sideband_record(record).as_bytes())?;
                log_file.write_all(b"\n")?;
            }
            log_file.flush()?;
        }
        Ok(result)
    }

    fn scan_async_text(&mut self, bytes: &[u8], logs: &mut Vec<String>) {
        self.sideband.push(bytes, |line| logs.push(line));
    }
}

/// Host-only presentation of structured CBOR sideband. Numeric tags are
/// preserved; malformed records fall back to text or hex, never disappear.
pub fn render_sideband_record(bytes: &[u8]) -> String {
    fn value(d: &mut mesh_api::cbor::Decoder<'_>, out: &mut String, depth: usize) -> Option<()> {
        use std::fmt::Write;
        if depth > 8 {
            return None;
        }
        let start = d.position();
        let (major, count) = d.head()?;
        match major {
            0 => write!(out, "{count}").ok()?,
            1 => write!(out, "-{}", u128::from(count) + 1).ok()?,
            3 => {
                d.set_position(start);
                write!(out, "{:?}", core::str::from_utf8(d.text_ref()?).ok()?).ok()?;
            }
            4 | 5 if count <= 128 => {
                out.push(if major == 5 { '{' } else { '[' });
                for i in 0..count {
                    if i != 0 {
                        out.push(' ');
                    }
                    value(d, out, depth + 1)?;
                    if major == 5 {
                        out.push('=');
                        value(d, out, depth + 1)?;
                    }
                }
                out.push(if major == 5 { '}' } else { ']' });
            }
            7 if count == 20 => out.push_str("false"),
            7 if count == 21 => out.push_str("true"),
            7 if count == 22 => out.push_str("null"),
            _ => return None,
        }
        Some(())
    }
    let mut decoder = mesh_api::cbor::Decoder::new(bytes);
    let mut out = String::new();
    if bytes.first().is_some_and(|byte| byte >> 5 == 5)
        && value(&mut decoder, &mut out, 0).is_some()
        && decoder.is_finished()
    {
        return out;
    }
    if let Ok(text) = core::str::from_utf8(bytes) {
        return String::from(text);
    }
    use std::fmt::Write;
    out.clear();
    out.push_str("cbor_invalid hex=");
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

impl<const SLOTS: usize, const MTU: usize> PacketEgress<PoolBufferLease<'static, SLOTS, MTU>>
    for TokioUartEgress<SLOTS, MTU>
{
    fn submit(
        &mut self,
        _peer_l2_address: PeerL2Address,
        submission: EgressSubmission<PoolBufferLease<'static, SLOTS, MTU>>,
    ) -> Result<(), PacketSubmitError<PoolBufferLease<'static, SLOTS, MTU>>> {
        let mut tx = self.tx.state.lock().unwrap();
        if tx.active.is_some() {
            return Err(PacketSubmitError::WouldBlock(submission));
        }
        tx.active = Some(PendingSend {
            submission,
            cursor: crate::codec::EncoderCursor::prefixed(PACKET_MARKER),
        });
        let progress = TokioUartWriter::try_write_pending(
            &self.tx.fd,
            tx.active
                .as_mut()
                .expect("accepted UART submission is active"),
        );
        if matches!(progress, Ok(WriteProgress::Complete) | Err(_)) {
            let pending = tx
                .active
                .take()
                .expect("finished UART submission remains active");
            drop(tx);
            pending.submission.complete(
                if progress.is_ok() {
                    PacketSendOutcome::Sent
                } else {
                    PacketSendOutcome::Failed
                },
                0,
            );
            return Ok(());
        }
        drop(tx);
        // The first write is deliberately synchronous and nonblocking. Wake
        // the task only when the kernel accepted a partial frame or reported
        // EAGAIN, so the common one-write packet path needs no task handoff.
        self.tx.accepted.notify_waiters();
        Ok(())
    }
}

impl<const SLOTS: usize, const MTU: usize> PacketEgress<PoolBufferLease<'static, SLOTS, MTU>>
    for TokioUartBearer<SLOTS, MTU>
{
    fn submit(
        &mut self,
        peer_l2_address: PeerL2Address,
        submission: EgressSubmission<PoolBufferLease<'static, SLOTS, MTU>>,
    ) -> Result<(), PacketSubmitError<PoolBufferLease<'static, SLOTS, MTU>>> {
        TokioUartEgress {
            tx: self.tx.clone(),
        }
        .submit(peer_l2_address, submission)
    }
}

impl<const SLOTS: usize, const MTU: usize> PacketBearer<PacketPool<SLOTS, MTU>>
    for TokioUartBearer<SLOTS, MTU>
{
    type AttachError = io::Error;

    fn info(&self) -> BearerInfo {
        self.info
    }

    fn attach(
        &mut self,
        context: BearerContext<PacketPool<SLOTS, MTU>>,
    ) -> Result<(), Self::AttachError> {
        let reader_fd = self.reader.take().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "UART bearer is already attached",
            )
        })?;
        let writer = self.writer.take().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "UART bearer is already attached",
            )
        })?;
        let mut reader = TokioUartReader {
            fd: reader_fd,
            rx_decoder: PooledDecoder::new(context.pool()),
            sideband: SidebandText::new(),
            log_file: self.log_file.clone(),
        };
        let receive_context = context.clone();
        let sideband = self.sideband.clone();
        let mut reader_closed = self.closed.subscribe();
        let mut writer_closed = self.closed.subscribe();
        tokio::spawn(async move {
            let peer = PeerL2Address::new(1).expect("one is a valid UART peer address");
            loop {
                let received = tokio::select! {
                    // The sender is only ever dropped, never sent on.
                    _ = reader_closed.changed() => break,
                    received = reader.receive_into(
                        peer,
                        quic_lite::PACKET_PREFIX_RESERVE,
                        0,
                        &receive_context,
                    ) => received,
                };
                match received {
                    Ok(received) => {
                        if (!received.logs.is_empty()
                            || !received.log_records.is_empty()
                            || received.pool_drops != 0)
                            && let Some(handler) = sideband.as_ref()
                        {
                            handler(received);
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        let writer_context = context;
        tokio::spawn(async move {
            loop {
                let ready = tokio::select! {
                    _ = writer_closed.changed() => break,
                    ready = writer.write_ready() => ready,
                };
                match ready {
                    Ok(true) => writer_context.send_ready(),
                    Ok(false) => {}
                    Err(_) => break,
                }
            }
        });
        Ok(())
    }
}

fn wait_fd(file: &File, events: libc::c_short, timeout: Duration) -> io::Result<()> {
    let mut fd = libc::pollfd {
        fd: file.as_raw_fd(),
        events,
        revents: 0,
    };
    let ready = unsafe { libc::poll(&mut fd, 1, timeout.as_millis().min(i32::MAX as u128) as i32) };
    if ready < 0 {
        return Err(io::Error::last_os_error());
    }
    if ready == 0 {
        return Ok(());
    }
    if fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "UART disconnected",
        ));
    }
    Ok(())
}

fn configure(file: &File, baud: Option<u32>) -> io::Result<()> {
    let mut termios: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(file.as_raw_fd(), &mut termios) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let original = termios;
    unsafe { libc::cfmakeraw(&mut termios) };
    termios.c_cflag |= libc::CLOCAL;
    termios.c_cflag &= !libc::HUPCL;
    if let Some(baud) = baud {
        let speed = match baud {
            9_600 => libc::B9600,
            19_200 => libc::B19200,
            38_400 => libc::B38400,
            57_600 => libc::B57600,
            115_200 => libc::B115200,
            230_400 => libc::B230400,
            460_800 => libc::B460800,
            921_600 => libc::B921600,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported UART baud",
                ));
            }
        };
        if unsafe { libc::cfsetispeed(&mut termios, speed) } != 0
            || unsafe { libc::cfsetospeed(&mut termios, speed) } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    if unsafe {
        libc::memcmp(
            (&original as *const libc::termios).cast(),
            (&termios as *const libc::termios).cast(),
            std::mem::size_of::<libc::termios>(),
        )
    } != 0
        && unsafe { libc::tcsetattr(file.as_raw_fd(), libc::TCSANOW, &termios) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn passive_frames_separate_structured_logs_from_quic() {
        let log = [0xa1, 1, 3];
        assert_eq!(
            super::framed_record(&log),
            Some(super::UartRecord::Log("{1=3}".into()))
        );
        assert_eq!(
            super::framed_record(&[crate::PACKET_MARKER, 0x40, 1]),
            Some(super::UartRecord::Datagram(vec![0x40, 1]))
        );
        assert_eq!(super::framed_record(b"boot text"), None);
        assert!(
            matches!(super::framed_record(&[0xa1, 1]), Some(super::UartRecord::Log(s)) if s.starts_with("cbor_invalid"))
        );
    }
    #[test]
    fn structured_sideband_preserves_numeric_tags_and_values() {
        assert_eq!(
            super::render_sideband_record(&[
                0xa2, 1, 0x67, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 2, 3
            ]),
            "{1=\"example\" 2=3}"
        );
        assert_eq!(
            super::render_sideband_record(&[0xa1, 7, 0xa2, 1, 0xf5, 2, 0xf6]),
            "{7={1=true 2=null}}"
        );
    }

    #[test]
    fn cbor_sideband_is_not_misidentified_as_console_text() {
        let payload = [0xa1, 1, 0x65, b'h', b'i', b'\n', b'h', b'i'];
        let wire = crate::codec::encode_payload(&payload, 128).unwrap();
        let mut decoder = super::SidebandText::new();
        let mut lines = Vec::new();
        for chunk in wire.chunks(3) {
            decoder.push(chunk, |line| lines.push(line));
        }
        decoder.push(b"boot text\n", |line| lines.push(line));
        assert_eq!(lines, vec!["boot text"]);
    }

    #[test]
    fn malformed_cbor_sideband_is_visible() {
        assert!(super::render_sideband_record(&[0xa1, 1]).starts_with("cbor_invalid hex="));
    }
    #[test]
    fn long_console_line_survives_fragmented_reads() {
        let expected = format!(
            "event=quic.progress {} quic_submission_failures=17",
            "counter=1234567890 ".repeat(90)
        );
        let wire = format!("{expected}\r\n");
        let mut decoder = super::SidebandText::new();
        let mut lines = Vec::new();
        for chunk in wire.as_bytes().chunks(37) {
            decoder.push(chunk, |line| lines.push(line));
        }
        assert_eq!(lines, vec![expected]);
    }

    #[test]
    fn oversized_console_line_keeps_prefix_and_reports_truncation_once() {
        let wire = format!(
            "{}\nnext complete line\n",
            "x".repeat(super::MAX_LOG_LINE + 1024)
        );
        let mut decoder = super::SidebandText::new();
        let mut lines = Vec::new();
        for chunk in wire.as_bytes().chunks(73) {
            decoder.push(chunk, |line| lines.push(line));
        }
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            format!(
                "{} [uart_log_truncated limit=4096]",
                "x".repeat(super::MAX_LOG_LINE)
            )
        );
        assert_eq!(lines[1], "next complete line");
    }

    #[test]
    fn marked_packet_after_oversized_text_does_not_leak_into_console() {
        let mut decoder = super::SidebandText::new();
        let mut lines = Vec::new();
        decoder.push(&vec![b'x'; super::MAX_LOG_LINE + 1], |line| {
            lines.push(line)
        });
        decoder.push(
            &[
                super::UART_FLAG,
                super::PACKET_MARKER,
                b'h',
                b'i',
                b'\n',
                super::UART_FLAG,
            ],
            |line| lines.push(line),
        );
        decoder.push(b"real console\n", |line| lines.push(line));
        assert_eq!(lines, vec!["real console"]);
    }
    use super::*;
    use std::format;
    use std::os::fd::FromRawFd;
    use std::vec;

    static NODE_POOL: PacketPool<4, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }> =
        PacketPool::new();

    #[test]
    fn baud_negotiation_waits_for_matching_ack_then_changes_termios() {
        let mut master = 0;
        let mut slave = 0;
        assert_eq!(unsafe { libc::openpty(&mut master, &mut slave,
            std::ptr::null_mut(), std::ptr::null(), std::ptr::null()) }, 0);
        let mut master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        let path = fs::read_link(format!("/proc/self/fd/{}", slave.as_raw_fd())).unwrap();
        let mut port = UartPort::open(path, None).unwrap();
        let peer = std::thread::spawn(move || {
            let mut decoder = Decoder::with_max(64);
            let mut bytes = [0u8; 64];
            loop {
                let n = master.read(&mut bytes).unwrap();
                for record in decoder.push(&bytes[..n]).unwrap() {
                    let mut request = crate::BaudHandshake::decode(&record).unwrap();
                    assert_eq!(request.baud, 921600);
                    assert!(!request.acknowledged);
                    let mut termios: libc::termios = unsafe { std::mem::zeroed() };
                    assert_eq!(unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut termios) }, 0);
                    assert_eq!(unsafe { libc::cfgetispeed(&termios) }, libc::B115200);
                    request.acknowledged = true;
                    let record = request.record().unwrap();
                    master.write_all(&crate::codec::encode_payload(&record, 6).unwrap()).unwrap();
                    return (master, slave);
                }
            }
        });
        port.negotiate_baud_blocking(921600).unwrap();
        let (_master, _slave) = peer.join().unwrap();
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(port.file.as_raw_fd(), &mut termios) }, 0);
        assert_eq!(unsafe { libc::cfgetispeed(&termios) }, libc::B921600);
    }

    #[test]
    fn wake_train_resynchronizes_after_lost_trigger_bytes() {
        let mut master = 0;
        let mut slave = 0;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let mut master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        let path = fs::read_link(format!("/proc/self/fd/{}", slave.as_raw_fd())).unwrap();
        let mut port = UartPort::open(path, None).unwrap();
        port.send_wake_blocking().unwrap();
        let mut wire = [0u8; 512];
        let len = master.read(&mut wire).unwrap();
        assert!(len >= 6, "wake sender must retry complete records");
        let mut decoder = Decoder::with_max(8);
        let records = decoder.push(&wire[2..len]).unwrap();
        assert!(records.iter().any(|record| record == &[crate::WAKE_MARKER]));
        assert!(records.iter().all(|record| record == &[crate::WAKE_MARKER]));
    }

    #[test]
    fn open_without_baud_restores_protocol_default_from_b0() {
        let mut master = 0;
        let mut slave = 0;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let _master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut termios) },
            0
        );
        assert_eq!(unsafe { libc::cfsetispeed(&mut termios, libc::B0) }, 0);
        assert_eq!(unsafe { libc::cfsetospeed(&mut termios, libc::B0) }, 0);
        assert_eq!(
            unsafe { libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &termios) },
            0
        );

        let path = fs::read_link(format!("/proc/self/fd/{}", slave.as_raw_fd())).unwrap();
        let port = UartPort::open(&path, None).unwrap();
        let mut actual: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(port.file.as_raw_fd(), &mut actual) },
            0
        );
        assert_eq!(unsafe { libc::cfgetispeed(&actual) }, libc::B115200);
        assert_eq!(unsafe { libc::cfgetospeed(&actual) }, libc::B115200);
    }

    #[test]
    fn enumeration_deduplicates_stable_names_without_opening() {
        let root = std::env::temp_dir().join(format!("uart-codec-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("serial/by-id")).unwrap();
        fs::write(root.join("ttyACM0"), []).unwrap();
        std::os::unix::fs::symlink("../../ttyACM0", root.join("serial/by-id/device")).unwrap();
        let ports = list_ports_under(&root).unwrap();
        assert_eq!(ports.len(), 1);
        assert!(ports[0].path.ends_with("serial/by-id/device"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pty_delivers_only_marked_frames_and_keeps_console_lines_outside_them() {
        let mut master = 0;
        let mut slave = 0;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let mut master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        let path = fs::read_link(format!("/proc/self/fd/{}", slave.as_raw_fd())).unwrap();
        let mut port = UartPort::open(&path, None).unwrap();
        drop(slave);
        let encoded = crate::codec::encode_payload(&[PACKET_MARKER, 1, 2], 128).unwrap();
        master.write_all(&encoded).unwrap();
        let records = port.receive_blocking(Duration::from_millis(100)).unwrap();
        assert!(records.contains(&UartRecord::Datagram(vec![1, 2])));
        let encoded = crate::codec::encode_payload(&[3, 4], 128).unwrap();
        master.write_all(&encoded).unwrap();
        let records = port.receive_blocking(Duration::from_millis(100)).unwrap();
        assert!(records.is_empty(), "unmarked PPP is not a QUIC datagram");
        master.write_all(b"boot line\n").unwrap();
        let records = port.receive_blocking(Duration::from_millis(100)).unwrap();
        assert!(records.contains(&UartRecord::Log(String::from("boot line"))));

        let encoded =
            crate::codec::encode_payload(&[PACKET_MARKER, b'f', b'a', b'k', b'e', b'\n', 1], 128)
                .unwrap();
        master.write_all(&encoded).unwrap();
        let records = port.receive_blocking(Duration::from_millis(100)).unwrap();
        assert_eq!(
            records,
            vec![UartRecord::Datagram(vec![b'f', b'a', b'k', b'e', b'\n', 1])]
        );
    }

    #[test]
    fn pty_blocking_egress_adds_uart_framing() {
        let mut master = 0;
        let mut slave = 0;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let mut master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        let path = fs::read_link(format!("/proc/self/fd/{}", slave.as_raw_fd())).unwrap();
        let mut port = UartPort::open(&path, None).unwrap();
        drop(slave);

        port.send_datagram_blocking(&[0x40, 1, 2]).unwrap();
        let mut wire = [0u8; 32];
        let used = master.read(&mut wire).unwrap();
        let mut decoder = Decoder::with_max(32);
        let records = decoder.push(&wire[..used]).unwrap();
        assert_eq!(decode_packet(&records[0]), Ok(&[0x40, 1, 2][..]));
    }

    #[tokio::test]
    async fn tokio_uart_is_registered_and_driven_only_by_quic_node() {
        let mut master = 0;
        let mut slave = 0;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let mut master = unsafe { File::from_raw_fd(master) };
        let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
        let slave = unsafe { File::from_raw_fd(slave) };
        let path = fs::read_link(format!("/proc/self/fd/{}", slave.as_raw_fd())).unwrap();
        let port = UartPort::open(&path, None).unwrap();
        drop(slave);
        let bearer = port
            .into_tokio::<4, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>(
                BearerName::new("uart0").unwrap(),
            )
            .unwrap();
        let mut node = quic_lite::QuicNode::<_>::new(&NODE_POOL);
        let bearer_id = node.add_bearer(bearer).unwrap();
        node.associate(
            PacketMeta {
                bearer: bearer_id,
                peer_l2_address: PeerL2Address::new(1).unwrap(),
                received_at_us: 0,
            },
            0,
        )
        .unwrap();

        let mut wire = [0u8; 2048];
        // The normal short-frame path writes during submit; it must not rely
        // on scheduling the continuation task before bytes reach the device.
        let immediate = master.read(&mut wire).unwrap();
        assert_ne!(immediate, 0);
        let used = immediate;
        let mut decoder = Decoder::with_max(quic_lite::DEFAULT_MAX_PACKET_SIZE + 1);
        let records = decoder.push(&wire[..used]).unwrap();
        assert_eq!(records.len(), 1);
        assert!(decode_packet(&records[0]).is_ok());
    }
}
