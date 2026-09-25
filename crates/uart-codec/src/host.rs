//! Linux UART bearer: discovery of device nodes does not claim a port.

use crate::codec::{DEFAULT_RECORD_MAX, Decoder, Encoder, UART_FLAG};
#[cfg(test)]
use std::format;
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
    string::{String, ToString},
    time::Duration,
    vec::Vec,
};

/// Marker for a complete QUIC-lite datagram inside one PPP information field.
pub const TRANSPORT_MARKER: u8 = 0xf7;
const MAX_LOG_LINE: usize = 512;

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

    pub fn wait(&self, timeout: Duration) -> io::Result<bool> {
        wait_fd(&self.fd, libc::POLLIN, timeout)?;
        self.changed()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UartRecord {
    /// One complete QUIC-lite datagram, without the physical marker.
    Frame(Vec<u8>),
    /// One unmarked connectionless QUIC-lite long packet.
    Message(Vec<u8>),
    /// Boot/crash text observed outside normal service framing.
    Log(String),
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
    text: Vec<u8>,
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
        configure(&file, baud)?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            decoder: Decoder::with_max(DEFAULT_RECORD_MAX),
            text: Vec::new(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn set_baud(&self, baud: u32) -> io::Result<()> {
        configure(&self.file, Some(baud))
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

    pub fn reset(&self) -> io::Result<()> {
        self.set_lines(Some(false), Some(false))?;
        self.set_lines(None, Some(true))?;
        std::thread::sleep(Duration::from_millis(120));
        self.set_lines(None, Some(false))
    }

    pub fn send_frame(&mut self, packet: &[u8]) -> io::Result<()> {
        self.write_record(Some(TRANSPORT_MARKER), packet)
    }

    pub fn send_message(&mut self, packet: &[u8]) -> io::Result<()> {
        self.write_record(None, packet)
    }

    fn write_record(&mut self, prefix: Option<u8>, packet: &[u8]) -> io::Result<()> {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut encoder = match prefix {
            Some(prefix) => Encoder::new_prefixed(prefix, packet, DEFAULT_RECORD_MAX),
            None => Encoder::new(packet, DEFAULT_RECORD_MAX),
        }
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
    pub fn receive(&mut self, timeout: Duration) -> io::Result<Vec<UartRecord>> {
        wait_fd(&self.file, libc::POLLIN, timeout)?;
        let mut bytes = [0u8; 1024];
        let used = match self.file.read(&mut bytes) {
            Ok(used) => used,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => 0,
            Err(error) => return Err(error),
        };
        let mut records = self.scan_text(&bytes[..used]);
        for payload in self
            .decoder
            .push(&bytes[..used])
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?
        {
            if payload.first() == Some(&TRANSPORT_MARKER) {
                if payload.len() > 1 {
                    records.push(UartRecord::Frame(payload[1..].to_vec()));
                }
            } else {
                records.push(UartRecord::Message(payload));
            }
        }
        Ok(records)
    }

    fn scan_text(&mut self, bytes: &[u8]) -> Vec<UartRecord> {
        let mut logs = Vec::new();
        for &byte in bytes {
            match byte {
                UART_FLAG => self.text.clear(),
                b'\r' => {}
                b'\n' if !self.text.is_empty() => {
                    if let Ok(text) = String::from_utf8(std::mem::take(&mut self.text)) {
                        logs.push(UartRecord::Log(text));
                    }
                }
                b'\n' => {}
                byte if byte.is_ascii_graphic() || byte == b' ' || byte == b'\t' => {
                    if self.text.len() < MAX_LOG_LINE {
                        self.text.push(byte);
                    } else {
                        self.text.clear();
                    }
                }
                _ => self.text.clear(),
            }
        }
        logs
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
    use super::*;
    use std::os::fd::FromRawFd;
    use std::vec;

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
    fn pty_distinguishes_frames_messages_and_console_lines() {
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
        let encoded = crate::codec::encode_payload(&[TRANSPORT_MARKER, 1, 2], 128).unwrap();
        master.write_all(&encoded).unwrap();
        let records = port.receive(Duration::from_millis(100)).unwrap();
        assert!(records.contains(&UartRecord::Frame(vec![1, 2])));
        let encoded = crate::codec::encode_payload(&[3, 4], 128).unwrap();
        master.write_all(&encoded).unwrap();
        let records = port.receive(Duration::from_millis(100)).unwrap();
        assert!(records.contains(&UartRecord::Message(vec![3, 4])));
        master.write_all(b"boot line\n").unwrap();
        let records = port.receive(Duration::from_millis(100)).unwrap();
        assert!(records.contains(&UartRecord::Log(String::from("boot line"))));
    }
}
