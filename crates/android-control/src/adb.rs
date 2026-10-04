//! Device connection layer built on `adb_client` (the `adb connect` path).
//!
//! `adb_client::tcp::ADBTcpDevice` already implements raw TCP → `A_CNXN` →
//! `A_STLS` → TLS (client cert from the key file) → `A_AUTH` → shell/sync.
//! We wrap it so the rest of the crate (and the later mesh transport seam)
//! talks to one type and the key location is controlled by us.

use std::io::{Cursor, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use adb_client::tcp::ADBTcpDevice;
use adb_client::{ADBDeviceExt, ADBListItemType, RebootType};
use anyhow::{Context, Result};

/// A connected ADB device (over TCP, post-`adb connect`).
pub struct AdbDevice {
    inner: ADBTcpDevice,
}

impl AdbDevice {
    /// Connect to `addr` using the adbkey at `key_path` (PKCS#8 PEM).
    /// Performs the full CNXN/STLS/TLS/AUTH handshake.
    pub fn connect<A: Into<SocketAddr>>(addr: A, key_path: &Path) -> Result<Self> {
        crate::pairing::ensure_provider();
        let inner = ADBTcpDevice::new_with_custom_private_key(addr, key_path)
            .context("adb connect (TCP + TLS + auth)")?;
        Ok(Self { inner })
    }

    /// Run a shell command and return combined stdout+stderr as a string.
    pub fn shell<S: AsRef<str>>(&mut self, command: S) -> Result<String> {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let _exit = self
            .inner
            .shell_command(&command, Some(&mut stdout), Some(&mut stderr))
            .context("shell_command")?;
        let mut out = String::from_utf8_lossy(&stdout).into_owned();
        let err = String::from_utf8_lossy(&stderr).into_owned();
        if !err.is_empty() {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&err);
        }
        Ok(out)
    }

    /// Run a command with explicit stdin, capturing stdout.
    pub fn exec<S: AsRef<str>>(
        &mut self,
        command: S,
        stdin: &[u8],
    ) -> Result<String> {
        let shared: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let mut reader = Cursor::new(stdin);
        let writer = SharedWriter(Arc::clone(&shared));
        self.inner.exec(command.as_ref(), &mut reader, Box::new(writer))
            .context("exec")?;
        Ok(String::from_utf8_lossy(&shared.lock().unwrap()).into_owned())
    }

    /// `adb push` a byte payload to `remote_path`.
    pub fn push<S: AsRef<str>>(&mut self, data: &[u8], remote_path: S) -> Result<()> {
        let mut stream = Cursor::new(data);
        self.inner
            .push(&mut stream, &remote_path)
            .context("push")
    }

    /// `adb pull` `remote_path` into a buffer.
    pub fn pull<S: AsRef<str>>(&mut self, remote_path: S) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.inner.pull(&remote_path, &mut out).context("pull")?;
        Ok(out)
    }

    /// List a remote directory.
    pub fn list<S: AsRef<str>>(&mut self, path: S) -> Result<Vec<ADBListItemType>> {
        self.inner.list(&path).context("list")
    }

    /// Reboot the device into the given mode.
    pub fn reboot(&mut self, target: RebootType) -> Result<()> {
        self.inner.reboot(target).context("reboot")
    }

    /// Install an APK from a local path.
    pub fn install<P: AsRef<Path>>(
        &mut self,
        apk_path: P,
        user: Option<&str>,
    ) -> Result<()> {
        self.inner.install(&apk_path, user).context("install")
    }

    /// Uninstall a package.
    pub fn uninstall<S: AsRef<str>>(
        &mut self,
        package: S,
        user: Option<&str>,
    ) -> Result<()> {
        self.inner.uninstall(&package, user).context("uninstall")
    }
}

struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_writer_accumulates() {
        use std::io::Write;
        let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let mut w = SharedWriter(buf.clone());
        w.write_all(b"hello ").unwrap();
        w.write_all(b"world").unwrap();
        assert_eq!(&*buf.lock().unwrap(), b"hello world");
    }

    #[test]
    fn connect_signature_typechecks() {
        // Compile-time check that the addr generic is satisfied.
        fn assert_connect<A: Into<SocketAddr>>(_: A, _: &Path) {}
        let addr: SocketAddr = "127.0.0.1:5555".parse().unwrap();
        assert_connect(addr, Path::new("/dev/null"));
    }
}
