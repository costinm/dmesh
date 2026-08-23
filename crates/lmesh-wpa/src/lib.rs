//! Direct wpa_supplicant UDS control.
//!
//! Managed authenticated-STA control is deliberately separate from the
//! nl80211/raw-NAN bearer. This library is not used by raw-NAN or
//! open AP or STA mode - will be used to configure regular WPA STA.

use anyhow::{Context, Result, bail};
use std::fs;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct WpaClient {
    control: PathBuf,
}

impl WpaClient {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            control: path.into(),
        }
    }
    pub fn control_path(&self) -> &Path {
        &self.control
    }

    /// Send one direct UDS command and return the textual response.  The
    /// The caller owns the managed authenticated-STA command semantics.
    pub fn command(&self, command: &str, timeout: Duration) -> Result<String> {
        if command.trim().is_empty() {
            bail!("wpa command is empty");
        }
        let socket_path = std::env::temp_dir().join(format!(
            "dmesh-wpa-{}-{}",
            std::process::id(),
            unique_nonce()
        ));
        let socket =
            UnixDatagram::bind(&socket_path).context("bind temporary WPA control socket")?;
        socket.set_read_timeout(Some(timeout)).ok();
        socket
            .connect(&self.control)
            .with_context(|| format!("connect WPA control {}", self.control.display()))?;
        socket
            .send(command.as_bytes())
            .context("send WPA command")?;
        let mut response = vec![0u8; 8192];
        let len = socket.recv(&mut response).context("receive WPA response")?;
        let _ = fs::remove_file(&socket_path);
        Ok(String::from_utf8_lossy(&response[..len]).trim().to_owned())
    }
}

fn unique_nonce() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
