//! Minimal local USB utility surface.
//!
//! `lmesh-uart` no longer owns a serial forwarding service, TCP listener, or
//! firmware command protocol. QUIC-lite device sessions live in `client`; this
//! module remains only for explicit local adapter inventory and safe modem-line
//! utilities used by provisioning diagnostics.

use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt},
    },
};

#[derive(Clone, Default)]
pub struct UartService;

impl UartService {
    pub fn from_environment() -> Self {
        Self
    }
    pub fn from_environment_without_uart() -> Self {
        Self
    }

    pub fn status(&self) -> Value {
        json!({
            "service": "lmesh-uart",
            "role": "device-session-helper",
            "legacy_forwarding": false,
            "tcp": false,
        })
    }

    /// Legacy route selection is retired. The caller must select a device
    /// profile or bearer through the shared device-session client instead.
    pub fn default_esp_route(
        &self,
        _port: Option<&str>,
        _adapter: Option<&str>,
    ) -> Option<(String, String)> {
        None
    }

    pub fn usb_serial_list(&self, _handshake: Option<bool>) -> Value {
        json!({"devices": discover_usb_serial_devices(), "forwarding": false})
    }

    pub fn usb_serial_handshake(
        &self,
        port: Option<String>,
        _profile: Option<String>,
        _timeout_sec: Option<f64>,
        baud: Option<u32>,
    ) -> Value {
        match resolve_serial_path(port.as_deref()) {
            Ok(path) => match fs::OpenOptions::new().read(true).write(true).open(&path) {
                Ok(file) => {
                    json!({"ok": true, "path": path, "baud": baud, "fd": file.as_raw_fd(), "transport": "use dmesh-cli"})
                }
                Err(error) => json!({"ok": false, "path": path, "error": error.to_string()}),
            },
            Err(error) => json!({"ok": false, "error": error}),
        }
    }

    /// Firmware boot selection belongs to Stage2/esptool provisioning; it is
    /// not a serial forward control command.
    pub fn usb_serial_boot(
        &self,
        _port: Option<String>,
        _command: Option<String>,
        _timeout_sec: Option<f64>,
        _reset: Option<bool>,
    ) -> Value {
        json!({"ok": false, "error": "USB boot commands are retired; use scripts/flash-device.py stage or the QUIC-lite device session"})
    }

    pub fn serial_modem_reset(&self, port: Option<String>) -> Value {
        self.serial_modem_line(port, libc::TIOCM_RTS, None, 120)
    }

    pub fn serial_modem_dtr(
        &self,
        port: Option<String>,
        asserted: Option<bool>,
        pulse_ms: Option<u64>,
    ) -> Value {
        if asserted == Some(true) {
            return json!({"ok": false, "error": "DTR assertion is disabled; only release or pulse is allowed"});
        }
        self.serial_modem_line(port, libc::TIOCM_DTR, asserted, pulse_ms.unwrap_or(100))
    }

    fn serial_modem_line(
        &self,
        port: Option<String>,
        line: libc::c_int,
        asserted: Option<bool>,
        pulse_ms: u64,
    ) -> Value {
        let path = match resolve_serial_path(port.as_deref()) {
            Ok(path) => path,
            Err(error) => return json!({"ok": false, "error": error}),
        };
        let result = (|| -> std::io::Result<()> {
            let file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOCTTY)
                .open(&path)?;
            let set = |value: bool| -> std::io::Result<()> {
                let mut mask = line;
                let request = if value {
                    libc::TIOCMBIS
                } else {
                    libc::TIOCMBIC
                };
                if unsafe { libc::ioctl(file.as_raw_fd(), request, &mut mask) } < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            };
            match asserted {
                Some(value) => set(value)?,
                None => {
                    set(true)?;
                    std::thread::sleep(std::time::Duration::from_millis(pulse_ms));
                    set(false)?;
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                json!({"ok": true, "path": path, "line": if line == libc::TIOCM_RTS {"RTS"} else {"DTR"}, "asserted": asserted, "pulse_ms": pulse_ms})
            }
            Err(error) => json!({"ok": false, "path": path, "error": error.to_string()}),
        }
    }

    pub fn esp_serial_command(
        &self,
        adapter: Option<String>,
        port: Option<String>,
        command: String,
        timeout_sec: Option<f64>,
    ) -> Value {
        self.esp_serial_command_with_options(adapter, port, command, timeout_sec, false)
    }

    pub fn esp_serial_command_with_options(
        &self,
        _adapter: Option<String>,
        port: Option<String>,
        command: String,
        _timeout_sec: Option<f64>,
        _force_direct: bool,
    ) -> Value {
        json!({
            "ok": false,
            "port": port,
            "command": command,
            "error": "raw UART commands are retired; use the schema-aware QUIC-lite device-session client",
        })
    }
}

fn resolve_serial_path(port: Option<&str>) -> Result<String, String> {
    let port = port.ok_or("missing USB serial path")?;
    if port.starts_with("/dev/") {
        return Ok(port.to_owned());
    }
    let profile = crate::device::load_device(port)?;
    profile
        .serial_path()
        .map(|path| path.display().to_string())
        .ok_or_else(|| format!("device {port:?} has no serial_id"))
}

fn discover_usb_serial_devices() -> Vec<Value> {
    let mut paths = BTreeMap::<String, Value>::new();
    for prefix in ["/dev/ttyUSB", "/dev/ttyACM"] {
        for index in 0..64 {
            let path = format!("{prefix}{index}");
            if fs::metadata(&path).is_ok_and(|metadata| metadata.file_type().is_char_device()) {
                paths.insert(path.clone(), serial_device_json(&path, None));
            }
        }
    }
    if let Ok(entries) = fs::read_dir("/dev/serial/by-id") {
        for entry in entries.flatten() {
            let symlink = entry.path();
            let Ok(target) = fs::canonicalize(&symlink) else {
                continue;
            };
            let Some(path) = target.to_str().map(str::to_owned) else {
                continue;
            };
            let by_id = symlink.to_string_lossy().into_owned();
            paths
                .entry(path.clone())
                .and_modify(|device| device["by_id"] = json!(by_id))
                .or_insert_with(|| serial_device_json(&path, Some(by_id)));
        }
    }
    paths.into_values().collect()
}

fn serial_device_json(path: &str, by_id: Option<String>) -> Value {
    let mode = fs::metadata(path)
        .ok()
        .map(|metadata| metadata.permissions().mode() & 0o7777);
    json!({
        "path": path,
        "by_id": by_id,
        "kind": if path.contains("ttyACM") { "cdc-acm" } else { "usb-serial" },
        "mode": mode.map(|mode| format!("{mode:04o}")),
    })
}
