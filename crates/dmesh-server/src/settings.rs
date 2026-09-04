//! Bearer- and platform-neutral settings storage contract.
//!
//! The control schema is in [`crate::control`]. This module contains only the
//! get/set/list behavior shared by ESP NVS, host configuration, and tests.

extern crate alloc;

use alloc::{string::String, vec::Vec};

/// Keys that are portable across ESP NVS and host/Android settings files.
/// Platform-specific credentials remain in their private stores; this list is
/// deliberately limited to values safe to return from `settings.list`.
pub const COMMON_SETTING_KEYS: &[&str] = &[
    "mode",
    "name",
    "domain",
    "sta_ssid",
    "sta_server_ll",
    "sta_server_port",
];

/// Backing store for the common `settings.*` handler.
pub trait SettingsStore {
    fn namespace(&self) -> &str;
    fn get_str(&self, key: &str) -> Result<Option<String>, String>;
    fn set_str(&mut self, key: &str, value: &str) -> Result<(), String>;
    fn known_keys(&self) -> &[&str];
}

/// Common get/set/list behavior. An adapter supplies only storage; it must
/// not parse a UART command or invent a bearer-local request format.
pub struct SettingsHandler<'a, S: SettingsStore> {
    store: &'a mut S,
}

impl<'a, S: SettingsStore> SettingsHandler<'a, S> {
    pub fn new(store: &'a mut S) -> Self {
        Self { store }
    }

    pub fn namespace(&self) -> &str {
        self.store.namespace()
    }

    pub fn get(&self, key: &str) -> Result<String, String> {
        Ok(self.store.get_str(key)?.unwrap_or_default())
    }

    pub fn set(&mut self, key: &str, value: &str) -> Result<(), String> {
        self.store.set_str(key, value)
    }

    pub fn list(&self) -> Result<Vec<(String, String)>, String> {
        let mut values = Vec::new();
        for key in self.store.known_keys() {
            if let Some(value) = self.store.get_str(key)? {
                values.push(((*key).into(), value));
            }
        }
        Ok(values)
    }
}

/// Small durable host/Android implementation of [`SettingsStore`].
///
/// The file is intentionally a restricted `key=value` format rather than a
/// second schema language: blank lines and `#` comments are ignored, only the
/// reviewed [`COMMON_SETTING_KEYS`] can be read or written, and updates are
/// atomic. Android supplies a private path below its mesh base directory;
/// Linux deployment supplies an explicit path through `DMESH_SETTINGS_FILE`.
#[cfg(feature = "std")]
pub struct FileSettings {
    path: std::path::PathBuf,
    namespace: String,
}

#[cfg(feature = "std")]
impl FileSettings {
    pub fn new(path: impl Into<std::path::PathBuf>, namespace: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            namespace: namespace.into(),
        }
    }

    fn read_values(&self) -> Result<std::collections::BTreeMap<String, String>, String> {
        let source = match std::fs::read_to_string(&self.path) {
            Ok(source) => source,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Default::default());
            }
            Err(error) => return Err(format!("read settings: {error}")),
        };
        let mut values = std::collections::BTreeMap::new();
        for line in source.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim();
            if COMMON_SETTING_KEYS.contains(&key) && !value.contains(['\n', '\r']) {
                values.insert(key.to_owned(), value.to_owned());
            }
        }
        Ok(values)
    }
}

/// Load the provisioned device/control-plane root from private platform
/// storage and derive only its stateless-reset branch.  The raw root is never
/// returned to callers: it must not leak into the common text settings file,
/// a handler response, a log record, or a packet.
///
/// ESP uses the equivalent `sec:key` NVS blob. Linux and Android use a
/// mode-0600 binary file in their private data directory, typically named
/// `device-secret.bin` beside `settings.conf`. Provisioning owns creation;
/// a missing file simply leaves reset detection on the normal PTO fallback.
#[cfg(feature = "std")]
pub fn stateless_reset_key_from_private_file(
    path: impl AsRef<std::path::Path>,
) -> Result<Option<quic_lite::StatelessResetKey>, String> {
    let path = path.as_ref();
    let secret = match std::fs::read(path) {
        Ok(secret) => secret,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("read device secret: {error}")),
    };
    quic_lite::StatelessResetKey::from_device_secret(&secret)
        .map(Some)
        .map_err(|_| "invalid device secret: expected at least 16 private bytes".to_owned())
}

/// Persist provisioned root material in platform-private storage.
///
/// This is intentionally separate from [`SettingsStore`]: the common
/// `settings.*` stream API cannot read, list, or write this value. ESP has the
/// equivalent binary `sec:key` NVS path. Host and Android provisioning invoke
/// this helper before starting their QUIC listener, then quic-lite receives
/// only the derived reset-key branch. Future PSP-style traffic-key branches
/// use the same root under distinct labels.
#[cfg(feature = "std")]
pub fn write_private_device_secret_file(
    path: impl AsRef<std::path::Path>,
    secret: &[u8],
) -> Result<(), String> {
    if !(16..=crate::announce::MAX_PUBLIC_KEY).contains(&secret.len()) {
        return Err("invalid device secret: expected 16..=128 private bytes".to_owned());
    }
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create device-secret directory: {error}"))?;
    }
    let temporary = path.with_extension("tmp");
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| format!("write device secret: {error}"))?;
        use std::io::Write;
        file.write_all(secret)
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("write device secret: {error}"))?;
    }
    #[cfg(not(unix))]
    std::fs::write(&temporary, secret).map_err(|error| format!("write device secret: {error}"))?;
    std::fs::rename(&temporary, path).map_err(|error| format!("replace device secret: {error}"))
}

/// Resolve the shared host convention without teaching a bearer about a
/// platform-specific credential store. An explicit private secret path wins;
/// otherwise a configured common settings file supplies only the directory,
/// never the secret itself.
#[cfg(feature = "std")]
pub fn stateless_reset_key_from_environment() -> Result<Option<quic_lite::StatelessResetKey>, String>
{
    let path = if let Some(path) = std::env::var_os("DMESH_DEVICE_SECRET_FILE") {
        std::path::PathBuf::from(path)
    } else if let Some(settings) = std::env::var_os("DMESH_SETTINGS_FILE") {
        std::path::PathBuf::from(settings)
            .parent()
            .map(|parent| parent.join("device-secret.bin"))
            .ok_or_else(|| "settings path has no parent directory".to_owned())?
    } else {
        return Ok(None);
    };
    stateless_reset_key_from_private_file(path)
}

#[cfg(feature = "std")]
impl SettingsStore for FileSettings {
    fn namespace(&self) -> &str {
        &self.namespace
    }

    fn get_str(&self, key: &str) -> Result<Option<String>, String> {
        if !COMMON_SETTING_KEYS.contains(&key) {
            return Err("unknown setting".into());
        }
        Ok(self.read_values()?.remove(key))
    }

    fn set_str(&mut self, key: &str, value: &str) -> Result<(), String> {
        if !COMMON_SETTING_KEYS.contains(&key) || value.contains(['\n', '\r']) {
            return Err("invalid setting".into());
        }
        let mut values = self.read_values()?;
        values.insert(key.to_owned(), value.to_owned());
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create settings directory: {error}"))?;
        }
        let temporary = self.path.with_extension("tmp");
        let mut content = String::from("# DMesh common settings\n");
        for (key, value) in values {
            content.push_str(&key);
            content.push('=');
            content.push_str(&value);
            content.push('\n');
        }
        std::fs::write(&temporary, content).map_err(|error| format!("write settings: {error}"))?;
        std::fs::rename(&temporary, &self.path)
            .map_err(|error| format!("replace settings: {error}"))
    }

    fn known_keys(&self) -> &[&str] {
        COMMON_SETTING_KEYS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    struct MemorySettings {
        values: BTreeMap<String, String>,
    }

    impl SettingsStore for MemorySettings {
        fn namespace(&self) -> &str {
            "test"
        }
        fn get_str(&self, key: &str) -> Result<Option<String>, String> {
            Ok(self.values.get(key).cloned())
        }
        fn set_str(&mut self, key: &str, value: &str) -> Result<(), String> {
            self.values.insert(key.into(), value.into());
            Ok(())
        }
        fn known_keys(&self) -> &[&str] {
            &["ssid", "log_level"]
        }
    }

    #[test]
    fn host_store_has_the_same_get_set_list_behavior() {
        let mut store = MemorySettings {
            values: BTreeMap::new(),
        };
        let mut handler = SettingsHandler::new(&mut store);
        assert_eq!(handler.namespace(), "test");
        handler.set("ssid", "DIRECT-test").unwrap();
        assert_eq!(handler.get("ssid").unwrap(), "DIRECT-test");
        assert_eq!(
            handler.list().unwrap(),
            vec![("ssid".into(), "DIRECT-test".into())]
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn file_store_persists_only_common_settings() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.conf");
        let mut store = FileSettings::new(&path, "linux");
        let mut handler = SettingsHandler::new(&mut store);
        handler.set("name", "lmesh").unwrap();
        assert_eq!(handler.get("name").unwrap(), "lmesh");
        assert!(handler.set("sec:key", "no").is_err());
        drop(handler);
        let store = FileSettings::new(&path, "linux");
        assert_eq!(
            SettingsHandler::new(&mut { store }).get("name").unwrap(),
            "lmesh"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn private_device_secret_exposes_only_its_reset_key_branch() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("device-secret.bin");
        assert!(
            stateless_reset_key_from_private_file(&path)
                .unwrap()
                .is_none()
        );
        std::fs::write(&path, [0x55; 32]).unwrap();
        let key = stateless_reset_key_from_private_file(&path)
            .unwrap()
            .unwrap();
        let cid = quic_lite::ConnectionId::new(9).unwrap();
        assert_eq!(key.token_for(cid), key.token_for(cid));
        std::fs::write(&path, [0x55; 15]).unwrap();
        assert!(stateless_reset_key_from_private_file(&path).is_err());
    }

    #[cfg(feature = "std")]
    #[test]
    fn private_device_secret_write_is_not_a_common_setting() {
        let directory = tempfile::tempdir().unwrap();
        let secret_path = directory.path().join("device-secret.bin");
        write_private_device_secret_file(&secret_path, &[0x7a; 32]).unwrap();
        assert_eq!(std::fs::read(&secret_path).unwrap(), [0x7a; 32]);
        assert!(write_private_device_secret_file(&secret_path, &[0x7a; 15]).is_err());

        let mut common = FileSettings::new(directory.path().join("settings.conf"), "test");
        assert!(
            SettingsHandler::new(&mut common)
                .set("sec:key", "never")
                .is_err()
        );
    }
}
