//! Host settings storage contract for `lmesh`.
//!
//! The control schema is in [`dmesh_discovery::control`]. This module contains
//! the get/set/list behavior over the restricted `key=value` file store.

use std::{collections::BTreeMap, path::PathBuf};

/// Keys that are portable across ESP NVS and host settings files.
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

/// Backing store for the `settings.*` handler.
pub trait SettingsStore {
    fn namespace(&self) -> &str;
    fn get_str(&self, key: &str) -> Result<Option<String>, String>;
    fn set_str(&mut self, key: &str, value: &str) -> Result<(), String>;
    fn known_keys(&self) -> &[&str];
}

/// Get/set/list behavior over a [`SettingsStore`].
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

/// Durable host implementation of [`SettingsStore`].
///
/// Blank lines and `#` comments are ignored, only the reviewed
/// [`COMMON_SETTING_KEYS`] can be read or written, and updates are atomic.
/// Linux deployment supplies an explicit path through `DMESH_SETTINGS_FILE`.
pub struct FileSettings {
    path: PathBuf,
    namespace: String,
}

impl FileSettings {
    pub fn new(path: impl Into<PathBuf>, namespace: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            namespace: namespace.into(),
        }
    }

    fn read_values(&self) -> Result<BTreeMap<String, String>, String> {
        let source = match std::fs::read_to_string(&self.path) {
            Ok(source) => source,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Default::default());
            }
            Err(error) => return Err(format!("read settings: {error}")),
        };
        let mut values = BTreeMap::new();
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
        let mut store = FileSettings::new(&path, "linux");
        assert_eq!(SettingsHandler::new(&mut store).get("name").unwrap(), "lmesh");
    }
}
