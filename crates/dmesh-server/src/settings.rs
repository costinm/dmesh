//! Bearer- and platform-neutral settings storage contract.
//!
//! The control schema is in [`crate::control`]. This module contains only the
//! get/set/list behavior shared by ESP NVS, host configuration, and tests.

extern crate alloc;

use alloc::{string::String, vec::Vec};

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
}
