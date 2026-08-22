//! Main-specific shims only.
//!
//! The former Main component catalog owns legacy Wi-Fi, NAN, BLE, power, and
//! command lifecycles. It is intentionally not compiled by the Recovery-core
//! Main image: each would create a second owner of an ESP-IDF subsystem that
//! the common transport already owns.

pub mod recovery;
