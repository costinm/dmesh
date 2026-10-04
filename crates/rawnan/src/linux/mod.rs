//! Linux backend of the raw Wi-Fi bearer: nl80211 and rtnetlink plumbing, the monitor
//! interface, and the native open AP. Everything here is Linux-only system code; the
//! on-air formats stay in the rest of this crate.
#![allow(dead_code)]
use std::{borrow::ToOwned, string::{String, ToString}, vec::Vec};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::os::fd::RawFd;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::{SystemTime, UNIX_EPOCH};
use std::time::Duration;

pub mod capture;
pub mod chain;
pub mod espnow_bearer;
pub mod frames;
pub mod monitor;
pub mod nl80211;
pub mod radio;
pub mod open_ap;
pub mod rtnl;
pub mod util;

pub use capture::*;
pub use chain::*;
pub use frames::*;
pub use monitor::*;
pub use nl80211::*;
pub use radio::*;
pub use open_ap::*;
pub use rtnl::*;
pub use util::*;
