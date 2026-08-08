#![no_std]

#[cfg(test)]
extern crate std;

use core::ffi::c_void;

pub mod nan;

pub trait RawWifiIo {
    type Error;
    fn set_a3_filter(&mut self, address: MacAddr, enabled: bool)
        -> Result<FilterMode, Self::Error>;
    fn transmit(&mut self, frame: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppliedFilter {
    Hardware,
    Kernel,
    Software,
    Unsupported,
}

pub const NAN_A3_FILTER: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacAddr(pub [u8; 6]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RxFrame<'a> {
    pub bytes: &'a [u8],
    pub rssi_dbm: i8,
    pub timestamp_us: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilterMode {
    Discovery,
    Cluster,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    None,
    ArmA3(MacAddr),
    DropForeign,
    Rediscover,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NanState {
    mode: FilterMode,
    cluster: Option<MacAddr>,
    last_beacon_us: u64,
    stale_after_us: u64,
}

impl NanState {
    pub const fn new(stale_after_us: u64) -> Self {
        Self {
            mode: FilterMode::Discovery,
            cluster: None,
            last_beacon_us: 0,
            stale_after_us,
        }
    }

    pub const fn mode(&self) -> FilterMode {
        self.mode
    }
    pub const fn cluster(&self) -> Option<MacAddr> {
        self.cluster
    }

    pub fn observe(&mut self, frame: RxFrame<'_>) -> Action {
        let Some(a3) = nan::bssid(frame.bytes) else {
            return Action::None;
        };
        let a3 = MacAddr(a3);
        if nan::is_nan_beacon(frame.bytes) {
            if self.cluster.is_none() {
                self.cluster = Some(a3);
                self.mode = FilterMode::Cluster;
                self.last_beacon_us = frame.timestamp_us;
                return Action::ArmA3(a3);
            }
            if self.cluster == Some(a3) {
                self.last_beacon_us = frame.timestamp_us;
                return Action::None;
            }
            if frame.timestamp_us.saturating_sub(self.last_beacon_us)
                >= nan::NAN_CLUSTER_RESELECT_AFTER_US
            {
                self.cluster = Some(a3);
                self.last_beacon_us = frame.timestamp_us;
                return Action::ArmA3(a3);
            }
            return Action::DropForeign;
        }
        if self.mode == FilterMode::Cluster && self.cluster != Some(a3) {
            return Action::DropForeign;
        }
        Action::None
    }

    pub fn tick(&mut self, now_us: u64) -> Action {
        if self.mode == FilterMode::Cluster
            && now_us.saturating_sub(self.last_beacon_us) >= self.stale_after_us
        {
            self.mode = FilterMode::Discovery;
            self.cluster = None;
            return Action::Rediscover;
        }
        Action::None
    }
}

impl Default for NanState {
    fn default() -> Self {
        Self::new(5_000_000)
    }
}

#[repr(C)]
pub struct ModuleContext {
    pub abi_version: u32,
    pub size: u32,
    pub user: *mut c_void,
    pub root: *const RootTable,
}

#[repr(C)]
pub struct TableRef {
    pub id: u32,
    pub abi_version: u32,
    pub size: u32,
    pub table: *const c_void,
}

#[repr(C)]
pub struct RootTable {
    pub abi_version: u32,
    pub size: u32,
    pub features: u32,
    pub user: *mut c_void,
    pub table_count: u32,
    pub tables: *const TableRef,
}

impl RootTable {
    /// Look up a capability table without assuming a fixed directory order.
    pub unsafe fn find(&self, id: u32, min_size: u32) -> Option<&TableRef> {
        if self.tables.is_null() {
            return None;
        }
        let tables = core::slice::from_raw_parts(self.tables, self.table_count as usize);
        tables.iter().find(|entry| {
            entry.id == id && entry.abi_version >= ABI_VERSION && entry.size >= min_size
        })
    }
}

pub const ABI_VERSION: u32 = 1;

#[no_mangle]
pub unsafe extern "C" fn dmesh_module_entry(
    context: *const ModuleContext,
    _payload: *const u8,
    _payload_len: usize,
    _args: *const u8,
    _args_len: usize,
) -> i32 {
    if context.is_null() {
        return -100;
    }
    let ctx = &*context;
    if ctx.abi_version != ABI_VERSION
        || ctx.size < core::mem::size_of::<ModuleContext>() as u32
        || ctx.root.is_null()
    {
        return -101;
    }
    let root = &*ctx.root;
    if root.abi_version != ABI_VERSION || root.size < core::mem::size_of::<RootTable>() as u32 {
        return -102;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn beacon(a3: [u8; 6]) -> [u8; 24] {
        let mut f = [0u8; 24];
        f[0] = 0x80;
        f[16..22].copy_from_slice(&a3);
        f
    }

    #[test]
    fn cluster_filter_arms_on_beacon_and_drops_foreign() {
        let mut s = NanState::new(5_000_000);
        let a = beacon([0x50, 0x6f, 0x9a, 4, 5, 6]);
        assert_eq!(
            s.observe(RxFrame {
                bytes: &a,
                rssi_dbm: -40,
                timestamp_us: 10
            }),
            Action::ArmA3(MacAddr([0x50, 0x6f, 0x9a, 4, 5, 6]))
        );
        let foreign = beacon([0x50, 0x6f, 0x9a, 3, 2, 1]);
        assert_eq!(
            s.observe(RxFrame {
                bytes: &foreign,
                rssi_dbm: -60,
                timestamp_us: 20
            }),
            Action::DropForeign
        );
    }

    #[test]
    fn stale_cluster_returns_to_discovery() {
        let mut s = NanState::new(10);
        let a = beacon([0x50, 0x6f, 0x9a, 1, 1, 1]);
        s.observe(RxFrame {
            bytes: &a,
            rssi_dbm: 0,
            timestamp_us: 100,
        });
        assert_eq!(s.tick(109), Action::None);
        assert_eq!(s.tick(110), Action::Rediscover);
        assert_eq!(s.mode(), FilterMode::Discovery);
    }

    #[test]
    fn nan_classification_reuses_main_wire_markers() {
        let beacon = beacon([0x50, 0x6f, 0x9a, 1, 2, 3]);
        assert_eq!(nan::classify(&beacon), nan::FrameKind::Beacon);
        assert_eq!(nan::fnv1a32(b"dmesh"), 0x3a497b36);
    }
}
