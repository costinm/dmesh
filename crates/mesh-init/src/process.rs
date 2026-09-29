//! Process lifecycle management for mesh-init services.
//!
//! Handles fork/exec with privilege drop (setuid/setgid), service sandboxing,
//! signal-based stop/freeze/unfreeze, and PID 1 zombie reaping.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

use tracing::{debug, error, info, warn};

use crate::config::AppConfig;
use crate::protocol::{FreezeReason, ServiceState, StopReason};
use crate::states;

pub use states::ServiceState as RuntimeState;

/// CLOCK_MONOTONIC microseconds, the same clock `X_MESH_WAKE_AT` uses.
pub fn monotonic_micros() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as u64) * 1_000_000 + (ts.tv_nsec as u64 / 1_000)
}

/// Convert a `X_MESH_WAKE_AT` deadline (CLOCK_MONOTONIC µs) into an Instant.
/// Deadlines in the past map to now.
pub fn instant_from_monotonic_us(wake_at_us: u64) -> Option<Instant> {
    let now = monotonic_micros();
    let delta = wake_at_us.checked_sub(now)?;
    Some(Instant::now() + Duration::from_micros(delta))
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const CAP_CHOWN: i32 = 0;
const CAP_DAC_OVERRIDE: i32 = 1;
const CAP_FOWNER: i32 = 3;
const CAP_KILL: i32 = 5;
const CAP_SETGID: i32 = 6;
const CAP_SETUID: i32 = 7;
const CAP_SETPCAP: i32 = 8;
const CAP_NET_BIND_SERVICE: i32 = 10;
const CAP_NET_ADMIN: i32 = 12;
const CAP_NET_RAW: i32 = 13;
const CAP_SYS_ADMIN: i32 = 21;
const CAP_LAST_SUPPORTED: i32 = 40;

#[repr(C)]
struct UserCapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UserCapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

// ============================================================================
// Error Types
// ============================================================================

/// Errors from process operations.
#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Process not found: PID {0}")]
    NotFound(u32),

    #[error("Spawn failed: {0}")]
    SpawnFailed(String),

    #[error("Signal error: {0}")]
    SignalError(String),

    #[error("Cgroup error: {0}")]
    Cgroup(#[from] crate::cgroup::CgroupError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtectSystemMode {
    True,
    Full,
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtectHomeMode {
    Yes,
    ReadOnly,
    Tmpfs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MaskKind {
    Directory,
    File,
}

#[derive(Debug, Clone)]
struct SandboxPlan {
    private_tmp: bool,
    private_devices: bool,
    private_network: bool,
    no_new_privileges: bool,
    protect_system: Option<ProtectSystemMode>,
    protect_home: Option<ProtectHomeMode>,
    read_write_paths: Vec<CString>,
    read_only_paths: Vec<CString>,
    inaccessible_paths: Vec<(CString, MaskKind)>,
    bounding_caps: Option<Vec<i32>>,
    ambient_caps: Vec<i32>,
}

impl SandboxPlan {
    fn needs_mount_namespace(&self) -> bool {
        self.private_tmp
            || self.private_devices
            || self.protect_system.is_some()
            || self.protect_home.is_some()
            || !self.read_write_paths.is_empty()
            || !self.read_only_paths.is_empty()
            || !self.inaccessible_paths.is_empty()
    }

    fn needs_keepcaps(&self) -> bool {
        !self.ambient_caps.is_empty()
    }
}

fn parse_protect_system(value: Option<&str>) -> Result<Option<ProtectSystemMode>, ProcessError> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    match value.to_ascii_lowercase().as_str() {
        "0" | "false" | "no" | "off" => Ok(None),
        "1" | "true" | "yes" => Ok(Some(ProtectSystemMode::True)),
        "full" => Ok(Some(ProtectSystemMode::Full)),
        "strict" => Ok(Some(ProtectSystemMode::Strict)),
        unsupported => {
            warn!(value = unsupported, "unsupported_protect_system");
            Err(ProcessError::SpawnFailed(format!(
                "unsupported ProtectSystem value: {value}"
            )))
        }
    }
}

fn parse_protect_home(value: Option<&str>) -> Result<Option<ProtectHomeMode>, ProcessError> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    match value.to_ascii_lowercase().as_str() {
        "0" | "false" | "no" | "off" => Ok(None),
        "1" | "true" | "yes" => Ok(Some(ProtectHomeMode::Yes)),
        "read-only" | "readonly" => Ok(Some(ProtectHomeMode::ReadOnly)),
        "tmpfs" => Ok(Some(ProtectHomeMode::Tmpfs)),
        unsupported => {
            warn!(value = unsupported, "unsupported_protect_home");
            Err(ProcessError::SpawnFailed(format!(
                "unsupported ProtectHome value: {value}"
            )))
        }
    }
}

fn path_to_cstring(path: &str, field: &str) -> Result<CString, ProcessError> {
    if path.is_empty() {
        warn!(field = %field, "empty_path");
        return Err(ProcessError::SpawnFailed(format!(
            "{field} contains an empty path"
        )));
    }
    if !path.starts_with('/') {
        warn!(field = %field, path = %path, "path_not_absolute");
        return Err(ProcessError::SpawnFailed(format!(
            "{field} path must be absolute: {path}"
        )));
    }
    CString::new(path.as_bytes()).map_err(|_| {
        warn!(field = %field, path = ?path, "path_contains_nul");
        ProcessError::SpawnFailed(format!("{field} path contains NUL byte: {path:?}"))
    })
}

fn path_list_to_cstrings(paths: &[String], field: &str) -> Result<Vec<CString>, ProcessError> {
    paths
        .iter()
        .map(|path| path_to_cstring(path, field))
        .collect()
}

fn inaccessible_path_kind(path: &str) -> Result<MaskKind, ProcessError> {
    let meta = std::fs::metadata(path).map_err(|error| {
        warn!(path = %path, error = %error, "cannot_inspect_inaccessible_path");
        ProcessError::SpawnFailed(format!("InaccessiblePaths path missing or invalid: {path}"))
    })?;
    Ok(if meta.is_dir() {
        MaskKind::Directory
    } else {
        MaskKind::File
    })
}

fn inaccessible_paths(paths: &[String]) -> Result<Vec<(CString, MaskKind)>, ProcessError> {
    paths
        .iter()
        .map(|path| {
            let kind = inaccessible_path_kind(path)?;
            Ok((path_to_cstring(path, "InaccessiblePaths")?, kind))
        })
        .collect()
}

fn cap_name_to_number(name: &str) -> Option<i32> {
    let normalized = name
        .trim()
        .strip_prefix("cap_")
        .or_else(|| name.trim().strip_prefix("CAP_"))
        .unwrap_or_else(|| name.trim())
        .to_ascii_uppercase();
    match normalized.as_str() {
        "CHOWN" => Some(CAP_CHOWN),
        "DAC_OVERRIDE" => Some(CAP_DAC_OVERRIDE),
        "FOWNER" => Some(CAP_FOWNER),
        "KILL" => Some(CAP_KILL),
        "SETGID" => Some(CAP_SETGID),
        "SETUID" => Some(CAP_SETUID),
        "SETPCAP" => Some(CAP_SETPCAP),
        "NET_BIND_SERVICE" => Some(CAP_NET_BIND_SERVICE),
        "NET_ADMIN" => Some(CAP_NET_ADMIN),
        "NET_RAW" => Some(CAP_NET_RAW),
        "SYS_ADMIN" => Some(CAP_SYS_ADMIN),
        _ => None,
    }
}

fn parse_cap_list(values: &[String], field: &str) -> Result<Vec<i32>, ProcessError> {
    let mut caps = Vec::new();
    for value in values {
        let Some(cap) = cap_name_to_number(value) else {
            warn!(field = %field, capability = %value, "unsupported_capability");
            return Err(ProcessError::SpawnFailed(format!(
                "{field} capability is not supported: {value}"
            )));
        };
        if !caps.contains(&cap) {
            caps.push(cap);
        }
    }
    Ok(caps)
}

fn build_sandbox_plan(config: &AppConfig) -> Result<SandboxPlan, ProcessError> {
    let protect_system = parse_protect_system(config.protect_system.as_deref())?;
    let protect_home = parse_protect_home(config.protect_home.as_deref())?;
    let bounding_caps = config
        .capability_bounding_set
        .as_ref()
        .map(|caps| parse_cap_list(caps, "CapabilityBoundingSet"))
        .transpose()?;
    let ambient_caps = parse_cap_list(&config.ambient_capabilities, "AmbientCapabilities")?;
    if let Some(bounding_caps) = &bounding_caps {
        for cap in &ambient_caps {
            if !bounding_caps.contains(cap) {
                warn!(capability = cap, "ambient_cap_outside_bounding_set");
                return Err(ProcessError::SpawnFailed(
                    "AmbientCapabilities must be a subset of CapabilityBoundingSet".to_string(),
                ));
            }
        }
        if !ambient_caps.is_empty() && !bounding_caps.contains(&CAP_SETPCAP) {
            warn!("ambient_caps_require_setpcap");
            return Err(ProcessError::SpawnFailed(
                "AmbientCapabilities with CapabilityBoundingSet requires CAP_SETPCAP".to_string(),
            ));
        }
    }

    Ok(SandboxPlan {
        private_tmp: config.private_tmp,
        private_devices: config.private_devices,
        private_network: config.private_network,
        no_new_privileges: config.no_new_privileges,
        protect_system,
        protect_home,
        read_write_paths: path_list_to_cstrings(&config.read_write_paths, "ReadWritePaths")?,
        read_only_paths: path_list_to_cstrings(&config.read_only_paths, "ReadOnlyPaths")?,
        inaccessible_paths: inaccessible_paths(&config.inaccessible_paths)?,
        bounding_caps,
        ambient_caps,
    })
}

fn cstr(bytes: &'static [u8]) -> *const libc::c_char {
    bytes.as_ptr().cast()
}

unsafe fn mount_checked(
    source: *const libc::c_char,
    target: *const libc::c_char,
    fstype: *const libc::c_char,
    flags: libc::c_ulong,
    data: *const libc::c_void,
) -> std::io::Result<()> {
    if unsafe { libc::mount(source, target, fstype, flags, data) } < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

unsafe fn mkdir_0755(path: *const libc::c_char) -> std::io::Result<()> {
    if unsafe { libc::mkdir(path, 0o755) } < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(error);
        }
    }
    Ok(())
}

unsafe fn mknod_chr(
    path: *const libc::c_char,
    mode: libc::mode_t,
    major: u64,
    minor: u64,
) -> std::io::Result<()> {
    if unsafe {
        libc::mknod(
            path,
            mode | libc::S_IFCHR,
            libc::makedev(major as libc::c_uint, minor as libc::c_uint),
        )
    } < 0
    {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(error);
        }
    }
    Ok(())
}

unsafe fn bind_remount(path: &CString, flags: libc::c_ulong) -> std::io::Result<()> {
    unsafe { bind_remount_raw(path.as_ptr(), flags) }
}

unsafe fn bind_remount_raw(path: *const libc::c_char, flags: libc::c_ulong) -> std::io::Result<()> {
    unsafe {
        mount_checked(
            path,
            path,
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        )?;
        mount_checked(
            std::ptr::null(),
            path,
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REMOUNT | flags,
            std::ptr::null(),
        )
    }
}

unsafe fn bind_remount_raw_optional(
    path: *const libc::c_char,
    flags: libc::c_ulong,
) -> std::io::Result<()> {
    match unsafe { bind_remount_raw(path, flags) } {
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
        result => result,
    }
}

unsafe fn mount_tmpfs(path: *const libc::c_char, options: &'static [u8]) -> std::io::Result<()> {
    unsafe {
        mount_checked(
            cstr(b"tmpfs\0"),
            path,
            cstr(b"tmpfs\0"),
            libc::MS_NOSUID | libc::MS_NODEV,
            cstr(options).cast(),
        )
    }
}

unsafe fn mount_tmpfs_optional(
    path: *const libc::c_char,
    options: &'static [u8],
) -> std::io::Result<()> {
    match unsafe { mount_tmpfs(path, options) } {
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
        result => result,
    }
}

unsafe fn apply_private_tmp() -> std::io::Result<()> {
    unsafe {
        mount_tmpfs(cstr(b"/tmp\0"), b"mode=1777\0")?;
        mount_tmpfs_optional(cstr(b"/var/tmp\0"), b"mode=1777\0")?;
    }
    Ok(())
}

unsafe fn apply_private_devices() -> std::io::Result<()> {
    unsafe {
        mount_checked(
            cstr(b"tmpfs\0"),
            cstr(b"/dev\0"),
            cstr(b"tmpfs\0"),
            libc::MS_NOSUID,
            cstr(b"mode=0755\0").cast(),
        )?;
        mknod_chr(cstr(b"/dev/null\0"), 0o666, 1, 3)?;
        mknod_chr(cstr(b"/dev/zero\0"), 0o666, 1, 5)?;
        mknod_chr(cstr(b"/dev/full\0"), 0o666, 1, 7)?;
        mknod_chr(cstr(b"/dev/random\0"), 0o666, 1, 8)?;
        mknod_chr(cstr(b"/dev/urandom\0"), 0o666, 1, 9)?;
        mknod_chr(cstr(b"/dev/tty\0"), 0o666, 5, 0)?;
        mkdir_0755(cstr(b"/dev/pts\0"))?;
        mkdir_0755(cstr(b"/dev/shm\0"))?;
        let _ = mount_checked(
            cstr(b"devpts\0"),
            cstr(b"/dev/pts\0"),
            cstr(b"devpts\0"),
            libc::MS_NOSUID | libc::MS_NOEXEC,
            cstr(b"newinstance,ptmxmode=0666,mode=0620\0").cast(),
        );
        let _ = mount_tmpfs(cstr(b"/dev/shm\0"), b"mode=1777\0");
    }
    Ok(())
}

unsafe fn apply_protect_system(mode: ProtectSystemMode) -> std::io::Result<()> {
    unsafe {
        if mode == ProtectSystemMode::Strict {
            bind_remount_raw(cstr(b"/\0"), libc::MS_RDONLY)?;
            return Ok(());
        }
        for path in [cstr(b"/usr\0"), cstr(b"/boot\0"), cstr(b"/efi\0")] {
            bind_remount_raw_optional(path, libc::MS_RDONLY)?;
        }
        if mode == ProtectSystemMode::Full {
            bind_remount_raw_optional(cstr(b"/etc\0"), libc::MS_RDONLY)?;
        }
    }
    Ok(())
}

unsafe fn apply_protect_home(mode: ProtectHomeMode) -> std::io::Result<()> {
    let homes = [cstr(b"/home\0"), cstr(b"/root\0"), cstr(b"/run/user\0")];
    for path in homes {
        unsafe {
            match mode {
                ProtectHomeMode::Yes => {
                    mount_tmpfs_optional(path, b"mode=000\0")?;
                }
                ProtectHomeMode::ReadOnly => {
                    bind_remount_raw_optional(path, libc::MS_RDONLY)?;
                }
                ProtectHomeMode::Tmpfs => {
                    mount_tmpfs_optional(path, b"mode=0755\0")?;
                }
            }
        }
    }
    Ok(())
}

unsafe fn apply_default_read_only_host_mounts() -> std::io::Result<()> {
    unsafe {
        bind_remount_raw_optional(cstr(b"/nix\0"), libc::MS_RDONLY)?;
        bind_remount_raw_optional(cstr(b"/opt\0"), libc::MS_RDONLY)?;
    }
    Ok(())
}

unsafe fn apply_inaccessible_path(path: &CString, kind: MaskKind) -> std::io::Result<()> {
    unsafe {
        match kind {
            MaskKind::Directory => mount_tmpfs(path.as_ptr(), b"mode=000\0"),
            MaskKind::File => {
                mount_checked(
                    cstr(b"/dev/null\0"),
                    path.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )?;
                mount_checked(
                    std::ptr::null(),
                    path.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID,
                    std::ptr::null(),
                )
            }
        }
    }
}

unsafe fn cap_drop_bounding(cap: i32) -> std::io::Result<()> {
    if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) } < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn cap_mask(caps: &[i32], word: usize) -> u32 {
    caps.iter().fold(0u32, |mask, cap| {
        let cap = *cap as usize;
        if cap / 32 == word {
            mask | (1u32 << (cap % 32))
        } else {
            mask
        }
    })
}

fn chown_path(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    let path = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL byte")
    })?;
    let rc = unsafe { libc::chown(path.as_ptr(), uid as libc::uid_t, gid as libc::gid_t) };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn prepare_service_directory(
    config: &AppConfig,
    dir: &Path,
    mode: u32,
    directory: &str,
) -> Result<(), ProcessError> {
    let uid = config.uid.unwrap_or(0);
    let gid = config.gid.unwrap_or(0);
    let prepare = || -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode))?;
        if unsafe { libc::geteuid() } == 0 {
            chown_path(dir, uid, gid)?;
        }
        Ok(())
    };

    match prepare() {
        Ok(()) => {
            debug!(
                service = %config.name,
                path = %dir.display(),
                uid,
                gid,
                mode,
                directory,
                "service_directory_ready"
            );
            Ok(())
        }
        Err(error) if unsafe { libc::geteuid() } != 0 => {
            warn!(
                service = %config.name,
                path = %dir.display(),
                error = %error,
                directory,
                "service_directory_prepare_skipped_non_root"
            );
            Ok(())
        }
        Err(error) => Err(ProcessError::Io(error)),
    }
}

fn prepare_service_directories(config: &AppConfig) -> Result<(), ProcessError> {
    let paths = mesh::paths::AppPaths::for_app(&config.name);
    prepare_service_directory(config, &paths.home, 0o755, "home")?;
    prepare_service_directory(config, &paths.mesh_ipc_dir, 0o755, "runtime")
}

fn service_home(config: &AppConfig) -> String {
    config.env.get("HOME").cloned().unwrap_or_else(|| {
        mesh::paths::AppPaths::for_app(&config.name)
            .home
            .to_string_lossy()
            .into_owned()
    })
}

/// Deterministic executable search path for supervised services. Service-local
/// mutable and per-user Nix profiles take precedence over host profiles.
fn service_path(config: &AppConfig) -> String {
    let home = service_home(config);
    [
        format!("{home}/bin"),
        format!("{home}/.local/bin"),
        format!("{home}/.nix-profile/bin"),
        "/nix/var/nix/profiles/default/bin".to_string(),
        "/run/current-system/sw/bin".to_string(),
        "/usr/local/bin".to_string(),
        "/usr/bin".to_string(),
        "/bin".to_string(),
    ]
    .join(":")
}

unsafe fn apply_capset(caps: &[i32], include_setpcap: bool) -> std::io::Result<()> {
    let mut caps = caps.to_vec();
    if include_setpcap && !caps.contains(&CAP_SETPCAP) {
        caps.push(CAP_SETPCAP);
    }
    let mut header = UserCapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [
        UserCapData {
            effective: cap_mask(&caps, 0),
            permitted: cap_mask(&caps, 0),
            inheritable: cap_mask(&caps, 0),
        },
        UserCapData {
            effective: cap_mask(&caps, 1),
            permitted: cap_mask(&caps, 1),
            inheritable: cap_mask(&caps, 1),
        },
    ];
    if unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_mut_ptr()) } < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

unsafe fn raise_ambient_caps(caps: &[i32]) -> std::io::Result<()> {
    for cap in caps {
        if unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE, *cap, 0, 0) } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

unsafe fn apply_sandbox_before_identity(plan: &SandboxPlan) -> std::io::Result<()> {
    unsafe {
        if plan.needs_mount_namespace() {
            if libc::unshare(libc::CLONE_NEWNS) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            mount_checked(
                std::ptr::null(),
                cstr(b"/\0"),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )?;
            apply_default_read_only_host_mounts()?;
        }
        if plan.private_tmp {
            apply_private_tmp()?;
        }
        if plan.private_devices {
            apply_private_devices()?;
        }
        if let Some(mode) = plan.protect_system {
            apply_protect_system(mode)?;
        }
        if let Some(mode) = plan.protect_home {
            apply_protect_home(mode)?;
        }
        for path in &plan.read_only_paths {
            bind_remount(path, libc::MS_RDONLY)?;
        }
        for (path, kind) in &plan.inaccessible_paths {
            apply_inaccessible_path(path, *kind)?;
        }
        for path in &plan.read_write_paths {
            bind_remount(path, 0)?;
        }
        if plan.private_network && libc::unshare(libc::CLONE_NEWNET) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if let Some(caps) = &plan.bounding_caps {
            for cap in 0..=CAP_LAST_SUPPORTED {
                if !caps.contains(&cap) {
                    cap_drop_bounding(cap)?;
                }
            }
        }
        if plan.needs_keepcaps() && libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

// ============================================================================
// Managed Process
// ============================================================================

/// A process managed by the daemon.
#[derive(Debug)]
pub struct ManagedProcess {
    /// The service configuration.
    pub config: AppConfig,
    /// Current lifecycle state, frozen reason and epoch included.
    pub state: states::ServiceState,
    /// The requested state (whether the daemon wants it to be running or stopped).
    pub target_state: states::ServiceState,
    /// PID of the running process (None if stopped).
    pub pid: Option<u32>,
    /// PID of the network sidecar process, if one is attached.
    pub network_pid: Option<u32>,
    /// Host-held network namespace descriptor registered by a child mesh-init.
    ///
    /// Keeping the fd open pins the namespace and gives the host daemon a
    /// stable handle it can pass to mesh-tun later, while pasta can still be
    /// used today as a PID-based validation backend.
    pub netns_fd: Option<std::os::fd::OwnedFd>,
    /// Optional user namespace descriptor for targets created in a userns.
    pub userns_fd: Option<std::os::fd::OwnedFd>,
    /// PID in the service namespace that registered the namespace descriptors.
    pub namespace_pid: Option<u32>,
    /// True after the shared mesh-tun daemon accepted this service namespace.
    pub mesh_tun_attached: bool,
    /// pidfd for the main process. None when the process is not running.
    /// Used by `pidfd_send_signal(2)` to signal without PID-recycle risk.
    pub pidfd: Option<std::os::fd::OwnedFd>,
    /// When the process was last started.
    pub started_at: Option<Instant>,
    /// Number of times this service has been restarted.
    pub restarts: u32,
    /// Number of consecutive crashes for backoff calculation.
    pub consecutive_failures: u32,
    /// Time when the service can be restarted next.
    pub next_restart_at: Option<Instant>,
    /// Cgroup path for this service.
    pub cgroup_path: Option<String>,
    pub ready: bool,
    pub last_watchdog_ping: Option<Instant>,
    pub last_stderr_at: Option<Instant>,
    pub last_active: Option<u64>,
    pub last_sess: Option<u64>,
    /// Why the service is stopped. Set by `states::transition`.
    pub stop_reason: Option<StopReason>,
    /// Why the service is frozen, when frozen or freezing.
    pub freeze_reason: Option<FreezeReason>,
    /// A user explicitly froze this service; activity may not thaw it.
    pub explicit_freeze: bool,
    /// When the service became idle (metrics-based idle tracking).
    pub idle_since: Option<Instant>,
    /// Last activity counters reported over the notify channel or stderr.
    pub notify_activity: Option<ActivityCounts>,
    /// CLOCK_MONOTONIC µs deadline the service asked to be woken at.
    pub wake_at: Option<u64>,
    /// Echoed freeze epoch the service acknowledged in `ready {epoch}`.
    pub freeze_ack: Option<u64>,
    /// When the service entered `Stopping`. Set by every path that signals a
    /// live service for termination so the scheduler can escalate to SIGKILL
    /// if the signal does not take effect.
    pub stopping_since: Option<Instant>,
}

/// Simple activity counts, standard interface for metrics reported by the
/// service (over NOTIFY_SOCKET or stderr).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActivityCounts {
    pub connections: u32,
    pub requests: u32,
    pub holds: u32,
}

impl ActivityCounts {
    /// Whether all counters are zero, i.e. the service reports idle.
    pub fn is_idle(&self) -> bool {
        self.connections == 0 && self.requests == 0 && self.holds == 0
    }
}

impl ManagedProcess {
    /// Create a new managed process from config.
    pub fn new(config: AppConfig) -> Self {
        Self {
            config,
            state: states::ServiceState::Stopped,
            target_state: states::ServiceState::Stopped,
            pid: None,
            network_pid: None,
            netns_fd: None,
            userns_fd: None,
            namespace_pid: None,
            mesh_tun_attached: false,
            pidfd: None,
            started_at: None,
            restarts: 0,
            consecutive_failures: 0,
            next_restart_at: None,
            cgroup_path: None,
            ready: false,
            last_watchdog_ping: None,
            last_stderr_at: None,
            last_active: None,
            last_sess: None,
            stop_reason: None,
            freeze_reason: None,
            explicit_freeze: false,
            idle_since: None,
            notify_activity: None,
            wake_at: None,
            freeze_ack: None,
            stopping_since: None,
        }
    }

    /// The supervised state seen by control clients. A pending freeze is
    /// still Running on the wire.
    pub fn protocol_state(&self) -> ServiceState {
        <crate::protocol::ServiceState>::from(self.state)
    }

    /// When the service became frozen, if it is frozen now.
    pub fn frozen_since(&self) -> Option<Instant> {
        match self.state {
            states::ServiceState::Frozen { since, .. } => Some(since),
            _ => None,
        }
    }

    /// The stop deadline recorded by a `Stopping` service, if any.
    pub fn stopping_deadline(&self) -> Option<Instant> {
        match self.state {
            states::ServiceState::Stopping { since } => Some(since),
            _ => self.stopping_since,
        }
    }

    fn stop_escalation_at(&self, grace: std::time::Duration) -> Option<Instant> {
        self.stopping_deadline().map(|since| since + grace)
    }

    /// Whether a stop is overdue and must escalate.
    pub fn stop_escalation_due(&self, now: Instant, grace: std::time::Duration) -> bool {
        self.stop_escalation_at(grace)
            .is_some_and(|deadline| now >= deadline && self.pid.is_some())
    }

    /// When a stopping service should next be checked for escalation.
    pub fn stop_escalation_deadline(&self, grace: std::time::Duration) -> Option<Instant> {
        self.stop_escalation_at(grace)
    }

    /// Get uptime in seconds, if running or frozen.
    pub fn uptime_secs(&self) -> Option<u64> {
        self.started_at.map(|t| t.elapsed().as_secs())
    }

    /// Convert to a status report.
    pub fn status(&self) -> crate::protocol::ServiceStatus {
        let activity = self.reported_activity();
        crate::protocol::ServiceStatus {
            name: self.config.name.clone(),
            state: self.protocol_state(),
            pid: self.pid,
            network_pid: self.network_pid,
            netns_registered: self.netns_fd.is_some(),
            userns_registered: self.userns_fd.is_some(),
            mesh_tun_attached: self.mesh_tun_attached,
            uptime_secs: self.uptime_secs(),
            restarts: self.restarts,
            consecutive_failures: self.consecutive_failures,
            next_restart_in_secs: self.next_restart_at.map(|t| {
                let now = Instant::now();
                if t > now { (t - now).as_secs() } else { 0 }
            }),
            cgroup_path: self.cgroup_path.clone(),
            stop_reason: self
                .stop_reason
                .filter(|_| self.protocol_state() == ServiceState::Stopped),
            freeze_reason: self
                .freeze_reason
                .filter(|_| matches!(self.state, states::ServiceState::Frozen { .. })),
            activity: activity.map(|counts| {
                serde_json::json!({
                    "connections": counts.connections,
                    "requests": counts.requests,
                    "holds": counts.holds,
                })
            }),
            idle: activity.as_ref().map(ActivityCounts::is_idle),
            memory_bytes: self.cgroup_memory_current(),
        }
    }

    /// The last reported activity counts, preferring the notify channel over
    /// the legacy stderr metrics.
    fn reported_activity(&self) -> Option<ActivityCounts> {
        if let Some(counts) = self.notify_activity {
            return Some(counts);
        }
        self.last_active.map(|active| ActivityCounts {
            connections: active.max(self.last_sess.unwrap_or(0)) as u32,
            requests: 0,
            holds: 0,
        })
    }

    /// Read memory.current from the service cgroup, best effort.
    pub fn cgroup_memory_current(&self) -> Option<u64> {
        let path = self.cgroup_path.as_deref()?;
        let value = crate::cgroup::read_cgroup_file(path, "memory.current").ok()?;
        value.trim().parse().ok()
    }
}

// ============================================================================
// Process Operations
// ============================================================================

/// How an FD should be passed to an activated service.
pub enum ActivationFd {
    /// Accept=true inetd style: accepted client socket to stdin/stdout/stderr.
    Stdio(std::os::fd::OwnedFd),
    /// Terminal-style activation with distinct stdin/stdout/stderr pipes.
    StdioPipes {
        stdin: std::os::fd::OwnedFd,
        stdout: std::os::fd::OwnedFd,
        stderr: std::os::fd::OwnedFd,
    },
    /// Terminal-style activation: PTY slave → controlling terminal and stdio.
    Pty(std::os::fd::OwnedFd),
    /// Accept=false mode: listening sockets passed to the child using systemd
    /// socket activation conventions: fd 3.. with `LISTEN_FDS=N`.
    Listen(Vec<ActivationListenFd>),
}

/// A listener fd plus its optional `LISTEN_FDNAMES` entry.
pub struct ActivationListenFd {
    pub fd: std::os::fd::OwnedFd,
    pub name: Option<String>,
}

fn open_standard_file(value: &str) -> Result<File, ProcessError> {
    if let Some(path) = value.strip_prefix("file:") {
        return OpenOptions::new()
            .create(true)
            .write(true)
            .open(path)
            .map_err(ProcessError::Io);
    }
    if let Some(path) = value.strip_prefix("append:") {
        return OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(ProcessError::Io);
    }
    if let Some(path) = value.strip_prefix("truncate:") {
        return OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(ProcessError::Io);
    }
    Err(ProcessError::SpawnFailed(format!(
        "unsupported stdio file target: {value}"
    )))
}

fn standard_stdio(value: Option<&str>, field: &str) -> Result<Stdio, ProcessError> {
    let value = value.unwrap_or("inherit").trim();
    match value {
        "" | "inherit" => Ok(Stdio::inherit()),
        "null" => Ok(Stdio::null()),
        "journal" | "journal+console" | "kmsg" | "kmsg+console" | "console" => {
            // mesh-init does not own a journal. Map common systemd log targets
            // to the daemon's own stdout/stderr destination.
            Ok(Stdio::inherit())
        }
        value
            if value.starts_with("file:")
                || value.starts_with("append:")
                || value.starts_with("truncate:") =>
        {
            open_standard_file(value).map(Stdio::from)
        }
        other => {
            warn!(field = %field, value = %other, "unsupported_stdio_setting");
            Err(ProcessError::SpawnFailed(format!(
                "unsupported {field} value: {other}"
            )))
        }
    }
}

fn apply_standard_io(
    cmd: &mut std::process::Command,
    config: &AppConfig,
) -> Result<(), ProcessError> {
    cmd.stdin(Stdio::null());

    let stdout = config
        .standard_output
        .as_deref()
        .unwrap_or("inherit")
        .trim();
    let stderr = config.standard_error.as_deref().unwrap_or("inherit").trim();

    if stderr == "stdout" {
        match stdout {
            "" | "inherit" => {
                cmd.stdout(Stdio::inherit());
                cmd.stderr(Stdio::inherit());
            }
            "null" => {
                cmd.stdout(Stdio::null());
                cmd.stderr(Stdio::null());
            }
            "journal" | "journal+console" | "kmsg" | "kmsg+console" | "console" => {
                cmd.stdout(Stdio::inherit());
                cmd.stderr(Stdio::inherit());
            }
            value
                if value.starts_with("file:")
                    || value.starts_with("append:")
                    || value.starts_with("truncate:") =>
            {
                let stdout_file = open_standard_file(value)?;
                let stderr_file = stdout_file.try_clone().map_err(ProcessError::Io)?;
                cmd.stdout(Stdio::from(stdout_file));
                cmd.stderr(Stdio::from(stderr_file));
            }
            other => {
                warn!(value = %other, "unsupported_stdout_setting");
                return Err(ProcessError::SpawnFailed(format!(
                    "unsupported StandardOutput value: {other}"
                )));
            }
        }
    } else {
        cmd.stdout(standard_stdio(
            config.standard_output.as_deref(),
            "StandardOutput",
        )?);
        cmd.stderr(standard_stdio(
            config.standard_error.as_deref(),
            "StandardError",
        )?);
    }

    Ok(())
}

/// Spawn a new process for a service.
///
/// Uses `std::process::Command` to fork and exec. Sets uid/gid if configured.
/// After spawn, moves the child into the service's cgroup and sets OOM score.
pub fn spawn_process(
    config: &AppConfig,
    cgroup_path: &str,
    passed_fd: Option<ActivationFd>,
) -> Result<(u32, Option<std::process::ChildStderr>), ProcessError> {
    info!(
        service = %config.name,
        command = %config.command,
        args = ?config.args,
        "spawning_service"
    );

    prepare_service_directories(config)?;

    let mut cmd = std::process::Command::new(&config.command);
    cmd.args(&config.args);
    let home = service_home(config);
    cmd.current_dir(config.working_directory.as_deref().unwrap_or(&home));

    // Set environment
    for (key, value) in &config.env {
        cmd.env(key, value);
    }
    // Every service receives its own mutable home by default. A config may
    // deliberately override HOME in [Environment] for an exceptional layout.
    cmd.env("HOME", &home);
    cmd.env(
        "PATH",
        config
            .env
            .get("PATH")
            .cloned()
            .unwrap_or_else(|| service_path(config)),
    );
    // Let common runtime facilities, including the default log writer, use
    // the supervised service identity rather than the executable name.
    cmd.env("MESH_SERVICE_NAME", &config.name);
    let sandbox = build_sandbox_plan(config)?;

    // A2: Privilege drop and hardening — all in pre_exec, in the correct
    // order. Rust's std applies cmd.uid()/cmd.gid() BEFORE pre_exec, which
    // means setgroups would fail (EPERM) after the uid drop. So we do NOT use
    // cmd.uid()/cmd.gid() and instead perform the full privilege drop inside
    // pre_exec where we control the ordering:
    //
    //   1. mount/capability namespace setup — needs privileges
    //   2. unshare(CLONE_NEWNET)            — needs CAP_SYS_ADMIN
    //   3. setgroups                        — needs CAP_SETGID; clear or set
    //   4. setresgid                        — drop GID
    //   5. setresuid                        — drop UID
    //   6. capability ambient/effective set — after identity drop if requested
    //   7. umask
    //   8. prctl(NoNewPrivs)                — when requested
    //
    // The PTY/listen pre_exec closures (registered after this one) run
    // next; they don't need root.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        let drop_uid = config.uid;
        let drop_gid = config.gid;
        let supplementary_groups = config.supplementary_groups.clone();
        let umask = config.umask;

        unsafe {
            cmd.pre_exec(move || {
                apply_sandbox_before_identity(&sandbox)?;
                // 2. Set supplementary groups (or clear them). Must run
                //    while we still have CAP_SETGID, i.e. before setresgid.
                if supplementary_groups.is_empty() {
                    // Clear all supplementary groups so the child doesn't
                    // retain the daemon's groups (root, disk, shadow, etc.).
                    let ret = libc::setgroups(0, std::ptr::null());
                    if ret < 0 {
                        let err = std::io::Error::last_os_error();
                        // EPERM is expected if we're already non-root.
                        if err.raw_os_error() != Some(libc::EPERM) {
                            return Err(err);
                        }
                    }
                } else {
                    let groups: Vec<libc::gid_t> = supplementary_groups
                        .iter()
                        .copied()
                        .map(|gid| gid as libc::gid_t)
                        .collect();
                    if libc::setgroups(groups.len(), groups.as_ptr()) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                // 3. Drop GID (real, effective, saved)
                if let Some(gid) = drop_gid {
                    if libc::setresgid(gid, gid, gid) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                // 4. Drop UID (real, effective, saved)
                if let Some(uid) = drop_uid {
                    if libc::setresuid(uid, uid, uid) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                if !sandbox.ambient_caps.is_empty() {
                    apply_capset(&sandbox.ambient_caps, true)?;
                    raise_ambient_caps(&sandbox.ambient_caps)?;
                    apply_capset(&sandbox.ambient_caps, false)?;
                } else if let Some(caps) = &sandbox.bounding_caps
                    && drop_uid.is_none()
                    && drop_gid.is_none()
                {
                    apply_capset(caps, false)?;
                }
                // 7. Umask
                if let Some(mask) = umask {
                    libc::umask(mask as libc::mode_t);
                }
                // 8. NoNewPrivs — prevents setuid re-escalation.
                if sandbox.no_new_privileges
                    && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let is_passed_fd_some = passed_fd.is_some();
    let mut _passed_fd_keepalive: Vec<std::os::fd::OwnedFd> = Vec::new();
    match passed_fd {
        Some(ActivationFd::Stdio(fd)) => {
            // inetd-style: map client socket to stdin/stdout/stderr
            let stdout_fd = fd.try_clone().map_err(ProcessError::Io)?;
            let stderr_fd = fd.try_clone().map_err(ProcessError::Io)?;
            cmd.stdin(std::process::Stdio::from(fd));
            cmd.stdout(std::process::Stdio::from(stdout_fd));
            cmd.stderr(std::process::Stdio::from(stderr_fd));
        }
        Some(ActivationFd::StdioPipes {
            stdin,
            stdout,
            stderr,
        }) => {
            cmd.stdin(std::process::Stdio::from(stdin));
            cmd.stdout(std::process::Stdio::from(stdout));
            cmd.stderr(std::process::Stdio::from(stderr));
        }
        Some(ActivationFd::Pty(fd)) => {
            use std::os::fd::AsRawFd;
            use std::os::unix::process::CommandExt;

            let raw_fd = fd.as_raw_fd();
            let stdin_fd = fd.try_clone().map_err(ProcessError::Io)?;
            let stdout_fd = fd.try_clone().map_err(ProcessError::Io)?;
            let stderr_fd = fd.try_clone().map_err(ProcessError::Io)?;
            cmd.stdin(std::process::Stdio::from(stdin_fd));
            cmd.stdout(std::process::Stdio::from(stdout_fd));
            cmd.stderr(std::process::Stdio::from(stderr_fd));
            _passed_fd_keepalive.push(fd);

            // SAFETY: pre_exec runs in the child after fork and before exec.
            // It only calls async-signal-safe libc operations.
            unsafe {
                cmd.pre_exec(move || {
                    if libc::setsid() < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::ioctl(raw_fd, libc::TIOCSCTTY, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::dup2(raw_fd, 0) < 0
                        || libc::dup2(raw_fd, 1) < 0
                        || libc::dup2(raw_fd, 2) < 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        Some(ActivationFd::Listen(fds)) => {
            // Accept=false: pass listening FDs to the child using systemd
            // socket activation conventions.
            use std::os::fd::AsRawFd;
            let raw_fds: Vec<i32> = fds.iter().map(|fd| fd.fd.as_raw_fd()).collect();
            cmd.env("LISTEN_FDS", raw_fds.len().to_string());
            cmd.env(
                "LISTEN_FDNAMES",
                fds.iter()
                    .map(|fd| fd.name.as_deref().unwrap_or(&config.name))
                    .collect::<Vec<_>>()
                    .join(":"),
            );
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                // SAFETY: only calls async-signal-safe libc functions
                unsafe {
                    cmd.pre_exec(move || {
                        for (idx, raw) in raw_fds.iter().copied().enumerate() {
                            let target_fd = 3 + idx as i32;
                            if libc::dup2(raw, target_fd) < 0 {
                                return Err(std::io::Error::last_os_error());
                            }
                            let flags = libc::fcntl(target_fd, libc::F_GETFD);
                            if flags >= 0 {
                                libc::fcntl(target_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
                            }
                        }
                        Ok(())
                    });
                }
            }
            // Keep the OwnedFd values alive so they aren't closed before exec. Hold them
            // until after `cmd.spawn()` returns; the child inherits the FD
            // values (CLOEXEC was cleared in pre_exec), and the parent's copy is
            // then closed when `_passed_fd_keepalive` drops at end of scope.
            _passed_fd_keepalive = fds.into_iter().map(|fd| fd.fd).collect();
        }
        None => {
            apply_standard_io(&mut cmd, config)?;
        }
    }

    let has_watchdog_or_ready = config.watchdog_sec.is_some()
        || config.ready_match.is_some()
        || config.idle_termination_sec.is_some();
    if has_watchdog_or_ready && !is_passed_fd_some {
        let std_err = config.standard_error.as_deref().unwrap_or("inherit").trim();
        if std_err == "null"
            || std_err.starts_with("file:")
            || std_err.starts_with("append:")
            || std_err.starts_with("truncate:")
        {
            warn!(value = %std_err, "stderr_redirected_watchdog_disabled");
        } else {
            cmd.stderr(std::process::Stdio::piped());
        }
    }

    let mut child = cmd.spawn().map_err(|e| {
        error!(service = %config.name, error = %e, "service_spawn_failed");
        ProcessError::SpawnFailed(format!("{}: {}", config.command, e))
    })?;

    let pid = child.id();
    let stderr = child.stderr.take();
    info!(service = %config.name, pid, "service_spawned");

    // Move into cgroup
    if let Err(e) = crate::cgroup::move_to_cgroup(pid, cgroup_path) {
        warn!(pid, cgroup = %cgroup_path, error = %e, "move_to_cgroup_failed");
    }

    // Set OOM score
    if let Some(oom) = config.oom_score_adjust
        && let Err(e) = crate::cgroup::set_oom_score(pid, oom)
    {
        warn!(pid, error = %e, "set_oom_score_failed");
    }

    Ok((pid, stderr))
}

pub fn run_service_command(
    config: &AppConfig,
    command: &str,
    timeout_secs: Option<u64>,
) -> Result<i32, ProcessError> {
    prepare_service_directories(config)?;
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-c").arg(command);
    for (key, value) in &config.env {
        cmd.env(key, value);
    }
    let home = service_home(config);
    cmd.env("HOME", &home);
    cmd.env(
        "PATH",
        config
            .env
            .get("PATH")
            .cloned()
            .unwrap_or_else(|| service_path(config)),
    );
    cmd.current_dir(config.working_directory.as_deref().unwrap_or(&home));

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        if let Some(uid) = config.uid {
            cmd.uid(uid);
        }
        if let Some(gid) = config.gid {
            cmd.gid(gid);
        }
    }

    let mut child = cmd.spawn().map_err(|e| {
        error!(command = %command, error = %e, "run_service_command_failed");
        ProcessError::SpawnFailed(format!("{}: {}", command, e))
    })?;
    let pid = child.id();
    let deadline = timeout_secs
        .filter(|secs| *secs > 0)
        .map(|secs| std::time::Instant::now() + std::time::Duration::from_secs(secs));

    loop {
        match child.try_wait().map_err(ProcessError::Io)? {
            Some(status) => return Ok(status.code().unwrap_or(1)),
            None => {
                if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                    let _ = send_signal(pid, libc::SIGKILL);
                    return Err(ProcessError::SpawnFailed(format!(
                        "service command timed out after {:?}: {}",
                        timeout_secs, command
                    )));
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }
}

/// Open a pidfd for the given PID. Caller owns the returned fd and
/// should store it in `ManagedProcess::pidfd`.
///
/// `pidfd_open(2)` returns a pollable fd that is invalidated when the
/// process exits, making it safe to use with `pidfd_send_signal(2)`
/// without PID-recycle risk. Requires Linux 5.3+; the daemon startup
/// check in `daemon::new` enforces this.
pub fn open_pidfd(pid: u32) -> Result<std::os::fd::OwnedFd, ProcessError> {
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_int, 0u32) };
    if raw < 0 {
        let err = std::io::Error::last_os_error();
        return Err(ProcessError::SignalError(format!(
            "pidfd_open({}): {}",
            pid, err
        )));
    }
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw as i32) };
    Ok(fd)
}

/// Send a signal to a process using `pidfd_send_signal(2)` if a pidfd
/// is available, falling back to `kill(2)` otherwise.
///
/// Prefer `pidfd_send_signal` because it cannot be confused with a
/// recycled PID — the pidfd is invalidated when the original process
/// exits.
pub fn send_signal_pidfd(
    pidfd: Option<&std::os::fd::OwnedFd>,
    pid: u32,
    signal: i32,
) -> Result<(), ProcessError> {
    if let Some(fd) = pidfd {
        let raw = fd.as_raw_fd();
        let res = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                raw,
                signal as libc::c_int,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        };
        if res == 0 {
            debug!(pid, signal, "pidfd_signal_sent");
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Err(ProcessError::NotFound(pid));
        }
        // Fall through to kill() for non-fatal errors (e.g. EINVAL on
        // some exotic signal values).
        warn!(pid, error = %err, "pidfd_signal_failed_falling_back");
    }
    send_signal(pid, signal)
}

/// Send a signal to a process.
pub fn send_signal(pid: u32, signal: i32) -> Result<(), ProcessError> {
    let res = unsafe { libc::kill(pid as i32, signal) };
    if res == 0 {
        debug!(pid, signal, "signal_sent");
        Ok(())
    } else {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            Err(ProcessError::NotFound(pid))
        } else {
            Err(ProcessError::SignalError(format!(
                "kill({}, {}): {}",
                pid, signal, err
            )))
        }
    }
}

/// Stop a process. Sends the given signal (default SIGTERM), waits briefly,
/// then sends SIGKILL if still alive.
///
/// A pidfd (from `pidfd_open(2)`) is used for signaling when available,
/// making the operation immune to PID recycling. Liveness is checked with
/// `waitpid(pid, WNOHANG)` rather than `kill(pid, 0)` to avoid the
/// PID-recycle hazard: if the child already exited and its PID was
/// recycled by the kernel, `kill(pid, 0)` would succeed (alive) and we
/// would SIGKILL an unrelated process. `waitpid(pid)` returns `ECHILD`
/// for a PID that is not our child (already reaped or recycled), so we
/// never signal a stranger.
pub async fn stop_process(
    pid: u32,
    pidfd: Option<&std::os::fd::OwnedFd>,
    signal: Option<i32>,
    timeout_secs: Option<u64>,
    send_sigkill: bool,
) -> Result<(), ProcessError> {
    let sig = signal.unwrap_or(libc::SIGTERM);
    info!(pid, signal = sig, "stopping_process");

    send_signal_pidfd(pidfd, pid, sig)?;

    // Give it a moment to exit
    tokio::time::sleep(std::time::Duration::from_secs(
        timeout_secs.unwrap_or(1).max(1),
    ))
    .await;

    // Check if the child has exited using waitpid on the specific PID.
    // Returns:
    //   0   — child still running
    //   pid — child exited, status reaped
    //  -1   — ECHILD: not our child (already reaped by the global reaper, or
    //         PID was recycled). Either way, do NOT escalate to SIGKILL.
    let mut status: libc::c_int = 0;
    let ret = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
    if ret == 0 && send_sigkill {
        warn!(
            pid,
            signal = sig,
            "process_alive_after_signal_escalating_to_sigkill"
        );
        let _ = send_signal_pidfd(pidfd, pid, libc::SIGKILL);
        // Reap the killed child if we can (best-effort; the global reaper may
        // race us, which is harmless).
        let mut s: libc::c_int = 0;
        let _ = unsafe { libc::waitpid(pid as libc::pid_t, &mut s, libc::WNOHANG) };
    } else if ret == 0 {
        warn!(pid, signal = sig, "process_alive_after_signal_no_sigkill");
    } else {
        debug!(
            "PID {} exited after signal {} (waitpid ret={})",
            pid, sig, ret
        );
    }

    Ok(())
}

/// Freeze a service cgroup and wait for the kernel to confirm it.
///
/// Freezing without a cgroup is refused: there is no SIGSTOP fallback, since a
/// SIGSTOPped process bypasses `pidfd_send_signal` wake-up guarantees and
/// cannot be trusted with socket wakeup semantics. Returns
/// `CgroupError::CgroupError` when the cgroup is missing or does not confirm
/// the frozen state within the timeout.
pub fn freeze_cgroup_confirmed(cgroup_path: &str, timeout: Duration) -> Result<(), ProcessError> {
    let events_path = format!("{cgroup_path}/cgroup.events");
    if !Path::new(&events_path).exists() {
        return Err(ProcessError::Cgroup(
            crate::cgroup::CgroupError::CgroupError(format!(
                "service has no cgroup {cgroup_path}; freeze refused"
            )),
        ));
    }
    crate::cgroup::freeze_cgroup(cgroup_path, true)?;
    let deadline = Instant::now() + timeout;
    loop {
        if crate::cgroup::cgroup_is_frozen(cgroup_path)? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            // Undo a half-applied freeze so the state model stays truthful.
            let _ = crate::cgroup::freeze_cgroup(cgroup_path, false);
            return Err(ProcessError::Cgroup(
                crate::cgroup::CgroupError::CgroupError(format!(
                    "cgroup {cgroup_path} did not confirm frozen state within {timeout:?}"
                )),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// Unfreeze a service cgroup. Thaw is a single write; no confirmation loop.
#[allow(dead_code)]
pub fn unfreeze_cgroup(cgroup_path: &str) -> Result<(), ProcessError> {
    crate::cgroup::freeze_cgroup(cgroup_path, false)?;
    info!(cgroup = %cgroup_path, "cgroup_unfrozen");
    Ok(())
}

/// Start the background task to listen for child process exits.
/// When a child exits, its PID and exit code are sent through the channel.
///
/// When running as PID 1 (or with `MESH_INIT_REAP_ALL=1`), uses
/// `waitpid(-1, WNOHANG)` to reap any child. When not PID 1, this is dangerous
/// because `waitpid(-1)` reaps *every* child of the process, stealing exit
/// notifications from any other `Child::wait()` caller in the same process
/// (e.g. libraries that spawn helper processes). In that case we instead reap
/// only PIDs that the caller registers via the returned `tracked_pids` set.
pub fn start_child_reaper(
    tx: tokio::sync::mpsc::Sender<(u32, i32)>,
) -> std::sync::Arc<parking_lot::Mutex<std::collections::HashSet<u32>>> {
    let tracked_pids =
        std::sync::Arc::new(parking_lot::Mutex::new(std::collections::HashSet::new()));
    let reap_all = is_pid1()
        || std::env::var("MESH_INIT_REAP_ALL")
            .map(|v| v.trim().eq_ignore_ascii_case("1") || v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false);
    let tracked = tracked_pids.clone();

    tokio::spawn(async move {
        let mut sigchld = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child())
        {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "register_sigchld_failed");
                return;
            }
        };

        loop {
            sigchld.recv().await;

            if reap_all {
                // PID 1: reap all children.
                loop {
                    let mut status = 0;
                    let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
                    if pid <= 0 {
                        break;
                    }
                    let exit_code = exit_code_from_status(status);
                    debug!(pid, exit_code, "reaped_child");
                    let _ = tx.send((pid as u32, exit_code)).await;
                }
            } else {
                // Not PID 1: reap only tracked PIDs to avoid stealing reaps
                // from other Child::wait() callers in this process.
                let pids: Vec<u32> = tracked.lock().iter().copied().collect();
                for pid in pids {
                    let mut status = 0;
                    let ret =
                        unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
                    if ret == pid as libc::pid_t {
                        let exit_code = exit_code_from_status(status);
                        debug!(pid, exit_code, "reaped_tracked_child");
                        tracked.lock().remove(&pid);
                        let _ = tx.send((pid, exit_code)).await;
                    } else if ret > 0 {
                        // reaped but pid mismatch (shouldn't happen for specific pid)
                        tracked.lock().remove(&pid);
                    }
                    // ret == 0: still running; ret < 0: already reaped or not ours
                    if ret < 0 {
                        tracked.lock().remove(&pid);
                    }
                }
            }
        }
    });

    tracked_pids
}

fn exit_code_from_status(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        -libc::WTERMSIG(status)
    } else {
        -1
    }
}

/// Check if the current process is PID 1.
pub fn is_pid1() -> bool {
    std::process::id() == 1
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Read;
    use std::os::fd::{FromRawFd, OwnedFd};

    fn test_config(name: &str) -> AppConfig {
        AppConfig {
            name: name.to_string(),
            command: "/bin/true".to_string(),
            args: vec![],
            uid: None,
            gid: None,
            user: None,
            group: None,
            env: HashMap::new(),
            priority: 500,
            oneshot: false,
            oom_score_adjust: None,
            resources: crate::config::ResolvedResourceLimits::default(),
            activation: vec![],
            source_path: None,
            ..Default::default()
        }
    }

    #[test]
    fn default_service_path_prefers_service_local_bins() {
        let config = test_config("echo");
        let paths = mesh::paths::AppPaths::for_app("echo");
        let path = service_path(&config);
        assert!(path.starts_with(&format!("{}/bin:", paths.home.display())));
        assert!(path.contains(&format!("{}/.nix-profile/bin", paths.home.display())));
        assert!(path.contains(":/run/current-system/sw/bin:"));
        assert!(path.contains(":/usr/bin:"));
    }

    #[test]
    fn configured_home_controls_service_path() {
        let mut config = test_config("echo");
        config
            .env
            .insert("HOME".to_string(), "/srv/echo".to_string());
        assert!(service_path(&config).starts_with("/srv/echo/bin:"));
    }

    #[test]
    fn test_pty_activation_gives_child_terminal() {
        let mut config = test_config("pty-test");
        config.command = "/bin/sh".to_string();
        config.args = vec![
            "-c".to_string(),
            "if test -t 0; then echo tty-ok; else echo no-tty; fi".to_string(),
        ];
        config.oneshot = true;

        let mut master = 0;
        let mut slave = 0;
        let open_result = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(
            open_result,
            0,
            "openpty failed: {}",
            std::io::Error::last_os_error()
        );

        let mut master = unsafe { std::fs::File::from_raw_fd(master) };
        let slave = unsafe { OwnedFd::from_raw_fd(slave) };
        let (pid, _) =
            spawn_process(&config, "/sys/fs/cgroup", Some(ActivationFd::Pty(slave))).unwrap();

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid as i32, &mut status, 0) };
        assert_eq!(waited, pid as i32);
        assert!(libc::WIFEXITED(status), "status={status}");
        assert_eq!(libc::WEXITSTATUS(status), 0, "status={status}");

        let mut output = String::new();
        let _ = master.read_to_string(&mut output);
        assert!(output.contains("tty-ok"), "{output}");
    }

    #[test]
    fn test_listen_activation_sets_fd_names() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("fdnames");
        let (fd, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(peer);

        let mut config = test_config("fdnames-test");
        config.command = "/bin/sh".to_string();
        config.args = vec![
            "-c".to_string(),
            format!("printf '%s' \"$LISTEN_FDNAMES\" > {}", out.display()),
        ];
        config.oneshot = true;

        let (pid, _) = spawn_process(
            &config,
            "/sys/fs/cgroup",
            Some(ActivationFd::Listen(vec![ActivationListenFd {
                fd: fd.into(),
                name: Some("http".to_string()),
            }])),
        )
        .unwrap();

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid as i32, &mut status, 0) };
        assert_eq!(waited, pid as i32);
        assert!(libc::WIFEXITED(status), "status={status}");
        assert_eq!(libc::WEXITSTATUS(status), 0, "status={status}");

        assert_eq!(std::fs::read_to_string(out).unwrap(), "http");
    }

    #[test]
    fn service_directories_use_service_name_under_standard_bases() {
        let paths = mesh::paths::AppPaths::for_app("example-service");
        assert_eq!(paths.home.file_name().unwrap(), "example-service");
        assert_eq!(paths.mesh_ipc_dir.file_name().unwrap(), "example-service");
    }

    #[test]
    fn ssh_mesh_default_has_a_non_root_identity_and_inherits_its_home() {
        let config = crate::config::parse_service(
            include_str!("../defaults/ssh-mesh.toml"),
            Some("ssh-mesh"),
        )
        .unwrap();
        assert_eq!(config.uid, Some(150));
        assert_eq!(config.gid, Some(150));
        assert!(!config.env.contains_key("HOME"));
        assert_eq!(
            mesh::paths::AppPaths::for_app(&config.name)
                .home
                .file_name()
                .unwrap(),
            "ssh-mesh"
        );
    }

    #[test]
    fn sandbox_plan_accepts_common_hardening_fields() {
        let mut config = test_config("sandbox-plan");
        config.private_tmp = true;
        config.private_devices = true;
        config.private_network = true;
        config.no_new_privileges = true;
        config.protect_system = Some("full".to_string());
        config.protect_home = Some("read-only".to_string());
        config.read_write_paths = vec!["/tmp".to_string()];
        config.read_only_paths = vec!["/etc".to_string()];
        config.capability_bounding_set = Some(vec![
            "CAP_NET_BIND_SERVICE".to_string(),
            "CAP_SETPCAP".to_string(),
        ]);
        config.ambient_capabilities = vec!["CAP_NET_BIND_SERVICE".to_string()];

        let plan = build_sandbox_plan(&config).unwrap();
        assert!(plan.needs_mount_namespace());
        assert_eq!(plan.protect_system, Some(ProtectSystemMode::Full));
        assert_eq!(plan.protect_home, Some(ProtectHomeMode::ReadOnly));
        assert_eq!(
            plan.bounding_caps.as_ref().unwrap(),
            &vec![CAP_NET_BIND_SERVICE, CAP_SETPCAP]
        );
        assert_eq!(plan.ambient_caps, vec![CAP_NET_BIND_SERVICE]);
    }

    #[test]
    fn sandbox_plan_rejects_unsupported_protect_value() {
        let mut config = test_config("bad-protect");
        config.protect_system = Some("kernel-tent".to_string());
        let err = build_sandbox_plan(&config).unwrap_err();
        assert!(err.to_string().contains("unsupported ProtectSystem"));
    }

    #[test]
    fn sandbox_plan_rejects_unsupported_capability() {
        let mut config = test_config("bad-cap");
        config.capability_bounding_set = Some(vec!["CAP_WAKE_ALARM".to_string()]);
        let err = build_sandbox_plan(&config).unwrap_err();
        assert!(err.to_string().contains("CapabilityBoundingSet capability"));
    }

    #[test]
    fn sandbox_plan_explicit_empty_bounding_set_drops_all() {
        let mut config = test_config("drop-all-caps");
        config.capability_bounding_set = Some(Vec::new());
        let plan = build_sandbox_plan(&config).unwrap();
        assert_eq!(plan.bounding_caps.as_ref().unwrap(), &Vec::<i32>::new());
    }

    #[test]
    fn sandbox_plan_requires_ambient_subset_and_setpcap() {
        let mut config = test_config("bad-ambient");
        config.capability_bounding_set = Some(vec!["CAP_NET_BIND_SERVICE".to_string()]);
        config.ambient_capabilities = vec!["CAP_NET_BIND_SERVICE".to_string()];
        let err = build_sandbox_plan(&config).unwrap_err();
        assert!(err.to_string().contains("requires CAP_SETPCAP"));

        config.capability_bounding_set =
            Some(vec!["CAP_SETPCAP".to_string(), "CAP_NET_ADMIN".to_string()]);
        let err = build_sandbox_plan(&config).unwrap_err();
        assert!(err.to_string().contains("subset"));
    }

    #[test]
    fn sandbox_plan_accepts_net_raw_for_radio_services() {
        let mut config = test_config("radio-caps");
        config.capability_bounding_set = Some(vec![
            "CAP_SETPCAP".to_string(),
            "CAP_NET_ADMIN".to_string(),
            "CAP_NET_RAW".to_string(),
        ]);
        config.ambient_capabilities = vec!["CAP_NET_ADMIN".to_string(), "CAP_NET_RAW".to_string()];

        let plan = build_sandbox_plan(&config).unwrap();
        assert_eq!(
            plan.bounding_caps.as_ref().unwrap(),
            &vec![CAP_SETPCAP, CAP_NET_ADMIN, CAP_NET_RAW]
        );
        assert_eq!(plan.ambient_caps, vec![CAP_NET_ADMIN, CAP_NET_RAW]);
    }

    #[test]
    fn unsupported_sandbox_request_fails_service_spawn() {
        let mut config = test_config("bad-sandbox-spawn");
        config.protect_home = Some("maybe".to_string());
        let err = spawn_process(&config, "/sys/fs/cgroup", None).unwrap_err();
        assert!(err.to_string().contains("unsupported ProtectHome"));
    }

    #[test]
    fn private_tmp_smoke_when_mount_namespace_allowed() {
        let mut config = test_config("private-tmp-smoke");
        config.command = "/bin/sh".to_string();
        config.args = vec![
            "-c".to_string(),
            "test -d /tmp && touch /tmp/mesh-init-private-tmp-smoke".to_string(),
        ];
        config.private_tmp = true;

        let pid = match spawn_process(&config, "/sys/fs/cgroup", None) {
            Ok((pid, _)) => pid,
            Err(ProcessError::SpawnFailed(error))
                if error.contains("Operation not permitted") || error.contains("EPERM") =>
            {
                eprintln!("skipping PrivateTmp smoke: mount namespace unavailable: {error}");
                return;
            }
            Err(error) => panic!("unexpected PrivateTmp spawn error: {error}"),
        };

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid as i32, &mut status, 0) };
        assert_eq!(waited, pid as i32);
        assert!(libc::WIFEXITED(status), "status={status}");
        assert_eq!(libc::WEXITSTATUS(status), 0, "status={status}");
    }

    #[test]
    fn test_managed_process_status() {
        let mut proc = ManagedProcess::new(test_config("my-svc"));
        proc.state = states::ServiceState::Running;
        proc.pid = Some(42);
        proc.restarts = 3;

        let status = proc.status();
        assert_eq!(status.name, "my-svc");
        assert_eq!(status.state, ServiceState::Running);
        assert_eq!(status.pid, Some(42));
        assert_eq!(status.restarts, 3);
    }

    #[test]
    fn test_activity_counts_idle() {
        assert!(ActivityCounts::default().is_idle());
        let counts = ActivityCounts {
            connections: 1,
            requests: 0,
            holds: 0,
        };
        assert!(!counts.is_idle());
    }

    #[test]
    fn test_is_pid1() {
        // We're not PID 1 in tests
        assert!(!is_pid1());
    }
}
