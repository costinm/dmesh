use anyhow::Result;
use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::CString;
use std::fmt;

use crate::auth::{AuthConfig, ImpersonationRule, PeerConfig};

/// Default IP MTU used by mesh-tun managed TAP namespaces.
///
/// 65520 leaves room for IPv4 and TCP headers under the IPv4 65535-byte
/// packet limit while still allowing Linux to send near-maximum TCP segments.
pub const DEFAULT_MESH_TUN_MTU: u32 = 65_520;

// ============================================================================
// Service / Job Unified Config
// ============================================================================

/// Top-level TOML structure for a mesh-init service or job config file.
///
/// Keep `crates/mesh-init/examples/all-fields.toml` in sync with this parser.
/// That example is the canonical annotated reference for every supported field,
/// including where each field applies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppConfigFile {
    #[serde(rename = "Service")]
    pub service: ServiceSection,
    /// Optional endpoint and catalog information consumed by generic mesh
    /// clients. This is intentionally part of the common service definition so
    /// callers do not need the legacy OpenSSH configuration parser.
    #[serde(default, rename = "Mesh")]
    pub mesh: Option<MeshSection>,
    #[serde(default, rename = "Socket")]
    pub socket: Option<SocketSection>,
    #[serde(default, rename = "Resources")]
    pub resources: ResourceLimits,
    #[serde(default, rename = "Environment")]
    pub environment: HashMap<String, String>,
    #[serde(default, rename = "Network")]
    pub network: NetworkConfig,
    #[serde(default, rename = "Schedule")]
    pub schedule: Option<ScheduleConfig>,
    #[serde(default, rename = "Constraints")]
    pub constraints: Option<ConstraintConfig>,
    #[serde(default, rename = "Backoff")]
    pub backoff: BackoffConfig,
    /// Authorization peer entries. Same shape as standalone `auth.toml`.
    #[serde(default, rename = "Peer")]
    pub peers: Vec<PeerConfig>,
    /// Identity impersonation entries. Same shape as standalone auth.
    #[serde(default, rename = "MeshImpersonation")]
    pub impersonation: Vec<ImpersonationRule>,

    // Job-specific metadata
    #[serde(default = "default_true", rename = "MeshPersisted")]
    pub persisted: bool,
    #[serde(default, rename = "MeshPrefetch")]
    pub prefetch: bool,
    #[serde(default, rename = "MeshSaveResult")]
    pub save_result: bool,
    #[serde(rename = "MeshTraceTag")]
    pub trace_tag: Option<String>,
    #[serde(default, rename = "MeshUserInitiated")]
    pub user_initiated: bool,
    #[serde(default, rename = "MeshExpedited")]
    pub expedited: bool,
    #[serde(rename = "MeshEstimatedDownloadBytes")]
    pub estimated_download_bytes: Option<u64>,
    #[serde(rename = "MeshEstimatedUploadBytes")]
    pub estimated_upload_bytes: Option<u64>,
    #[serde(rename = "MeshMinimumNetworkChunkBytes")]
    pub minimum_network_chunk_bytes: Option<u64>,
}

/// Client-visible mesh endpoint metadata for one service.
///
/// A service name may resolve to this endpoint before normal host discovery.
/// `address` accepts the same URI forms as the `mesh` CLI; an omitted address
/// uses the service's standard mesh Unix socket.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshSection {
    /// Explicit endpoint URI or path for this logical service/host.
    #[serde(rename = "Address")]
    pub address: Option<String>,
    /// Transport selected for an endpoint whose address alone is ambiguous.
    #[serde(rename = "Transport")]
    pub transport: Option<String>,
    /// Optional OpenSSH-compatible local ControlMaster socket path.
    #[serde(rename = "ControlPath")]
    pub control_path: Option<String>,
    /// Default outbound encoding: `auto`, `cbor`, `json`, `text`, or `mux`.
    #[serde(rename = "DestinationFormat")]
    pub destination_format: Option<String>,
    /// Stable advertised/discovery name when it differs from the service name.
    #[serde(rename = "DiscoveryName")]
    pub discovery_name: Option<String>,
}

/// The `[Service]` section of a config file.
///
/// When adding or changing fields here, update
/// `crates/mesh-init/examples/all-fields.toml` and `crates/mesh-init/CONFIG.md`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ServiceSection {
    #[serde(rename = "ExecStart")]
    pub exec_start: String,
    #[serde(default, rename = "ExecStartPre", deserialize_with = "string_or_vec")]
    pub exec_start_pre: Vec<String>,
    #[serde(default, rename = "ExecStartPost", deserialize_with = "string_or_vec")]
    pub exec_start_post: Vec<String>,
    #[serde(default, rename = "ExecStop", deserialize_with = "string_or_vec")]
    pub exec_stop: Vec<String>,
    #[serde(default, rename = "ExecReload", deserialize_with = "string_or_vec")]
    pub exec_reload: Vec<String>,
    /// How mesh-init handles Accept=true socket-unit activations for this
    /// service. `stdio` is classic inetd. `hybrid` starts the service with a
    /// systemd-style JSONL listener first, then forwards accepted connection
    /// FDs to that JSONL socket.
    #[serde(default, rename = "MeshActivationMode")]
    pub activation_mode: ServiceActivationMode,
    /// JSONL Unix socket used by hybrid activation. Defaults to
    /// `/home/<service>/run/<service>/control.sock` when omitted.
    #[serde(rename = "MeshActivationSocket")]
    pub activation_socket: Option<String>,
    /// What mesh-init does after the idleFreezeSec window elapses while the
    /// service reports itself idle. `freeze` (default when a freeze window is
    /// configured), `stop`, or `none`.
    #[serde(rename = "IdleAction")]
    pub idle_action: Option<String>,
    /// Freeze the service after this much self-reported idle time.
    #[serde(rename = "IdleFreezeSec")]
    pub idle_freeze_sec: Option<serde_json::Value>,
    /// Optional `socket` detection option (phase 2e), reserved.
    #[serde(rename = "IdleDetect")]
    pub idle_detect: Option<String>,
    #[serde(rename = "User")]
    pub user: Option<String>,
    #[serde(rename = "Group")]
    pub group: Option<String>,
    #[serde(rename = "WorkingDirectory")]
    pub working_directory: Option<String>,
    #[serde(default, rename = "Restart")]
    pub restart: RestartPolicy,
    #[serde(rename = "RestartSec")]
    pub restart_sec: Option<String>,
    #[serde(rename = "ReadyMatch")]
    pub ready_match: Option<String>,
    #[serde(rename = "WatchdogMatch")]
    pub watchdog_match: Option<String>,
    #[serde(rename = "WatchdogSec")]
    pub watchdog_sec: Option<serde_json::Value>,
    #[serde(rename = "IdleTerminationSec")]
    pub idle_termination_sec: Option<serde_json::Value>,
    #[serde(rename = "TimeoutStartSec")]
    pub timeout_start_sec: Option<String>,
    #[serde(rename = "TimeoutStopSec")]
    pub timeout_stop_sec: Option<String>,
    #[serde(rename = "KillSignal")]
    pub kill_signal: Option<String>,
    #[serde(default, rename = "KillMode")]
    pub kill_mode: KillMode,
    #[serde(default = "default_true", rename = "SendSIGKILL")]
    pub send_sigkill: bool,
    #[serde(rename = "UMask")]
    pub umask: Option<String>,
    #[serde(rename = "StandardOutput")]
    pub standard_output: Option<String>,
    #[serde(rename = "StandardError")]
    pub standard_error: Option<String>,
    #[serde(
        default,
        rename = "SupplementaryGroups",
        deserialize_with = "string_or_vec"
    )]
    pub supplementary_groups: Vec<String>,
    /// Dangerous environment variables that callers may pass to this service.
    ///
    /// Caller-supplied env is otherwise filtered against mesh-init's dangerous
    /// env list. Entries support exact names and a trailing `*` prefix match.
    #[serde(
        default,
        rename = "AllowDangerousEnv",
        deserialize_with = "string_or_vec"
    )]
    pub allow_dangerous_env: Vec<String>,
    /// `Type=oneshot` marks the service as one-shot and disables restart.
    /// `Type=notify` enables readiness via `READY=1` on NOTIFY_SOCKET.
    #[serde(rename = "Type")]
    pub service_type: Option<String>,
    /// OOM score adjustment (-1000 to 1000).
    #[serde(rename = "OOMScoreAdjust")]
    pub oom_score_adjust: Option<i32>,
    /// Shield this service from pressure eviction entirely.
    #[serde(rename = "Evictable")]
    pub evictable: Option<bool>,
    /// Reclaim memory from the service when it is frozen.
    #[serde(rename = "MemoryReclaimOnFreeze")]
    pub memory_reclaim_on_freeze: Option<bool>,
    #[serde(default, rename = "NoNewPrivileges")]
    pub no_new_privileges: bool,
    #[serde(default, rename = "PrivateTmp")]
    pub private_tmp: bool,
    #[serde(default, rename = "PrivateDevices")]
    pub private_devices: bool,
    #[serde(default, rename = "PrivateNetwork")]
    pub private_network: bool,
    #[serde(rename = "ProtectSystem")]
    pub protect_system: Option<String>,
    #[serde(rename = "ProtectHome")]
    pub protect_home: Option<String>,
    #[serde(default, rename = "ReadWritePaths", deserialize_with = "string_or_vec")]
    pub read_write_paths: Vec<String>,
    #[serde(default, rename = "ReadOnlyPaths", deserialize_with = "string_or_vec")]
    pub read_only_paths: Vec<String>,
    #[serde(
        default,
        rename = "InaccessiblePaths",
        deserialize_with = "string_or_vec"
    )]
    pub inaccessible_paths: Vec<String>,
    #[serde(
        default,
        rename = "CapabilityBoundingSet",
        deserialize_with = "option_string_or_vec"
    )]
    pub capability_bounding_set: Option<Vec<String>>,
    #[serde(
        default,
        rename = "AmbientCapabilities",
        deserialize_with = "string_or_vec"
    )]
    pub ambient_capabilities: Vec<String>,
}

/// The optional `[Socket]` section of a config file.
///
/// `[[Socket.Listen]]` preserves mixed stream/datagram declaration order.
/// `ListenStream` and `ListenDatagram` remain shorthand forms. Keep
/// `crates/mesh-init/examples/all-fields.toml` updated when socket fields
/// change.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SocketSection {
    #[serde(default, rename = "Listen")]
    pub listen: Vec<SocketListenEntry>,
    #[serde(default, rename = "ListenStream", deserialize_with = "string_or_vec")]
    pub listen_streams: Vec<String>,
    #[serde(default, rename = "ListenDatagram", deserialize_with = "string_or_vec")]
    pub listen_datagrams: Vec<String>,
    #[serde(default, rename = "Accept")]
    pub accept: bool,
    #[serde(rename = "SocketMode")]
    pub socket_mode: Option<u32>,
    #[serde(rename = "SocketUser")]
    pub socket_user: Option<String>,
    #[serde(rename = "SocketGroup")]
    pub socket_group: Option<String>,
    #[serde(
        default,
        rename = "FileDescriptorName",
        deserialize_with = "string_or_vec"
    )]
    pub file_descriptor_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SocketListenEntry {
    #[serde(rename = "Type")]
    pub listen_type: SocketListenType,
    #[serde(rename = "Address")]
    pub address: String,
    #[serde(rename = "Name")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SocketListenType {
    Stream,
    Datagram,
}

/// The `[resources]` section — maps to cgroup v2 knobs.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ResourceLimits {
    #[serde(rename = "MemoryMin", alias = "memory_min", alias = "memory.low")]
    pub memory_low: Option<String>,
    #[serde(rename = "MemoryHigh", alias = "memory_high", alias = "memory.high")]
    pub memory_high: Option<String>,
    #[serde(rename = "MemoryMax", alias = "memory_max", alias = "memory.max")]
    pub memory_max: Option<String>,
    #[serde(rename = "CPUWeight", alias = "cpu_weight", alias = "cpu.weight")]
    pub cpu_weight: Option<u32>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    #[default]
    No,
    Always,
    OnSuccess,
    OnFailure,
    OnAbnormal,
    OnAbort,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum KillMode {
    #[default]
    ControlGroup,
    Mixed,
    Process,
    None,
}

/// What the supervisor does when a service has been idle for its window.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum IdleAction {
    /// Freeze the cgroup until a connection wakes the service.
    Freeze,
    /// Terminate the service, like IdleTerminationSec alone.
    Stop,
    /// Leave the service running.
    #[default]
    None,
}

/// Service-level behavior for Accept=true socket activations.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceActivationMode {
    /// Classic inetd: accepted socket becomes child stdin/stdout/stderr.
    #[default]
    Stdio,
    /// Hybrid: service receives its JSONL listener first, then accepted FDs
    /// are sent to that socket with SCM_RIGHTS.
    Hybrid,
}

/// Socket activation entry derived from a service TOML `[Socket]` table.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ActivationConfig {
    pub port: Option<u16>,
    pub socket: Option<String>,
    /// AF_VSOCK CID for `ListenStream=vsock:CID:PORT`. An omitted CID in the
    /// socket unit is represented as `None` and defaults to VMADDR_CID_ANY at
    /// bind time.
    #[serde(default)]
    pub vsock_cid: Option<u32>,
    /// AF_VSOCK port for `ListenStream=vsock:CID:PORT`.
    #[serde(default)]
    pub vsock_port: Option<u32>,
    #[serde(default)]
    pub wait: bool,
    /// Bind address for TCP activation. For systemd-style `[Socket]`, a bare
    /// `ListenStream=PORT` defaults to IPv6-any with dual-stack enabled where
    /// the OS permits it. Inline activation entries without `bind` use the same
    /// default.
    #[serde(default)]
    pub bind: Option<String>,
    /// File descriptor name passed through `LISTEN_FDNAMES` for systemd-style
    /// activation. From `[Socket]` this comes from `FileDescriptorName`,
    /// defaulting to the service name.
    #[serde(default)]
    pub fd_name: Option<String>,
    /// ListenDatagram (true) vs ListenStream (false). Maps to SOCK_DGRAM vs
    /// SOCK_STREAM. Datagram activation with Accept=true is not supported.
    #[serde(default)]
    pub datagram: bool,
    /// Socket file permissions (octal, e.g. 0o660) for UDS activation.
    /// Ignored for TCP and when receiving FDs from systemd activation.
    pub socket_mode: Option<u32>,
    /// Socket file owner for UDS activation. Ignored for TCP.
    pub socket_user: Option<String>,
    /// Socket file group for UDS activation. Ignored for TCP.
    pub socket_group: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkBackend {
    #[default]
    None,
    Pasta,
    MeshTun,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkConfig {
    #[serde(default)]
    pub backend: NetworkBackend,
    /// Backend command for sidecars like pasta.
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Control socket for a shared mesh-tun daemon.
    pub control_socket: Option<String>,
    /// Interface name created in the service network namespace.
    pub if_name: Option<String>,
    /// Address assigned to the service side of the TAP, for example `10.5.0.2/24`.
    pub address: Option<String>,
    /// Gateway used for the service default route.
    pub gateway: Option<String>,
    /// MTU for the service-side TAP interface.
    pub mtu: Option<u32>,
    /// Install a default route through the TAP gateway.
    #[serde(default)]
    pub default_route: bool,
    /// Redirect service TCP egress to this in-namespace listener port.
    ///
    /// mesh-tun uses this for an Istio-style fast path: nftables captures TCP
    /// connections at connect time, while TAP remains available for UDP and
    /// any future TCP traffic intentionally excluded from the redirect policy.
    pub egress_redirect_port: Option<u16>,
    /// Optional uid excluded from egress redirect rules.
    pub egress_redirect_uid: Option<u32>,
}

// ============================================================================
// Job-Specific Configuration Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkType {
    #[default]
    None,
    Any,
    Unmetered,
    NotRoaming,
    Cellular,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BackoffPolicy {
    Linear,
    #[default]
    Exponential,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackoffConfig {
    pub initial_secs: u64,
    #[serde(default)]
    pub policy: BackoffPolicy,
    #[serde(default)]
    pub max_retries: Option<u32>,
    /// Hard cap on the computed backoff delay in seconds. Defaults to 24h to
    /// prevent an exponential backoff from scheduling effectively-never after
    /// many failures. Set to override.
    #[serde(default = "default_max_backoff_secs")]
    pub max_secs: u64,
}

fn default_max_backoff_secs() -> u64 {
    24 * 60 * 60
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            initial_secs: 1,
            policy: BackoffPolicy::Exponential,
            max_retries: None,
            max_secs: default_max_backoff_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ScheduleConfig {
    pub periodic_secs: Option<u64>,
    pub flex_secs: Option<u64>,
    pub minimum_latency_secs: Option<u64>,
    pub override_deadline_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ConstraintConfig {
    pub network_type: Option<NetworkType>,
    #[serde(default)]
    pub requires_charging: bool,
    #[serde(default)]
    pub requires_device_idle: bool,
    #[serde(default)]
    pub requires_battery_not_low: bool,
    #[serde(default)]
    pub requires_storage_not_low: bool,
    #[serde(default)]
    pub triggers: Vec<String>,
    pub trigger_max_delay_secs: Option<u64>,
    #[serde(default)]
    pub custom: HashMap<String, bool>,
}

// ============================================================================
// Resolved Config (Used in runtime)
// ============================================================================

/// Parsed, validated unified configuration.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AppConfig {
    // Service base
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub exec_start_pre: Vec<String>,
    pub exec_start_post: Vec<String>,
    pub exec_stop: Vec<String>,
    pub exec_reload: Vec<String>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub working_directory: Option<String>,
    pub restart: RestartPolicy,
    pub restart_sec: u64,
    pub timeout_start_sec: Option<u64>,
    pub timeout_stop_sec: Option<u64>,
    pub kill_signal: i32,
    pub kill_mode: KillMode,
    pub send_sigkill: bool,
    pub umask: Option<u32>,
    pub standard_output: Option<String>,
    pub standard_error: Option<String>,
    pub supplementary_groups: Vec<u32>,
    pub env: HashMap<String, String>,
    pub allow_dangerous_env: Vec<String>,
    pub priority: u32,
    pub oneshot: bool,
    pub service_type: Option<String>,
    pub ready_match: Option<String>,
    pub watchdog_match: Option<String>,
    pub watchdog_sec: Option<u64>,
    pub idle_termination_sec: Option<u64>,
    pub idle_action: IdleAction,
    pub idle_freeze_sec: Option<u64>,
    pub evictable: Option<bool>,
    pub memory_reclaim_on_freeze: Option<bool>,
    pub activation_mode: ServiceActivationMode,
    pub activation_socket: Option<String>,
    pub oom_score_adjust: Option<i32>,
    pub no_new_privileges: bool,
    pub private_tmp: bool,
    pub private_devices: bool,
    pub private_network: bool,
    pub protect_system: Option<String>,
    pub protect_home: Option<String>,
    pub read_write_paths: Vec<String>,
    pub read_only_paths: Vec<String>,
    pub inaccessible_paths: Vec<String>,
    pub capability_bounding_set: Option<Vec<String>>,
    pub ambient_capabilities: Vec<String>,
    pub resources: ResolvedResourceLimits,
    pub activation: Vec<ActivationConfig>,
    pub network: NetworkConfig,
    /// Optional client-visible endpoint metadata from the common `[Mesh]`
    /// service-definition section.
    pub mesh: Option<MeshSection>,
    pub source_path: Option<String>,
    /// Resolved authorization config from `[[peer]]` entries.
    pub auth: Option<AuthConfig>,

    // Job optional sections
    pub schedule: Option<ScheduleConfig>,
    pub constraints: Option<ConstraintConfig>,
    pub backoff: BackoffConfig,

    // Job metadata
    pub persisted: bool,
    pub prefetch: bool,
    pub save_result: bool,
    pub trace_tag: Option<String>,
    pub user_initiated: bool,
    pub expedited: bool,
    pub estimated_download_bytes: Option<u64>,
    pub estimated_upload_bytes: Option<u64>,
    pub minimum_network_chunk_bytes: Option<u64>,
}

impl AppConfig {
    /// True if this config has schedule or constraints, i.e. it's a job.
    pub fn is_job(&self) -> bool {
        self.schedule.is_some() || self.constraints.is_some()
    }
}

/// Resource limits with human-readable sizes resolved to bytes.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ResolvedResourceLimits {
    pub memory_low: Option<u64>,
    pub memory_high: Option<u64>,
    pub memory_max: Option<u64>,
    pub cpu_weight: Option<u32>,
}

// ============================================================================
// Defaults
// ============================================================================

fn default_true() -> bool {
    true
}

fn string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrVec;

    impl<'de> Visitor<'de> for StringOrVec {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a string or list of strings")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(split_systemd_words(value))
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(split_systemd_words(&value))
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut values = Vec::new();
            while let Some(value) = seq.next_element::<String>()? {
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_any(StringOrVec)
}

fn option_string_or_vec<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    string_or_vec(deserializer).map(Some)
}

fn split_systemd_words(value: &str) -> Vec<String> {
    value
        .split_ascii_whitespace()
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

// ============================================================================
// Parsing
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("I/O error reading config: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("Invalid config: {0}")]
    Invalid(String),
}

pub fn parse_memory_size(s: &str) -> Result<u64, ConfigError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(ConfigError::Invalid("empty memory size".to_string()));
    }

    let (num_str, multiplier) = match s.as_bytes().last() {
        Some(b'K' | b'k') => (&s[..s.len() - 1], 1024u64),
        Some(b'M' | b'm') => (&s[..s.len() - 1], 1024 * 1024),
        Some(b'G' | b'g') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        Some(b'T' | b't') => (&s[..s.len() - 1], 1024 * 1024 * 1024 * 1024),
        _ => (s, 1u64),
    };

    let value: u64 = num_str
        .trim()
        .parse()
        .map_err(|e| ConfigError::Invalid(format!("invalid memory size '{}': {}", s, e)))?;

    Ok(value * multiplier)
}

fn parse_duration_secs(value: Option<&str>, field: &str) -> Result<Option<u64>, ConfigError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.eq_ignore_ascii_case("infinity") {
        return Ok(None);
    }
    let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
        (number, 1.0 / 1000.0)
    } else if let Some(number) = value.strip_suffix("min") {
        (number, 60.0)
    } else if let Some(number) = value.strip_suffix('h') {
        (number, 60.0 * 60.0)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1.0)
    } else {
        (value, 1.0)
    };
    let parsed = number
        .trim()
        .parse::<f64>()
        .map_err(|_| ConfigError::Invalid(format!("{field} has invalid duration: {value}")))?;
    if !parsed.is_finite() || parsed < 0.0 {
        return Err(ConfigError::Invalid(format!(
            "{field} must be a non-negative duration"
        )));
    }
    Ok(Some((parsed * multiplier).ceil() as u64))
}

fn parse_duration_from_value(
    value: Option<&serde_json::Value>,
    field: &str,
) -> Result<Option<u64>, ConfigError> {
    let Some(val) = value else {
        return Ok(None);
    };
    match val {
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Ok(Some(u))
            } else if let Some(f) = n.as_f64() {
                if f >= 0.0 && f.is_finite() {
                    Ok(Some(f.ceil() as u64))
                } else {
                    Err(ConfigError::Invalid(format!(
                        "{field} must be a non-negative number"
                    )))
                }
            } else {
                Err(ConfigError::Invalid(format!(
                    "{field} must be a valid number"
                )))
            }
        }
        serde_json::Value::String(s) => parse_duration_secs(Some(s.as_str()), field),
        _ => Err(ConfigError::Invalid(format!(
            "{field} must be a number or a duration string"
        ))),
    }
}

fn parse_umask(value: Option<&str>) -> Result<Option<u32>, ConfigError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    u32::from_str_radix(value.trim_start_matches("0o").trim_start_matches('0'), 8)
        .or_else(|_| u32::from_str_radix(value, 8))
        .map(Some)
        .map_err(|_| ConfigError::Invalid(format!("UMask has invalid octal value: {value}")))
}

fn parse_signal(value: Option<&str>) -> Result<i32, ConfigError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(libc::SIGTERM);
    };
    if let Ok(signal) = value.parse::<i32>() {
        return Ok(signal);
    }
    let normalized = value
        .strip_prefix("SIG")
        .unwrap_or(value)
        .to_ascii_uppercase();
    let signal = match normalized.as_str() {
        "TERM" => libc::SIGTERM,
        "KILL" => libc::SIGKILL,
        "INT" => libc::SIGINT,
        "HUP" => libc::SIGHUP,
        "QUIT" => libc::SIGQUIT,
        "ABRT" => libc::SIGABRT,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        "CONT" => libc::SIGCONT,
        "STOP" => libc::SIGSTOP,
        _ => {
            return Err(ConfigError::Invalid(format!(
                "KillSignal has unsupported signal: {value}"
            )));
        }
    };
    Ok(signal)
}

fn parse_socket_listen_address(
    address: &str,
    accept: bool,
    datagram: bool,
) -> Result<ActivationConfig, ConfigError> {
    let addr = address.trim();
    if addr.is_empty() {
        return Err(ConfigError::Invalid(
            "empty socket listen address".to_string(),
        ));
    }

    if let Some(rest) = addr.strip_prefix("vsock:") {
        if datagram {
            return Err(ConfigError::Invalid(format!(
                "ListenDatagram AF_VSOCK address is not supported: {addr}"
            )));
        }
        let Some((cid_str, port_str)) = rest.split_once(':') else {
            return Err(ConfigError::Invalid(format!(
                "invalid ListenStream AF_VSOCK address: {addr}"
            )));
        };
        let vsock_cid = if cid_str.is_empty() {
            None
        } else {
            Some(cid_str.parse::<u32>().map_err(|_| {
                ConfigError::Invalid(format!("invalid ListenStream AF_VSOCK CID: {addr}"))
            })?)
        };
        let vsock_port = port_str.parse::<u32>().map_err(|_| {
            ConfigError::Invalid(format!("invalid ListenStream AF_VSOCK port: {addr}"))
        })?;
        return Ok(ActivationConfig {
            vsock_cid,
            vsock_port: Some(vsock_port),
            wait: !accept,
            datagram,
            ..Default::default()
        });
    }

    if addr.starts_with('@') || addr.starts_with('\0') {
        return Err(ConfigError::Invalid(format!(
            "abstract namespace socket activation is not supported: {addr:?}"
        )));
    }

    if addr.starts_with('/') {
        return Ok(ActivationConfig {
            socket: Some(addr.to_string()),
            wait: !accept,
            datagram,
            ..Default::default()
        });
    }

    if let Ok(port) = addr.parse::<u16>() {
        return Ok(ActivationConfig {
            port: Some(port),
            bind: Some("[::]".to_string()),
            wait: !accept,
            datagram,
            ..Default::default()
        });
    }

    if addr.starts_with('[') {
        if let Some(bracket_end) = addr.find(']') {
            let host = &addr[1..bracket_end];
            let rest = &addr[bracket_end + 1..];
            if let Some(port_str) = rest.strip_prefix(':') {
                let port = port_str.parse::<u16>().map_err(|_| {
                    ConfigError::Invalid(format!("invalid listen address port: {addr}"))
                })?;
                return Ok(ActivationConfig {
                    port: Some(port),
                    bind: Some(format!("[{host}]")),
                    wait: !accept,
                    datagram,
                    ..Default::default()
                });
            }
        }
    } else if let Some((host, port_str)) = addr.rsplit_once(':') {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| ConfigError::Invalid(format!("invalid listen address port: {addr}")))?;
        return Ok(ActivationConfig {
            port: Some(port),
            bind: Some(host.to_string()),
            wait: !accept,
            datagram,
            ..Default::default()
        });
    }

    Err(ConfigError::Invalid(format!(
        "unsupported socket listen address: {addr}"
    )))
}

fn socket_to_activation_configs(
    socket: Option<&SocketSection>,
    service_name: &str,
) -> Result<Vec<ActivationConfig>, ConfigError> {
    let Some(socket) = socket else {
        return Ok(Vec::new());
    };
    if socket.listen.is_empty()
        && socket.listen_streams.is_empty()
        && socket.listen_datagrams.is_empty()
    {
        let paths = crate::paths::AppPaths::for_app(service_name);
        return Ok(vec![ActivationConfig {
            socket: Some(paths.mesh_socket.to_string_lossy().into_owned()),
            wait: !socket.accept,
            fd_name: Some(service_name.to_string()),
            socket_mode: socket.socket_mode,
            socket_user: socket.socket_user.clone(),
            socket_group: socket.socket_group.clone(),
            ..Default::default()
        }]);
    }

    let mut activations: Vec<(ActivationConfig, Option<String>)> = Vec::new();
    for listen in &socket.listen {
        let datagram = listen.listen_type == SocketListenType::Datagram;
        if socket.accept && datagram {
            return Err(ConfigError::Invalid(format!(
                "Accept=true with datagram listener is not supported: {}",
                listen.address
            )));
        }
        activations.push((
            parse_socket_listen_address(&listen.address, socket.accept, datagram)?,
            listen.name.clone(),
        ));
    }

    for addr in &socket.listen_streams {
        activations.push((
            parse_socket_listen_address(addr, socket.accept, false)?,
            None,
        ));
    }

    let (udp_datagrams, unix_datagrams): (Vec<_>, Vec<_>) = socket
        .listen_datagrams
        .iter()
        .partition(|addr| !addr.trim().starts_with('/'));
    for addr in udp_datagrams.into_iter().chain(unix_datagrams) {
        if socket.accept {
            return Err(ConfigError::Invalid(format!(
                "Accept=true with ListenDatagram is not supported: {addr}"
            )));
        }
        activations.push((
            parse_socket_listen_address(addr, socket.accept, true)?,
            None,
        ));
    }

    for (idx, (activation, name)) in activations.iter_mut().enumerate() {
        activation.fd_name = name
            .clone()
            .or_else(|| socket.file_descriptor_names.get(idx).cloned())
            .or_else(|| socket.file_descriptor_names.first().cloned())
            .or_else(|| Some(service_name.to_string()));
        if activation.socket.is_some() {
            activation.socket_mode = socket.socket_mode;
            activation.socket_user.clone_from(&socket.socket_user);
            activation.socket_group.clone_from(&socket.socket_group);
        }
    }

    Ok(activations
        .into_iter()
        .map(|(activation, _)| activation)
        .collect())
}

fn resolve_limits(limits: &ResourceLimits) -> Result<ResolvedResourceLimits, ConfigError> {
    Ok(ResolvedResourceLimits {
        memory_low: limits
            .memory_low
            .as_deref()
            .map(parse_memory_size)
            .transpose()?,
        memory_high: limits
            .memory_high
            .as_deref()
            .map(parse_memory_size)
            .transpose()?,
        memory_max: limits
            .memory_max
            .as_deref()
            .map(parse_memory_size)
            .transpose()?,
        cpu_weight: limits.cpu_weight,
    })
}

pub fn parse_toml(content: &str) -> Result<AppConfig, ConfigError> {
    parse_service(content, None)
}

fn reject_removed_identity_fields(content: &str) -> Result<(), ConfigError> {
    let value: toml::Value = toml::from_str(content)?;
    let Some(service) = value.get("Service").and_then(toml::Value::as_table) else {
        return Ok(());
    };
    let mut removed = Vec::new();
    if service.contains_key("MeshUID") {
        removed.push("MeshUID");
    }
    if service.contains_key("MeshGID") {
        removed.push("MeshGID");
    }
    if removed.is_empty() {
        Ok(())
    } else {
        Err(ConfigError::Invalid(format!(
            "{} removed; use systemd-compatible User=/Group= instead",
            removed.join(" and ")
        )))
    }
}

fn resolve_user(user: Option<&str>) -> Result<(Option<u32>, Option<u32>), ConfigError> {
    let Some(user) = user.map(str::trim).filter(|user| !user.is_empty()) else {
        return Ok((None, None));
    };

    if let Ok(uid) = user.parse::<u32>() {
        return Ok((Some(uid), None));
    }

    let c_user = CString::new(user)
        .map_err(|_| ConfigError::Invalid(format!("User contains NUL byte: {user:?}")))?;
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buffer = vec![0u8; 16 * 1024];
    let rc = unsafe {
        libc::getpwnam_r(
            c_user.as_ptr(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return Err(ConfigError::Invalid(format!("User not found: {user}")));
    }
    Ok((Some(entry.pw_uid), Some(entry.pw_gid)))
}

fn resolve_group(group: Option<&str>) -> Result<Option<u32>, ConfigError> {
    let Some(group) = group.map(str::trim).filter(|group| !group.is_empty()) else {
        return Ok(None);
    };

    if let Ok(gid) = group.parse::<u32>() {
        return Ok(Some(gid));
    }

    let c_group = CString::new(group)
        .map_err(|_| ConfigError::Invalid(format!("Group contains NUL byte: {group:?}")))?;
    let mut entry: libc::group = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::group = std::ptr::null_mut();
    let mut buffer = vec![0u8; 16 * 1024];
    let rc = unsafe {
        libc::getgrnam_r(
            c_group.as_ptr(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return Err(ConfigError::Invalid(format!("Group not found: {group}")));
    }

    Ok(Some(entry.gr_gid))
}

fn resolve_group_required(group: &str, field: &str) -> Result<u32, ConfigError> {
    resolve_group(Some(group))?
        .ok_or_else(|| ConfigError::Invalid(format!("{field} contains an empty group")))
}

pub fn parse_service(content: &str, service_name: Option<&str>) -> Result<AppConfig, ConfigError> {
    reject_removed_identity_fields(content)?;
    let file: AppConfigFile = toml::from_str(content)?;
    let resolved = resolve_limits(&file.resources)?;

    if file.service.exec_start.trim().is_empty() {
        return Err(ConfigError::Invalid(
            "Service.ExecStart must not be empty".to_string(),
        ));
    }

    let (command, args) = parse_exec_start(&file.service.exec_start)?;
    let name = service_name
        .map(str::to_string)
        .unwrap_or_else(|| "service".to_string());

    // Reject names that could escape the jobs/cgroup directory or be used in
    // filesystem paths unsafely.
    if let Err(reason) = validate_service_name(&name) {
        return Err(ConfigError::Invalid(format!(
            "invalid service name: {reason}"
        )));
    }

    if let Some(oom) = file.service.oom_score_adjust {
        if !(-1000..=1000).contains(&oom) {
            return Err(ConfigError::Invalid(format!(
                "OOMScoreAdjust must be between -1000 and 1000, got {}",
                oom
            )));
        }
    }

    if let Some(t) = file
        .service
        .service_type
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if !t.eq_ignore_ascii_case("oneshot")
            && !t.eq_ignore_ascii_case("exec")
            && !t.eq_ignore_ascii_case("notify")
        {
            return Err(ConfigError::Invalid(format!(
                "unsupported Type '{}'; supported values are: oneshot, exec, notify",
                t
            )));
        }
    }

    let idle_action = parse_idle_action(
        file.service.idle_action.as_deref(),
        file.service.idle_freeze_sec.is_some(),
    )?;
    let idle_freeze_sec =
        parse_duration_from_value(file.service.idle_freeze_sec.as_ref(), "IdleFreezeSec")?;

    let (uid, primary_gid) = resolve_user(file.service.user.as_deref())?;
    let gid = resolve_group(file.service.group.as_deref())?.or(primary_gid);
    let restart_sec =
        parse_duration_secs(file.service.restart_sec.as_deref(), "RestartSec")?.unwrap_or(1);
    let watchdog_sec =
        parse_duration_from_value(file.service.watchdog_sec.as_ref(), "WatchdogSec")?;
    let idle_termination_sec = parse_duration_from_value(
        file.service.idle_termination_sec.as_ref(),
        "IdleTerminationSec",
    )?;
    let timeout_start_sec =
        parse_duration_secs(file.service.timeout_start_sec.as_deref(), "TimeoutStartSec")?;
    let timeout_stop_sec =
        parse_duration_secs(file.service.timeout_stop_sec.as_deref(), "TimeoutStopSec")?;
    let kill_signal = parse_signal(file.service.kill_signal.as_deref())?;
    let umask = parse_umask(file.service.umask.as_deref())?;
    let activation = socket_to_activation_configs(file.socket.as_ref(), &name)?;
    let supplementary_groups = file
        .service
        .supplementary_groups
        .iter()
        .map(|group| resolve_group_required(group, "SupplementaryGroups"))
        .collect::<Result<Vec<_>, _>>()?;

    let activation_socket = validate_activation_socket(file.service.activation_socket, &name)?;
    Ok(AppConfig {
        name,
        command,
        args,
        exec_start_pre: file.service.exec_start_pre,
        exec_start_post: file.service.exec_start_post,
        exec_stop: file.service.exec_stop,
        exec_reload: file.service.exec_reload,
        activation_mode: file.service.activation_mode,
        activation_socket,
        uid,
        gid,
        user: file.service.user,
        group: file.service.group,
        working_directory: file.service.working_directory,
        restart: file.service.restart,
        restart_sec,
        timeout_start_sec,
        timeout_stop_sec,
        kill_signal,
        kill_mode: file.service.kill_mode,
        send_sigkill: file.service.send_sigkill,
        umask,
        standard_output: file.service.standard_output,
        standard_error: file.service.standard_error,
        supplementary_groups,
        env: file.environment,
        allow_dangerous_env: file.service.allow_dangerous_env,
        priority: priority_from_oom_score(file.service.oom_score_adjust),
        oneshot: file
            .service
            .service_type
            .as_deref()
            .is_some_and(|t| t.eq_ignore_ascii_case("oneshot")),
        service_type: file.service.service_type.clone(),
        ready_match: file.service.ready_match.clone(),
        watchdog_match: file.service.watchdog_match.clone().or_else(|| {
            if watchdog_sec.is_some() {
                Some("active".to_string())
            } else {
                None
            }
        }),
        watchdog_sec,
        idle_termination_sec,
        idle_action,
        idle_freeze_sec,
        evictable: file.service.evictable,
        memory_reclaim_on_freeze: file.service.memory_reclaim_on_freeze,
        oom_score_adjust: file.service.oom_score_adjust,
        no_new_privileges: file.service.no_new_privileges,
        private_tmp: file.service.private_tmp,
        private_devices: file.service.private_devices,
        private_network: file.service.private_network,
        protect_system: file.service.protect_system,
        protect_home: file.service.protect_home,
        read_write_paths: file.service.read_write_paths,
        read_only_paths: file.service.read_only_paths,
        inaccessible_paths: file.service.inaccessible_paths,
        capability_bounding_set: file.service.capability_bounding_set,
        ambient_capabilities: file.service.ambient_capabilities,
        resources: resolved,
        activation,
        network: file.network,
        mesh: file.mesh,
        source_path: None,
        auth: if file.peers.is_empty() && file.impersonation.is_empty() {
            None
        } else {
            Some(AuthConfig {
                peers: file.peers,
                impersonation: file.impersonation,
            })
        },

        schedule: file.schedule,
        constraints: file.constraints,
        backoff: file.backoff,
        persisted: file.persisted,
        prefetch: file.prefetch,
        save_result: file.save_result,
        trace_tag: file.trace_tag,
        user_initiated: file.user_initiated,
        expedited: file.expedited,
        estimated_download_bytes: file.estimated_download_bytes,
        estimated_upload_bytes: file.estimated_upload_bytes,
        minimum_network_chunk_bytes: file.minimum_network_chunk_bytes,
    })
}

fn priority_from_oom_score(oom_score_adjust: Option<i32>) -> u32 {
    match oom_score_adjust {
        Some(score) => (score + 1000).clamp(0, 2000) as u32,
        None => 1000,
    }
}

fn parse_idle_action(
    value: Option<&str>,
    freeze_sec_configured: bool,
) -> Result<IdleAction, ConfigError> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        // A freeze window implies the freeze action even when IdleAction is
        // not written out.
        return Ok(if freeze_sec_configured {
            IdleAction::Freeze
        } else {
            IdleAction::None
        });
    };
    match value.to_ascii_lowercase().as_str() {
        "freeze" => Ok(IdleAction::Freeze),
        "stop" => Ok(IdleAction::Stop),
        "none" => Ok(IdleAction::None),
        other => Err(ConfigError::Invalid(format!(
            "IdleAction must be freeze, stop, or none: {other}"
        ))),
    }
}

fn parse_exec_start(exec_start: &str) -> Result<(String, Vec<String>), ConfigError> {
    let words = split_exec_words(exec_start)?;
    let Some((command, args)) = words.split_first() else {
        return Err(ConfigError::Invalid(
            "Service.ExecStart must include a command".to_string(),
        ));
    };
    Ok((command.clone(), args.to_vec()))
}

fn split_exec_words(input: &str) -> Result<Vec<String>, ConfigError> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut quote = None;
    let mut in_word = false;

    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), '\\') => {
                if let Some(next) = chars.next() {
                    current.push(next);
                    in_word = true;
                } else {
                    current.push('\\');
                    in_word = true;
                }
            }
            (Some(_), c) => {
                current.push(c);
                in_word = true;
            }
            (None, '\'' | '"') => {
                quote = Some(ch);
                in_word = true;
            }
            (None, '\\') => {
                if let Some(next) = chars.next() {
                    current.push(next);
                    in_word = true;
                } else {
                    current.push('\\');
                    in_word = true;
                }
            }
            (None, c) if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut current));
                    in_word = false;
                }
            }
            (None, c) => {
                current.push(c);
                in_word = true;
            }
        }
    }

    if let Some(q) = quote {
        return Err(ConfigError::Invalid(format!(
            "unterminated quote {} in Service.ExecStart",
            q
        )));
    }

    if in_word {
        words.push(current);
    }

    Ok(words)
}

/// Validate a service/job name for safe use in filesystem paths (cgroup
/// scopes, jobs directory, user config directory).
///
/// A valid name:
/// - is non-empty
/// - is at most 251 characters (leaving room for suffixes under NAME_MAX=255)
/// - contains no path separators (`/`, `\`)
/// - is not `.` or `..` and contains no `..` component
/// - contains no NUL bytes
/// - does not start with `-` (could be mistaken for a flag in some contexts)
///
/// Returns `Ok(())` if valid, or `Err(String)` with a reason.
pub fn validate_service_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("name must not be empty".to_string());
    }
    if name.len() > 251 {
        return Err(format!(
            "name must be at most 251 characters, got {}",
            name.len()
        ));
    }
    if name.contains('\0') {
        return Err("name must not contain NUL bytes".to_string());
    }
    if name.contains('/') || name.contains('\\') {
        return Err("name must not contain path separators".to_string());
    }
    if name == "." || name == ".." {
        return Err("name must not be '.' or '..'".to_string());
    }
    // Reject any path component equal to ParentDir, which would let `..`
    // sneak in as part of a joined path.
    if std::path::Path::new(name)
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return Err("name must not contain '..' components".to_string());
    }
    if name.starts_with('-') {
        return Err("name must not start with '-'".to_string());
    }
    Ok(())
}

/// Validate that `MeshActivationSocket` is under the service's safe run directory.
///
/// The activation socket path is used by mesh-init (running as root) to
/// `create_dir_all` the parent directory and `bind()` the socket. Without
/// this check, a config can set `MeshActivationSocket = "/etc/evil.sock"`
/// and have mesh-init create arbitrary files on the host. This function
/// requires the path to be under `<AppPaths::for_app(name).run_dir(name)>`.
///
/// The validation is purely lexical: we walk the path components and
/// ensure no `..` escapes, then compare to the run_dir's components. This
/// works whether or not the run_dir exists on disk, which is important
/// because mesh-init creates the run_dir on first run.
fn validate_activation_socket(
    socket: Option<String>,
    service_name: &str,
) -> Result<Option<String>, ConfigError> {
    let Some(socket) = socket else {
        return Ok(None);
    };
    let run_dir = crate::paths::AppPaths::for_app(service_name).run_dir(service_name);

    // Reject relative paths — they resolve against CWD which varies.
    let path = std::path::Path::new(&socket);
    if !path.is_absolute() {
        return Err(ConfigError::Invalid(format!(
            "MeshActivationSocket '{}' must be an absolute path under {}",
            socket,
            run_dir.display()
        )));
    }

    // Reject any `..` components — they would let the path escape the
    // run_dir via symlink resolution or CWD-relative resolution.
    for component in path.components() {
        if let std::path::Component::ParentDir = component {
            return Err(ConfigError::Invalid(format!(
                "MeshActivationSocket '{}' must not contain '..' components",
                socket
            )));
        }
    }

    // Lexical prefix check: the socket path must start with the run_dir
    // path. We do this component-by-component (rather than via
    // `Path::starts_with`) to avoid the trailing-component edge case
    // where `/foo` would be a prefix of `/foo-bar`.
    let run_components: Vec<std::ffi::OsString> = run_dir
        .components()
        .map(|c| c.as_os_str().to_os_string())
        .collect();
    let path_components: Vec<std::ffi::OsString> = path
        .components()
        .map(|c| c.as_os_str().to_os_string())
        .collect();
    if path_components.len() <= run_components.len() {
        return Err(ConfigError::Invalid(format!(
            "MeshActivationSocket '{}' must be under '{}'",
            socket,
            run_dir.display()
        )));
    }
    for (i, expected) in run_components.iter().enumerate() {
        if path_components[i] != *expected {
            return Err(ConfigError::Invalid(format!(
                "MeshActivationSocket '{}' must be under '{}'",
                socket,
                run_dir.display()
            )));
        }
    }

    Ok(Some(socket))
}

#[cfg(test)]
mod name_validation_tests {
    use super::*;

    #[test]
    fn rejects_dotdot() {
        assert!(validate_service_name("../etc").is_err());
        assert!(validate_service_name("..").is_err());
        assert!(validate_service_name("foo/../bar").is_err());
    }

    #[test]
    fn rejects_separators() {
        assert!(validate_service_name("a/b").is_err());
        assert!(validate_service_name("a\\b").is_err());
    }

    #[test]
    fn rejects_empty_and_long() {
        assert!(validate_service_name("").is_err());
        let long = "a".repeat(252);
        assert!(validate_service_name(&long).is_err());
    }

    #[test]
    fn rejects_leading_dash() {
        assert!(validate_service_name("-foo").is_err());
    }

    #[test]
    fn accepts_valid() {
        assert!(validate_service_name("app1").is_ok());
        assert!(validate_service_name("worker-1.mesh").is_ok());
        assert!(validate_service_name("_underscore").is_ok());
    }

    #[test]
    fn validate_activation_socket_rejects_outside_run_dir() {
        // The test working directory is the crate root; the resolved run_dir
        // for "my-svc" will be under it. A clearly absolute path outside
        // the run_dir must be rejected.
        assert!(validate_activation_socket(Some("/etc/evil.sock".to_string()), "my-svc",).is_err());
        assert!(validate_activation_socket(Some("../escape.sock".to_string()), "my-svc",).is_err());
        assert!(validate_activation_socket(None, "my-svc",).is_ok());
    }

    #[test]
    fn parses_allow_dangerous_env() {
        let config = parse_service(
            r#"
[Service]
ExecStart = "/bin/true"
AllowDangerousEnv = ["PATH", "LD_LIBRARY_PATH"]
"#,
            Some("env-test"),
        )
        .unwrap();

        assert_eq!(
            config.allow_dangerous_env,
            vec!["PATH".to_string(), "LD_LIBRARY_PATH".to_string()]
        );
    }

    #[test]
    fn test_service_type_validation() {
        // Valid types
        assert!(
            parse_service(
                "[Service]\nExecStart = \"/bin/true\"\nType = \"oneshot\"",
                Some("t1")
            )
            .is_ok()
        );
        assert!(
            parse_service(
                "[Service]\nExecStart = \"/bin/true\"\nType = \"exec\"",
                Some("t2")
            )
            .is_ok()
        );
        assert!(
            parse_service(
                "[Service]\nExecStart = \"/bin/true\"\nType = \"Exec\"",
                Some("t3")
            )
            .is_ok()
        );

        // Invalid types
        assert!(
            parse_service(
                "[Service]\nExecStart = \"/bin/true\"\nType = \"simple\"",
                Some("t4")
            )
            .is_err()
        );
        assert!(
            parse_service(
                "[Service]\nExecStart = \"/bin/true\"\nType = \"forking\"",
                Some("t5")
            )
            .is_err()
        );
        // Type=notify is supported since mesh-init owns NOTIFY_SOCKET.
        assert!(
            parse_service(
                "[Service]\nExecStart = \"/bin/true\"\nType = \"notify\"",
                Some("t6")
            )
            .is_ok()
        );
        assert!(
            parse_service(
                "[Service]\nExecStart = \"/bin/true\"\nType = \"dbus\"",
                Some("t7")
            )
            .is_err()
        );
        assert!(
            parse_service(
                "[Service]\nExecStart = \"/bin/true\"\nType = \"\"",
                Some("t8")
            )
            .is_ok()
        ); // empty type is omitted/ignored and is OK
    }

    #[test]
    fn legacy_mesh_tools_setting_does_not_affect_endpoint_parsing() {
        let config = parse_service(
            "[Service]\nExecStart = \"/bin/true\"\n\n[Mesh]\nAddress = \"unix:///run/mesh/demo/mesh.sock\"\nTools = \"/old/tools.json\"\n",
            Some("demo"),
        )
        .unwrap();
        assert_eq!(
            config.mesh.unwrap().address.as_deref(),
            Some("unix:///run/mesh/demo/mesh.sock")
        );
    }
}
