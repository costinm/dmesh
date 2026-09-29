//! JSON-lines protocol for the mesh-init UDS control socket.
//!
//! Inspired by MCP/LSP — each message is a single JSON line terminated by `\n`.
//! The daemon reads requests and writes responses on the same connection.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Linux namespace descriptor kind passed over the control socket.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NamespaceKind {
    /// Network namespace, opened from a path such as `/proc/<pid>/ns/net`.
    #[default]
    Net,
    /// User namespace, opened from a path such as `/proc/<pid>/ns/user`.
    User,
}

/// Extra metadata describing why a service is being activated.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActivationContext {
    /// Protocol or caller-specific activation kind, for example `ssh`.
    #[serde(default)]
    pub kind: String,
    /// Authenticated incoming username or route identity.
    #[serde(default)]
    pub user: String,
    /// Optional command that triggered the activation.
    #[serde(default)]
    pub command: Option<String>,
    /// Optional certificate principal/user from the authenticated peer.
    #[serde(default)]
    pub certificate_user: Option<String>,
    /// Optional fingerprint of the authenticated peer key.
    #[serde(default)]
    pub peer_key_sha: Option<String>,
    /// Optional caller connection id.
    #[serde(default)]
    pub client_id: Option<u64>,
    /// Additional environment fields to pass to the activated service.
    #[serde(default)]
    pub env: HashMap<String, String>,
}

impl ActivationContext {
    /// Convert context into environment variables for an activated service.
    pub fn to_env(&self) -> HashMap<String, String> {
        let mut env = self.env.clone();
        if !self.kind.is_empty() {
            env.insert("MESH_INIT_CONTEXT_KIND".to_string(), self.kind.clone());
        }
        if !self.user.is_empty() {
            env.insert("MESH_INIT_CONTEXT_USER".to_string(), self.user.clone());
            env.insert("SSH_MESH_ROUTE_USER".to_string(), self.user.clone());
        }
        if let Some(command) = &self.command {
            env.insert("MESH_INIT_CONTEXT_COMMAND".to_string(), command.clone());
            env.insert("SSH_MESH_ROUTE_COMMAND".to_string(), command.clone());
        }
        if let Some(certificate_user) = &self.certificate_user {
            env.insert(
                "SSH_MESH_ROUTE_CERTIFICATE_USER".to_string(),
                certificate_user.clone(),
            );
        }
        if let Some(peer_key_sha) = &self.peer_key_sha {
            env.insert(
                "SSH_MESH_ROUTE_PEER_KEY_SHA".to_string(),
                peer_key_sha.clone(),
            );
        }
        if let Some(client_id) = self.client_id {
            env.insert(
                "SSH_MESH_ROUTE_CLIENT_ID".to_string(),
                client_id.to_string(),
            );
        }
        if let Ok(json) = serde_json::to_string(self) {
            env.insert("MESH_INIT_CONTEXT_JSON".to_string(), json);
        }
        env
    }
}

// ============================================================================
// Requests
// ============================================================================

/// A request from a client to the mesh-init daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method")]
pub enum Request {
    /// Start a named service. If not already running, loads config and spawns.
    #[serde(rename = "start")]
    Start {
        name: String,
        /// Additional args appended to the service command.
        #[serde(default)]
        args: Vec<String>,
        /// Additional env vars merged with the config's environment.
        #[serde(default)]
        env: HashMap<String, String>,
        /// Optional activation context from the caller.
        #[serde(default)]
        context: Option<ActivationContext>,
    },

    /// Prepare context for a later socket activation connection.
    ///
    /// This is used when the control request and the activated stdin/stdout
    /// socket are separate connections.
    #[serde(rename = "prepare_activation")]
    PrepareActivation {
        name: String,
        context: ActivationContext,
    },

    /// Start a terminal session using one passed file descriptor.
    ///
    /// The daemon uses a service config named `name` when one exists. Otherwise
    /// it creates a one-shot dynamic shell rooted at `home` and running as
    /// `uid`/`gid` when possible.
    #[serde(rename = "start_terminal")]
    StartTerminal {
        name: String,
        home: String,
        uid: u32,
        gid: Option<u32>,
        /// Treat the passed file descriptor as a PTY slave and make it the
        /// child process's controlling terminal.
        #[serde(default)]
        pty: bool,
        #[serde(default)]
        env: HashMap<String, String>,
        #[serde(default)]
        context: Option<ActivationContext>,
        /// Optional command string to execute. When absent, mesh-init starts
        /// the user's interactive shell.
        #[serde(default)]
        command: Option<String>,
        /// The number of file descriptors being passed (usually 1, or 3 for separate stdin/stdout/stderr).
        #[serde(default)]
        fd_count: Option<u32>,
    },

    /// Register a namespace descriptor for a running service.
    ///
    /// This lets an unprivileged in-container mesh-init expose its namespace to
    /// the host mesh-init via SCM_RIGHTS. The host daemon can then hand that fd
    /// to a privileged backend such as mesh-tun without requiring NET_ADMIN in
    /// the container.
    #[serde(rename = "register_namespace")]
    RegisterNamespace {
        name: String,
        #[serde(default)]
        kind: NamespaceKind,
        #[serde(default)]
        target_pid: Option<u32>,
    },

    /// Resize an active terminal session that was returned by `start_terminal`.
    #[serde(rename = "terminal_resize")]
    TerminalResize {
        terminal_id: String,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    },

    /// Send a control command to an active terminal session.
    ///
    /// Currently supported commands include `close`, `hup`, and `signal`.
    #[serde(rename = "terminal_command")]
    TerminalCommand {
        terminal_id: String,
        command: String,
        #[serde(default)]
        data: serde_json::Value,
    },

    /// Stop a running service.
    #[serde(rename = "stop")]
    Stop {
        name: String,
        /// Signal to send (default: SIGTERM).
        signal: Option<i32>,
    },

    /// Freeze (suspend) a running service via `cgroup.freeze`.
    ///
    /// The optional reason changes who may thaw: `user` waits for an explicit
    /// unfreeze, `pressure` also thaws on activity or when pressure clears.
    #[serde(rename = "freeze")]
    Freeze {
        name: String,
        #[serde(default)]
        reason: Option<String>,
    },

    /// Unfreeze (resume) a frozen service.
    #[serde(rename = "unfreeze")]
    Unfreeze { name: String },

    /// Reconcile managed service state after host resume or external recovery.
    #[serde(rename = "reconcile")]
    Reconcile,

    /// Query status of a specific service or all services.
    #[serde(rename = "status")]
    Status { name: Option<String> },

    /// Shutdown the daemon gracefully.
    #[serde(rename = "shutdown")]
    Shutdown,

    /// Reload all configurations from disk and restart changed services.
    #[serde(rename = "reload")]
    Reload,

    /// Schedule a new job.
    #[serde(rename = "schedule_job")]
    ScheduleJob { config: serde_json::Value },

    /// Cancel a scheduled job.
    #[serde(rename = "cancel_job")]
    CancelJob { name: String },

    /// Enqueue a work item to an existing job.
    #[serde(rename = "enqueue_work")]
    EnqueueWork {
        job_name: String,
        work: serde_json::Value,
    },

    /// List all scheduled jobs.
    #[serde(rename = "list_jobs")]
    ListJobs,

    /// Mark a job as finished.
    #[serde(rename = "job_finished")]
    JobFinished {
        name: String,
        reschedule: bool,
        result: Option<serde_json::Value>,
    },

    /// Deliver a system event to the job scheduler.
    #[serde(rename = "event")]
    Event { event: serde_json::Value },

    /// List observed processes from mesh-init's process observer.
    #[serde(rename = "processes", alias = "list_processes")]
    Processes,

    /// Return detailed information for one process.
    #[serde(rename = "process", alias = "get_process")]
    Process { pid: u32 },

    /// Return a single process record without cgroup expansion.
    #[serde(rename = "process_only", alias = "ps_one")]
    ProcessOnly { pid: u32 },

    /// Return all observed cgroups.
    #[serde(rename = "cgroups", alias = "list_cgroups")]
    Cgroups,

    /// Return detailed information for one cgroup path.
    #[serde(rename = "cgroup", alias = "get_cgroup")]
    Cgroup { path: String },

    /// Return pressure watch state.
    #[serde(rename = "pressure", alias = "psi", alias = "psi_watches")]
    Pressure,

    /// Set memory.high for a cgroup based on current memory usage.
    #[serde(rename = "cgroup_high")]
    CgroupHigh {
        path: String,
        percentage: f64,
        interval: u64,
    },

    /// List process records for PIDs in a cgroup.
    #[serde(rename = "cgroup_procs")]
    CgroupProcs { path: String },

    /// Move a process to a named cgroup.
    #[serde(rename = "move_process")]
    MoveProcess {
        pid: u32,
        cgroup_name: Option<String>,
    },

    /// Write to /proc/<pid>/clear_refs.
    #[serde(rename = "clear_refs")]
    ClearRefs { pid: u32, value: String },

    /// Freeze or thaw one process.
    #[serde(rename = "freeze_process")]
    FreezeProcess { pid: u32, freeze: bool },

    /// Freeze or thaw one cgroup.
    #[serde(rename = "freeze_cgroup")]
    FreezeCgroup { path: String, freeze: bool },
}

// ============================================================================
// Responses
// ============================================================================

/// A response from the daemon to a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl Response {
    /// Create a successful response with no data.
    pub fn ok() -> Self {
        Self {
            success: true,
            error: None,
            data: None,
        }
    }

    /// Create a successful response with data.
    pub fn ok_with_data(data: serde_json::Value) -> Self {
        Self {
            success: true,
            error: None,
            data: Some(data),
        }
    }

    /// Create an error response.
    pub fn err(message: impl Into<String>) -> Self {
        Self {
            success: false,
            error: Some(message.into()),
            data: None,
        }
    }
}

// ============================================================================
// Service Status
// ============================================================================

/// Current state of a managed service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceState {
    Stopped,
    Starting,
    Running,
    Frozen,
    Stopping,
    Failed,
}

/// Why a stopped service is stopped.
///
/// `Idle` and `Evicted` distinguish lifecycle decisions from a plain exit so
/// the scheduler and the pressure policy can decide whether a Stopped service
/// may restart on an activation or an admission check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Exited,
    Requested,
    Idle,
    Evicted,
    CrashLimit,
}

/// Why a service is frozen. The reason decides who may thaw: `User` waits for
/// an explicit unfreeze, `Idle` thaws on activity, and `Pressure` thaws on
/// activity or when pressure clears.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreezeReason {
    User,
    Idle,
    Pressure,
}

impl std::fmt::Display for FreezeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User => write!(f, "user"),
            Self::Idle => write!(f, "idle"),
            Self::Pressure => write!(f, "pressure"),
        }
    }
}

impl std::fmt::Display for ServiceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stopped => write!(f, "stopped"),
            Self::Starting => write!(f, "starting"),
            Self::Running => write!(f, "running"),
            Self::Frozen => write!(f, "frozen"),
            Self::Stopping => write!(f, "stopping"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// Status information for a service, returned by the `status` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub name: String,
    pub state: ServiceState,
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub netns_registered: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub userns_registered: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mesh_tun_attached: bool,
    pub uptime_secs: Option<u64>,
    pub restarts: u32,
    pub consecutive_failures: u32,
    pub next_restart_in_secs: Option<u64>,
    pub cgroup_path: Option<String>,
    /// Why the service is stopped, when it is stopped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<StopReason>,
    /// Why the service is frozen, when it is frozen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freeze_reason: Option<FreezeReason>,
    /// Reported activity counters from the service (connections, requests,
    /// holds) or stderr metrics, when any have been observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity: Option<serde_json::Value>,
    /// Whether the service last reported itself idle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle: Option<bool>,
    /// Current memory.current of the service cgroup in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<u64>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_start_request() {
        let req = Request::Start {
            name: "chrome".to_string(),
            args: vec!["--headless".to_string()],
            env: HashMap::from([("DISPLAY".to_string(), ":0".to_string())]),
            context: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"method\":\"start\""));
        assert!(json.contains("\"chrome\""));
    }

    #[test]
    fn test_deserialize_start_request() {
        let json = r#"{"method":"start","name":"chrome","args":[],"env":{}}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        match req {
            Request::Start { name, .. } => assert_eq!(name, "chrome"),
            _ => panic!("expected Start"),
        }
    }

    #[test]
    fn test_serialize_response() {
        let resp = Response::ok_with_data(serde_json::json!({"pid": 1234}));
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();
        assert!(parsed.success);
        assert!(parsed.data.is_some());
    }

    #[test]
    fn test_error_response() {
        let resp = Response::err("service not found");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"success\":false"));
        assert!(json.contains("service not found"));
        // data should be omitted
        assert!(!json.contains("\"data\""));
    }

    #[test]
    fn test_deserialize_status_response() {
        let json = r#"{
            "name": "chrome",
            "state": "running",
            "pid": 1234,
            "uptime_secs": 60,
            "restarts": 0,
            "consecutive_failures": 0,
            "cgroup_path": "/sys/fs/cgroup/mesh.slice/chrome.scope"
        }"#;
        let status: ServiceStatus = serde_json::from_str(json).unwrap();
        assert_eq!(status.name, "chrome");
        assert_eq!(status.state, ServiceState::Running);
        assert_eq!(status.pid, Some(1234));
        assert_eq!(status.consecutive_failures, 0);
    }

    #[test]
    fn test_service_state_display() {
        assert_eq!(ServiceState::Running.to_string(), "running");
        assert_eq!(ServiceState::Frozen.to_string(), "frozen");
        assert_eq!(ServiceState::Failed.to_string(), "failed");
    }

    #[test]
    fn test_deserialize_all_methods() {
        let cases = [
            r#"{"method":"stop","name":"x","signal":9}"#,
            r#"{"method":"freeze","name":"x"}"#,
            r#"{"method":"unfreeze","name":"x"}"#,
            r#"{"method":"reconcile"}"#,
            r#"{"method":"status","name":null}"#,
            r#"{"method":"shutdown"}"#,
            r#"{"method":"reload"}"#,
            r#"{"method":"start_terminal","name":"alice","home":"/home/alice","uid":1000,"gid":1000,"env":{}}"#,
        ];
        for json in cases {
            let _req: Request = serde_json::from_str(json).unwrap();
        }
    }
}
