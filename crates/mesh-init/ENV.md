# mesh-init environment variables

Runtime variables read by the `mesh-init` supervisor, foreground execution
mode, and service activation code.

Common variables inherited from the `mesh` crate are documented in
[`../mesh/ENV.md`](../mesh/ENV.md). That includes `MESH_HOME`,
`MESH_HOME_BASE`, `MESH_OPT_BASE`, `MESH_APP_HOME`, `MESH_APP_OPT`,
`MESH_RES_DIR`, `MESH_SYSTEM_UID`,
`MESH_SSH_MESH_UID`, `RUST_LOG`, `MESH_LOG_FILE`, `MESH_LOG_DIR`,
`LISTEN_FD`, `LISTEN_FDS`, and `LISTEN_FDNAMES`.

## mesh-init

| Variable | Default | Effect |
| --- | --- | --- |
| `MESH_INIT_PRIVILEGED_UIDS` | `0,1000,150` | Comma-separated UIDs allowed to operate on services for other UIDs/GIDs. If set to a non-empty parsed list, it fully replaces the default (root, system, ssh-mesh). |
| `MESH_INIT_MAX_ACTIVATION_CHILDREN` | `64` | Maximum concurrent inetd-style activation children. Invalid, zero, or unset values use `64`. |
| `MESH_INIT_REAP_ALL` | `false` unless running as PID 1 | When `1` or `true`, the child reaper uses `waitpid(-1)` even when not PID 1. |
| `MESH_INIT_MAX_CONTROL_CONNECTIONS` | `32` | Maximum concurrent control-socket connections. Excess connections wait for a slot to free up. Invalid, zero, or unset values use `32`. |

## Child environment

| Variable | Set for | Effect |
| --- | --- | --- |
| `NOTIFY_SOCKET` | every spawned service | Path of the service's sd_notify-compatible datagram channel. The service may send `READY=1`, `WATCHDOG=1`, `STOPPING=1`, `STATUS=…`, `FDSTORE=1`+`FDNAME=…`, and the mesh extensions `X_MESH_IDLE=1`/`X_MESH_BUSY=1` (with `X_MESH_ACTIVE=`, `X_MESH_CONNS=`, `X_MESH_WAKE_AT=`). mesh-init verifies the sender PID belongs to the service cgroup before applying anything. Set `NOTIFY_SOCKET = "none"` in `[Environment]` to disable the channel. |
| `MESH_IDLE_GRACE` | every spawned service | Idle grace period in seconds for the mesh activity tracker (see `../mesh/`): all counters (connections, requests, holds) must be zero for this long before the service reports idle. Default 2 s. |

## Pressure thresholds

| Variable | Default | Effect |
| --- | --- | --- |
| `MESH_INIT_PSI_LOW` | `5.0` | Memory PSI some avg10 entering the Low level (trim). |
| `MESH_INIT_PSI_MEDIUM` | `20.0` | Enter Medium (reclaim frozen/idle cgroups). |
| `MESH_INIT_PSI_HIGH` | `40.0` | Enter High (freeze idle services). |
| `MESH_INIT_PSI_CRITICAL` | `60.0` | Enter Critical (stop evictions). |

## Privileged UIDs

mesh-init requires a non-root system and ssh-mesh sidecar user. The three
privileged service UIDs below ship enabled by default and can be disabled
by setting their env var to `none` or `off`. Disabling any of them is not
supported as a core feature — mesh-init's design assumes ssh-mesh and the
system service account can be trusted to perform service lifecycle on
behalf of any user.

## Privileged UIDs

mesh-init recognizes four privileged service UIDs. Each can be disabled by
setting its env var to `none` or `off`:

| UID  | Env var                  | Default | Purpose                                              |
|------|--------------------------|---------|------------------------------------------------------|
| 0    | (root)                   | —       | Unrestricted, always trusted.                        |
| 1000 | `MESH_SYSTEM_UID`        | 1000    | "system" service account; **root-equivalent** for all permissions including observer methods. |
| 150  | `MESH_SSH_MESH_UID`      | 150     | ssh-mesh service account. Trusted for terminal/start operations and impersonation. **Not** authorized for system-wide observer methods (`freeze_process`, `move_process`, `cgroup_high`, `clear_refs`, `freeze_cgroup`) — those require root or system. |

## Socket Activation Syntax

`mesh-init` implements a small systemd-compatible `[Socket]` subset inside each
service `.toml` file. For VSOCK stream listeners, use:

```toml
[Service]
ExecStart = "/opt/example/bin/server"

[Socket]
Accept = false

[[Socket.Listen]]
Type = "stream"
Address = "vsock:2:5000"
Name = "vsock"
```

Use `Address = "vsock::5000"` to omit the CID and bind `VMADDR_CID_ANY`.
For ordered mixed listeners, use `[[Socket.Listen]]` entries:

```toml
[Service]
ExecStart = "/opt/example/bin/server"

[Socket]
Accept = false

[[Socket.Listen]]
Type = "stream"
Address = "8443"
Name = "http-secure"

[[Socket.Listen]]
Type = "datagram"
Address = "127.0.0.1:8444"
Name = "udp-events"

[[Socket.Listen]]
Type = "stream"
Address = "vsock:2:5000"
Name = "vm-ipc"
```

Specialized:
| `MESH_DANGEROUS_ENV` | default dangerous env list | Comma-separated replacement for the dangerous caller env names mesh-init filters before starting services. Entries support exact names and trailing-`*` prefixes. The built-in list is `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `LD_BIND_NOW`, `LD_DEBUG`, `LD_DEBUG_OUTPUT`, `LD_DYNAMIC_WEAK`, `LD_HWCAP_MASK`, `LD_KEEPDIR`, `LD_NOEXEC`, `LD_ORIGIN_PATH`, `LD_POINTER_GUARD`, `LD_PROFILE`, `LD_SHOW_AUXV`, `LD_USE_LOAD_BIAS`, `BASH_ENV`, `ENV`, `BASH_FUNC_*`, `PYTHONPATH`, `PYTHONSTARTUP`, `PERL5OPT`, `PERL5LIB`, `PERLLIB`, `NODE_OPTIONS`, `NODE_PATH`, `RUBYOPT`, `GEM_PATH`, `JAVA_TOOL_OPTIONS`, and `PATH`. Services can allow individual dangerous names with `AllowDangerousEnv`. |
| `MESH_TUN_CONTROL_SOCKET` | `/tmp/mesh-tun-control.sock` | Fallback control socket used when attaching a service namespace to mesh-tun and no service config `control_socket` is set. |
| `LISTEN_PID` | unset | Process ID that owns systemd-style inherited socket FDs. FDs are collected only when it matches the current process. |


Config and identity:

| `MESH_INIT_DIR` | root: `/home/system/etc/mesh-init`; non-root: `$HOME/etc/mesh-init` | Full replacement directory for core service configs. |
| `MESH_INIT_SOCK` | `/run/mesh/mesh-init/mesh.sock` for root systems | Exact mesh-init control/API socket path. |
| `MESH_INIT_SEQPACKET_SOCK` | `${MESH_INIT_SOCK}.cbor` | Tagged-CBOR `SOCK_SEQPACKET` control socket; pairs each CBOR record with any `SCM_RIGHTS` descriptors. |
| `MESH_INIT_UIDMAP` | `/home/system/etc/uidmap` | Persistent root-mode on-demand app UID/GID map. |
| `MESH_INIT_UID_MIN` | `2000` | First UID/GID mesh-init may allocate for root-mode on-demand apps. |
| `MESH_INIT_UID_MAX` | `59999` | Last UID/GID mesh-init may allocate for root-mode on-demand apps. |
| `MESH_RUN_USER_BASE` | `/run/user` | Advanced/test override for the root-mode on-demand app runtime directory base. |
| `USER_INIT` | root: `/opt/<name>/etc/mesh-init/<name>.toml`, then `/home/<name>/etc/mesh-init/<name>.toml`; non-root: `$HOME/etc/mesh-init/<name>.toml` | Legacy replacement base for on-demand configs. When set, lookup is `<USER_INIT>/<name>/init.toml`. |

Deprecated - use explicit socket/config envs:

| `MESH_INIT_RUN` | `<system_home>/run/mesh-init` | Deprecated runtime directory override; socket path is `<MESH_INIT_RUN>/control.sock`. |


## Generated Variables

Generated variables passed to child processes or activated services.

| Variable | Default | Effect |
| --- | --- | --- |
| `HOME` | service home from config or terminal request | Child process home. |
| `USER` | service/user name | Child process user name. |
| `LISTEN_FDS` | unset | Set to the number of listener FDs for Accept=false socket activation children. |
| `LISTEN_FDNAMES` | unset | Listener fd names for Accept=false children. `mesh-init` emits colon-separated names; receivers also accept spaces. Names come from `[[Socket.Listen]]` `Name` first, then `[Socket]` `FileDescriptorName`, otherwise from the service filename. |
| `MESH_INIT_CONTEXT_KIND` | unset | Activation context kind, when present. |
| `MESH_INIT_CONTEXT_USER` | unset | Activation context user, when present. |
| `MESH_INIT_CONTEXT_COMMAND` | unset | Activation-triggering command, when present. |
| `MESH_INIT_CONTEXT_JSON` | unset | Full activation context JSON, when serializable. |
| `SSH_MESH_ROUTE_USER` | unset | Compatibility alias for activation context user. |
| `SSH_MESH_ROUTE_COMMAND` | unset | Compatibility alias for activation-triggering command. |
| `SSH_MESH_ROUTE_CERTIFICATE_USER` | unset | Certificate principal/user from SSH activation context, when present. |
| `SSH_MESH_ROUTE_PEER_KEY_SHA` | unset | Authenticated peer key fingerprint from SSH activation context, when present. |
| `SSH_MESH_ROUTE_CLIENT_ID` | unset | Caller connection ID from SSH activation context, when present. |

Every service receives `HOME` for its service home and a deterministic `PATH`
beginning with `$HOME/bin`, `$HOME/.local/bin`, and
`$HOME/.nix-profile/bin`, followed by the system Nix profile,
`/run/current-system/sw/bin`, and conventional `/usr` paths. Explicit
`[Environment] HOME` or `PATH` values override these defaults. The default
working directory is `HOME`.
