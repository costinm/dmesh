# mesh-init Config

`mesh-init` loads services from `*.toml` files. Service names come from the
filename stem: `worker.toml` defines service `worker`. Socket activation is
declared in the same file with an optional `[Socket]` table.

When started as root and `MESH_INIT_DIR` is unset, core config is loaded from
`/home/system/etc/mesh-init`. `MESH_INIT_DIR` replaces that default directory.
Non-root `mesh-init` defaults to `$HOME/etc/mesh-init`.

Service definitions are node-local client policy: they describe how processes
on this node connect to a logical FQDN, including `[Mesh].Address`, transport,
and encoding. `ExecStart` is the local-exec
connection mechanism, comparable to invoking a remote serverless service over
HTTPS. Existing lifecycle, socket, environment, network, and resource fields
remain unchanged. A future `[Workload]` section will make provider-side
runtime/resource policy explicit; this iteration does not move existing
fields.

For on-demand `start NAME` requests without a loaded core config, root mode
looks for `/opt/NAME/etc/mesh-init/NAME.toml` and then
`/home/NAME/etc/mesh-init/NAME.toml`; `/home` wins. If `/home/NAME` exists,
its UID/GID become the service identity. If it does not exist, mesh-init
allocates a UID/GID in `/home/system/etc/uidmap`, creates `/home/NAME`, and
creates `/run/user/UID` mode `0700`. If `USER_INIT` is set, config lookup uses
the legacy `<USER_INIT>/NAME/init.toml` path, but root-mode identity still
comes from `/home/NAME` or the uidmap allocator.

The mesh sidecar can start services on-demand when SSH or HTTP requests use the service
name, by calling the 'start' method on mesh-init. 

## TOML Service Files

Service files are TOML documents. The required table is `[Service]`.

### `[Service]`

Systemd-compatible fields:

- `ExecStart` (string, required): command line. The first word is resolved from
  the service PATH when it is not an absolute path; remaining words become
  argv. Single quotes, double quotes, and backslash escaping are supported.
- `ExecStartPre`, `ExecStartPost`, `ExecStop`, `ExecReload` (string or string
  list): hook commands run through `/bin/sh -c`.
- `Type` (string): supported values are `oneshot` (runs once at startup), and `exec` (starts as a daemon at boot). If omitted or empty, the service does not auto-start at boot and is only started on-demand via socket activation or an explicit start command.
- `User` (string): user name or numeric UID string. Names are resolved with passwd.
- `Group` (string): group name or numeric GID string. Names are resolved with the group database. When omitted, a named `User` uses its primary passwd GID.
- `WorkingDirectory` (string): child working directory. Defaults to the
  service home, normally `/home/<service>`.
- `Restart` (string): `no`, `always`, `on-success`, `on-failure`,
  `on-abnormal`, or `on-abort`.
- `RestartSec`, `TimeoutStartSec`, `TimeoutStopSec` (duration string): seconds
  by default; `ms`, `s`, `min`, and `h` suffixes are accepted.
- `KillSignal` (string): common signal name such as `SIGTERM`, `TERM`, or a
  numeric signal.
- `KillMode` (string): parsed as `control-group`, `mixed`, `process`, or
  `none`. Current enforcement is process-oriented except `none`, which skips
  signalling the main process.
- `SendSIGKILL` (boolean): controls final SIGKILL after `TimeoutStopSec`.
- `UMask` (octal string): child umask.
- `StandardOutput`, `StandardError` (string): daemon-started service stdio.
  Supported values are `inherit`, `null`, `journal`, `journal+console`, `kmsg`,
  `kmsg+console`, `console`, `file:/path`, `append:/path`, and
  `truncate:/path`. Journal/kmsg/console values inherit mesh-init's own
  stdout/stderr destination. `StandardError = "stdout"` shares stdout.
- `SupplementaryGroups` (string or string list): group names or numeric GID
  strings.
- `OOMScoreAdjust` (integer, -1000..1000): applied as the Linux OOM score
  adjustment and used as mesh priority. Internal priority is
  `OOMScoreAdjust + 1000`, clamped to `0..2000`; lower is more protected.
- `NoNewPrivileges` (boolean): applied with `prctl(PR_SET_NO_NEW_PRIVS)` when
  set.
- `PrivateNetwork` (boolean): applied with `unshare(CLONE_NEWNET)`.
- `PrivateTmp` (boolean): creates private tmpfs mounts for `/tmp` and
  `/var/tmp`.
- `PrivateDevices` (boolean): creates a minimal private `/dev` with `null`,
  `zero`, `full`, `random`, `urandom`, `tty`, `pts`, and `shm`.
- `ProtectSystem` (string): `true`, `full`, `strict`, or `off`. Any service
  that creates a private mount namespace also gets `/nix` and `/opt`
  bind-remounted read-only when those paths exist. `true` also makes `/usr`,
  `/boot`, and `/efi` read-only. `full` adds `/etc`. `strict` makes `/`
  read-only.
- `ProtectHome` (string): `true`, `yes`, `read-only`, `tmpfs`, or `off`.
  Applies to `/home`, `/root`, and `/run/user`. `true`/`yes` hides them with
  mode-000 tmpfs mounts, `read-only` bind-remounts them read-only, and `tmpfs`
  overlays them with mode-0755 tmpfs mounts. Missing paths are skipped.
- `ReadWritePaths`, `ReadOnlyPaths`, `InaccessiblePaths` (string or string
  list): path-based mount protections. Paths must be absolute.
- `CapabilityBoundingSet`, `AmbientCapabilities` (string or string list):
  common Linux capability names. Supported names are `CAP_CHOWN`,
  `CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_KILL`, `CAP_SETGID`, `CAP_SETUID`,
  `CAP_SETPCAP`, `CAP_NET_BIND_SERVICE`, `CAP_NET_ADMIN`, `CAP_NET_RAW`, and
  `CAP_SYS_ADMIN`. `CapabilityBoundingSet = []` explicitly drops all supported
  capabilities; omitting the field leaves the bounding set unchanged.

Unsupported hardening values or capability names are logged with `WARN` and
fail only that service start. mesh-init continues running.

Before spawning a service, mesh-init creates `/run/mesh/<service-name>/`, sets
mode `0777`, and when running as root changes ownership to the service
`User`/`Group`. This directory is the default place for service-owned UDS
control sockets and runtime files. Socket servers must still perform
peer-credential authorization; the directory permission is for reachability and
socket lifecycle, not authorization.

- `AllowDangerousEnv` (array of strings, default `[]`): dangerous
  caller-supplied environment variables this service accepts. Exact names and
  trailing-`*` prefix patterns are supported. By default mesh-init drops
  dangerous caller env such as `LD_PRELOAD`, `LD_LIBRARY_PATH`, `BASH_ENV`,
  `ENV`, `BASH_FUNC_*`, `PYTHONPATH`, `NODE_OPTIONS`, `JAVA_TOOL_OPTIONS`, and
  `PATH`. Set `MESH_DANGEROUS_ENV` on mesh-init to replace the global dangerous
  list with comma-separated names/prefixes. Client-side code decides which env
  variables to send; mesh-init only filters what it receives.

Custom mesh-init health and lifecycle fields:

- `ReadyMatch` (string): substring to search for in stderr. The service is considered ready when this is seen.
- `WatchdogMatch` (string): substring to search for in stderr. Only lines containing this pattern reset the watchdog timer. Defaults to `"active"` if `WatchdogSec` is set.
- `WatchdogSec` (integer or duration string): watchdog timeout. If no line matching `WatchdogMatch` is printed in this duration, the service is killed and restarted.
- `IdleTerminationSec` (integer or duration string): stop the service after this duration of being idle, frozen or not. A service is idle when its activity counters (self-reported over NOTIFY_SOCKET or the legacy stderr metrics) are all zero and no output has been written to stderr.

Idle freeze (the service self-reports idle over NOTIFY_SOCKET; see ENV.md):

- `IdleAction` (string): `freeze`, `stop`, or `none`. `freeze` parks the cgroup
  with `cgroup.freeze` after the idle window and wakes it on the next
  connection; `stop` terminates the service; `none` (default) only counts.
- `IdleFreezeSec` (integer or duration string): idle window before the
  prepare-freeze handshake. A configured window implies `IdleAction = 
  "freeze"` when `IdleAction` is omitted.
- `IdleDetect` (string): detection for services without self-reports; only
  `"socket"` is defined (reserved, phase 2e). Requires mesh-init-owned
  listeners.

Pressure policy (phase 3):

- `Evictable` (boolean): set to `false` to shield the service from trim,
  freeze, and eviction under memory pressure. Defaults to evictable.
- `MemoryReclaimOnFreeze` (boolean): write `memory.reclaim` to the service
  cgroup after an idle or pressure freeze.

### Unsupported systemd features

The following systemd features are explicitly **not supported**:
- Service dependencies (`Wants=`, `Requires=`, `After=`, `Before=`) are not supported.
- `ExecStopPost` is not supported (only `ExecStartPre`, `ExecStartPost`, `ExecStop`, and `ExecReload` are supported).

`Type = "notify"` is supported: mesh-init sets `NOTIFY_SOCKET` for every
service it spawns and treats `READY=1` as readiness, `WATCHDOG=1` as a
watchdog ping, and `FDSTORE=1` as sockets to hand back on restart.

mesh-init extension fields:

- `MeshActivationMode` (string): `stdio` or `hybrid`. `stdio` passes accepted
  sockets as stdin/stdout/stderr. `hybrid` forwards accepted sockets to the
  service JSONL Unix socket.
- `MeshActivationSocket` (string): Unix socket path used by `hybrid` activation.
  If omitted, mesh-init uses the service's default JSONL socket path.

Removed fields: `MeshName`, `MeshArgs`, `MeshPriority`, and `MeshOneshot`.
Use the filename, `ExecStart`, `OOMScoreAdjust`, and `Type = "oneshot"`.

### `[Resources]`

mesh-init extension table for cgroup v2 resource controls:

- `MemoryMin` (string): maps to `memory.low`.
- `MemoryHigh` (string): maps to `memory.high`.
- `MemoryMax` (string): maps to `memory.max`.
- `CPUWeight` (integer): maps to `cpu.weight`.

Memory strings may use raw bytes or `K`, `M`, `G`, `T` suffixes.

### `[Environment]`

mesh-init extension table. Each key/value pair is passed as an environment
variable to the service.

### `[Network]`

mesh-init extension table for service network setup:

- `backend`: `none`, `pasta`, or `mesh-tun`.
- `command`: sidecar command for backends such as `pasta`.
- `args`: sidecar argv list.
- `env`: sidecar environment map.
- `control_socket`: shared mesh-tun control socket.
- `if_name`: interface name inside the service namespace.
- `address`: service-side address, for example `10.5.0.2/24`.
- `gateway`: default-route gateway.
- `mtu`: service-side interface MTU.
- `default_route`: boolean.
- `egress_redirect_port`: TCP redirect listener port.
- `egress_redirect_uid`: uid excluded from egress redirects.

### Auth Tables

mesh-init extension tables:

- `[[Peer]]`: embedded auth peer. Supported fields are the same as `auth.toml`,
  including `uid`, `id`, `email`, and `delegate`.
- `[[MeshImpersonation]]`: embedded impersonation rule with `from` and `to`.

### Job Fields

Job definitions use the same TOML parser and add mesh-init extension fields:
place these top-level fields before the first table header.

- `MeshPersisted`
- `MeshPrefetch`
- `MeshSaveResult`
- `MeshTraceTag`
- `MeshUserInitiated`
- `MeshExpedited`
- `MeshEstimatedDownloadBytes`
- `MeshEstimatedUploadBytes`
- `MeshMinimumNetworkChunkBytes`

Job extension tables:

- `[Schedule]`: `periodic_secs`, `flex_secs`, `minimum_latency_secs`,
  `override_deadline_secs`.
- `[Constraints]`: `network_type`, `requires_charging`,
  `requires_device_idle`, `requires_battery_not_low`,
  `requires_storage_not_low`, `triggers`, `trigger_max_delay_secs`, and
  `[Constraints.custom]`.
- `[Backoff]`: `initial_secs`, `policy`, `max_retries`, `max_secs`.

### `[Socket]`

Optional systemd-compatible socket activation table in the same TOML document
as `[Service]`.

An otherwise empty `[Socket]` declares one `Accept=false` stream listener at
the service's standard mesh socket, normally
`/run/mesh/<service>/mesh.sock`.

Systemd-compatible fields:

- `[[Socket.Listen]]`: ordered listener entry. `Type` is `stream` or
  `datagram`; `Address` is a TCP/UDP port or address, Unix socket path, or
  `vsock:CID:PORT` for stream listeners; `Name` is an optional fd name.
- `ListenStream`: shorthand string or string list for stream listeners.
- `ListenDatagram`: shorthand string or string list for datagram listeners.
- `Accept`: boolean. `false` passes listener FDs with systemd activation;
  `true` accepts connections in mesh-init. Datagram listeners only support
  `Accept=false`.
- `SocketMode`: Unix socket mode, for example `0o660`.
- `SocketUser`: Unix socket owner.
- `SocketGroup`: Unix socket group.
- `FileDescriptorName`: descriptor name or descriptor name list for
  `Accept=false` activation.

No xinetd-style listener-fd mode is supported. Hybrid accepted-fd forwarding is
selected in `[Service]` with `MeshActivationMode = "hybrid"`.

When a service has multiple `Accept=false` listeners, mesh-init passes all of
them to the child in declaration order using the systemd convention:
`LISTEN_FDS=N` and descriptors starting at fd 3. Use `[[Socket.Listen]]` when
mixed stream/datagram ordering matters. The shorthand arrays are expanded as
all `ListenStream` entries first, followed by UDP `ListenDatagram` entries and
then Unix datagram entries.
