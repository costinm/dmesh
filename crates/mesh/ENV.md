# mesh common environment variables

Runtime variables read by the `mesh` crate and `mesh` CLI. Crates that use
`mesh::paths::AppPaths`, `mesh::server::MeshListener`, or
`mesh::local_trace` inherit the relevant variables from this file.

Apps using `mesh::local_trace::init` inherit the common file logging settings
below. Some older binaries still keep their own telemetry setup, but should
prefer the common helper when possible.

## App Layout And Resources

| Variable | Default | Effect |
| --- | --- | --- |
| `MESH_HOME` | `$PWD/mesh` for non-root, unset for root | Pseudo-root for mesh app layout. When set, defaults become `<MESH_HOME>/home/<app>` and `<MESH_HOME>/opt/<app>`. |
| `MESH_APP_HOME` | `<home_base>/<app>` | Overrides the full mutable app home path used by `AppPaths::for_app`. |
| `MESH_APP_OPT` | `<opt_base>/<app>` | Overrides the full packaged/read-only app path used by `AppPaths::for_app`. |
| `MESH_RUN_BASE` | `$HOME/.local/run` for non-root, `/run/mesh` for root | Base directory for public mesh IPC endpoints. App endpoints are `<MESH_RUN_BASE>/<app>/mesh.sock`. An explicit `MESH_HOME` retains the pseudo-root layout at `<MESH_HOME>/run/mesh`. |
| `MESH_RES_DIR` | `<app_home>/etc/resources`, then `<app_opt>/resources` | Replaces the normal resource lookup overlay with one explicit resource directory. |
| `MESH_TOOLS` | unset | Exact client-owned `tools.json` override used by the shared catalog resolver. Failure to load an explicit override is an error. |
| `MESH_SCHEMA_DIR` | unset | Common schema root; service `S` resolves all `.json` files under `$MESH_SCHEMA_DIR/S/`, then `/opt/S/etc/schemas/`, `$HOME/opt/S/etc/schemas/`, and `$HOME/etc/schemas/` (user-installed schemas). |

Deprecated:
| `MESH_HOME_BASE` | `<MESH_HOME>/home` for non-root, `/home` for root | Base directory for mutable app homes when `MESH_APP_HOME` is unset. Takes precedence over `MESH_HOME`. |
| `MESH_OPT_BASE` | `<MESH_HOME>/opt` for non-root, `/opt` for root | Base directory for packaged app paths when `MESH_APP_OPT` is unset. Takes precedence over `MESH_HOME`. |

## Listener Activation And Auth

| Variable | Default | Effect |
| --- | --- | --- |
| `MESH_ENFORCE_DELEGATION` | `false` | When `1`, `true`, or `yes`, `MeshListener` requires trusted delegate peers to send a valid delegation envelope before serving a UDS connection. |
| `MESH_SYSTEM_UID` | `1000` | UID of the "system" service account. Root-equivalent for all mesh-init permissions, including system-wide observer methods. Set to `none`/`off` to disable. |
| `MESH_SSH_MESH_UID` | `150` | UID of the ssh-mesh service account. Trusted for terminal/start operations and impersonation, but NOT for observer methods. Set to `none`/`off` to disable. |
| `LISTEN_FDS` | unset | Number of inherited listener FDs starting at fd 3, systemd-style. |
| `LISTEN_FDNAMES` | empty | Names for inherited listener FDs. Systemd separates socket-unit names with `:`; `mesh` also accepts spaces for mesh-init single-unit name lists. |
| `<APP>_RUN` | `<app_home>/run/<app>` | `mesh` CLI socket override for the target app, where `<APP>` is the uppercased app name with `-` replaced by `_` (for example `MESH_INIT_RUN`). |

Deprecated:
| `LISTEN_FD` | unset | Single inherited listener FD to use for activation. Takes precedence over `LISTEN_FDS`. |

## Local Trace

| Variable | Default | Effect |
| --- | --- | --- |
| `RUST_LOG` | tracing subscriber default | Initial tracing filter for `local_trace::init` and binaries using `EnvFilter::from_default_env`. |
| `MESH_LOG_FILE` | unset | Exact JSON trace log path for `local_trace::init`, for example `/dev/stderr` or `/tmp/ssh-mesh.log`. Takes precedence over `MESH_LOG_DIR`. Regular files rotate by size (`MESH_LOG_FILE_MAX_BYTES`); special files under `/dev` are opened as-is and never rotate. |
| `MESH_LOG_DIR` | `./logs` | Directory for `local_trace::init` JSON trace logs; writes `<MESH_LOG_DIR>/<service>.log` with size-based rotation. With mesh-init, `service` is the unit name; otherwise it is the application name. If unset, `./logs` is relative to the process working directory. |
| `MESH_LOG_FILE_MAX_BYTES` | `8m` | Size at which the active log file rotates to `<file>.1` (backups shift to `.2`, ...). Suffixes k/m/g (or kib/mib/gib) are accepted. `0` disables rotation. |
| `MESH_LOG_MAX_TOTAL_BYTES` | `64m` | Maximum combined size kept for rotated `<file>.*` backups; oldest backups are removed first so backups plus one full active file fit within the cap. Also bounds legacy rotated files at startup. |
| `TRACE_SOCKET_DIR` | `<mesh_home>/run/mesh` | Shared directory for local trace sockets; producer sockets are `<TRACE_SOCKET_DIR>/<app>.sock`. |

## Generated Variables

Generated variables passed to child processes or activated services.

| Variable | Default | Effect |
| --- | --- | --- |
| `MESH_INIT_CONTEXT_KIND` | unset | Activation context kind, when present. |
| `MESH_INIT_CONTEXT_USER` | unset | Activation context user, when present. |
| `MESH_INIT_CONTEXT_COMMAND` | unset | Activation-triggering command, when present. |
| `MESH_INIT_CONTEXT_JSON` | unset | Full activation context JSON, when serializable. |
| `MESH_JOB_WORK_ITEMS` | unset | Comma-separated work item IDs passed to scheduled job commands when a job has pending work. |
| `SSH_MESH_ROUTE_CERTIFICATE_USER` | unset | Certificate principal/user from SSH activation context, when present. |
| `SSH_MESH_ROUTE_PEER_KEY_SHA` | unset | Authenticated peer key fingerprint from SSH activation context, when present. |
| `SSH_MESH_ROUTE_CLIENT_ID` | unset | Caller connection ID from SSH activation context, when present. |

## Deprecated

| Variable | Default | Effect |
| --- | --- | --- |
| `SSH_MESH_ROUTE_USER` | unset | Compatibility alias for activation context user. |
| `SSH_MESH_ROUTE_COMMAND` | unset | Compatibility alias for activation-triggering command. |
