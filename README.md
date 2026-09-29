# SSH-Mesh

`ssh-mesh` is a secure, daemonless process supervisor and L4 proxy system. It
runs local applications with per-app isolation, resource limits and a
cryptographic workload identity, and connects them over SSH, HTTP/2 and
WebSocket.

It is designed to orchestrate secure edge networks and run on-demand,
socket-activated containers, bubblewrap sandboxes, or virtual machines.

---

## What it is

The design borrows from several existing systems:

- **Serverless**: workloads run only while they are needed. Services are
  started on the first connection, and stopped or frozen when idle, so there
  are no long-running daemons holding resources.
- **Android**: each app runs under its own UID, and a small privileged init
  manages its lifecycle. As with Android's low memory killer, memory pressure
  (PSI) and usage are watched, and when memory is low lower-priority apps are
  frozen or stopped.
- **Kubernetes pods**: apps are started declaratively from a config that
  includes cgroup-based resource limits (systemd services work similarly).
- **Istio**: each host has a workload identity, using OpenSSH ECDSA keys and
  CA-signed certificates in addition to X.509/mTLS. HTTP/2 is supported, and
  the goal is to eventually be compatible with Istio HBONE.
- **systemd**: `mesh-init` implements a subset of systemd functionality and
  can act as the init (PID 1), or run as a service under systemd. The socket
  activation protocol (`LISTEN_FDS`/`LISTEN_FDNAMES`) is the same, so existing
  activated servers work unchanged. App configs are TOML files that reuse
  systemd section and key names (`[Service]`, `[Socket]`, `ExecStart`,
  `User=`, `Group=`); there is no converter from systemd unit files yet.
  `mesh-init` deliberately limits what an app config can grant rather than
  giving the config owner broad power.

### Architecture

The part that needs root and the part that handles networking are separate
processes:

```
   remote peers / browsers / ssh clients
                 │  SSH, H2/H2C, WebSocket, mTLS
          ┌──────▼───────┐
          │   ssh-mesh   │  unprivileged: SSH client+server, L4 proxy,
          │ (+ h2t, ws)  │  ControlMaster mux, REST/MCP/JSONL gateway
          └──────┬───────┘
                 │ UDS: JSONL / tagged-CBOR + passed FDs (stdio/PTY, listeners)
          ┌──────▼───────┐
          │  mesh-init   │  root (optionally PID 1), deliberately small:
          │              │  start/stop/freeze, socket activation,
          └──────┬───────┘  cgroups, PSI/memory observer, OOM priority
                 │ fork → drop privileges → exec (direct, or bwrap/podman/VM)
          ┌──────▼───────┐
          │   workloads  │  per-app UID, cgroup, namespaces; speak stdio,
          └──────────────┘  UDS, or the mesh API (sftp-server, mesh9p, …)
```

- `ssh-mesh` never runs as root and never executes commands itself. SSH
  shell/exec and the HTTP exec endpoint authenticate the caller, then pass
  the terminal or stdio descriptors to `mesh-init`, which runs the command as
  that user.
- `mesh-init` loads a config file per app that defines the sandbox,
  resources and command. Callers can change only a small set of options.
- Apps need no mesh-specific code: stdin/stdout or a UDS is enough, and the
  mesh proxy handles HTTP/2 or SSH forwarding. The optional `mesh` library adds
  a JSONL control socket, activation helpers and telemetry.

### APIs

The mesh components define their own APIs in `API.md` files: ordinary
Markdown documentation with tables that give every field a stable numeric tag.
`mesh-api-gen` generates Rust types, numeric IDs, JSON Schema and `tools.json`
catalogs from them. Services can use the same approach, but it is optional:
most services are expected to use JSON-RPC or other protocols, and `ssh-mesh`
translates between protocols based on a `tools.json` catalog, however it was
generated. MCP is added by a gateway (`mesh-mcp`) rather than by each worker.

The mesh's own wire format is tagged-CBOR, a subset of CBOR equivalent to
protobuf. JSONL/JSON-RPC and a structured text format are converted
mechanically. Protobuf itself is planned, using the same dynamic,
schema-driven translation with no generated stubs.

The intent is that clients and services using any supportable encoding can
communicate with each other, with the mesh gateways translating between them.

---

## Key Features

- **On-Demand Process Supervisor (`mesh-init`)**: Coordinates process lifecycles, socket activation, and system configurations. Supports freezing/unfreezing applications when idle to eliminate daemon resource overhead.
- **Secure Multiplexed L4 Proxy (`ssh-mesh`)**: Built-in SSH client and server supporting SOCKS5, UDS/vsock forwarding, ControlMaster Control Socket multiplexing, and HTTP/2 and WebSocket tunneling.
- **Resource Limits & Monitoring (`mesh-init`)**: Real-time observer for process cgroups, CPU, and Memory Pressure Stall Information (PSI), exposed through generic mesh JSONL/MCP proxying.
- **Secure Workload Identity**: End-to-end encryption with OpenSSH ECDSA public keys and CA-signed user/host certificates.

---

## Workspace Layout

The project consists of several Rust crates:

- **[ssh-mesh](crates/ssh-mesh)**: Core SSH/HTTP server/client and ControlMaster multiplexer. Also builds the `h2t` and `meshkeys` binaries.
- **[mesh-init](crates/mesh-init)**: Minimal system init/supervisor daemon and root process observer.
- **[mesh](crates/mesh)**: Common mesh library (config, auth, JSONL and tagged-CBOR protocols, UDS helpers, activation).
- **[mesh-api](crates/mesh-api)**: Platform-neutral shared structures and tagged-CBOR encoding, also used by firmware and Android.
- **[mesh-api-gen](crates/mesh-api-gen)**: Build tool that generates types, IDs, schemas and `tools.json` from `API.md`.
- **[mesh-cli](crates/mesh-cli)**: The `mesh` command-line client for local mesh services.
- **[mesh-mcp](crates/mesh-mcp)**: Optional Model Context Protocol adapter for mesh gateways.
- **[ws](crates/ws)**: WebSocket bridging and client management.
- **[sftp](crates/sftp)**: SFTP virtual file-system handler (`sftp-server`).
- **[mesh9p](crates/mesh9p)**: 9p file server, an alternative to sshfs for host and VM file sharing.
- **[ssh-config](crates/ssh-config)**: SSH client configuration file parser.

Outside the crates:

- **[python](python)**: `dmesh`, a pure-Python client for local mesh services, used in tests.
- **[nixos](nixos)**, **[flake.nix](flake.nix)**, **[manifests](manifests)**, **[Dockerfile](Dockerfile)**: Nix, NixOS, container and Cloud Run packaging.
- **[bin](bin)**, **[scripts](scripts)**: bubblewrap and podman launchers and build helpers.
- **[tests](tests)**: Python and NixOS integration tests.

---

## Documentation & Getting Started

- **[Local Multi-Host Examples](docs/examples/README.md)**: Detailed multi-host mesh topology (Gateway, VMs, Bubblewrap) using checked-in certificates.
- **[App VM Debugging Guide](docs/examples/app-vm-debugging.md)**: Detailed troubleshooting commands and logs for VM-based apps.
- **[mesh-init all-fields TOML](crates/mesh-init/examples/all-fields.toml)**: Canonical annotated reference for every supported mesh-init service config field. Keep this file up to date when adding or changing config fields.
- **[mesh-init config](crates/mesh-init/CONFIG.md)** and **[termination model](crates/mesh-init/TERMINATION.md)**: Service configuration, activation and idle handling.
- **[mesh-init systemd unit](crates/mesh-init/examples/mesh-init.service)**: Production installation under systemd.
- **[Mesh library](crates/mesh/README.md)**: Protocols, framing and the echo worker examples.
- **[NixOS](docs/nixos.md)**: NixOS module usage.
