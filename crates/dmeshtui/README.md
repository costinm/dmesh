# dmeshtui

Linux terminal UI for exercising DMesh/ssh-mesh message flows.

The crate is split so the shared UI model is available without terminal
dependencies:

- `dmeshtui` library: message/event model and `MeshClient` abstraction.
- `dmeshtui` binary: ratatui/crossterm Linux frontend.

By default the binary sends submitted lines through:

the local `mesh-init` JSONL UDS. No commands are executed for each request.

Run it with:

```sh
cargo run -p dmeshtui
```

Type a JSONL method name in the input field, for example:

```text
status
```

If the method takes parameters, put a JSON object after the method:

```text
status {"name":"ssh-mesh"}
```

Non-JSON text after the method is sent as `{"text":"..."}`.

Override the local mesh client or target app with:

```sh
cargo run -p dmeshtui -- --app mesh-init
cargo run -p dmeshtui -- --socket /run/mesh/mesh-init/mesh.sock
```

Environment equivalents:

```sh
DMESHTUI_MESH_APP=mesh-init cargo run -p dmeshtui
DMESHTUI_MESH_SOCK=/run/mesh/mesh-init/mesh.sock cargo run -p dmeshtui
```

For a remote node, the TUI still connects only to a local UDS. Requests are
wrapped and sent to the local mesh service, which is responsible for routing
through ssh-mesh:

```sh
cargo run -p dmeshtui -- --remote node1 --target-app mesh-init
```

That defaults to connecting to the local `ssh-mesh` UDS and sending:

```json
{
  "method": "mesh.remote.jsonl",
  "node": "node1",
  "app": "mesh-init",
  "data": {
    "method": "status"
  }
}
```

Override the routing method with `--remote-method` or
`DMESHTUI_REMOTE_METHOD` if the local ssh-mesh handler uses a different method
name.

The Android `dmeshui` crate reuses the library model for its ratatui-style
eframe preview activity without depending on ratatui/crossterm on Android.
