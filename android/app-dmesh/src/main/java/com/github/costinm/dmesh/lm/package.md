# Local Mesh 

## Security model

Each device belongs to a mesh, with a 'control plane' and root certificate. The control plane 
provides config, discovery and control - and can execute all commands.


## Tools

The app implements a number of commands ('tools'), which may be called locally or from a control
plane or from the minimal UI.

It is expected that the tools will be exposed to an LLM or other apps which may execute the 
same commands.

Commands are implemented in DMService and the Rust dmesh native library.
Android features stay in Java, while low-level mesh networking belongs in Rust.

Current Android-local commands include:

- `companion status` / `companion clear` for the single ESP companion slot.
- `messages file` for the BLE message store path and byte count.
- `messages list limit=N` for stored BLE message headers.
- `messages read seq=N preview=N` for a bounded hex preview of one raw payload.

Keep these commands available through the same message/mux path used by the
ADB shell provider, SSH JSONL bridge, and web command bridge.
