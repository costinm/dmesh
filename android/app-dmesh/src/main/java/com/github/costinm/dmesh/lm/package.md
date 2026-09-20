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

Current Android-local BLE control is exposed through the shared `ble` HTTP
service. Use the `ble` service methods for scripted scans and CoC connections.
Companion association is started from the app UI.

The ADB shell provider remains for the remaining Rust shell transport commands
that do not yet have an Android HTTP service equivalent.
