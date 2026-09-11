# Demo chat app

This is a strange android app: it is using Rust for UI, in particular the TUI
interface.

It should provide a chat (or terminal) like interface: messages are sent 
over mesh, and messages from the mesh are shown in the app.

Commands "/" are supported and allow low-level control. The same app also
runs on Linux - the Android app is just a wrapper to integrate it.