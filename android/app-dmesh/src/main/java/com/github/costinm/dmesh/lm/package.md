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
