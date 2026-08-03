# `mod_hello` dynamic-module experiment

This is a `no_std`, allocation-free Rust module with one exported C ABI entry
point: `dmesh_module_entry`. It receives a versioned context, payload bytes,
and argument bytes. Its initial host capability is a bounded `log_line`
callback; the ABI also reserves `call_service`, which queues a service command
to Main's serialized command registry.

The module is intended to be linked as position-independent code and wrapped
in the 64-byte `DMOD` header from `include/dmesh_module_abi.h`. The wrapper is
written to a 64 KiB-aligned offset of the ESP `data` region using DRS2 target
`module`; Main maps it into instruction space and invokes the entry after
validating the header.

This is deliberately an ABI experiment, not a sandbox. Module code executes
with Main's privileges. It must not define retained state, call host symbols,
or retain context/payload/argument pointers after return.

The module crate itself is target-independent and can be checked on any Rust
target. `src/bin/mod_hello.rs` supplies the one flat-image entry point.

Build the ESP image with the repository-local toolchain:

```sh
bash fw/mod_hello/build.sh xtensa-esp32-espidf
```

This writes `target/modules/xtensa-esp32-espidf/mod_hello.dmod`. The script
links at address zero and refuses artifacts with relocations, global symbols,
data, or BSS. The Xtensa Rust backend currently rejects the formal PIC
relocation model, but the accepted flat artifact has no relocations and its
disassembly uses only local control flow plus the callback supplied in the
context. It can therefore be mapped at any 64 KiB-aligned flash location.

The wrapped image is named `hello`. Upload it through DRS2 target `module` at
a 64 KiB-aligned offset, then invoke it from Main with
`hello offset=0 size=65536 args=world`. The generic equivalent is
`module op=run name=hello offset=0 size=65536`. The image name is checked by
the loader before it is called, so the same module can safely be put in more
than one 64 KiB slot.
`module op=status` reports the flash execution requirements. PSRAM remains out
of scope for deployment: ESP32-S3 XiP supports application-linked sections,
but this experiment does not treat generic PSRAM heap memory as a dynamic code
loader.
