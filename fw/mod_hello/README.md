# `mod_hello` dynamic-module experiment

This is a `no_std`, allocation-free Rust module with one exported C ABI entry
point: `dmesh_module_entry`. It receives a versioned context, payload bytes,
and argument bytes. Its initial host capability is a bounded `log_line`
callback; the ABI also reserves `call_service`, which queues a service command
to Main's serialized command registry.

The module is wrapped in the 64-byte `DMOD` header from
`include/dmesh_module_abi.h`. The wrapper is
written to a 64 KiB-aligned offset of the ESP `data` region using DRS2 target
`module`; Main maps it into instruction space and invokes the entry after
validating the header. The header records the module's requested FreeRTOS
stack depth in words; Main clamps it to its supported range before creating
the task.

This is deliberately an ABI experiment, not a sandbox. Module code executes
with Main's privileges. It must not define retained state, call host symbols,
or retain context/payload/argument pointers after return.

The module crate itself is target-independent and can be checked on any Rust
target. `src/bin/mod_hello.rs` supplies the one flat-image entry point.

Build the ESP image with the repository-local toolchain:

```sh
bash fw/mod_hello/build.sh xtensa-esp32-espidf
```

For RISC-V boards, use the Espressif target instead:

```sh
bash fw/mod_hello/build.sh riscv32imac-esp-espidf
```

The RISC-V build uses Rust's PIC relocation model and is checked for an empty
relocation table before packaging.

This writes `target/modules/xtensa-esp32-espidf/mod_hello.dmod`. Xtensa builds
default to the Main-reserved fixed window and refuse artifacts with
relocations, global symbols, data, or BSS. Xtensa Rust does not currently
produce a safe generic PIC image: a flat image with VMA zero must not be mapped
at an arbitrary virtual address. The current loader exposes one canonical
window per CPU; an override is accepted only when it names that exact window,
for example:

```sh
DMESH_MODULE_VMA=0x43000040 bash fw/mod_hello/build.sh xtensa-esp32s3-espidf
```

That sets the DMOD fixed-VMA flag; Main must be built with the corresponding
reserved MMU window before such an image is deployed. A different slot/window
requires a coordinated Main loader change and is intentionally rejected by
the build scripts for now.

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
