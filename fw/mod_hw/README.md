# `hw.dmod`

Minimal replaceable hardware-policy module for the ESP32 Main firmware.

`hw.dmod` is a flat, position-independent `no_std` image. It does not link
ESP-IDF. Main supplies the generic ABI declared in
`fw/modules/include/dmesh_hw_abi.h`; the implementation is in
`fw/esp32/rust/native/dmesh_module_loader/dmesh_hw_host.c`.

The normative wire and callback contract is [API.md](API.md).

The module uses compact CBOR tuple requests: operation `1` is battery, `2` is
ADC probing, and `3` is the GPIO button task. Events are CBOR tuples carried as
module event type 5. The button operation uses Main's GPIO0 interrupt queue
and reports short, long, and double presses without formatted text.
The module is intentionally small and independent of the mesh application so
it can be replaced through the common module flash protocol.

Build:

```sh
source ../../env.sh
bash build.sh xtensa-esp32-espidf
bash build.sh riscv32imac-esp-espidf
```

The RISC-V build uses Rust's `relocation-model=pic`, links at VMA zero, and
rejects relocations plus writable `.data`/`.bss` sections. The C6 test board
has now executed this image through Main's dynamically mapped instruction
window. Its default ADC pin is GPIO0; classic ESP32 builds retain GPIO35.

The output is under `target/modules/<target>/mod_hw.dmod`. It is deployed to
the hardware module slot with:

```sh
scripts/flash-device.py lora2 module --module hw
```

This is an incremental migration: Main still owns boot-critical button wake,
the established battery/peripheral commands, and the emergency LED path.
Complete policy migration and simultaneous module execution are future work.
