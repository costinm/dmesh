# DMesh ESP boot supervisor

This directory will contain the custom ESP-IDF second-stage bootloader for
DMesh. It is the small, deterministic supervisor that runs after the ROM
bootloader and before either application image.

The bootloader does not contain Wi-Fi, HTTP, update parsing, or product logic.
It only decides which application to load:

```text
ROM bootloader
      |
      v
fw/boot second-stage bootloader
      |
      +-- recovery request, button hold, or Main crash loop -> Recovery
      |
      +-- otherwise -----------------------------------------> Main
```

There is deliberately no `otadata` partition. The bootloader owns the choice
between the fixed Recovery and Main application partitions.

The first hardware target was the `e5` lab board: classic ESP32,
MAC `fc:f5:c4:0e:f1:e8`, with no LoRa hardware. The same layout has now been
validated on the attached classic fleet and the 8 MB ESP32-S3 `lora4` board.

The bootloader and Recovery have been built for the E5 layout and exercised
through the managed lmesh path. Direct USB flashing remains reserved for
initial provisioning and emergency recovery.

See [DESIGN.md](DESIGN.md) for the architecture, failure policy, and rationale.
