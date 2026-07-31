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

The first hardware target is the `e5` lab board: classic ESP32,
MAC `fc:f5:c4:0e:f1:e8`, with no LoRa hardware. The existing LoRa profiles are
not part of the initial bring-up.

The bootloader and Recovery have been built for the E5 layout. Hardware flash
testing remains an explicit bring-up step; the layout is now measured rather
than provisional.

See [DESIGN.md](DESIGN.md) for the architecture, failure policy, and rationale.
