# DMesh ESP second-stage bootloader

`fw/boot` is the small supervisor between the ESP ROM and the two application
partitions. It normally starts Main and selects Recovery when Main requested an
update, a host responds during the 50 ms UART window, rapid resets are observed,
or Main repeatedly fails to reach its healthy marker.

```text
ROM -> stage2 -> Main
               Recovery -> Wi-Fi DRS2 update -> reboot -> Main
```

There is no OTA-data partition and no ESP-IDF boot-partition switch. Recovery
is the fixed `factory` application and Main is the fixed `ota_0` application.
Wi-Fi, signatures, flash writes, and update policy are outside this component.

Current release artifacts:

| chip | bootloader size | configured raw boot region |
|---|---:|---:|
| ESP32 | 28,192 bytes | `0x7000` bytes |
| ESP32-S3 | 22,816 bytes | `0x7000` bytes |

Build both fleet variants from the repository root:

```sh
scripts/build-recovery-fleet.sh all
```

Outputs are under `target/recovery-fleet/<chip>/`. The same build also produces
the matching partition table and Recovery image.

The application images are deliberately built against the common 4 MiB
layout in [`partitions.csv`](partitions.csv). Recovery and Main keep those
offsets and are not rebuilt or reprovisioned for the physical flash size.
The 4 MiB layout reserves a 256 KiB `data` partition at `0x3c0000`; Main uses
additional physical flash above that range for modules and other explicit raw
data when the hardware provides it.

The bootloader has a provisioning-only physical-size variant. Any board with
more than 4 MiB of flash must receive a stage2 and partition table whose
configured limit covers that physical flash. The current fleet is:

| board | chip | physical flash | initial stage2/table |
|---|---|---:|---|
| `e5`, `lora1`, `lora2`, `lora3` | ESP32 | 4 MiB | common 4 MiB build |
| `lora4` | ESP32-S3 | 8 MiB | 8 MiB stage2 and table |

`lora4` needs the 8 MiB stage2/table because stage2 validates the installed
partition table against the configured flash limit. The same rule applies to
any future board above 4 MiB; use the smallest matching expanded table and
stage2 variant. This distinction applies only to initial USB/esptool
provisioning (or emergency repair). It is not a second Main/Recovery image
family and it is never part of routine updates. Use the real chip size with
esptool when provisioning; do not flash an expanded table onto a smaller
board.

Routine Main updates do not flash stage2 and do not use USB. USB/esptool is
reserved for first provisioning or emergency repair. Although Main's shared
flash worker can technically target stage2, rewriting the only bootloader copy
has no power-loss rollback and should remain rare and explicitly controlled.

Implemented triggers are UART, the NVS request marker, rapid resets, and RTC
failure counters. A button trigger is not currently implemented. The intended
both-images-failed halt and RTC-corruption handling still need the hardening
listed in [DESIGN.md](DESIGN.md).

See [DESIGN.md](DESIGN.md) for the exact selector, RTC ABI, request ABI,
partition layout, limitations, and long-term options.
