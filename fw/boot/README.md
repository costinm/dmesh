# DMesh ESP second-stage bootloader

The normative stage2 wire/RTC contract is [API.md](API.md). This README is
operational/build guidance only.

`fw/boot` is the small supervisor between the ESP ROM and the two application
partitions. It normally starts Main and selects Recovery when Main requested an
update, a host responds during the bounded 500 ms UART window, rapid resets are observed,
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
stage2 variant. This distinction applies only to initial USB
provisioning (or emergency repair). It is not a second Main/Recovery image
family and it is never part of routine updates. Use the real chip size with
the provisioning tool when provisioning; do not flash an expanded table onto a smaller
board.

Routine Main updates do not flash stage2 and do not use USB. USB provisioning is
reserved for first provisioning or emergency repair. Although Main's shared
flash worker can technically target stage2, rewriting the only bootloader copy
has no power-loss rollback and should remain rare and explicitly controlled.

The stage2 UART selector is controlled by binary `u32` `recovery:uart_boot` in
NVS. It is enabled when the key is missing or nonzero, preserving the lab/default behavior.
Production provisioning should write `uart_boot=0`; stage2 then emits no
UART identity and performs no UART polling, leaving rapid resets and the RTC
failure counters as the recovery path. The enabled selector window is 1000 ms.
For an NVS image made from a dump, use
`scripts/prepare-nvs-image.py ... --uart-boot 0`.

Implemented triggers are UART (when enabled), rapid resets, and RTC failure
counters. A button trigger is not currently implemented. The intended
both-images-failed halt and RTC-corruption handling still need the hardening
listed in [DESIGN.md](DESIGN.md).

See [DESIGN.md](DESIGN.md) for the exact selector, RTC ABI, request ABI,
partition layout, limitations, and long-term options.
