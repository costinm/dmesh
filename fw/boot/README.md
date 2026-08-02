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

Both ESP32 and ESP32-S3 use the single 4 MiB layout in
[`partitions.csv`](partitions.csv). It reserves a 256 KiB `data` partition at
`0x3c0000`; boards with more physical flash may use addresses above 4 MiB
through explicit Main code without changing the Recovery/stage2 layout.

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
