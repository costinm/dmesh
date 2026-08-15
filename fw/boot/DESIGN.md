# DMesh second-stage bootloader design

## Executable and partition model

```text
ESP ROM
  -> DMesh second-stage bootloader (fw/boot)
       -> Recovery application (factory subtype, label recovery_app)
       -> Main application     (ota_0 subtype, label main)
```

There is no `otadata` partition and no call to
`esp_ota_set_boot_partition()`. `factory` and `ota_0` are fixed identifiers
used by the custom selector; they are not ESP-IDF OTA slots.

Main and Recovery use one canonical application layout. It preserves deployed
NVS and PHY offsets and fits a 4 MiB flash:

| Region | Offset | Size |
|---|---:|---:|---:|
| second stage | chip boot offset | up to `0x7000` bytes |
| partition table | `0x8000` | `0x1000` |
| NVS | `0x9000` | `0x6000` |
| PHY init | `0xf000` | `0x1000` |
| Recovery | `0x10000` | `0xd0000` |
| Main | `0xe0000` | `0x2e0000` |
| data | `0x3c0000` | `0x40000` |

Recovery and main are compiled with a 4M partition.csv - main can use 
the full 8M, with top 4M for data. Only boot needs to have the right
partition table, so 8M devices need to be provisioned with 8M table
when boot/recovery are installed - no longer needed after that.

This simplifies the main and recovery images - they are independent
of the flash size.


## Recovery request ABI

Stage2 reads only this NVS field in namespace `recovery`:

| Key | Accepted type | Meaning |
|---|---|---|
| `stg2:uart_boot` | `u32` | missing/nonzero enables the stage2 UART selector; `0` disables it |
| `stg2:boot_target` | `u32` | lab-only unconditional target: `1` Main, `2` Recovery |

## Failure behavior and power loss

- A crashing Main leaves `MAIN_OK` unset, so repeated stage2 handoffs eventually
  select Recovery.
- An interrupted Main write leaves the Recovery request set. The next boot
  selects Recovery and retries.
- An unavailable AP does not make Recovery reboot immediately; Recovery keeps
  retrying association in bounded windows.
- A corrupt or non-starting Recovery eventually causes a Main fallback.
- A corrupt Main and corrupt Recovery are intended to stop in UART-repair mode.

The terminal path now disables the applicable bootloader watchdog before its
low-activity UART-repair halt. It is only used when Main is in a crash loop and
Recovery has also exhausted its retry budget. A healthy Main falls back to Main
after Stage2 emits a framed Recovery-failure event.

## Security boundary

Stage2 does not authenticate update traffic. It relies on Recovery's verified
flash path and on optional ESP secure-boot/flash-encryption facilities if those
are enabled for a product. It does not implement version policy, rollback
policy, key rotation, networking, or application semantics.

Loading and mapping an ESP image still requires structurally valid segments.
The custom policy does not currently add a separate signed digest index or
explicit pre-handoff Main/Recovery hash check.

## High-value improvements

In priority order:

1. Verify terminal halt on each supported chip: watchdog disabled, no reboot
   loop, and UART repair remains available.
3. Calibrate the rapid-reset threshold from the RTC slow clock and filter reset
   reasons so planned reboot/deep-sleep cycles do not imitate a crash loop.
4. Add host tests for the complete state machine: normal boot, healthy marker,
   rapid-reset entry, six Main failures, six Recovery failures, both-failed
   halt, RTC corruption, timer wrap, and power-on reset.

## Long-term options

- A signed per-partition digest index could let stage2 cheaply reject an image
  that does not match the last committed update. The index must be committed
  last and must not become another mutable selection database.
- ESP secure boot is the stronger production root of code authenticity. DRS2
  signatures protect update input but do not replace ROM-to-stage2 secure boot.
- A/B Recovery is worth considering on larger flash devices if Recovery itself
  will be updated frequently. It is probably not worth the space on 4 MB
  devices while Recovery remains stable.
- Remotely rewriting the single stage2 at the ROM boot offset is inherently
  risky. Keep it rare. A truly rollback-safe stage2 update requires an
  immutable first shim or vendor-supported bootloader recovery mechanism, not
  merely another DRS2 target.

## Non-goals

Stage2 does not connect to Wi-Fi, parse DRS2, erase applications, compare
versions, schedule updates, provide product recovery UI, or make rollout
policy decisions.
