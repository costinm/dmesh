# DMesh ESP second-stage bootloader

`fw/boot` is the small (<32k) adapter between the ESP ROM and the two application
partitions. To save space, it expects a small Recovery partition (< 1M - most 
of it in Wifi libraries) and the rest is Main or modules.

It normally boots Main. 

Recovery is selected:
- when Main requests an upgrade
- if rapid resets are observed
- if Main repeatedly fails to reach its healthy marker.

RTC is used to communicate - reboots, selecting recovery, 'good state' from main.

```text
ROM -> stage2 -> Main
                 Recovery -> Wi-Fi STA and flash server -> reboot -> Main
```

There is no OTA-data partition and no ESP-IDF boot-partition switch.

Stage2 must be compiled with the correct partition size, matching the device
(4M, 8M, etc). This is required only for stage2.  Main and Recovery are not
 actually using their partition size so both are compiled with 4M even if 
 the device has more.

| Region | Offset | Size |
|---|---:|---:|---:|
| second stage | chip boot offset | up to `0x7000` |
| partition table | `0x8000` | `0x1000` |
| NVS | `0x9000` | `0x6000` |
| PHY init | `0xf000` | `0x1000` |
| Recovery | `0x10000` | `0x100000` |
| Main | `0x110000` | `0x2b0000` |
| data | `0x3c0000` | `0x40000` |

Recovery and main are compiled with a 4M partition.csv - main can use 
the full 8M, with top 4M for data. Only boot needs to have the right
partition table, so 8M devices need to be provisioned with 8M table
when boot/recovery are installed - no longer needed after that.

This simplifies the main and recovery images - they are independent
of the flash size.

The 4 MiB layout reserves a 256 KiB `data` partition at `0x3c0000`; Main uses
additional physical flash above that range for modules and other explicit raw
data when the hardware provides it - so max size for Main is ~3M, and 
can use extra flash for data (most ESP32 devices I have are 4M - just few are 8M).

Routine Main updates do not flash stage2 or Recovery. Both must be flashed 
over UART/USB - Main can be flashed over Wifi, using Recovery. After Main is 
flashed, it can upgrade both stage2 and Recovery.

# Build


Outputs are under `target/stage2/<chip>/` and contain only the matching
bootloader and partition table. Recovery2 is built separately with
`scripts/build-recovery2.sh CPU`.

Explicit RTC Main/Recovery handoffs are consumed once and outrank the NVS
boot selector. Recovery2 writes the Main handoff before its deliberate exits;
it never writes NVS. The persistent selector and crash-loop budgets remain
fallback policy when no explicit handoff is present.

## Failure behavior and power loss

- A crashing Main leaves `MAIN_OK` unset, so repeated stage2 handoffs eventually
  select Recovery.
- An interrupted Recovery2 Main write leaves the image head erased. Stage2's
  image loader rejects Main and falls back to factory Recovery.
- An unavailable AP does not make Recovery reboot immediately; Recovery keeps
  retrying association in bounded windows.
- A corrupt or non-starting Recovery eventually causes a Main fallback.
- If both Main and Recovery exhaust their retry budgets, Stage2 keeps
  booting Recovery. Recovery stays in its bounded repair state (AP retry,
  flash-server wait) until an operator flashes a new image, so a device
  never dead-ends in the bootloader.

## Flash read mode (QIO for Main)

Stage2 is always built as DIO; the build fails on a QIO/QOUT sdkconfig. It
chooses the mode used to read code from flash on each boot, after selecting
the partition. This mode applies to the whole app run: C6 apps never change
it, and classic ESP32/S3 apps adjust only the clock.

NVS `stg2:flash` (u32) selects Main's mode:

| Value | Mode | Behavior |
|---|---|---|
| 1 | DIO | Never enable QIO. |
| 2 | QIO | Always enable QIO for Main, with no fallback. |
| 3 | auto | Default, also used when the key is unset. Enable QIO for Main until one QIO boot fails, then use DIO until RTC memory is lost (power off). |

Any other value is treated as DIO. Set it with
`scripts/flash-device.py BOARD nvs --stage2-flash dio|qio|auto`.

Recovery always runs in DIO. Stage2 also stays in DIO when Main's partition
has no image header (Recovery erases it first during an update), because the
loader would then fall through to Recovery.

In auto mode, Stage2 records a QIO trial in the RTC byte at custom offset 6
(`DMESH_RTC_FLASH`) and clears Main's health event. If the next boot does not
see `MAIN_OK` from that Main boot, it marks QIO as failed. Failures include a
crash, a failed image check, a fallback to Recovery, or a reset before Main
reported healthy. A chip that rejects its quad-enable bit also counts as
failed. After power loss, the next boot tries QIO once more. A reset while a
healthy QIO Main is still starting up costs QIO until the next power cycle.

The RTC byte's bits are `0x01` trial pending, `0x02` QIO failed, and `0x04`
QIO active for the current boot. Apps may read it; only Stage2 writes it.
The ROM console shows the byte as `rtc_flash=` on the first Stage2 line, and
the chosen mode as `flash=` on the `load partition` line:

| `flash=` | Meaning |
|---|---|
| `qio` | Main is reading code in QIO. |
| `dio` | `stg2:flash=1`. |
| `dio-fallback` | Auto mode after a failed QIO boot. |
| `dio-no-main` | Main has no image header. |
| `dio-qe-failed` | The flash chip did not accept its quad-enable bit. |
| `dio-recovery` | Recovery was selected. |

Main's and Recovery2's own flash drivers (NVS, `esp_partition_*`) use their
own sdkconfig mode, and both must be DIO. ESP-IDF's driver never clears the
quad-enable bit, so a DIO driver is safe under QIO code reads. A QIO driver
is not: it relies on Stage2 having switched the flash pins to quad mode,
which Stage2 does only when it boots Main in QIO. Under a DIO boot (always
for Recovery; for Main after a fallback, `stg2:flash=1`, or a missing
header) every driver read returns garbage. On 2026-10-09 a QIO-driver
Recovery2 on e8 failed to read its STA profile, and NVS initialization in
that boot damaged NVS: it lost the `dmesh` namespace, `sec:key`, and
`sec:sta`, and Main then generated a new identity.

Stage2 emits no framed wire events. It logs plain console lines (tag
`dmesh-boot`): one boot line with the stage2 version, reset reason, RTC
handoff/health state, failure counters, and the NVS `boot_target`, followed by
the selection decision and its reason.

## Security boundary

Stage2 is not currently verifying the signature on Main or Stage2, and it is not 
encrypted/verified. It is possible to add this - but without disabling JTAG and
making the device fully locked it is not useful.

In general the main assumption of the device mesh is that relay nodes are completely
untrusted - and not all of them are under our control, but other users who have
their own policies (and can't be trusted). ESP32 is not a secure device - no TPM,
manufacturer is not specialized in secure devices - which is fine in a mesh that
doesn't depend on trusting the infra.


# Notes

- `stg2:boot_target` (1=Main, 2=Recovery) overrides automatic selection, but not
  explicit one-shot RTC handoffs.
- `stg2:flash` (1=DIO, 2=QIO, 3=auto, default auto) selects Main's flash read
  mode; see "Flash read mode" above.
- current implementation of recovery is passive: sends discovery multicast but waits for a server to create associations.

Rationale: with encryption/auth we want the ESP32 and recovery to just verify, not have the code to originate associations
and handle control plane. ESP32 to ESP32 is not needed even in main mode - Android or host create relays and use the 
control plane to authn/z with the relays.
