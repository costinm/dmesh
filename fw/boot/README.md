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
bootloader and partition table. Rust Recovery is built separately.

## Failure behavior and power loss

- A crashing Main leaves `MAIN_OK` unset, so repeated stage2 handoffs eventually
  select Recovery.
- An interrupted Main write leaves the Recovery request set. The next boot
  selects Recovery and retries.
- An unavailable AP does not make Recovery reboot immediately; Recovery keeps
  retrying association in bounded windows.
- A corrupt or non-starting Recovery eventually causes a Main fallback.
- If both Main and Recovery exhaust their retry budgets, Stage2 keeps
  booting Recovery. Recovery stays in its bounded repair state (AP retry,
  flash-server wait) until an operator flashes a new image, so a device
  never dead-ends in the bootloader.

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

- `stg2:boot_target` (1=Main, 2=Recovery) in NVS overrides the boot recovery logic.
- current implementation of recovery is passive: sends discovery multicast but waits for a server to create associations.

Rationale: with encryption/auth we want the ESP32 and recovery to just verify, not have the code to originate associations
and handle control plane. ESP32 to ESP32 is not needed even in main mode - Android or host create relays and use the 
control plane to authn/z with the relays.