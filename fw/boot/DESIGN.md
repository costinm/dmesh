# DMesh second-stage bootloader design

## Status and judgment

The architecture is on the right track: keep the always-executed supervisor
small, keep Wi-Fi and flash-update logic in a normal ESP-IDF application, and
keep Main policy out of both. This gives a broken Main a recovery path without
putting a network stack in the bootloader.

The implementation is usable and has booted the classic ESP32 fleet and the
8 MB ESP32-S3 board. It is not yet a hardened immutable root of recovery. The
highest-value remaining work is listed below; in particular, the RTC state and
terminal halt behavior need stronger validation before calling the supervisor
fail-safe.

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

The authoritative application table is `partitions.csv`. Physical flash
larger than 4 MiB is deliberately not represented in that application layout;
Main uses the additional region explicitly for modules/raw data. The
`partitions_8mb.csv` table is the current boot-provisioning artifact for
boards with more than 4 MiB and up to 8 MiB of flash; `lora4` is the current
example. It preserves the same NVS, Recovery, and Main offsets while
expanding the data entry. Its matching 8 MiB stage2 is flashed only during
initial USB provisioning or emergency repair. Future flash sizes need
the same treatment with a matching table/stage2 limit.

The current fleet policy is:

| boards | physical flash | stage2/table at initial provisioning | Main/Recovery images |
|---|---:|---|---|
| `e5`, `lora1`, `lora2`, `lora3` | 4 MiB | common 4 MiB | common 4 MiB-layout images |
| `lora4` | 8 MiB | 8 MiB-specific stage2 and table | common 4 MiB-layout images |

The expanded stage2/table distinction exists because stage2 validates
partition entries against its configured flash limit. It is not an OTA
variant and is not touched by routine Main or module updates. After
provisioning, Main owns the data/module region and the normal update path uses
the Main TCP control plane; Recovery remains the failure-recovery updater for
Main.
Current measured second-stage binaries are 28,192 bytes on ESP32 and 22,816
bytes on ESP32-S3.

## Implemented boot sequence

After ESP-IDF bootloader initialization and partition-table loading, stage2:

1. emits a fixed DMB1 identity in PPP/HDLC framing;
2. when `recovery:uart_boot` is enabled, waits 500 ms for either the fixed framed Recovery command or legacy ASCII
   `RECOVER`;
3. reads the Recovery request marker from NVS;
4. consumes the application health event in RTC memory;
5. evaluates rapid boots and Main/Recovery failure counters;
6. loads the selected fixed application partition with ESP-IDF bootloader
   loading primitives.

There is currently no boot-button check. A healthy device needs no button:
Main requests Recovery through its normal command path, while repeated rapid
resets are the local fallback.

Selection priority is:

1. explicit UART Recovery selector;
2. valid/persisting NVS Recovery request;
3. four boots close enough that three prior timestamps fall within the raw RTC
   tick window;
4. failure-counter fallback;
5. Main.

When Recovery was explicitly selected but has failed six times, stage2 tries
Main if Main has not also reached six failures. When both counters have reached
the limit, the intended terminal state is a low-activity UART-repair halt.

## RTC boot-health ABI

Stage2 reserves 32 bytes of RTC retain memory. Its custom state contains:

- magic and layout generation;
- Main and Recovery failure counters;
- four raw RTC boot timestamps;
- four boot-kind bytes (reserved by the current logic).

Applications write one volatile event byte:

- `MAIN_START` immediately after Main begins;
- `MAIN_OK` after Main reaches its ready point;
- `RECOVERY_START` when Recovery starts;
- `RECOVERY_OK` only after a successful flash session.

Stage2 increments a target's counter before handoff. `MAIN_OK` clears only
Main's failure counter; rapid-reset timestamps are retained so three deliberate
external resets can select Recovery even when Main normally reaches `MAIN_OK`.
Entries older than the rapid-reset window are ignored. `RECOVERY_OK` clears
both counters and the history so the next boot is a fresh Main attempt. Routine
boots do not update NVS.

Current limitations are important:

- the custom RTC bytes are outside ESP-IDF's retained-memory CRC;
- magic and generation detect an uninitialized layout but not arbitrary bit
  corruption;
- the rapid-boot window uses a fixed raw-tick threshold and does not calibrate
  the selected RTC slow clock;
- reset reasons are logged but not used to exclude deep-sleep wakeups, planned
  resets, or other benign rapid boots;
- `RECOVERY_START` and `MAIN_START` are informational in the current selector;
  only the `*_OK` events alter counters.

RTC state is the right storage medium for wear and latency, but it must be
treated as volatile evidence rather than trusted persistent state.

## Recovery request ABI

Stage2 reads only these NVS fields in namespace `recovery`:

| Key | Accepted type | Meaning |
|---|---|---|
| `request_magic` | `u32` or numeric string | `0x52455131` (`REQ1`) |
| `request_version` | `u32` or numeric string | currently `1` |
| `uart_boot` | `u32` or numeric string | missing/nonzero enables the stage2 UART selector; `0` disables it |

For compatibility with older provisioned devices, version `1` currently
selects Recovery even when `request_magic` cannot be read. That compatibility
exception is an availability risk: a stale version key can repeatedly select
Recovery. It should be removed after fleet migration or replaced by a compact
record with an integrity check.

Main also stores transport fields (`ssid`, `password`, `server`, `ip`, `port`,
`update_url`, and `flags`). Stage2 deliberately does not parse them. Recovery
retains transport configuration but clears the one-shot marker fields only
after a successful update.

The P-256 trust key is consumed by Recovery, not stage2.

## UART boot handoff

DMB1 is a fixed byte layout, not general CBOR. PPP/HDLC delimiters and escaping
allow a UART receiver to regain framing. The identity includes version, role,
partition, reset reason, and a short RTC tick value; remaining bytes are
reserved. The 500 ms window is deliberately bounded on every boot. The managed
lmesh host sends the fixed command immediately after the reset pulse; it does not
wait for the identity to make the round trip first. This is necessary because the
old 50 ms window was shorter than the managed forwarding path and caused stage2
to report its identity while still falling through to Main. Stage2 also logs
whether Recovery was selected by the NVS request, the flash reset journal, or
the RTC rapid-reset history; these reasons are intentionally diagnostic only.

The selector is controlled by `recovery:uart_boot` in NVS. Missing or malformed
values default to enabled for development and backward compatibility. A value
of zero disables the DMB1 identity, legacy `RECOVER` parsing, and all stage2
UART polling. Production provisioning must set this key to zero explicitly;
rapid reboot history and the RTC failure counters remain available.
`scripts/prepare-nvs-image.py` accepts `--uart-boot 0` to add or replace this
setting while generating a provisioning NVS image.

DRS2 is not used in stage2. TCP does not need PPP framing, and pulling the full
flash protocol into the bootloader would weaken the size and audit boundary.

## Failure behavior and power loss

- A crashing Main leaves `MAIN_OK` unset, so repeated stage2 handoffs eventually
  select Recovery.
- An interrupted Main write leaves the Recovery request set. The next boot
  selects Recovery and retries.
- An unavailable AP does not make Recovery reboot immediately; Recovery keeps
  retrying association in bounded windows.
- A corrupt or non-starting Recovery eventually causes a Main fallback.
- A corrupt Main and corrupt Recovery are intended to stop in UART-repair mode.

The last item is not fully proven: `halt_for_uart()` loops without feeding or
disabling the enabled bootloader watchdog. The watchdog may reset the chip,
turning the intended halt into another boot loop. Fix and test this before
relying on the six-plus-six terminal policy for power savings.

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

1. Make terminal halt real: disable or feed the bootloader watchdog, enter the
   lowest safe wait state available, and verify current draw and UART recovery.
2. Add a CRC to the custom RTC structure and reset state on CRC, generation,
   impossible counter, or impossible timestamp values.
3. Calibrate the rapid-reset threshold from the RTC slow clock and filter reset
   reasons so planned reboot/deep-sleep cycles do not imitate a crash loop.
4. Remove the version-only NVS request compatibility exception after all fleet
   writers use the typed magic, or replace the split keys with a small
   checksummed request marker.
5. Add host tests for the complete state machine: normal boot, healthy marker,
   rapid-reset entry, six Main failures, six Recovery failures, both-failed
   halt, RTC corruption, timer wrap, and power-on reset.
6. Record a compact boot-decision reason that Main/Recovery can report later;
   RTC or serial is preferable to routine NVS writes.

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
- ESP8266 remains a separate future design because its RAM, flash layouts, ROM
  loader, and SDK primitives differ materially.

## Non-goals

Stage2 does not connect to Wi-Fi, parse DRS2, erase applications, compare
versions, schedule updates, provide product recovery UI, or make rollout
policy decisions.
