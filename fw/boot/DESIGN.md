# Recovery boot design and rationale

## Objective

Provide a stable, reusable boot supervisor for ESP32 projects. The supervisor
must make Main recoverable even when Main cannot initialize, request recovery,
or remain alive long enough to handle a reset.

The system has three executable images:

1. the ROM bootloader;
2. this custom second-stage bootloader;
3. two application images: Recovery and Main.

The second-stage bootloader is not an application and must remain small. The
Recovery application owns networking and update transport.

## Boot policy

After normal second-stage initialization, the bootloader checks these sources
in order:

1. a valid long button hold during the first three seconds;
2. the exact ASCII string `RECOVER` on the boot console UART during the first
   three seconds;
3. a valid bootloader-readable Recovery request in NVS;
4. six consecutive Main boot failures without a healthy-start acknowledgement;
5. otherwise, Main.

If any of the first three conditions is true, the bootloader loads Recovery.
Otherwise it loads Main. Application image loading uses the ESP-IDF bootloader
loader with policy/hash validation disabled; the loader still has to parse
segments and configure RAM and flash mappings in order to start an image.

If Recovery has no provisioned trust key, Recovery may enter the explicitly
named `bootstrap` test mode. SSID presence selects STA versus AP, and remote
server-address presence selects TCP client versus TCP server. This is a
factory/development escape hatch for the first image installation, not a
response to a bad signature or a network failure. A present trust key always
disables unsigned input.

Recovery performs the authenticated update and clears the request only after
the stream has completed successfully. It then reboots. With no `otadata`
partition, the bootloader sees no pending request and starts Main.

Main writes a request before rebooting when it wants Recovery, and publishes a
healthy-start marker through the shared RTC-retained ABI. The bootloader only
reads NVS during selection; it never commits NVS for routine boot attempts.

## Crash-loop state

Use ESP-IDF RTC-retained bootloader memory, including its CRC, plus a small
custom field for:

- consecutive Main handoff attempts;
- a healthy-start acknowledgement state and separate Main/Recovery counters.

The counter is incremented before loading Main. Main clears it once startup is
healthy. Six consecutive attempts without that acknowledgement select
Recovery. Recovery has its own six-attempt counter; if both applications have
reached the limit, the bootloader halts and logs that UART flashing is
required. A successful Recovery transaction clears both counters before the
next Main attempt. The counters live in RTC RAM and are not NVS wear events.

The existing ESP-IDF primitives are the intended starting points:

- `bootloader_common_check_long_hold_gpio_level()` for the button;
- `bootloader_common_update_rtc_retain_mem()` and
  `bootloader_common_get_rtc_retain_mem()` for retained state;
- `bootloader_load_image_no_verify()` for image loading;
- the bootloader's `set_cache_and_start_app()` path for the final handoff.

## NVS request ABI

The bootloader uses the ESP-IDF `nvs_bootloader_read()` API. That API supports
integers and strings, not arbitrary blobs, so the first ABI stores request
fields separately:

| Namespace | Key | Type |
| --- | --- | --- |
| `recovery` | `request_magic` | `u32` |
| `recovery` | `request_version` | `u32` |
| `recovery` | `flags` | `u32` |
| `recovery` | `ssid` | string |
| `recovery` | `password` | string |
| `recovery` | `update_url` | string |

The request is valid only when magic, version, lengths, and required fields
match the checked-in ABI. Main writes these fields atomically from the user's
perspective, then reboots. Recovery clears them only after success.

The trust key is consumed by Recovery, not by the bootloader. Bootloader NVS
reads must remain small and safe even if the normal NVS contents are corrupt.

The bootloader does not select bootstrap mode itself. It only sends the device
to Recovery; Recovery decides whether the trust-key state permits bootstrap
mode.

## Partition layout

The E5 layout is based on the existing classic ESP32 4 MiB profile and keeps
the current NVS and PHY offsets to avoid destroying deployed settings. The
same Recovery/Main shape is used on the 8 MiB S3 layout, which additionally
contains `dmesh_store`.

The target shape is:

```text
0x00001000  second-stage bootloader
0x00008000  partition table
0x00009000  NVS                 (preserve current location)
0x0000F000  PHY init             (preserve current location)
0x........  Recovery app
0x........  Main app
```

Recovery and Main must be aligned to ESP app boundaries. The Recovery
partition starts conservatively; its exact size will be the optimized release
image size plus measured headroom. Main retains enough capacity for the
current firmware image and future growth.

No `otadata` partition or OTA slot is used. The S3 layout has a `dmesh_store`
partition for the larger-flash boards; it is a normal named data target for
Main-controlled raw TCP flashing.

## Scope boundary

The bootloader does not:

- connect to Wi-Fi;
- perform HTTP;
- parse update records;
- verify update signatures;
- compare versions;
- erase or write Main;
- make product policy decisions.

Those responsibilities belong to Recovery or Main.

## Rationale

Putting the decision in the second-stage bootloader avoids the failure mode
where Main is too broken to request Recovery. Keeping networking out of the
bootloader avoids porting a full TCP/IP stack into the tiny pre-RTOS
environment. Keeping update logic in the Recovery application allows normal
ESP-IDF Wi-Fi/HTTP APIs and makes Recovery independently reusable.

The no-`otadata` design also makes the boot path explicit: the supervisor
always owns the Recovery-versus-Main decision instead of depending on OTA
selection state.

## Validation before flashing

Before any E5 flash:

1. build the bootloader and Recovery release images;
2. record bootloader, Recovery, Main, and partition-table sizes;
3. inspect map files and retained-memory usage;
4. validate partition offsets with ESP-IDF tooling;
5. run host tests for request parsing, crash-loop state, and boot selection;
6. build a signed test stream and exercise Recovery without hardware writes;
7. review the final layout and only then prepare a sparse E5 flash image.

## Deferred integrity index

For future differential updates, reserve the final sector of each updatable
partition for a compact per-block digest index. It is deliberately outside
the usable image area. A device-first transfer can return that index, receive
a signed replacement index, and accept only blocks whose digests changed.
The replacement index is committed last, after all block writes verify. This
also gives the second-stage bootloader a bounded way to verify Main and
Recovery before starting them. Truncated SHA-256 is the first candidate; the
index must fit without requiring a Merkle tree, or the partition format must
explicitly reject images that exceed its capacity.

The current implementation does not reserve or consume this sector and still
uses complete-image `DRS1` transfers. PPP framing for the second-stage,
Recovery, and Main paths is a separate future evaluation, with size and RAM
cost as the deciding constraints.
