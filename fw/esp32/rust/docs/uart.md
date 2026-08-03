# UART Transport And Recovery

Updated: 2026-07-26

UART is primarily used to communicate with a host, with the ESP device acting as a modem - and for stats/debug.

Since the firmware is used as a multi-radio 'modem' and peripheral, not as a standalone host - it is more efficient and compact to use a binary protocol and
require a host translation for text / json interaction. Meshtastic is using proto,
others use custom binary formats - we use CBOR with PPP framing/escape.

The UART goes to sleep - keeping the crystal and circuit on all the time is expensive and most of the time not needed. Even if the device is attached to a host,
there is no need to waste power - a raspberry Pi powered by solar panel for example
or even an Android using USB API. Several mechanism wake the UART:

- periodically, during all or some 'active' windows (4 or 8 sec intervals)
- when receiving a LoRA/FSK frame
- `active` commands received via NAN/ESP-NOW.

GPIO0/PRG and USB modem-control lines are not runtime transports. DTR is
reserved for direct `esptool` flashing of the bootloader, second-stage, and
recovery image; lmesh never toggles it and firmware diagnostics must not
depend on it.

When the device is idle - after finishing the commands, including a small wait time - the UART, wifi are off and CPU in light sleep, unless the host activates an 'always on' mode, with firmware acting as infrastructure (active at all times). 

## Contract

Firmware accepts only framed compact CBOR:

```text
0x7e | escaped compact-CBOR | 0x7e
```

- `0x7e` is the frame delimiter; encode literal `0x7e` and `0x7d` as
  `0x7d` followed by `byte ^ 0x20`.
- Maximum decoded CBOR payload: 4,096 bytes.
- Application responses and logs are compact-CBOR frames. ESP ROM boot and
  panic text are outside the application protocol and ignored until a frame delimiter is detected.
- lmesh converts between this UART-only codec and its normal UDS mesh stream
  envelope. Do not send newline commands directly to a firmware UDS socket.

Future authenticated envelopes will add a message-authentication code over the
CBOR payload across all transports, and may add MAC auth for host-firmware auth. This UART codec intentionally has no UART-specific FCS/checksum.

## Periodic UART Heartbeat

`uart.hb_every` controls the raw-NAN host rendezvous heartbeat and defaults to
`16` for battery nodes (one empty frame every sixteenth raw-NAN wake):

This setting is for non-infrastructure, duty-cycled nodes only. An
infrastructure/AP owner is powered and always-on: it keeps UART active
continuously and has no battery heartbeat window or light-sleep schedule.

- `0`: explicitly disables the rendezvous. lmesh then retains queued UART
  commands until another wake source opens the console. Use only for a
  deliberate power experiment; it is not a usable battery-modem default.
- `N > 0`: on every Nth raw-NAN Wi-Fi wake, firmware opens UART only for that
raw-NAN active window (`nan.active_ms`, normally 64 ms) and writes exactly
  `0x7e 0x7e`. This is an empty UART frame, not a CBOR message. lmesh treats it
  as permission to flush its pending command queue. A received LoRa/FSK packet
  uses the same enabled setting with a 250 ms event window, then emits its
  normal binary notification.

UART RX is different: a complete host frame extends the normal configured
`uart.active_ms` interactive window (currently 2000 ms). A periodic heartbeat
or radio event must never create that longer window by itself.

For infrastructure mode, keep `uart.hb_every=1` because the UART is always
awake. For a non-infrastructure four-second `nan.wake_ms`, use `1` for every
wake, `4` for roughly sixteen seconds, or `16` for roughly 64 seconds. The active
window and its PM locks are deliberately part of this power measurement. Check
`power uart_status=true` for `uart_hb_*` counters and lmesh forward stats for
`uart_wake_*` plus `serial_pending_queue_high_water`.

After transport authentication is introduced, add a message-authentication
  code to the shared command envelope rather than a UART-only checksum.

This also works well with sending over the air in the wake window.

## Runtime Design

UART RX is owned by an ESP-IDF event-queue ingress task. It blocks on UART
events and emits bounded complete records to the control path. The main task
does not poll `uart_read_bytes`.

TX is a separate task using bounded FIFO writes and no TX ring. This avoids the
classic ESP32 TX-empty ISR/watchdog failure. The console window controls the
APB and no-light-sleep locks:

- Valid framed UART RX or an authenticated radio wake opens the normal
  two-second window. GPIO0/PRG is recovery hardware, not a diagnostic wake
  path.
- UART output does not extend that window; only input/wake activity does.
- After expiry, output is suppressed and the UART lock is released.
- `active` opens the same bounded UART window while its radio override remains
  active until `idle` or reset.

Classic ESP32 UART0 uses the APB clock source at 115200 while its APB lock is
held. This deliberately matches the ROM and second-stage bootloader console,
so a single managed raw capture can decode both boot and application output.
Do not select REF_TICK.

## Reset And Resynchronization

After a direct `esptool` reset, lmesh does not wait for a raw boot marker.
The first normal framed-CBOR response proves that the firmware is ready.
Unframed bytes are ignored until a `0x7e` delimiter. A malformed escape or a
payload above 4,000 bytes drops that frame and resumes at the next delimiter;
there is no synthetic `0xff` recovery stream and no command retry solely for
resynchronization.

## Validated State: 2026-07-26

The current implementation was validated after more than 35 seconds of
raw-NAN duty sleep on classic ESP32 and ESP32-S3 boards. The S3 uses the same
explicit timer/GPIO light-sleep path as classic ESP32; it does not rely on the
retired automatic-PM-only behavior. Runtime diagnostics do not pulse DTR or
reset a sleeping board; they wait for the configured UART heartbeat/active
window.

On a clean post-boot validation, `power uart_status=true` and `xstatus` should
show zero `uart_rx_drop`, `uart_rx_err`, `uart_frame_drop`, and
`uart_escape_err`. The PPP/HDLC migration and the disabled-by-default periodic
heartbeat are implemented; the shared authentication envelope remains future
work.

## lmesh Ownership

`mesh-init` runs lmesh. lmesh owns the serial FD, UDS forward, optional
TCP/RFC byte-stream endpoint, bounded queues, and per-forward counters. It is
passive: it never owns or changes modem-control lines.

```bash
mesh lmesh usb.serial.forward.list
mesh lmesh esp.serial.command port=lora2 command=status
```

Forward connections are passive: lmesh never toggles DTR/RTS or sends a
disposable probe on connect. Modem-line control is reserved for direct esptool
while flashing the bootloader/second-stage and recovery image; it is not
available as a lmesh diagnostic command or a firmware wake mechanism.

There is no lmesh `usb.serial.reset` operation. If a running image needs a
software restart, send the firmware's normal `rst` command through
`esp.serial.command`; this remains framed CBOR over the managed lmesh forward
and does not touch UART modem lines.

For firmware commands, use generic `mesh` against the lmesh control UDS with
the generated `resources/tools.json` catalog, or use high-level lmesh methods.
`esp.serial.command` queues its CBOR request until the firmware's empty UART
heartbeat opens RX. Bare serial-forward UDS traffic is binary and intended for
a binary client, not a text terminal.

## Flash Policy

Follow [flashing.md](flashing.md) for the complete build, preflight, Wi-Fi
update, recovery, and verification procedure. This section records the UART
constraints behind that procedure.

Do not flash via RFC2217. A bootloader probe can work while a long write is
corrupted. Deployed boards update through Wi-Fi DRS2 while lmesh remains
active. The local physical USB-UART fleet tool is only initial provisioning or
P0 stage-2/Recovery repair; it preserves NVS and PHY.

```bash
scripts/flash-recovery-fleet.py --stage-only lora2
```

Without `--skip-config`, the fleet tool provisions through the supervised lmesh
UDS after flashing. Commands and diagnostics never pulse DTR and never open a
raw UART; DTR/RTS are reserved for esptool bootloader/recovery operations.

If an old local bootstrap run left a forward absent, restore it:

```bash
python fw/esp32/rust/tools/flash_test_fleet.py \
  --restore-forwards --skip-build --skip-flash --skip-config --skip-sanity \
  --lmesh-mode local-release
```

Never use `write_flash 0x0 dmesh-rs-merged.bin`: that merged image contains
`ff` padding over NVS and will erase saved LoRa pins/settings.

## Diagnostic Procedure

1. Check the managed forward first:

   ```bash
   mesh lmesh usb.serial.forward.list
   ```

2. Request a framed status through lmesh:

   ```bash
   mesh lmesh esp.serial.command port=lora2 command=status timeout_sec=8
   ```

3. If the ready marker never arrives, preserve the managed forward and its
   capture, then hand the failed Wi-Fi update to the flash/recovery owner. Do
   not switch lmesh to RFC2217, stop the forward, or use modem-line toggles as
   a diagnostic workaround. Deployed devices may have no USB connection;
   esptool is only initial provisioning or a P0 repair of stage-2/Recovery.

   Capture the managed lmesh serial log for boot evidence; do not open an
   RFC2217 diagnostic path.

4. A repeated bootloader checksum failure is an image problem. Reflash directly
   and do not diagnose it as a UART wake failure.

5. Use `power uart_status=true` and `xstatus` after recovery. RX/TX drops and
   RX errors, `uart_frame_drop`, and `uart_escape_err` should remain zero over
   repeated idle/recovery cycles. The physical decoder has no boot marker or
   synthetic resynchronization stream.

## Managed-Forward Reliability Check

## UART evidence rule

The managed lab profile records every forwarded board TX/RX record, including
role, host timestamp, escaped text, and exact bytes in hex, in
`target/lmesh-radio-build/log/serial.log`. Before changing a forward, resetting
a board, or reflashing after any UART timeout/framing error, inspect the
relevant role's records in that file and retain the excerpt with the test
artifact. A timeout without this log evidence is not a firmware-crash claim.

Use the focused lora1/lora4 profile after changing UART framing, wake handling,
or lmesh forwarding. It keeps firmware in its normal light-sleep/raw-NAN mode;
it does not pulse DTR. The case queues commands until the configured UART
heartbeat/active window, requires monotonic uptime and zero UART RX/frame/
escape errors, and verifies that delayed UART output is still gated.

```bash
source env.sh
target/nix/profile/bin/python fw/esp32/rust/tools/presubmit.py \
  --topology fw/esp32/rust/tools/lab.uart-reliability.json \
  --case uart_wake_reliability --profile quick --timeout 15
```

The artifact directory printed by the runner is the evidence: inspect
`results.jsonl` and `commands/lora1.jsonl` / `commands/lora4.jsonl`. A slower
response is normal at a duty-window boundary; a timeout, uptime regression, or
nonzero UART error counter is not.

## lora2 Recovery: 2026-07-26

`lora2` is the CP2104-backed classic ESP32 at
`d8:a0:1d:4c:5e:1c` (`target=1d4c5e1c`). Its apparent UART garbage was a reset
loop. At 460800 the bootloader showed:

```text
E (...) esp_image: Checksum failed. Calculated 0x4d read 0x6e
E (...) boot: Factory app partition is not bootable
```

The direct sparse 4 MB flash command above repaired the app without erasing
NVS. After recovery, `status` returned framed CBOR with monotonic uptime and
`wifi status=true` returned the MAC above.

Remote recovery was then verified from powered `lora3`:

```text
For a deployed-board reset/bootloader failure, preserve the managed evidence
and hand it off; do not use USB as a fallback. Issue framed commands through
lmesh when the board is reachable.
mesh lmesh esp.serial.command port=lora2 command='mode raw_nan=true channel=6'
mesh lmesh esp.active port=lora3 active=true
mesh lmesh esp.active gateway=lora3 target=1d4c5e1c active=true
mesh lmesh esp.serial.command port=lora2 command='mode status=true'
```

The target reported `infra_active=true` and
`infra_active_persistent=true`. `idle` returned lora2 to raw-NAN duty mode.

## lora4 Recovery: 2026-07-26

`lora4` is the 8 MB ESP32-S3/SX126x at `44:1b:f6:fc:54:3c`
(`target=f6fc543c`). An incomplete app image produced `invalid segment length
0xffffffff`; flashing the 8 MB S3 sparse image repaired it. Addressed raw-NAN
`active` then set its `infra_active` state and opened its bounded UART window.

## History And Rejected Paths

- RFC2217 at 921600 and long RFC application writes were not reliable. Keep
  any RFC byte-stream compatibility strictly diagnostic; lmesh ignores
  modem-control commands and it is never a firmware flash path.
- Old 512-byte UART record validation rejected normal verbose status responses
  and provoked resync fills. The shared cap is now 4,000 bytes.
- Polling the main task or `uart_read_bytes` at fixed intervals prevents light
  sleep and previously caused unstable console behavior. Keep ingress/TX as
  blocking tasks with queues.
- UART RX wake can consume initial bytes on some silicon. It is not part of the
  product wake contract; use raw-NAN/BLE or GPIO0/PRG recovery.
- Before the 115200 unification, a bootloader line could look like garbage to
  a 460800 application forward. That is no longer an expected mixed-rate
  condition: garbage on the unified managed capture is actionable evidence of
  a firmware, forward, or physical-link fault.
