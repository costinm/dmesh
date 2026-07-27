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
- GPIO0/PRG button - this is also DTR, but some boards have troubles with DTR resetting the board.
- `active` commands received via NAN/ESP-NOW.

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

`uart.hb_every` controls an opt-in wake heartbeat and defaults to `0`:

- `0`: firmware keeps UART quiet during raw-NAN duty wakes and after LoRa/FSK
  receive. lmesh retains queued UART commands until another wake source opens
  the console.
- `N > 0`: on every Nth raw-NAN Wi-Fi wake, firmware opens UART only for that
  raw-NAN active window (`nan.active_ms`, normally 250 ms) and writes exactly
  `0x7e 0x7e`. This is an empty UART frame, not a CBOR message. lmesh treats it
  as permission to flush its pending command queue. A received LoRa/FSK packet
  uses the same enabled setting with a 250 ms event window, then emits its
  normal binary notification.

UART RX is different: a complete host frame extends the normal configured
`uart.active_ms` interactive window (currently 2000 ms). A periodic heartbeat
or radio event must never create that longer window by itself.

For a four-second `nan.wake_ms`, use `uart.hb_every=1` for every wake,
`2` for roughly eight seconds, or `4` for roughly sixteen seconds. The active
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

- GPIO0/PRG or valid UART RX opens the normal two-second window.
- UART output does not extend that window; only input/wake activity does.
- After expiry, output is suppressed and the UART lock is released.
- `active` opens the same bounded UART window while its radio override remains
  active until `idle` or reset.

Classic ESP32 UART0 must use the APB clock source at 460800 while its APB lock
is held. Do not select REF_TICK: it causes RX corruption at this baud.

## Reset And Resynchronization

After `usb.serial.reset mode=run`, lmesh does not wait for a raw boot marker.
The first normal framed-CBOR response proves that the firmware is ready.
Unframed bytes are ignored until a `0x7e` delimiter. A malformed escape or a
payload above 4,000 bytes drops that frame and resumes at the next delimiter;
there is no synthetic `0xff` recovery stream and no command retry solely for
resynchronization.

## Validated State: 2026-07-26

The current implementation was validated after more than 35 seconds of
raw-NAN duty sleep on classic ESP32 and ESP32-S3 boards. GPIO0/PRG and DTR are
processed before the raw-NAN sleep scheduler, so an asserted wake source opens
the console/active window instead of racing an explicit sleep entry. The S3
uses the same explicit timer/GPIO light-sleep path as classic ESP32; it does
not rely on the retired automatic-PM-only behavior.

On a clean post-boot validation, `power uart_status=true` and `xstatus` should
show zero `uart_rx_drop`, `uart_rx_err`, `uart_frame_drop`, and
`uart_escape_err`. The PPP/HDLC migration and the disabled-by-default periodic
heartbeat are implemented; the shared authentication envelope remains future
work.

## lmesh Ownership

`mesh-init` runs lmesh. lmesh owns the serial FD, modem controls, UDS forward,
optional TCP/RFC endpoint, bounded queues, and per-forward counters.

```bash
source env.sh
mesh lmesh usb.serial.forward.list
mesh lmesh usb.serial.reset port=lora2 mode=run
mesh lmesh esp.serial.command port=lora2 command=status
```

Forward connections are passive: lmesh never pulses DTR or sends a disposable
probe on connect. `dtr [milliseconds]` and `rst` are explicit lmesh-local
CP210x diagnostics, not firmware commands. An explicit `dtr` opens a bounded
two-second lmesh flush window, so the next framed CBOR command is written
directly to the firmware even when `uart.hb_every=0`. They can be
board-specific and may reset a board. Keep RTS released for DTR diagnostics.

For firmware commands, use `esp.serial.command` or high-level lmesh methods.
Bare UDS console traffic is binary and intended for a binary client, not a text
terminal.

## Flash Policy

Do not flash via RFC2217. A bootloader probe can work while a long write is
corrupted. Flash through the local physical USB-UART after releasing the lmesh
forward. Use the fleet tool's sparse write path so NVS and PHY remain intact.

```bash
source fw/esp32/env.sh
export LMESH_CONTROL_SOCKET=/run/mesh/lmesh/mesh.sock
export PYTHONPATH="${SSH_MESH_PYTHON:?set SSH_MESH_PYTHON to the ssh-mesh Python directory}"
python fw/esp32/rust/tools/flash_test_fleet.py \
  --lmesh-mode local-release --port lora2 --flash-size-esp32 4mb \
  --skip-config --skip-preflash-stability --jobs 1
```

Without `--skip-config`, the fleet tool provisions over the physical UART about
three seconds after the direct flash reset, while the firmware boot window is
known active, then restores lmesh. It deliberately does not pulse DTR because
that line resets some CP210x boards. The baseline sets `uart.hb_every=1` with
the raw-NAN duty profile, so subsequent UDS requests can flush on every Wi-Fi
wake. This is a provisioning detail; normal operation remains through lmesh
UDS.

Restore forwards after flashing:

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

2. Reset through lmesh and request a framed status:

   ```bash
   mesh lmesh usb.serial.reset port=lora2 mode=run
   mesh lmesh esp.serial.command port=lora2 command=status timeout_sec=8
   ```

3. If the ready marker never arrives, stop only that forward and use the
   reusable capture mode at both boot and application bauds:

   ```bash
   mesh lmesh usb.serial.forward.stop port=lora2
   python fw/esp32/rust/tools/serial_cmd.py --port /dev/serial/by-id/<device> \
     --baud 115200 --capture-ms 1800 --no-sync
   python fw/esp32/rust/tools/serial_cmd.py --port /dev/serial/by-id/<device> \
     --baud 460800 --capture-ms 1800 --no-sync
   ```

4. A repeated bootloader checksum failure is an image problem. Reflash directly
   and do not diagnose it as a UART wake failure.

5. Use `power uart_status=true` and `xstatus` after recovery. RX/TX drops and
   RX errors, `uart_frame_drop`, and `uart_escape_err` should remain zero over
   repeated idle/recovery cycles. The physical decoder has no boot marker or
   synthetic resynchronization stream.

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
mesh lmesh usb.serial.reset port=lora3 mode=run
mesh lmesh usb.serial.reset port=lora2 mode=run
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
  RFC as a diagnostic/remote serial option, never a firmware flash path.
- Old 512-byte UART record validation rejected normal verbose status responses
  and provoked resync fills. The shared cap is now 4,000 bytes.
- Polling the main task or `uart_read_bytes` at fixed intervals prevents light
  sleep and previously caused unstable console behavior. Keep ingress/TX as
  blocking tasks with queues.
- UART RX wake can consume initial bytes on some silicon. It is not part of the
  product wake contract; use raw-NAN/BLE or GPIO0/PRG recovery.
- A bootloader line at 115200 may look like garbage to a forward configured at
  460800. Only continuous application-era corruption or checksum errors prove
  a firmware/flash failure.
