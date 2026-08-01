# DMesh Recovery application and shared library

This directory contains the active C ESP-IDF Recovery application. Unlike the
second-stage bootloader in [`../boot`](../boot), Recovery has the runtime
needed for Wi-Fi, TCP, NVS, and flash writes.

Current status: the E5 C Recovery implements and has been exercised for the
unsigned bootstrap image transport. It does not yet implement signed-record
parsing or signature verification. The trust-key check is therefore only a
bootstrap gate at present; it is not an authentication boundary until record
verification is added.

The Recovery implementation is split so Main can link the same update code
when Main later needs to install a newer Recovery image:

```text
fw/recovery/
  core/       platform-neutral request, record, signature, and flash logic
  app/        Wi-Fi/TCP source and ESP-IDF Recovery entrypoint
```

The shared core must not depend on FreeRTOS, Wi-Fi, or application globals. It
uses small callback interfaces for:

- reading a byte stream;
- reading/writing/erasing a partition;
- obtaining the trust key;
- logging;
- reboot and request-state operations.

Recovery supplies the TCP and ESP-IDF adapters. Main can link the same core
with a local/file/mesh transport when updating the Recovery partition. Main
must never overwrite the running Recovery image; it writes a verified image to
the inactive Recovery partition location and reboots only after the write is
complete.

The supported fleet images are classic ESP32 (4 MB) and ESP32-S3 (8 MB).
The current fleet bootstrap remains unsigned; no LoRa, BLE, discovery, MQTT,
HTTPS, or product application logic belongs in Recovery. Main uses the same
raw TCP image framing for non-running partitions: CBOR starts the session,
then the host sends a `DRS1` header and the complete image over TCP. CBOR is
not used for each flash block.

For initial factory/testing bring-up, Recovery also has an explicit
`bootstrap` mode. It is available only when no trust key exists in NVS. If an
SSID exists, Recovery joins it as a station using the configured static `ip`;
otherwise it starts the open AP
`ESP32S3_8_BOOT_XXXX`, where `XXXX` is the last four hexadecimal MAC bytes,
with fixed address `192.168.4.1`. If a remote server address exists, Recovery
is a TCP client; otherwise it starts a bounded TCP image server. The UART
selectors are `RECOVER` and the runtime `STA` command. Recovery can consume
the form `RECOVER IMG_IP:port IP SSID [PASSWORD]`, or save transport settings
with `STA IMG_IP:port IP SSID [PASSWORD]`. UART transport values
override NVS transport values, but the trust key is always read from NVS.
At present, a signing key causes the unsigned bootstrap stream to be rejected,
but no signed TCP input is implemented yet.

See [DESIGN.md](DESIGN.md) for the shared-library boundary and update flow.

## E5 bootstrap test

With the E5 in Recovery AP mode and the USB Wi-Fi adapter available through
the existing lmesh-managed `wpa_supplicant` control socket, send a Main image
with:

```sh
python3 scripts/recovery_wifi_push.py \
  target/flash/e5/main-app.bin \
  --interface wlan1 \
  --ctrl-dir /run/mesh/wpa-supplicant-nan
```

The script scans for `ESP32S3_8_BOOT_XXXX` with raw commands on the managed
wpa_supplicant socket, asks the managed lmesh controller to perform the fixed
channel-6 open-STA join, assigns the host `192.168.4.2`, and sends the bounded
bootstrap stream to `192.168.4.1:3333`. The caller needs the same
`CAP_NET_ADMIN` privilege used by the lmesh service for the host address step.

The STA test path uses a static lab link because the host AP does not provide
DHCP. The tested values are host `10.78.0.1`, E5 `10.78.0.200`, and TCP port
3336. The one-shot sender is:

```sh
python3 scripts/recovery_tcp_server.py \
  target/flash/e5/main-app.bin --bind 10.78.0.1 --port 3336
```

The sender does not require pacing. TCP flow control handles receiver
backpressure; the Recovery receiver loops until it has collected each
expected byte range. `--pace-ms` is available only as a diagnostic option for
comparing burst behavior, not as part of the protocol.

The current build intentionally contains no HTTP client/server components.

## Fleet provisioning and normal updates

Build all chip-specific stage-2/Recovery artifacts and the matching custom
Main images with:

```sh
scripts/build-recovery-fleet.sh all
scripts/build-fw.sh e5
CARGO_TARGET_DIR="$PWD/target/fw/recovery-s3" scripts/build-fw.sh recovery-s3
```

For a new board, `scripts/flash-recovery-fleet.py` processes roles strictly in
the order given. It stops the selected lmesh forward only for the initial USB
stage-2/Recovery write and the one-time `RECOVER` UART handoff, then restores
the forward before the TCP transfer and Main health check:

```sh
scripts/flash-recovery-fleet.py e5 \\
  --ssid TEST_AP --board-ip e5=10.78.0.200
```

This is initial provisioning only. After Main contains the `recovery`
command, use `scripts/update-main-wifi-fleet.py`; it sends the request through
the managed lmesh UDS and never opens a physical UART or uses USB directly.
USB is reserved for initial provisioning and emergency repair:

```sh
scripts/update-main-wifi-fleet.py e5 target/flash/e5/main-app.bin \
  --ssid TEST_AP --board-ip e5=10.78.0.200
```

The current C Recovery build is 786,864 bytes on classic ESP32 and 783,504
bytes on ESP32-S3. Both fit the `0xd0000` Recovery partition. AP-only and
STA-only variants have not been measured; the production bootstrap remains
STA-capable with an open AP fallback.

Fleet evidence (2026-08-01): E5, lora1, lora2, lora3, and lora4 returned live
Main status after current Main-controlled updates through lmesh. Classic
lora1, lora2, and lora3 accepted stage2 and Recovery over raw TCP; lora4
accepted the S3 stage2, Recovery, and `dmesh_store` data target. The current
Recovery images include a bounded UART grace window for explicit handoff
commands. No signed records are implemented yet.

## E5 validation

The custom bootloader and optimized Recovery were flashed on E5 with the
measured layout: Recovery at `0x10000` with size `0xd0000`, Main at `0xe0000`
with size `0x2e0000`. A current 1,615,760-byte Main image transferred over
STA/TCP, Recovery rebooted, and the
second-stage bootloader handed control to Main. Main returned live status with
`uptime_ms=22445`, heap telemetry, and zero LoRa counters. The original NVS
was restored and its readback SHA-256 matched
`d04172aaef332b66fbb798234e66b9c90acc87d7b55ba6e8be9225009802c9ab`.

The current Main-side raw TCP worker has additionally completed these E5
targets over STA: Recovery (786,864 bytes), stage2 (27,808 bytes), the
partition table (3,072 bytes), and a sanitized full NVS image (24,576 bytes).
Each write was followed by a reboot and live Main status check. These are
unsigned bootstrap transfers; authenticated records remain unimplemented.

The lora4 S3 data-target qualification then passed with the current Main
image: a 24,576-byte stream was written to `dmesh_store` over STA/TCP, the
board was reset through managed lmesh, and Main returned live status. The
initial apparent bootloader mismatch was a verifier bug: esptool normalizes
the bootloader flash-parameter header and appended SHA during writes, so the
verifier now applies the same parameters.
