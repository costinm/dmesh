# DMesh Recovery application and shared library

This directory will contain the normal ESP-IDF Recovery application. Unlike
the second-stage bootloader in [`../boot`](../boot), Recovery has the runtime
needed for Wi-Fi, HTTP, NVS, flash writes, and authenticated update parsing.

The Recovery implementation is split so Main can link the same update code
when Main later needs to install a newer Recovery image:

```text
fw/recovery/
  core/       platform-neutral request, record, signature, and flash logic
  app/        Wi-Fi/HTTP source and ESP-IDF Recovery entrypoint
```

The shared core must not depend on FreeRTOS, Wi-Fi, or application globals. It
uses small callback interfaces for:

- reading a byte stream;
- reading/writing/erasing a partition;
- obtaining the trust key;
- logging;
- reboot and request-state operations.

Recovery supplies the HTTP and ESP-IDF adapters. Main can link the same core
with a local/file/mesh transport when updating the Recovery partition. Main
must never overwrite the running Recovery image; it writes a verified image to
the inactive Recovery partition location and reboots only after the write is
complete.

The first target is the classic ESP32 `e5` board with no LoRa hardware. No
LoRa, BLE, discovery, MQTT, HTTPS, or product application logic belongs in
Recovery.

For initial factory/testing bring-up, Recovery also has an explicit
`bootstrap` mode. It is available only when no trust key exists in NVS. If an
SSID exists, Recovery joins it as a station; otherwise it starts the open AP
`ESP32S3_8_BOOT_XXXX`, where `XXXX` is the last four hexadecimal MAC bytes,
with fixed address `192.168.4.1`. If a remote server address exists, Recovery
is a TCP client; otherwise it starts a bounded TCP image server. Once a
signing key is provisioned, unsigned input is unavailable; signed TCP input
remains available.

See [DESIGN.md](DESIGN.md) for the shared-library boundary and update flow.

## E5 bootstrap test

With the E5 in Recovery AP mode and the USB Wi-Fi adapter available through
the existing lmesh-managed `wpa_supplicant` control socket, send a Main image
with:

```sh
python3 scripts/recovery_wifi_push.py \
  target/fw/flash/e5/main-app.bin \
  --interface wlan1 \
  --ctrl-dir /run/mesh/wpa-supplicant-nan
```

The script scans for `ESP32S3_8_BOOT_XXXX`, joins it as an open network,
assigns the host `192.168.4.2`, and sends the bounded bootstrap stream to
`192.168.4.1:3333`.
