# Debugging

Start with read-only checks and preserve logs/captures before resetting,
reflashing or changing radio configuration. Record the selected device,
firmware version, transport, UTC time, request size and deadline. Use catalog,
discovery or the selected E2E matrix for addresses—never a remembered board/IP.

## Environment and reachability

```sh
cd /ws/dmesh
. ./env.sh
dmesh-cli DEVICE check
dmesh-cli DEVICE services
dmesh-cli DEVICE status
```

Use the staged release binaries. Rebuild only after source changes; build and
deployment instructions are in [AGENTS.md](../AGENTS.md) and
[flashing.md](flashing.md). Do not rerun dependency setup for ordinary debugging.
Verify the selected image hash: for serial repair from frozen artifacts, pass
`flash-device.py --artifact-root DIR`; build-output environment variables do not
select the image to flash.

For Linux service/radio state:

```sh
mesh mesh-init mesh-init status name=lmesh
mesh lmesh status
mesh lmesh discovery.nodes
mesh lmesh telemetry.nan_status
```

Use supervised service control, not `systemctl`, PID kills or a second daemon.
Stop/start only for a deliberate restart test, and verify recovery afterward.
Do not change channels or interfaces owned by lmesh merely to collect a capture.

If a method is unsupported, check `services` and [API.md](../API.md).
Reachable endpoints need not expose the same handlers or allow remote calls.

## Capture logs and packets

Flash attempts, speeds, methods and failures are recorded automatically in the
[flash audit journal](flashing.md#flash-audit-journal). Keep that journal when
comparing Wi-Fi transfers with serial fallback.

Probe output reports `upload_mbps` (client to target) and `download_mbps`
(target to client), not their sum. In `direction=both`, each direction has its
own elapsed time through the terminal response and FIN. These are application
completion rates, not physical line rates; UART 8N1 uses ten line bits per byte.

For a physical UART bridge, Main's persistent `uart.baud` setting takes effect
after reboot. Supported rates are 115200, 230400, 460800, and 921600. Write and
read back the setting at the current rate; then reboot and reconnect using
`--baud RATE`, or update the device record's `uart_baud`. Keep cable-limited
devices at their known working rate. Native USB-JTAG does not use UART baud.

ESP `transport.set` can change the volatile UART rate after its response:
`uart=1` selects115200, `uart=7` selects460800, and `uart=9` selects921600.
Send over a working Wi-Fi/NAN path to recover an incorrectly selected UART
rate; this does not change the persistent `uart.baud`. `transport.set` replaces
the radio profile too, so supply the desired mode/STA parameters rather than
assuming a baud-only request preserves Wi-Fi. ROM/Stage2/Recovery logs retain
115200; reconnect Main at its NVS-selected rate. Managed espflash NVS repair
is the last resort when neither UART nor radio control is reachable.
Use `scripts/flash-device.py DEVICE nvs --uart-baud 115200` for that
preserving repair; verify fresh Main status after reconnecting at the selected
rate. This changes only the baud setting, not the boot selector or credentials.

For the experimental runtime baud handshake, start with the device's current
rate (normally 115200 after boot) and set `UART_CODEC_NEGOTIATE_BAUD=460800`
or `921600` on the first command. Subsequent commands use `--baud RATE`
**after the command name**. Negotiate back with
`UART_CODEC_NEGOTIATE_BAUD=115200 dmesh-cli "$UART_TARGET" status --baud RATE`.
This changes neither NVS nor ROM boot baud. If the ACK is lost, the device may
already have switched: do not blindly retry at 115200; recover at the requested
rate or collect a controlled reset. Do not use this on native USB-JTAG or
cable-limited devices. This is opt-in diagnostic code, not automatic negotiation.

Catalog UART commands automatically send a framed wake train for sleepy targets.
`dmesh-cli DEVICE --wake` sends the same one-second train without a request.
Sending it is not proof of wake: require a subsequent status/probe response.
The train repairs framing after lost trigger bytes; it does not change the
persisted sleep profile or guarantee delivery across longer discovery intervals.

Only one process may own a serial device. To keep logs while making periodic
small requests:

```sh
UART_TARGET=/dev/serial/by-id/DEVICE
UART_CODEC_LOG=/tmp/session-uart.log \
QUIC_LITE_PCAP=/tmp/session-quic.pcap \
  dmesh-cli "$UART_TARGET" status --timeout-secs 3 \
    --repeat-secs 2 --linger-secs 10
```

`--repeat-secs` repeats requests until failure; `--linger-secs` keeps collecting
logs after the response or failure. Without repeat, linger follows one request.

- `UART_CODEC_LOG` appends host-observed console and decoded sideband logs.
- `QUIC_LITE_PCAP` captures QUIC packets on **all attached bearers**. It truncates
  the file for each new node: use a different path for every process/run.
- UART PCAP excludes physical framing and non-QUIC logs. Capture direction and
  bearer ID are in the Linux cooked-v2 header; transmission is not receipt proof.
  New outgoing records include a submission outcome (address length 1,
  first address byte: 1 accepted, 2 WouldBlock, 3 unresolved), including retries.
  Timestamps mark attempt start; only accepted attempts belong in TX pacing.
  Older captures without outcome metadata cannot distinguish busy attempts.

Analyze pacing and repeated bytes after sourcing `env.sh`:

For a single UDP bearer on x86_64 Linux, optionally set
`QUIC_LITE_UDP_RX_PCAP` to a **different** file from `QUIC_LITE_PCAP`.
It records kernel receive timestamps without raw-capture privileges. Keep one
process/socket per file; don't enable other socket timestamp options. Compare
the two captures with the timing helper described in the
[performance note](../notes/ai/2026-10-06-wifi-throughput-investigation.md).
This is diagnostic capture, not a change to QUIC's receive clock.

```sh
python3 scripts/analyze_probe_pacing.py /tmp/session-quic.pcap
```

`--decoded` accepts saved
wire-decoder output; repeated or unacked bytes alone do not prove radio loss.
For a single-association capture, `longest_stream_gap_context` shows observed
payload awaiting ACK and observed stream credit during long gaps. It does not
reconstruct actual congestion flight, initial credit or where network delay occurs.

If QUIC is unresponsive, collect passive boot/crash logs:

```sh
dmesh-cli "$UART_TARGET" --watch --timeout-secs 60 > /tmp/passive-uart.log 2>&1
```

For suspicious device timing, run
`python3 scripts/analyze_device_clock.py /tmp/passive-uart.log` on one
device/session. It reports backward timestamps
within continuing producer sequences, not reboot resets. This is log evidence;
confirm with independent clock/sleep measurements before changing timer behavior.

Passive `--watch` needs output redirection, not `UART_CODEC_LOG`.
It keeps collecting after fatal diagnostics until its deadline, including
following boot output, then exits with an error if a fatal marker was seen.
The loader has plain UART console logs and no UART bearer. Capture its TCP upload with an authorized network
capture (`tcpdump ... 'tcp port 5227 or udp port 5227'`); `QUIC_LITE_PCAP` does not see TCP. Preserve invalid CBOR
bytes; do not strip carriage returns heuristically. Upload pacing and congestion experiments, and the lwIP
`ERR_MEM` / retransmission / `link_drop` reading, are in the esp-wifi-loader repository's
`docs/dmesh-flash-lessons.md`.

For a Wi-Fi upload, watch UART in one process and set `QUIC_LITE_PCAP` on the
separate upload process. Keep captures through handoff/reboot. An optional
`tcpdump -i IFACE -w /tmp/network.pcap udp` captures the network layer;
bearer PCAP alone does not include raw IP/radio headers.

## Locate the stalled layer

Check these separately: device startup, transport availability, association
establishment, handler admission, body progress, response plus FIN, and
application completion. A queued frame, TX callback or ACK proves none of the
later steps. For firmware updates, additionally require durable commit,
expected boot role and fresh health; follow [flashing.md](flashing.md).

Query narrow snapshots on a reachable endpoint:

```sh
dmesh-cli DEVICE telemetry.quic
dmesh-cli DEVICE telemetry.memory
dmesh-cli DEVICE telemetry.bearers
dmesh-cli DEVICE log.watch limit=16
```

Select the transport-specific views advertised by `services` (for example,
`telemetry.udp6`, `telemetry.now`, `telemetry.wifi_link`, `telemetry.runtime`).
Field definitions are in [API.md](../API.md). Poll `log.watch` with its returned
cursor/`since_seq` so old records are not mistaken for a new event.
Records have a timestamp, severity, source and optional event kind or structured
fields. Normal firmware logs are collected through `log.watch`; UART console
output remains available for boot and crash diagnostics.

Compare deltas over the same interval:

- Pool availability, receive drops and free/minimum/largest heap block:
  distinguish packet pressure from heap exhaustion or fragmentation.
- QUIC RX/TX, in-flight data, loss/retransmissions and peer credit:
  distinguish loss, exhausted credit and missing owner progress.
- Bearer receive/send errors: distinguish physical submission from delivery.
  On ESP Wi-Fi, distinguish driver-buffer exhaustion from DMA heap exhaustion:
  `ESP_ERR_NO_MEM` alone proves neither, and ordinary free heap is not DMA
  headroom. Compare available driver/DMA diagnostics from the same interval.
- Body progress versus transport progress: distinguish an active connection
  from an application that stopped consuming.

QUIC snapshots cover live associations; removing an association removes its
counters. Zero workload callback errors do not mean zero bearer drops.
A timeout or `Blocked` error is not an application rejection or flash success.
If a flash ends early, assume the target may be partly erased/written.

## Slow streams or relay paths

For the opt-in Main TCP comparison adapter, build with
`DMESH_FW_FEATURES=tcp-stream scripts/build-fw.sh CPU` (on Xtensa also use
`DMESH_FW_NO_DEFAULT_FEATURES=1 DMESH_FW_FEATURES=modules,tcp-stream` to keep
BLE off). Run the same `probe.start` options with a discovered
`tcp://[ADDRESS%IFACE]:3341` endpoint. The adapter uses the existing registered
handler and CBOR-header/body/FIN protocol.
It currently admits two TCP clients for simultaneous upload/download and is
experimental, unencrypted, and off in normal builds. Keep verification and
byte counts identical when comparing with QUIC; TCP captures require a network
capture, not `QUIC_LITE_PCAP`.

Use the same probe, payload size, packet size and completion checks everywhere:

```sh
QUIC_LITE_PCAP=/tmp/probe.pcap \
  dmesh-cli DEVICE probe.start bytes=1048576 packet_size=1024 \
    direction=both timeout=60000 --timeout-secs 70
```

`direction=upload|download|both`; both is simultaneous and bytes are per
direction. Require exact byte counts and response FIN. Pattern verification
defaults off; use `verify=true` periodically and compare matching runs to
measure its cost. Report upload and download separately in decimal Mbps,
using each direction's completed-transfer elapsed time—not their sum.

Compare direct USB termination with USB → companion → STA → host using the
selected E2E pair, identical host limits/pool and repeated runs. Exclude setup.
Keep failed runs; a timeout has no valid completed-transfer throughput.
Harness details and measurements are in the
[performance note](../notes/ai/2026-10-06-dynamic-pool-usb-performance.md).

Check packet timing, retransmitted wire bytes, pool drops and CPU/task waits.
For a host-only control, run the normal probe over in-memory and UDP loopback
bearers in release mode, sequentially and without concurrent builds:

```sh
cargo test --release -p dmesh-server --lib probe_performance \
  -- --ignored --nocapture --test-threads=1
```

Measure CPU utilization during the workload; elapsed owner time includes
preemption and is not CPU cost. For single-core ESP diagnostic builds, use
`DMESH_FW_FEATURES=rtos-stats scripts/build-fw.sh CPU`, capture UART during the
probe, then run `python3 scripts/analyze_rtos_tasks.py LOG` for per-task runtime
deltas. Do not interpret missing/incomplete snapshots as idle CPU.
Diagnostic `quic.response_progress` events can be summarized with
`python3 scripts/analyze_response_progress.py LOG` to separate body generation,
QUIC write time and blocked attempts. These elapsed times include preemption;
accepted bytes are not evidence of peer delivery.
Where available, that analyzer also splits synchronous bearer submission from
the rest of a write; compare with RTOS runtime before attributing CPU cost.
Check heap headroom before increasing windows.
When changing flash mode/frequency, check Stage2 compatibility as well as Main.
The ROM's initial DIO/clock line is not the effective Main cache configuration.
If `quic.cache_config` is available, decode its registers with
`python3 scripts/analyze_cache_config.py LOG`; verify settings write/readback
and persistence across reboot before widening deployment.
Check the actual radio power-save state during the workload, not just its
configured profile; NAN-only sleep policy must not disable STA/AP/NOW listening.
A regular 10 ms gap suggests scheduling/timer granularity, not header overhead.
Check actual negotiated USB speed; a USB 2.0 label does not imply 480 Mbps.
Signaling rate is not application goodput, but a large gap still needs measurement.

## STA, NAN wake and sleep

For STA failures, collect status, `telemetry.wifi_link`, `radio.snapshot` and
UART logs. Check the actual associated BSSID/channel, disconnect reason,
scan/authentication timing and whether a leave was intentional. Configured
credentials or a cached BSSID do not prove association. DMesh APs are
password-protected; do not assume an SSID implies open authentication.

Test an already-awake transition before blaming sleep. Catalog-selected
repeated checks are available via `scripts/test_sta_lifecycle.py --help`;
UART association churn via `scripts/test_uart_association_churn.py --help`.

For NAN, distinguish beacon receipt, synchronization, wake admission, STA
association and first completed service response. Test from verified sleep,
not a still-awake device. Compare sleep-return counters with an independent
power meter; enabled power management alone is not proof of light sleep.

```sh
python3 scripts/test_nan_wake_timing.py DEVICE --output EVIDENCE_DIR \
  --require-sleep --settle-secs 100 --max-ready-secs 5
```

This changes runtime profile and restores NAN-only; it does not write NVS.
Run targets sequentially. Verify services within five seconds and reachability
for at least ten seconds afterward. Explicitly restore NAN-only after manual
tests; automatic handler-idle restoration is not implemented.
NOW/STA/AP require awake operation; UART/USB drivers remain installed.

## Android service and radio failures

Try the shared command surface before framework diagnostics:

```sh
adb -s SERIAL forward tcp:18480 tcp:18480
curl -sS http://127.0.0.1:18480/_m/mesh/services
dmesh-cli http://127.0.0.1:18480 status.text
dmesh-cli http://127.0.0.1:18480 ble.status
dmesh-cli http://127.0.0.1:18480 radio.history --limit=80 --keys=net,wifi,BLE
```

The HTTP service/catalog listing is `/_m/mesh/services`; use it to find available
methods. USB forwarding is not proof of service health. For SSH checks use
`scripts/build-android.sh ssh-forward-smoke`, `ssh-jsonl-smoke` and
`native-health`; message transport details are in [l2.md](l2.md).

If the service is absent, inspect `dumpsys activity services`; if permissions
fail, inspect `dumpsys package com.github.costinm.dmesh.lm`. Grant only required
permissions for the active Android user. Use filtered `logcat` for crashes or
WiFi Aware/Bluetooth/framework failures, not as the first message-level check.

For NAN attach failure, inspect `dumpsys wifi aware` and `dumpsys wifi`.
“Failed to allocate new Nan iface” can indicate an interface-concurrency
conflict: inspect app-owned P2P before changing the transport profile.
For BLE, distinguish advertising/scan discovery, connection and CoC data;
derive addresses from peer status, not MAC arithmetic.

## References

- [API.md](../API.md): current handler and telemetry schemas.
- [flashing.md](flashing.md): update/repair procedure and completion gates.
- [l2.md](l2.md): Android message and local-link commands.
- [Reference archive](../notes/ai/2026-10-06-debugging-reference-archive.md):
  private event-field dictionaries, extended tool examples, implementation
  explanations and historical experiments—not current deployment evidence.
