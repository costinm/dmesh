
# Debugging

Most difficult part is waking up doze/idle mode - most popular commands:

## Repo-local tooling

Keep DMesh builds self-contained under `target/`. The build helper
uses the repo-local Cargo and Gradle homes and the Nix profile in
`target/nix/profile`; manual commands should use the same environment:

```sh
cd "$(git rev-parse --show-toplevel)"
./scripts/build-android.sh deps
. target/nix/profile/bin/dmesh-setenv
export RUSTUP_HOME="$PWD/target/rustup"
export CARGO_HOME="$PWD/target/.cargo"
export GRADLE_USER_HOME="$PWD/target/.gradle"
```

Build only `app-dmesh` by default:

```sh
./scripts/build-android.sh build release
```

`DMESH_SSH_MESH_DIR` optionally selects a local ssh-mesh checkout. A sibling
checkout is detected automatically; the build keeps DMesh tooling and caches
under `target/`. To test the standalone Git dependency path instead, point the
override at a missing directory:

```sh
DMESH_SSH_MESH_DIR="$PWD/no-ssh-mesh-override" \
  ./scripts/build-android.sh build release
```

### Managed service control

Use the `mesh` CLI for `mesh-init` service control. The RPC component is
`mesh-init` and the service argument is `name=value`:

```sh
mesh mesh-init mesh-init status [name=SERVICE]
mesh mesh-init mesh-init start name=SERVICE
mesh mesh-init mesh-init stop name=SERVICE
mesh mesh-init mesh-init reload
```

```sh
adb -s SERIAL install -r target/apk/release/app-dmesh-release.apk
adb -s SERIAL shell am start-foreground-service \
  -n com.github.costinm.dmesh.lm/.DMService
```

Grant runtime permissions explicitly on physical devices:

```sh
adb -s SERIAL shell pm grant --user 0 \
  com.github.costinm.dmesh.lm android.permission.ACCESS_FINE_LOCATION
adb -s SERIAL shell pm grant --user 0 \
  com.github.costinm.dmesh.lm android.permission.ACCESS_BACKGROUND_LOCATION
adb -s SERIAL shell pm grant --user 0 \
  com.github.costinm.dmesh.lm android.permission.NEARBY_WIFI_DEVICES
adb -s SERIAL shell pm grant --user 0 \
  com.github.costinm.dmesh.lm android.permission.BLUETOOTH_SCAN
adb -s SERIAL shell pm grant --user 0 \
  com.github.costinm.dmesh.lm android.permission.BLUETOOTH_CONNECT
adb -s SERIAL shell pm grant --user 0 \
  com.github.costinm.dmesh.lm android.permission.BLUETOOTH_ADVERTISE
```

Prefer the app's command provider and in-memory history over `logcat` for normal
lmesh debugging. `logcat` is useful as a last resort for framework WiFi Aware,
Bluetooth, permission, or crash failures, but it is too noisy for routine
message-level checks.

JNI follows the same 'structured message' style as all transports. Rust modules should be 
reached through small generic handlers, with CBOR `byte[]` payloads,
and an FD slot when needed. 

## Tcpdump

```
# Wifi Direct uses 1,6,11 for announcements / discovery - useful to stay in those
# channels even in AP/client mode
iw phy phy0 set channel 6

# Radio tap shows signal level, freq, low level Wifi frames
wireshark -i wlan0 -I -y IEEE802_11_RADIO

Filters:
wlan_mgt.ssid contains "DIRECT"

```

## Host UART and QUIC captures

The host tools can save serial sideband logs and capture opaque QUIC packets
crossing Tokio bearers. Set either or both variables on the `dmesh-cli`
invocation:

```sh
UART_TARGET=/dev/serial/by-id/DEVICE
UART_CODEC_LOG=/tmp/dmesh-uart.log \
QUIC_LITE_PCAP=/tmp/dmesh-quic.pcap \
  dmesh-cli "$UART_TARGET" status --timeout-secs 3 \
    --repeat-secs 2 --linger-secs 10
```

`UART_CODEC_LOG` appends complete unframed UART console/sideband text lines
observed by the host reader; it excludes bytes inside marked QUIC packets.
`QUIC_LITE_PCAP` creates a classic PCAP of QUIC packets crossing the Tokio
node's bearer boundary, for all bearers attached to that node—not just UART.
The Linux cooked-v2 header records ingress/egress direction and bearer ID.
For UART, capture occurs after PPP decoding on receive and before PPP framing
on send; it does not include raw serial bytes, framing errors, or non-QUIC
sideband traffic.

The UART log is appended, but each new Tokio node creates/truncates its PCAP
path. Use a fresh PCAP filename for each process when preserving earlier
captures. Capture I/O errors are reported to stderr and do not stop packet
delivery. These are host observations; use `dmesh-cli SERIAL --watch` or a
tagged `log.watch` request to collect device-side logs separately.

For a UDP firmware object upload, set `QUIC_LITE_PCAP` on the `object.flash`
process; it records that process's flash association across the UDP bearer.
Run a separate `dmesh-cli SERIAL status --linger-secs 300` process with
`UART_CODEC_LOG` set to capture UART sideband logs. The passive `--watch`
path instead requires output redirection. The PCAP is a capture at the host QUIC bearer boundary, not
a record of raw UDP/IP headers or proof that the device application consumed
the captured bytes. Use a fresh capture path for each upload process.

Firmware still has legacy one-line UART diagnostics. Flash events and
periodic reports now use the existing CBOR `LogRecord` envelope from `API.md`,
with typed numeric fields and no device-side string formatting. Use a UART
status request with `--linger-secs` alongside the UDP flash to decode and save
these records; alternatively, passive `--watch` decodes CBOR without creating
a QUIC association (redirect its output to a file). The host renders numeric
maps as `1=... 2=...`. Legacy
QUIC dispatch records include the phase,
component/method tags, request ID, association handle, stream ID, and match
result. Every five seconds an active transfer emits `object_flash.progress`
(application bytes and idle time), `object_flash.quic_progress` (QUIC counters,
out-of-order/missing packets, dropped ACK ranges, PTO retransmissions and peer
send credit), and `object_flash.owner_progress` (next QUIC deadline, packet-pool
availability, explicitly labelled raw UDP6 drop/error counters, and internal
heap free/minimum/largest-block observations). These
reports use the same code in Main and Recovery; zero progress with increasing
QUIC receive/ACK counters distinguishes
transport processing from application acceptance. The debug UART queue is
lossy, so use `UART_CODEC_LOG` to retain what the host actually observed.
The original 240-byte firmware flash formatter silently cut the report before
most counters; this was not the host decoder's 512-byte cutoff. Flash log
records no longer use a text formatter: CBOR field encoding fails explicitly
if its fixed output buffer is insufficient. UART sideband carries the complete
CBOR record, never a truncated text suffix. Recovery configures console VFS
output as LF-only at startup: newline translation would expand binary `0x0a`
to `0x0d 0x0a` and corrupt framed CBOR. The 2026-10-02 UDP-only Recovery retry
verified intact reports after this fix. If `cbor_invalid hex=...` appears,
retain the bytes; do not remove CR bytes heuristically in the host decoder.
Main uses its UART writer rather than this Recovery console path.
Both writers frame CBOR logs without the QUIC packet marker. A Main log marked
as QUIC will appear as a transport packet to a passive watcher and may consume
receive-pool slots in the active bearer; packet counts alone are not log evidence.
`UART_CODEC_LOG` saves the host's
numeric-tag rendering of CBOR records as well as boot/crash console lines.
Host console lines allow 4096 bytes across serial reads; oversized lines retain
their prefix with `[uart_log_truncated limit=4096]` and discard the remainder
until newline, so a suffix cannot masquerade as a new log record. Marked QUIC
frames remain excluded from console decoding.

The flash report payload tags are private debugging fields (inside `LogRecord`
tag 7), not yet a stable telemetry handler schema:

The 2026-10-02 Recovery stall reproduced two generic QUIC recovery defects:
late ACKs can retire original payload while dropped replacement transmissions
still occupy flight, requiring an ACK-eliciting PTO PING; and a multi-second
RTT can round the packet pacing rate to zero, causing one-microsecond retries
that never refill packet tokens. Both now have core regressions, plus a
Tokio `write_all`/`read_to_end` test with a three-second peer pause and dropped
replacements. The hardware retry transferred a 1,858,000-byte Main image in
14.24 seconds, received the normal response plus FIN, observed durable
completion and Stage2 handoff to Main, and checked fresh Main health.

Main and Recovery incrementally erase aligned 64 KiB chunks immediately before
the first content write into each chunk. Unaligned region starts and image
tails use sector-aligned partial chunks; only the image extent rounded up to
4 KiB is erased. Each erase call remains synchronous in the QUIC owner, but
there is no longer one image-wide erase in `begin`. The owner can process
transport work between content deliveries. This does not eliminate packet
loss during a single erase call; QUIC pause/loss recovery is still required.
The C6 hardware check uploaded Main through Recovery in 13.86 seconds with
normal response/FIN, durable completion, reboot, and fresh Main UDP status.
Its 29 erase calls totaled 3.04 seconds; the longest took 118 ms. These are
single-run measurements, not a controlled speed comparison.

| Record kind | Payload tags |
|---|---|
| `object_flash.progress` | 1=request ID, 2=stream ID, 3=received bytes, 4=elapsed ms, 5=idle ms |
| `object_flash.erase` | 1=request ID, 2=target, 3=offset (partition-relative, or absolute for raw flash), 4=bytes, 5=elapsed us, 6=cumulative erase us, 7=strategy (`incremental64`), 8=success |
| `object_flash.storage_timing` | 1=request ID, 2=target, 3=erased bytes, 4=erase calls, 5=total erase us, 6=longest erase us, 7=total write us, 8=strategy (`incremental64`) |
| `object_flash.quic_progress` | 1=request ID, 2=stream ID; 10=RX, 11=TX, 12=stream TX, 13=control TX, 14=largest peer ACK (null if absent), 15=in-flight bytes, 16=retransmits, 17=loss events, 18=missing packet numbers, 19=duplicates, 20=submission failures, 21=stream RX, 22=control RX, 23=out-of-order packets, 24=peer max-data, 25=peer sent-data, 26=dropped ACK ranges, 27=PTO retransmits |
| `object_flash.owner_progress` | 1=next QUIC deadline ms (null if absent), 2=available pool slots, 3=UDP6 RX, 4=UDP6 RX drops, 5=UDP6 invalid RX, 6=UDP6 TX, 7=UDP6 frame TX, 8=UDP6 TX failures, 9=free internal heap bytes, 10=minimum free internal heap bytes, 11=largest free internal heap block bytes |

Recovery emits these same CBOR records using `uart-codec` sideband framing on
its output-only console; this does not enable a UART QUIC input bearer.

Classic ESP32 needs special attention to heap pressure. During the 2026-10-02
fleet rollout, a repeat Recovery upload in Main failed with `memory allocation
of 3968 bytes failed`; the device rebooted and Recovery was treated as unsafe
until a later complete upload succeeded. The rebuilt passive-watch retry
completed in 19.5 s, but reported about 13 KiB free internal heap and a minimum
below 3 KiB. This is a successful retry, not proof that the allocation failure
is fixed. The retired ingress-worker stub previously returned zero for heap
fields; these now come directly from ESP-IDF. Preserve those counters and PCAP
before adjusting runtime limits or attributing the failure to QUIC.

Connectionless CBOR discovery/signing must run on the firmware event owner,
not the ESP-IDF Wi-Fi callback stack. A C6 stack panic in tagged decoding and
S3 Wi-Fi watchdog were observed before this deferral. NOW control frames retain
their original shared-pool lease; UDP callback control bytes are admitted to
the shared pool before owner dispatch. No private packet queue is added.

`telemetry.quic` returns a node-wide snapshot over associations with
an active QUIC endpoint on firmware, Linux, and Android. The Rust
`quic_lite::NodeTelemetry` and
`AssociationTelemetry` snapshots expose QUIC packet, ACK, loss,
retransmission, and submission-failure counters; bearer-specific telemetry
remains the source for radio/UDP receive and transmit failures. QUIC ACKs and
retransmissions are not application-delivery or flash-commit proof. Aggregate
counters disappear when their association is removed and restart with the
node; use live `object_flash.progress` records for one upload.

Query the snapshot from any reachable DMesh node with
`dmesh-cli DEVICE telemetry.quic`. It is an empty request and returns
the required numeric counters documented in [`API.md`](../API.md).

Example: capture an object upload over UDP while passively watching UART logs
(run these in separate terminals; substitute a selected serial device and
discovered, scoped link-local endpoint):

```sh
UART_CODEC_LOG=/tmp/device-uart.log \
  dmesh-cli SERIAL status --timeout-secs 10 --linger-secs 300

QUIC_LITE_PCAP=/tmp/object-flash.pcap \
  dmesh-cli 'udp://[DEVICE_LINK_LOCAL%IFACE]:3339' object.flash \
    cpu=CPU target=TARGET dry_run=true --file IMAGE
```

The upload command reports completion only after the `object.flash` response
envelope and response FIN; ACKs are not upload-completion evidence. This is
the ordinary handler response contract, not a separate flash acknowledgment.
Recovery schedules its reboot after writing that response and FIN. Local
stream completion alone is not proof that the peer received it: retain the
client result and verify the rebooted Main identity and health separately.

Handover validation must separate `boot.recovery` response completion from
Stage2 selecting Recovery and from Recovery UDP readiness. A UART check on
2026-10-02 received the normal response with FIN, then observed Stage2
`handoff=1`, Recovery entry, STA association, and raw UDP6 startup. Subsequent
UDP identity requests still timed out and host neighbor resolution failed;
no Recovery-to-Main upload was attempted. Evidence is under
`target/evidence/handoff-envelope-svtj8MEm/`. STA association or an announce
being queued does not establish that UDP receive/transmit works.

Recovery QUIC owner regression: after the bearer refactor, packets were
queued for `quic_node_esp`, but Recovery never called its `progress()` function
and ingress notifications targeted Main's inactive event queue. Recovery now
drives that same owner and receives an ingress wake. Raw bearer preparation
also initializes the runtime before enabling receive callbacks; Main formerly
got that initialization implicitly from its UART startup. No QUIC-lite change
was required for these owner-lifecycle fixes.

With the owner-loop fix deployed, UDP completed association setup and admitted
`object.flash`, but the tested Main upload stopped at 9,303 body bytes and then
hit the 15-second handler idle timeout. The host's 30-second upload deadline
expired. This is not a successful flash; the Main partition may be partly
written and requires repair before relying on it. Recovery-side shared debug
lines now use its output-only console instead of Main's inactive framed UART
queue. Logs and bearer captures for this later run are the
`recovery-readable-*` files in the evidence directory above.

Firmware handler streams expire after 15 seconds without application progress.
Successful handler work records its **completion** time: a synchronous partition
erase may take longer than 15 seconds and must not make a progressing upload
look idle immediately afterward. Flash is not exempt from the idle timeout.
An `object_flash.idle_timeout` record before a terminal success means the
upload was abandoned; the destination may already be erased or partly written.

A full congestion window is retryable QUIC `Blocked`, not
`MissingEgressAddress`: the route still exists. Stream producers retain the
unchanged bytes/FIN until ACK or capacity progress. A host-driver exit reporting
`Transport(Blocked)` is not an application flash rejection; capture both
control/timer traffic and UART logs to locate the runtime path that treated
backpressure as fatal. Neither error proves a durable flash commit.

Host and Android stream applications use `AsyncRead`/`AsyncWrite`; the Tokio
node driver owns QUIC pacing, timers, credit and retryable backpressure.
Do not add window checks or QUIC retry loops to flash/probe handlers or clients.
QUIC-lite's `stream_probe` tests run identical generic byte-stream workloads
over TCP and QUIC bearers. Its `tokio_node_driver` tests also cover a slow
reader transferring more bytes than a 16 KiB receive window. These tests do
not replace a device upload and durable-commit check.

`dmesh_server::stream_client` provides common request, flash and probe
exchanges over `AsyncRead + AsyncWrite`. Flash's multipart body is assembled
there, not in a QUIC-specific client. Request/flash exchanges read responses
concurrently with writes; a TCP test checks the same flash helper and exact
header/manifest-length/manifest/content ordering. QUIC-lite separately tests
a 1 MiB transfer through delayed, reordered, lossy and `WouldBlock` links.
Path-status congestion/history pressure retains the status on the adaptive
loss clock, rather than stopping the driver or spinning an overdue timer.
Association CLOSE waits for a retained bearer packet before retiring state.

The 2026-10-02 common-stream canary uploaded a 899,568-byte Recovery image
through Main over UDP in 6.85 seconds with terminal `object.flash` success;
post-upload status and a 64 KiB probe passed. Evidence is under
`target/evidence/e8-common-stream-IJiUMKQ8/`. This did not test booting Recovery
or flashing Main from Recovery. Detailed flash UART diagnostics were missing:
the current formatter's association Debug braces include `0x7d`, which
`send_debug_text` rejects. Do not interpret their absence as no handler
admission; correlate the terminal response and packet capture.

The passive `--watch` path does not use `UART_CODEC_LOG`; redirect its output
to a file if using that mode. `status --linger-secs` uses the Tokio UART bearer
and therefore saves sideband logs through `UART_CODEC_LOG` while UDP uploads
run separately. Do not let two processes open the same serial device.

For UART QUIC diagnosis, `--repeat-secs N` keeps one host serial reader and
Tokio node open, repeats the read-only `status` or `services` request on a
fresh QUIC association after each N-second delay, and prints each response. It stops on the first
request failure, then continues collecting UART logs for `--linger-secs N`
before returning the error. Without `--repeat-secs`, `--linger-secs N` keeps
the reader alive after the one response for that many seconds. This is useful
for retaining crash or sleep-transition logs in the same `UART_CODEC_LOG`
file; it does not change the device's logging behavior.

## Remote adb

- Ssh with `LocalForward 6018 127.0.0.1:5027`
- ADB_SERVER_SOCKET=tcp:localhost:6018 adb devices

## app-dmesh SSH message bridge

`app-dmesh` starts the Rust `dmesh` SSH server on the device at port `15022`.
For local emulator testing, forward it to the host:

```sh
adb forward tcp:11522 tcp:15022
```

For a USB device or emulator that already has `app-dmesh` installed, provision a
host SSH public key into the app sandbox and verify authenticated SSH access:

```sh
DMESH_ADB_SERIAL=94AAY0LALC ./scripts/android_ssh_trust_and_verify.sh
```

The script writes the generated public key to:

```sh
/data/user/0/com.github.costinm.dmesh.lm/files/ssh-mesh/authorized_keys
```

It restarts `DMService`, forwards host `localhost:11522` to device port `15022`,
forwards host `localhost:18080` to device admin HTTP port `18480`, and checks the
SSH banner and `/_m/adm`. The `dmesh-msg:1` direct stream is binary records, so a
separate binary client smoke test owns message-routing verification.

To test CA trust instead of a single public key:

```sh
./scripts/android_ssh_trust_and_verify.sh ca
```

Generated test keys are under:

```sh
target/android-ssh/ca_ecdsa
target/android-ssh/ca_ecdsa.pub
target/android-ssh/id_ecdsa
target/android-ssh/id_ecdsa.pub
target/android-ssh/id_ecdsa-cert.pub
```

The smoke script installs the CA public key into the app sandbox as:

```sh
/data/user/0/com.github.costinm.dmesh.lm/files/ssh-mesh/authorized_cas
```

`MeshNode` loads `authorized_cas` on service startup, so restart `DMService`
after changing that file:

```sh
adb shell am force-stop com.github.costinm.dmesh.lm
adb shell am start-foreground-service \
  -n com.github.costinm.dmesh.lm/.DMService
```

`dmesh-msg:1` is a binary transport. Each record is a four-byte big-endian
length followed by one opaque message payload (currently limited to 2 KiB). SSH
does not parse CBOR or shell text; it forwards record bytes. JNI also passes
only `byte[]`. `dmeshnative` maps those bytes to/from `MeshStream` and the typed
Bundle API before an Android service sees them.

Plain SSH exec is intentionally not a message ingress. Use `dmesh-cli` for
shared controls or an explicit message client for `dmesh-msg:1`.

## app-dmesh REST admin bridge

The Android web UI uses the embedded ssh-mesh REST admin server. It listens
on the configured HTTP port and dispatches directly to the
Rust handler registry: it does not use the retired JSONL Java bridge or a
host-style `/mesh/run/mesh/...` UDS path.

### Finding the supported HTTP API

The gateway is its own discovery surface; two read-only GETs enumerate
everything a service answers (ssh-mesh `mesh_rest`):

```sh
# Every registered service: name, backend, encoding, catalog component.
curl -sS 'http://127.0.0.1:18480/_m/mesh/services'

# Every method of one service with descriptions and field tags.
# view=all includes masked and legacy methods; the default view shows
# only operator-facing entries (x-ui-visibility default or unspecified).
curl -sS 'http://127.0.0.1:18480/_m/mesh/services/wifi/tools?view=all'
```

Method and field tags are formally specified in the root `API.md`. The
installed catalogs it generates (`crates/lmesh/resources/tools.json` for
Linux `lmesh`, `crates/dmesh-server/platform/tools.json` for the shared
platform services) are checked against `API.md` in `scripts/build.sh`, so a
catalog GET and the documentation cannot drift apart silently. Over
QUIC/UART/SSH stream transports the tagged equivalent of the service list is
component 9, method 2 (`dmesh-cli DEVICE services`).

Commands then go through one of two POST routes:
`/_m/mesh/services/<svc>/records` (a tagged record; numeric tags need no
catalog) or `/_m/mesh/services/<svc>/call/<METHOD>` (named, resolved through
the service catalog). `dmesh-cli http://... SERVICE.METHOD` uses the records
route.

Registered Android HTTP services are `ble`, `companion`, `history`, `status`,
`transport`, `usb`, and `wifi`. The Linux `lmesh` admin endpoint (localhost
port 18981) registers a single `lmesh` service backed by its UDS; numeric
tagged records dispatch there without provisioning, while the named
convenience endpoints (`/tools`, `/call/<method>`, name-based records)
resolve through the shared catalog search: `/opt/lmesh/etc/schemas/`,
`$HOME/opt/lmesh/etc/schemas/`, and `$HOME/etc/schemas/`. The mesh-init
template no longer pins `MESH_TOOLS`; a host without an installed catalog can
place one under `$HOME/etc/schemas/` for its service user.

QUIC-lite on port `3336` exposes the portable discovery and telemetry
methods, including `telemetry.battery`. Framework callbacks and JNI
diagnostics are not separate HTTP commands.

If a defensive UDS fallback is ever needed on Android, JNI configures mesh paths
under the app files tree:

```text
/data/user/0/com.github.costinm.dmesh.lm/files/ssh-mesh/run/mesh
```

Do not add Android command paths that depend on host `/mesh` directories.

Manual REST smoke test:

```sh
adb -s SERIAL forward tcp:18480 tcp:18480

curl -sS 'http://127.0.0.1:18480/_m/mesh/services'
curl -sS 'http://127.0.0.1:18480/_m/mesh/services/ble/tools'

curl -sS -X POST \
  'http://127.0.0.1:18480/_m/mesh/services/ble/call/ble.status' \
  -H 'content-type: application/json' \
  -d '{"id":1}'

curl -sS -X POST \
  'http://127.0.0.1:18480/_m/mesh/services/transport/call/transport.set' \
  -H 'content-type: application/json' \
  -d '{"id":2,"wake_target":"10:BD:A3:AC:5A:20","mode":6,"ap":1,"now":1,"ble":1,"nan_dw_interval":1}'

curl -sS -o /dev/null -L -w '%{http_code} %{url_effective}\n' \
  'http://127.0.0.1:18480/_m/adm/ble.html'

curl -sS 'http://127.0.0.1:18480/_m/mesh/services/usb/tools'

curl -sS -X POST \
  'http://127.0.0.1:18480/_m/mesh/services/usb/call/usb.status' \
  -H 'content-type: application/json' \
  -d '{"id":1}'

curl -sS -X POST \
  'http://127.0.0.1:18480/_m/mesh/services/usb/call/usb.devices' \
  -H 'content-type: application/json' \
  -d '{"id":2}'

curl -sS -X POST \
  'http://127.0.0.1:18480/_m/mesh/services/usb/call/usb.open' \
  -H 'content-type: application/json' \
  -d '{"id":3,"auto":true}'
```

The same table the Android status screen shows is generated on the Rust side
and served over HTTP by the `status` service:

```sh
curl -sS -X POST \
  'http://127.0.0.1:18480/_m/mesh/services/status/call/status.text' \
  -H 'content-type: application/json' \
  -d '{"id":1}'
```

The admin landing page (`/_m/adm/`) renders the same text in its Status
section. Bearer letters are `A` Wi-Fi Aware, `B` BLE, `W` Wi-Fi UDP6,
`N` ESP-NOW, `U` USB; `P` marks paired companions (listed first) and `z`
marks devices that announced a pending sleep.

`transport.set.wake_target` is the sleepy device's STA or AP radio MAC, not
its BLE address. The firmware admits a targeted NAN wake only when the MAC
matches one of its local radio interfaces.

If `SSH_MESH_HTTP_API_KEY` is configured, add `?apikey=...` to the first URL;
the server validates it and issues the scoped `mesh_api_key` cookie for later
calls. A missing record ID is one-way submission; the observation methods are
normally called with an ID and return a correlated result.

SSH exec text and JSON Lines are not command APIs. `dmesh-msg:1` accepts a
four-byte big-endian record length followed by one size-limited opaque message record;
`dmeshnative` maps the record to/from the typed Android Bundle adapter.

## lmesh HTTP/JSON edge (ssh-mesh)

`lmesh` serves no HTTP. `ssh-mesh` is the HTTP server: it translates JSON to tagged CBOR with
the lmesh catalog and exchanges one record per datagram with lmesh's `SOCK_SEQPACKET`
socket (`/run/mesh/lmesh/mesh.sock.cbor`). Set `SSH_MESH_MESH_SERVICES=lmesh=<socket>` (comma
separated `catalog=socket` entries) and give ssh-mesh an activated listener named `admin`;
every component of the catalog is then served as `/_m/mesh/services/<component>/records`
(numeric tags) and `.../call/<component.method>` (names, mapped with the catalog).
`scripts/ssh-mesh-http.sh start|stop|status` runs it as the current user (no mesh-init, no special
permissions) on `127.0.0.1:18982`; `ssh-mesh-http.py` binds the port and passes it to ssh-mesh as the
activated `admin` listener.

```sh
curl http://127.0.0.1:18982/_m/mesh/services
dmesh-cli http://127.0.0.1:18982 telemetry.nan_status
```

lmesh, Android and the ESP32 firmware all serve the DMesh UDP port 3339; `dmesh-cli` uses source
port 3338 (an ephemeral port if that is busy; `DMESH_UDP_SOURCE_PORT` overrides).

## Companion pairing from the lab host

`companion.pair`/`companion.unpair` are `mesh lmesh` methods: `--kind=uart --id=<serial path>
[--baud=N]` or `--kind=ble --id=<BLE address>`. Owned-device files are written under
`DMESH_PAIRED_DEVICES_DIR` (`/home/lmesh/etc/paired` in `lmesh.toml`). The lmesh service needs the
`dialout` group for the serial port and `CAP_NET_ADMIN` for BLE (only to enable LE on the controller,
which the kernel requires before any LE connection; `lmesh-ble-hci::mgmt`). The BLE channel is a
plain CoC: no BLE pairing, bond or prompt, on Linux or Android.
Send `nan.pair_wakeup --to=<radio MAC>` first. Over BLE the device must be advertising
(`ble.start`) and the BLE address is the radio MAC plus 2 on ESP32 boards.

`scripts/e2e/60-pairing.sh` covers the Linux side. Android's `companion.pair kind=ble` connects the
channel; provisioning over it is not implemented on Android yet (TODO in `mesh_jni.rs`).

## app-dmesh control with dmesh-cli

Use the shared Rust service handlers. ADB may forward the HTTP port, but it no
longer carries commands through a ContentProvider. The direct Wi-Fi address
can instead be used as a `udp://HOST:3336` target for shared QUIC-lite methods.

```sh
adb -s SERIAL forward tcp:18480 tcp:18480
dmesh-cli http://127.0.0.1:18480 transport.set --mode=6
dmesh-cli http://127.0.0.1:18480 wifi.scan
dmesh-cli http://127.0.0.1:18480 radio.history --limit=80 --keys=net,wifi,BLE
dmesh-cli udp://[ANDROID_LINK_LOCAL%IFACE]:3336 discovery.nodes
```

The retired root-only provider and its device-secret provisioning command have
no replacement. Do not send secret material through the generic HTTP gateway.

## Radio Scan Debugging

Trigger BLE and Wi-Fi through the shared HTTP services, wait a few seconds,
then pull the retained message history:

```sh
adb -s SERIAL forward tcp:18480 tcp:18480

dmesh-cli http://127.0.0.1:18480 ble.scan
dmesh-cli http://127.0.0.1:18480 wifi.scan
dmesh-cli http://127.0.0.1:18480 transport.set --mode=6

sleep 6

dmesh-cli http://127.0.0.1:18480 ble.status
dmesh-cli http://127.0.0.1:18480 radio.history --limit=80 --keys=net,wifi,BLE
```

Expected message patterns:

- WiFi scan: `net.status` with `event=scan` and `visible=N`.
- BLE scan: `ble.status` should report `scan=true`, and `ble.scan_results`
  should list retained DMesh service-data advertisements.
- NAN: `net.NAN.Attach`, then `net.NAN.PubStart` and `net.NAN.SubStart` before
  `net.NAN.*ServiceDiscovered` messages. DMesh follow-ups appear as
  `net.NAN.FollowupRx` / `net.NAN.FollowupTx` with parsed JSON from the Rust
  protocol code. If the history shows `net.NAN.AttachError`, NAN did not reach
  publish/subscribe.

The Android side does not hold wake locks. The expected wake paths are the
foreground service while active, periodic `LMJob` update windows, and normal
WiFi Aware framework callbacks.

Companion pairing is started from the app UI's "Pair companion" action. The
UI uses the Android Companion Device Manager flow and the local BLE scanner;
it is not exposed as an ADB shell command. Use `ble.scan`, `ble.scan_results`,
and `ble.connect` over the HTTP service when a scripted BLE connection is
needed.

## Main firmware BLE tagged surface

Control the Main-owned NimBLE radio through its numeric tagged component
(`104`) over a normal `dmesh-cli` service stream:

```sh
dmesh-cli <device> ble.start
dmesh-cli <device> ble.status
dmesh-cli <device> ble.scan duration_ms=5000
dmesh-cli <device> ble.scan_stop
dmesh-cli <device> ble.connect addr=<peer_local_addr> addr_type=<peer_local_addr_type> psm=128
dmesh-cli <device> ble.coc.send data=deadbeef
dmesh-cli <device> ble.stop
```

`ble.start` begins advertising and the PSM `0x0080` CoC server. `ble.stop`
stops scan/advertising and terminates an active LE connection. `ble.connect`
initiates a central GAP connection to `addr`, then opens the requested CoC
channel. Read the peer address from its `ble.status` `local_addr` and
`local_addr_type` fields; `addr` accepts colon-separated or compact hex.
`ble.coc.send` transmits one SDU through the active CoC channel. Pairing is Just
Works with persisted bonding. Each CoC SDU is one opaque QUIC-lite packet and
enters the shared Main connection path with bearer ID `7`.

## Two Android BLE/NAN live test

Use this when two Android devices are connected over ADB and `app-dmesh` is
installed. The script starts `DMService`, starts a BLE scan through the shared
`ble` HTTP service, waits for NAN discovery, then reads
the remaining in-memory history buffer through the shared history service. It
leaves NAN running: the service, rather than test cleanup, owns the persistent
cluster.

```sh
scripts/live_android_radio_test.py \
  --device 94AAY0LALC \
  --device RFCNB05AJ7E \
  --auto-serial \
  --duration 12
```

Expected result:

- `ble_status=True` on both devices.
- `nan_status=True` on both devices.
- At least one device reports `nan_peer=True`.
- At least one device reports `nan_followup=True`.

The script saves ADB history and captured output under
`target/live-tests/android-radio-*`.

## LoRa to Android live test

Use this when two LoRa ESP32 boards are attached as serial devices and two
Android devices are connected over ADB. The intended path is:

```text
/dev/ttyUSB0 LoRa sender -> /dev/ttyUSB1 ESP32 repeater -> Android BLE/NAN receive
```

Default BLE plus raw NAN forwarding:

```sh
scripts/live_lora_android_test.py \
  --android 94AAY0LALC \
  --android RFCNB05AJ7E \
  --tx /dev/ttyUSB0 \
  --rx /dev/ttyUSB1 \
  --wait 12
```

Official WiFi Aware/NAN backend:

```sh
scripts/live_lora_android_test.py \
  --android 94AAY0LALC \
  --android RFCNB05AJ7E \
  --tx /dev/ttyUSB0 \
  --rx /dev/ttyUSB1 \
  --nan-backend official \
  --wait 14
```

Expected BLE evidence in Android history:

- `BLE.DISC proto=dmesh`
- `event=lora_rx`
- `pending`, `payload_len`, `payload_hash`, and `prefix`
- `BLE.PENDING`
- `BLE.PULL state=subscribed`
- `BLE.MSG seq=... len=...`
- `BLE.PULL state=done`

Expected firmware console evidence:

- `lora_rx`
- companion BLE advertising while data is pending
- DMesh GATT TX notification frames: `msg seq=... hash=... len=...`
- Android ACKs: `ack seq=... hash=...`
- pending queue empty and advertising stopped after ACK
- `ev=lora.fwd t=nan ...`

For the official NAN backend, discovery/match evidence is currently the main
signal to check. Firmware logs should show `nan.match`, and Android history may
show firmware service state such as `/nan/<device_id>` with
`role=firmware_publisher`. Payload follow-up over official NAN can still fail
and fall back to raw forwarding, for example `ev=lora.fwd t=nan ... ok=false`
followed by raw NAN forwarding. Android apps do not receive raw WiFi action
frames as WiFi Aware follow-up messages; BLE is the proven LoRa-to-Android
payload wake/notice path.

The serial harness uses Python `termios` directly and does not require
`pyserial`. Use `socat` for manual serial teeing if needed, or use the firmware
project's own scripts and dependency environment when driving lower-level
firmware tests.

Check Android runtime permissions granted to `app-dmesh`:

```sh
adb shell dumpsys package com.github.costinm.dmesh.lm
```

The relevant runtime permissions are `ACCESS_FINE_LOCATION`,
`ACCESS_BACKGROUND_LOCATION`, `NEARBY_WIFI_DEVICES`, `BLUETOOTH_SCAN`, and
`BLUETOOTH_CONNECT`, and `BLUETOOTH_ADVERTISE`.

For NAN attach failures that are not explained by app history or firmware
serial logs, collect the framework WiFi Aware logs:

```sh
adb shell logcat -d -v time -t 400 \
  WifiAwareService:D \
  WifiAwareNativeApi:D \
  WifiAwareNativeManager:D \
  WifiAwareStateManager:D \
  HalDevMgr:D \
  WifiNative:E \
  nan:D \
  LM-BLE:D \
  DM-SVC:D \
  AndroidRuntime:E \
  '*:S'
```

Useful failure patterns:

- `Failed to allocate new Nan iface`
- `Was not able to obtain a WifiNanIface`
- `enableAndConfigure: null interface`
- `bestIfaceCreationProposal is null, requestIface=NAN, existingIface=[name=wlan0 type=STA, name=p2p0 type=P2P]`

That last pattern means NAN is blocked below the app because the WiFi HAL cannot
allocate a NAN interface while a P2P interface exists. Stop app-owned P2P before
retrying NAN:

```sh
adb -s SERIAL forward tcp:18480 tcp:18480
dmesh-cli http://127.0.0.1:18480 transport.set --mode=6 --ap=0
```

Inspect the current WiFi HAL interface state and WiFi Aware counters:

```sh
adb shell dumpsys wifi
adb shell dumpsys wifi aware
```

In the output, look for:

- `Dump of HalDeviceManager`
- `mInterfaceInfoCache`
- `mDebugChipsInfo`
- `mWifiAwareMetrics`
- `mAttachStatusData`
- `totalNanScanTimeMs`

On devices with limited concurrency, a healthy state before NAN attach should
show `wlan0` STA without an app-owned `p2p0` interface.

Outbound SSH client operations use the admin HTTP bridge rather than the local
ADB shell:

```sh
adb -s SERIAL forward tcp:18480 tcp:18480

curl -sS -X POST \
  'http://127.0.0.1:18480/_m/api/sshc/connect' \
  -H 'content-type: application/json' \
  -d '{"host":"127.0.0.1","port":22,"user":"dmesh","server_key":"ssh-ed25519 ..."}'

curl -sS -X POST \
  'http://127.0.0.1:18480/_m/api/sshc/connections/1/exec' \
  -H 'content-type: application/json' \
  -d '{"command":"uname -a"}'

curl -sS -X POST \
  'http://127.0.0.1:18480/_m/api/sshc/connections/1/forward/local' \
  -H 'content-type: application/json' \
  -d '{"local_port":10022,"remote_host":"127.0.0.1","remote_port":22}'

curl -sS -X POST \
  'http://127.0.0.1:18480/_m/api/sshc/connections/1/forward/remote' \
  -H 'content-type: application/json' \
  -d '{"remote_port":10080,"local_host":"127.0.0.1","local_port":8080}'
```

# NAN-only wake policy

Main NVS `mode=sleepy` selects NAN-only boot even when STA credentials are
stored. Credentials are retained for the later targeted NAN wake; their
presence does not mean STA is enabled. UART/USB drivers remain installed.
`settings.set --key=nan_dw_interval --value=1` selects every 512-TU discovery
window (approximately 524 ms), with `8` and `16` also accepted. This setting
is read at boot; use `transport.set mode=nan now=2 ap=0 nan_dw_interval=1`
to select the same runtime personality without rebooting.

A matching targeted wake immediately reserves a 10-second awake lease before
the queued STA profile is applied. Repeated matching wakes renew it; an
explicit NAN-only `transport.set` cancels it. An old NAN owner snapshot cannot
enter physical sleep after a newer wake profile has been queued. STA/NOW/AP
profiles do not enter the NAN-only sleep boundary. Automatic return to the
persisted NAN profile a few seconds after all handlers become idle is not yet
implemented; until that follow-up, explicitly request NAN-only after testing.

NAN-only idle now retains the initialized Wi-Fi driver and its unassociated
STA radio interface; AP and IP STA association remain off. After the 60-second
debug command grace, the owner enables ESP-IDF automatic idle light sleep.
The DW adapter selects `PS_NONE` for the paired receive opportunity and
`PS_MAX_MODEM` afterward. Do not stop/start or deinitialize the driver every
DW just to release power constraints. UART/USB stay installed; UART does not
hold an explicit `NO_LIGHT_SLEEP` lock. Classic UART retains its APB frequency
constraint to preserve baud. `esp_wifi_force_wakeup_release` is not a generic
unlock: it must be paired with an acquire owned by the caller.

During the TX investigation, retained-but-repeatedly-stopped S3 Wi-Fi lost
heap across successive DW batches even after netif reconstruction was removed.
Private CBOR `nan heap free/minimum/largest` observations every 64 paired
windows help distinguish continued loss from startup settling. They are
debug events, not new telemetry methods. `telemetry.memory` remains the
public snapshot. Enabled idle PM alone is not proof of physical sleep;
its configuration must be distinguished from measured sleep entries.
Main enables ESP-IDF's idle light-sleep exit callback for this diagnosis.
The same private 64-window report includes `nan auto sleep callback`,
`nan auto sleep long_returns`, `nan auto sleep total_us`, and
`nan auto sleep last_us`. The callback does not allocate, log, or block.
ESP-IDF invokes it after rejected attempts too, so these observations count
only returns taking at least 10 ms, not every successful entry. Inter-window
durations of hundreds of milliseconds provide stronger evidence than an
enabled PM flag; compare with a power meter for independent physical proof.
The 32-bit cumulative microsecond counter wraps after approximately 71 minutes.
The 2026-10-02 check in `target/evidence/nan-auto-sleep/README.md` verified
approximately 460 ms inter-window returns on lora2, independently supported
by its USB meter's recurring 18 mA baseline (cycle average about 31 mA).
lora4/S3 registered the callback and enabled PM but reported zero long
returns: its inter-window light sleep remains unverified. Do not extrapolate
the classic ESP32 result to S3. Both were remotely updated and retained
persisted NAN-only mode with `nan_dw_interval=1`.
The 2026-10-03 follow-up found S3's cooperative UART task polling every RTOS
tick (10 ms), preventing the three-tick idle opportunity required by automatic
light sleep. S3 now shares classic ESP32's blocking physical RX/TX tasks,
with the same total stack budget, UART driver retained, and pool-backed QUIC
TX unchanged. The deployed S3 then reported long returns (62 returns totaling
19.6 seconds in its first post-grace report). A later passive sleep-to-wake
test observed the counter increase from 1513 to 1603 before a completed Main
QUIC/UDP status response 4.465 seconds after host NAN wake submission. This
supersedes the older S3 zero-return finding; no S3 power meter was read.
Fresh classic ESP32 baseline evidence included 201 meter samples over
20 seconds: 18 mA median, 30.24 mA mean, recurring low-current baseline and
discovery activity. Subsequent tests also exposed profiles that reported
NAN-only while idle sleep had not resumed; do not reuse that baseline as proof
of a later wake-from-sleep without checking the new interval's counters/current.
The subsequent clean wake check (`target/evidence/nan-auto-sleep/wake-results.md`)
missed the five-second services deadline: UART showed two full initial STA
scans of approximately 2.53 seconds each, separated by a driver replacement,
and association approximately 6.3 seconds after wake reception. A quick
response to a second wake while an earlier burst remains live is not a clean
sleep-to-wake timing result. Separate RF receipt, scan, association and the
first complete QUIC response when measuring this path.
NAN/STA profile transitions now retain the Wi-Fi driver and netif when AMPDU
and pre-start 11b policy are unchanged. Driver reinitialization is reserved
for actual changes to those policies, not association loss or a repeated
target-only wake. Repeated target-only wakes renew the awake lease without
creating another desired radio epoch. Initial AP selection still performs
the existing scan; cached BSSID/channel fast association is a separate change.
The driver-retention canary is recorded in
`target/evidence/nan-driver-retain-final/README.md`: all three ESP targets
built and the final lora2 Main update passed Wi-Fi commit/health checks.
UART-driven NAN -> STA retained the driver, but association setup still ran
twice and the owner fell back to NAN after association. Latest NAN wake
attempts did not reach target admission within five seconds. Driver retention
alone therefore does not establish that the wake latency objective is met.

Use `scripts/test_nan_wake_timing.py DEVICE --output EVIDENCE_DIR` for a
catalog-selected NAN-only control. It waits 65 seconds past the debug awake
grace, captures passive UART and QUIC PCAP, submits host `nan.wakeup`, and
requires a completed Main QUIC/UDP status response with STA associated. It
restores NAN-only afterward without writing NVS. The default 12-second
observation deadline allows slow responses to be measured, while the default
`--max-ready-secs 5` makes a response later than five seconds fail the timing
gate. Run devices sequentially: the host has one pending targeted wake slot.
Waiting past the grace is not independent
physical light-sleep proof: use the sleep callback counters or power meter.
`--require-sleep --settle-secs 100` requires increasing long-return observations
before wake. `--observe-current-profile --require-sleep` avoids a control
mutation when passively checking an already configured sleeping device.
Configured tests check committed `telemetry.runtime` state, not only status;
they retain the control session for two seconds as a diagnostic allowance and
verify that restoration has actually applied. After a successful wake they
also require another completed UDP status at least ten seconds after submission
before restoring NAN, avoiding late wake repetitions during restoration.
Use `scripts/capture_power_meter.py METER_SERIAL --seconds N --output FILE`
to record the operator-selected external streaming meter (second column in
amperes, converted to mA) with host timestamps. The meter is not an ESP target;
never send it firmware commands or use its port for flashing/reset.

NAN scheduling must map a beacon's TSF offset within the 512-TU period to
the receiver's local clock; a discovery beacon's arrival is not necessarily
a DW boundary. `dmesh_rawnan::nan_dw_boundary_local_us` is the shared phase
calculation used by host and ESP. Keep actual beacon reception time separate
for freshness. The 2026-10-03 regression test covers a beacon 100 TU inside
a slot, which previously moved the scheduled window to that arrival.
The post-fix lora2 check completed QUIC/UDP status in 4.394 seconds and held
STA reachability through 10.032 seconds. Its simultaneous meter showed median
18 mA before wake, 114 mA during STA activity, and 18 mA again after restoring
NAN-only; UART independently recorded increasing long sleep returns. Evidence:
`target/evidence/sleep-wake-verify-20261003/repeat-results.md`. This is not a
claim of reliable wake timing under every RF condition; latest-image results
are recorded below.

Subsequent S3 post-fix checks completed in 2.785 and 2.781 seconds; a classic
ESP32 repeat completed in 3.799 seconds. Both had increasing pre-wake sleep
returns, ten-second reachability and applied NAN-only restore. The earlier
S3 6.569-second cold association remains a failed timing gate. The additional
STA reattachment optimization preserves a previously successful driver's
BSSID/channel/RSN configuration only when SSID, password and requested target
still match; a failed direct attempt falls back to scan selection. Its private
CBOR `wifi.sta_target_reuse` fields are 1=reused, 2=BSSID number, 3=channel;
credentials are never logged. Both optimization images were committed through
Recovery over QUIC/UDP with independent UART and PCAP captures. Latest-image
strict checks measured lora2 first/repeat wake at 4.379/0.549 seconds and lora4
at 3.383/1.529 seconds, including increasing pre-wake sleep counters, completed
Main status responses, reachability after ten seconds, and NAN-only restore.
Both resumed long inter-window sleep after the final restore. The latest
lora2 image's continuous meter capture confirmed median 18 mA before and
after each wake and 114 mA during STA activity; sleeping-cycle means were
approximately 31 mA. These measured cases pass five seconds; the earlier
6.569-second result is retained as historical timing variability, not erased.
Automatic post-update Main health can still time out when Main returns directly
to NAN-only; object commit is not a passing flasher health gate. Separate
post-update NAN wake/status checks provided the Main health evidence here.

On Linux, unsupported optional nl80211 NAN beacon registration must not abort
radio startup when monitor RX is available. Check both radio active/publishing
and actual receive events after rebuilding/restarting: partial capture threads
alone do not prove the AP owner survived. Failed startup must stop any capture
threads already created. For host log collection, advance `log.watch since_seq`
until caught up; omitting the cursor returns retained records, which may predate
the current wake request.

# Telemetry and logs

Counters, state snapshots and logs are registered handlers like any other, and
`API.md` defines each response (`telemetry` and `log` sections). A device
omits a value it does not have; it never sends zero for "unknown".

- Firmware: `telemetry.now`, `nan`, `udp6`, `wifi_link`, `quic`, `memory`,
  `power`, `runtime`, `bearers`, and `log.watch`.
- Linux (lmesh): `telemetry.nan_status`, `quic`, `quic_associations`, `bearers`,
  `memory` and `log.watch`, each a typed handler, the same records as Android
  (`API.md` notes which fields Linux can supply). The raw-radio counters
  `telemetry.now`, `nan`, `udp6` and `wifi_link` are firmware-only. Its `log.watch` serves the process's `tracing` history
  (`mesh::local_trace`: warnings, errors and radio events) with `target` as
  `source` and the event type as `kind`. `metrics`, `events`, `log-watch` and
  `runtime.snapshot` are no longer registered there.
- Android: `telemetry.nan_status`, `battery`, `quic`, `memory` and `log.watch`.
  Its `log.watch` serves the process's `tracing` history plus NAN follow-ups and
  events (`kind` `nan.followup`, `nan.event`) and BLE scan results
  (`ble.scan_result`). The HTTP gateway exposes `telemetry` and `log` services.
- `metrics`, `events`, `log-watch` and the `runtime`/`power`/`memory.snapshot`
  methods are registered on no platform any more.
- `log.watch` polls retained records (`since_seq`, `limit`, `level`, `source`,
  `kind`) and returns a `cursor` for the next poll. With `stream=true` and a
  `timeout` the same method keeps the stream open and, with `snapshots`
  (`telemetry.quic`, ...) and `interval_ms`, interleaves each snapshot as a
  record whose `fields` are that method's response. The CLI does not decode the
  streamed body yet.
- Firmware logs are the last 32 ESP-IDF lines; a streamed `log.watch` is polled
  every 100 ms by the owner while it waits, so keep streams short.

# Handler registry

Any request may carry `timeout=MS` (envelope key 8, milliseconds): the time the
caller allows. `dmesh-cli DEVICE probe.start peer=... bytes=... timeout=60000`
lets the probe run for a minute; without it a probe runs for a size-based
default (30 s up to 300 s). A request that runs out is answered with a
`timeout` error. See ssh-mesh `crates/mesh-api/PROTOCOLS.md`.

Every platform registers its tagged-CBOR handlers in the one
`dmesh_server::registry`, by component and method number plus name, and every
ingress (QUIC streams, UART/UDP/NOW records, the Linux control socket, the
Android HTTP gateway) dispatches through it by number. Only implemented methods
are registered, so `services` lists exactly what a platform answers
(`[component, method, "name"]`) and a request for anything else receives
`unsupported or invalid stream request` with the request's component, method
and id. Stubs are not registered: Android has no `metrics`, `memory.snapshot` or
`telemetry.*_metrics`; Linux has no `telemetry.battery`, `power.snapshot`,
`memory.snapshot` or BLE scan/connect; boot, module, runtime-reset and
flash methods are firmware-only.

Android's platform methods (`ble` 201, `radio` 202, `usb` 204, `wifi` 205,
`companion`, `transport.set`) are registered local-only. The HTTP gateway
routes `/_m/mesh/services/<name>/call/<method>` to the registry as local
ingress; a QUIC peer calling the same numbers gets the unsupported error. Check
what a device registers with:

```sh
dmesh-cli DEVICE services
curl -sS -X POST 'http://127.0.0.1:18480/_m/mesh/services/ble/call/ble.status' \
  -H 'content-type: application/json' -d '{}'
```

# Permissions

In adb mode, grant the required permissions listed in
[Repo-local tooling](#repo-local-tooling). For a quick status check:

```sh
adb shell dumpsys package com.github.costinm.dmesh.lm | \
  sed -n '/runtime permissions:/,/install permissions:/p'
```

On some devices, especially Samsung builds, use `pm grant --user 0` so the
runtime grant is applied to the active user.
# ESP-IDF STA lifecycle diagnostics

STA transition callbacks and deadlines use Main's committed profile, not a
pending `transport.set` profile whose response has not finished. Explicit
profile changes clear the previous failure's automatic-retry cooldown.
Without these distinctions, an off/on test could start STA twice under
different generations, then suppress subsequent explicit attempts until the
five-minute discovery cadence. On lora1 the corrected owner passed three
awake transitions with UDP status in 5.33–5.49 seconds.

The shared DMesh AP selector accepts both the exact default `DIRECT-dmesh`
and the `DIRECT-...-dmesh` naming family. The former was previously excluded
from fallback selection and scan reporting. Default DMesh APs are
password-protected; do not infer open authentication from the SSID. Verify
the currently associated BSSID before counting a switch as successful.

If repeated short UART commands crash Main with a 12288-byte allocation
failure, inspect the matching ELF before blaming STA authentication. A
2026-10-03 classic ESP32 reproduction traced the allocation to growth of
`VecDeque<AssociationEvent>` during association admission. The firmware's
direct-stream owner must consume both `NoStdRuntime::next_association()` and
`next_event()` notifications during progress; otherwise completed command
connections leave queued notifications behind. Regression validation should
repeat fresh CLI associations, not just many requests on one association.
Use `python3 scripts/test_uart_association_churn.py DEVICE --requests 100
--output target/evidence/uart-churn.log` with the catalog-selected device.
The test requires every status response and monotonically nondecreasing
uptime; it fails if UART captures an allocation abort or backtrace.

Main and Recovery emit numeric-field CBOR `LogRecord` events on UART, without
`format!` or heap allocation in the Wi-Fi event callback. Capture with
`dmesh-cli SERIAL --watch --timeout-secs 180` and `UART_CODEC_LOG=FILE`.
These diagnostic event fields are private, not new stable telemetry handlers.
The CBOR field map is encoded directly into the event output, without a
second temporary map buffer. STA events use 256-byte output storage; the
richest candidate event is tested at maximum integer widths. This avoids
nesting large encoding buffers with the full UART queue record on ESP-IDF's
small `sys_evt` stack. A prior S3 startup overflow rolled back to Recovery;
do not mistake Recovery console output for a healthy sleeping Main.
Existing `radio.snapshot` still exposes association timing and the last
non-intentional disconnect reason.
`radio.snapshot`'s result map (outer tag 6) also exposes tag 131 cumulative
connections, 132 cumulative disconnections, 133 last raw disconnect reason
(including intentional release), and 134 dropped structured STA records.
These counters survive radio reconfiguration and reset only at boot.
Tags 135–144 expose non-secret live `esp_wifi_get_config(STA)` facts: RSSI and
auth thresholds, association channel hint, configured BSSID and pin flag,
scan method, PMF capability/requirement, SAE method, and the raw SSID array.
They are omitted when the driver cannot return its configuration. Do not
confuse tag 136 with `wifi.scan.configured_sta_auth_mode`: that scan field is
the AP's advertised mode. A configured BSSID/channel is not proof of a current
association; use the separate associated-peer fields.

| Event | Numeric fields |
|---|---|
| `wifi.sta_scan` | 1 SDK result, 2 blocking scan duration ms, 3 required BSSID (zero means unspecified) |
| `wifi.sta_candidate` | 1 selected BSSID, 2 channel, 3 SDK auth mode, 4 preferred SSID match, 5 set-config result, 6 readback result, 7 credential preserved, 8 credential present, 9 RSSI dBm, 10 readback channel, 11 readback BSSID, 12 BSSID pinned, 13 PMF capable, 14 PMF required |
| `wifi.sta_connect` | 1 SDK connect result, 2 explicit lifecycle reconnect (false for initial association) |
| `wifi.sta_connected` | 1 BSSID, 2 channel, 3 auth mode, 4 association ID, 5 connect-to-associated ms, 6 cumulative connections, 7 cumulative disconnections |
| `wifi.sta_disconnected` | 1 SDK disconnect reason, 2 BSSID, 3 previously associated, 4 time since connect request ms, 5 cumulative disconnections, 6 intentional owner leave, 7 cumulative connections |
| `wifi.sta_release` | 1 owner disconnect call result, 2 association state before the callback (may race with it) |
| `wifi.driver_event` | 1 SDK Wi-Fi event ID, 2 driver running, 3 associated, 4 actual primary channel, 5 secondary channel enum, 6 channel read result, 7 power-save enum, 8 power-save read result; per-frame NOW/ROC/window events are excluded |
| `wifi.sta_owner_start` | 1 requested generation, 2 applied STA generation, 3 announced generation, 4 owner Wi-Fi started, 5 owner NAN/NOW started, 6 owner associated, 7 SDK associated, 8 retry pending, 9 wake retry budget |
| `wifi.sta_owner_stop` | 1 generation, 2 profile still requests STA, 3 owner associated, 4 SDK associated, 5 retry pending, 6 last non-intentional reason |
| `wifi.profile_request` | 1 new generation, 2 stream response defers application, 3 requested profile is NAN-only/sleepy |
| `wifi.profile_response_finished` | 1 response generation, 2 current desired generation, 3 previously deferred generation, 4 response released that generation |
| `wifi.pm_wait_profile` | 1 committed owner generation, 2 current desired generation, 3 deferred response generation, 4 current ms, 5 grace deadline ms, 6 NAN owner started, 7 STA owner started; emitted once per pending generation |

BSSID numbers are the six MAC bytes in network order, not NAN's little-endian
MAC representation. Decode SDK reasons/events using the ESP-IDF version built
into the image; reason 36 is local `STA_LEAVING`, not evidence of a bad password.
Nonzero readback results make the corresponding fields unavailable, not zero
measurements. No passwords or password fingerprints are emitted.
Retained-driver replacement may report SDK leave reason 3 or 8 instead of
36. The owner tracks its intentional asynchronous disconnect so these leave
callbacks do not abort a new association. A reason 3/8 without owner intent
is still a failure. A hardware capture exposed the device deauthenticating
3 ms after its association request, before the host's successful response;
after correction, WPA authorization and QUIC/UDP status passed on DIRECT-dmesh.
Counters restart at boot; they count SDK callbacks, not successful application
transfers. UART egress can drop diagnostics under pressure, so missing events
alone do not prove that a transition did not happen. Compare an awake
NOW+NAN-to-STA transition with a measured sleeping transition before attributing
association failures to sleep.

Run the awake control on a catalog-selected device with
`python3 scripts/test_sta_lifecycle.py DEVICE --output target/evidence/sta-check`.
It keeps NOW enabled, captures UART while polling UDP status for 15 seconds,
and leaves the runtime requesting STA+NOW. It does not modify NVS. An accepted
`transport.set` response is not a successful association; inspect the separate
`udp_ready` result and the SDK/owner events.
For repeated testing, add `--cycles 5 --pause-secs 3`; each cycle has its own
UART/PCAP/result files. NOW remains on across the off/on cycles. No board name,
serial path, MAC, or BSSID is embedded in the test body.
