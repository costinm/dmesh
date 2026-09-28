# dmesh-cli

dmesh-cli sends tagged CBOR service requests over Wi-Fi/UDP or a local serial
port. Most remote communication should use the faster Wi-Fi path. In the
examples, DEVICE is a name from the device catalog, OBSERVER is a reachable
device that can observe NAN, and SERIAL is a local /dev/serial/by-id/... path.
Use your own names and addresses; the examples are syntax, not lab targets.

UART and BLE are intended for companion devices that add radios or protocols
to a Linux host or Android device. UART also provides local boot logs and
repair diagnostics. UART remains a normal QUIC-lite packet transport for
service requests, checks, probes, and log streams, but firmware object upload
is Wi-Fi-only. dmesh-cli opens a serial port or UDP to send commands; lmesh
owns the Linux Wi-Fi radio.

For Android's local HTTP gateway, forward the app's HTTP port and use the same
service method names. The gateway converts JSON records to the registered
tagged-CBOR handlers; adb carries only the TCP forward, not a control command.
If the HTTP service requires an API key, set `DMESH_HTTP_API_KEY` for the call.
HTTP fields infer booleans and unsigned integers; prefix a numeric-looking
text value with `text:` (for example `--ssid=text:1234`).

~~~sh
adb -s SERIAL forward tcp:18480 tcp:18480
dmesh-cli http://127.0.0.1:18480 radio.history --limit=32
dmesh-cli http://127.0.0.1:18480 transport.set --mode=6
~~~

~~~sh
. ./env.sh
export DMESH_DEVICE_CATALOG=/path/to/device-catalog.toml # Deprecated test override only.
dmesh-cli DEVICE status
dmesh-cli udp://[fe80::1234%wlan0]:3337 status
dmesh-cli SERIAL status
~~~

An IPv6 link-local address needs its interface scope, such as %wlan0. A
catalog name with a scoped Wi-Fi address tries it first and checks the signed
identity. If that fails, the CLI uses discovery and NAN activation. A catalog
VIP6 selects an identity; it is not a directly routable UDP address. See the
[example device catalog](examples/device-catalog.toml). Static host inventory
is deprecated; normal device selection is moving to discovery plus paired-device
leases. Hardware tests must restore and release acquired peers so later runs can
select them reproducibly.

## Find and inspect devices

~~~sh
dmesh-cli discover                     # Collect signed announcements and observer inventories.
dmesh-cli devices check                # Compare catalog VIP6 identities with visible peers.
dmesh-cli devices backfill --dry-run   # Preview VIP6 values from signed discovery.
dmesh-cli devices backfill             # Write matching VIP6 values to the catalog.
dmesh-cli DEVICE check                 # Request a direct discovery response.
dmesh-cli DEVICE services              # List registered numeric handlers.
dmesh-cli DEVICE status                # Read service status.
dmesh-cli DEVICE firmware.identity     # Read firmware identity after a boot or update.
~~~

discover asks reachable observers for active discovery, waits for a NAN
discovery window, and prints their observations. devices backfill modifies the
selected catalog unless --dry-run is given. A direct check confirms discovery;
firmware.identity and status provide application evidence.

## Wake a sleeping device

A normal service request to a catalogued target already attempts scoped UDP6,
then signed discovery and NAN wake when needed:

~~~sh
dmesh-cli DEVICE status
dmesh-cli DEVICE telemetry.nan_status
dmesh-cli DEVICE probe --bytes=4096 --packet_size=256
~~~

For step-by-step diagnosis, ask a reachable observer:

~~~sh
dmesh-cli OBSERVER discovery.active                 # Solicit a new discovery pass.
dmesh-cli OBSERVER discovery.nodes                  # Read observed devices.
dmesh-cli OBSERVER nan.wakeup --to=aa:bb:cc:dd:ee:ff # Queue a wake for the target radio MAC.
dmesh-cli discover                                 # Look for the target's fresh identity.
~~~

A successful nan.wakeup reply proves that the observer accepted the request.
Confirm the target appears again before treating it as awake. The to field is
the target radio MAC from the catalog or observation, not its VIP6.

## Logs, serial reset, and local diagnostics

~~~sh
dmesh-cli DEVICE log-watch --records=16               # Poll bounded firmware log records.
dmesh-cli DEVICE log-watch --since=100 --records=32     # Continue from a record cursor.
dmesh-cli DEVICE events --since=100                  # Read subsequent service events.
dmesh-cli DEVICE --watch --timeout-secs 30          # Passively read serial boot/platform text.
dmesh-cli DEVICE --watch --reset --timeout-secs 30  # Reset while capturing the new boot.
dmesh-cli DEVICE --reset                            # Pulse the local serial RTS reset line.
~~~

log-watch and events are service requests and can use Wi-Fi. --watch and
--reset require a local serial path or a catalog entry with serial_id; they
cannot reset a remote device through lmesh. --watch --interactive also accepts
terminal input. A physical UART bridge uses its catalog uart_baud or an
explicit --baud 115200; packetized USB/JTAG needs no nominal baud. A reset or
boot line alone is not proof of Main health: follow it with firmware.identity
and status.

## Read radio, runtime, and performance state

~~~sh
dmesh-cli DEVICE metrics                         # General service counters.
dmesh-cli DEVICE telemetry.nan_status            # NAN sync and publish state.
dmesh-cli DEVICE telemetry.nan_metrics           # NAN RX/TX and admission counters.
dmesh-cli DEVICE telemetry.now_metrics           # ESP-NOW TX and RX counters.
dmesh-cli DEVICE telemetry.udp6_metrics          # Raw IPv6/UDP delivery and failures.
dmesh-cli DEVICE telemetry.wifi_link_metrics     # Available per-peer Wi-Fi link facts.
dmesh-cli DEVICE runtime.snapshot                # Desired and applied runtime state.
dmesh-cli DEVICE power.snapshot                  # Power management observations.
dmesh-cli DEVICE memory.snapshot                 # Packet pool and memory observations.
dmesh-cli DEVICE radio.snapshot                  # Raw radio state and counters.
dmesh-cli DEVICE wifi.scan --last_results=true     # Retained Wi-Fi scan results.
dmesh-cli DEVICE probe --bytes=4096 --packet_size=256 # Bounded QUIC-lite transfer.
dmesh-cli DEVICE probe --bytes=65536 --packet_size=1024 --parallel_streams=2
~~~

probe reports bytes and timing; it does not prove that a separate application
request was admitted. wifi.scan --fresh=true starts a scan and may wake a
radio. Radio metrics help separate TX submission, raw reception, semantic
admission, and an application response.

## Settings and controls

The [single lmesh tools catalog](../lmesh/resources/tools.json) carries local and
device methods with their CBOR tags and field types. dmesh-cli discovers it in
the same per-service layout as mesh-cli: `MESH_SCHEMA_DIR/lmesh/tools.json`,
`$HOME/opt/lmesh/etc/schemas/tools.json`, or
`/opt/lmesh/etc/schemas/tools.json`. The repository `env.sh` selects the source
catalog; the packaged CLI selects its installed catalog. The shared device
control contract is specified in [root API](../../API.md).
The firmware transport [README](../../fw/dmesh-fw-transport/README.md) records
implementation and radio policy, not a second API schema.

The command form is dmesh-cli DEVICE METHOD --field=value. Named and numeric
field keys are equivalent when both are declared by the schema:

~~~sh
dmesh-cli DEVICE settings.list                     # List setting keys.
dmesh-cli DEVICE settings.get --key=name             # Read one key.
dmesh-cli DEVICE settings.set --key=name --value=demo  # Set one key.
dmesh-cli DEVICE settings.set --1=name --2=demo        # Same request using numeric tags.
dmesh-cli DEVICE settings.set --key=quic.pool --value=32 # Larger per-device packet ceiling.
dmesh-cli DEVICE relay.list                        # Inspect known relay entries.
dmesh-cli DEVICE connection.configure --ack_frequency=2 --ack_delay_ms=10
~~~

These controls change device state; choose values for the selected device:

~~~sh
dmesh-cli DEVICE transport.set --mode=nan --now=1 --nan_dw_interval=1 # Replace the radio profile.
dmesh-cli DEVICE radio.control --channel=6                      # Change raw radio control.
dmesh-cli DEVICE radio.reset_counters                          # Clear radio counters.
dmesh-cli DEVICE runtime.reset                                 # Reset runtime state.
dmesh-cli DEVICE boot.recovery                                 # Request Recovery handoff.
dmesh-cli DEVICE module.stop                                   # Stop a loaded module.
~~~

transport.set replaces a complete volatile profile. radio.tx --frame=hex:...
sends a caller-supplied raw frame and requires a valid complete frame; use it
only for controlled radio diagnostics. The normal firmware update below
handles Recovery handoff and completion checks.

## Firmware updates

~~~sh
dmesh-cli flash DEVICE                             # Update Main using the selected artifact.
dmesh-cli flash DEVICE --file /path/to/main.bin     # Use an explicit Main artifact.
dmesh-cli flash DEVICE --target MODULE              # Update a named module artifact.
~~~

flash discovers the target, wakes it over NAN if needed, hands off to
Recovery, transfers the object, then checks reboot identity and fresh Main
health. object.flash is the underlying tagged service operation; a direct
call requires matching artifact and target metadata and a Wi-Fi/UDP target.
It is rejected on UART. For initial provisioning or physical repair, use
scripts/flash-device.py.

## Companion BLE and lmesh radio requests

BLE operations depend on a connected companion that exposes the adapter:

~~~sh
dmesh-cli DEVICE ble.status                        # Adapter and connection state.
dmesh-cli DEVICE ble.scan --duration_ms=5000         # Start a bounded scan.
dmesh-cli DEVICE ble.scan_stop                     # Stop scanning.
dmesh-cli DEVICE ble.start                         # Start BLE service activity.
dmesh-cli DEVICE ble.stop                          # Stop BLE service activity.
dmesh-cli DEVICE ble.connect --addr=aa:bb:cc:dd:ee:ff --psm=128
dmesh-cli DEVICE ble.coc.send --data=hex:010203      # Send bytes on an established CoC.
~~~

lmesh is a regular mesh service, like mesh-init or ssh-mesh. Use the generic
mesh client for Linux Wi-Fi controls. Its socket uses upstream ssh-mesh tagged
CBOR; HTTP admin requests remain JSON at the HTTP edge and are translated by
ssh-mesh:

~~~sh
mesh lmesh wifi.interface.list                # List interfaces owned by lmesh.
mesh lmesh telemetry.nan_status               # Read NAN state.
mesh lmesh wifi.interface.channel --iface=wlan0 --channel=6 # Change the owned radio channel.
~~~

dmesh-cli also accepts the same method and --field=value form when a CLI
workflow needs to call lmesh directly: dmesh-cli lmesh wifi.interface.list.

For a direct bootstrap diagnostic while owning a local serial port:

~~~sh
dmesh-cli SERIAL --msg 'transport.set mode=nan now=1' # Send one direct tagged control record.
~~~

Normal API calls use tagged service streams over QUIC, including relay paths.
The direct tagged control record is reserved for bootstrap diagnostics.
