# ESP Wi-Fi Operation

The main design is centered around battery saving using synchronized wake windows.

Wifi is used as any other  radio - like LoRA and low-level FSK - without the higher level protocol. NAN and AP beacons are used to sync around the same window - NAN clusters have a larger span, while AP can only sync in its vicinity. 

The design is primarily using NAN and AP beacons for the time sync. We can send NAN follow-up frames in the DW - for Android or Hosts supporting NAN discovery, or ESP-NOW frames to other ESP devices or host with custom listener.

This is optimized for power saving and range - not latency or througput. The messages
can be used by a control plane to establish and modify AP (DIRECT in android) and STA
connections for higher speed, between hosts and android devices - the ESP is not 
directly involved in this.

This is the authoritative operating note for ESP firmware Wi-Fi behavior. It
collects the design decisions, timing settings, and lab verification needed to
work on raw/custom NAN, action frames, and the AP timing fallback. Host Linux
nl80211 details remain in [`crates/lmesh/WIFI.md`](../../../crates/lmesh/WIFI.md).

## Scope and Constraints

The firmware uses channel 6 by default and treats Wi-Fi as a short-window,
connectionless modem. It does **not** depend on IP, DHCP, lwIP data delivery,
or normal STA association for mesh control traffic.

- Raw/custom NAN uses management beacons and DMesh action frames.
- Today, action-frame payloads are compact CBOR. The reviewed transport
  direction is a minimal, plaintext QUIC-shaped short-packet envelope carrying
  compact-CBOR JSON-RPC; it is documented in
  [`docs/plans/nan-quic-short-transport.md`](../../../docs/plans/nan-quic-short-transport.md)
  and is **not implemented yet**. It will replace the former custom DMesh
  follow-up ACK, not add another acknowledgement layer.
- The raw path is ESP-NOW-like and connectionless at L2, but does not use the
  ESP-NOW API or its 250-byte limit.
- Promiscuous data-frame receive is deliberately off in normal operation. It
  wakes the device for unrelated channel traffic; data/AP/STA experiments are
  debug-only and must not become the battery transport.
- The receive callback performs an early DMesh/NAN filter before queuing work.
  It does not make promiscuous reception a hardware destination filter.
- Official Espressif NAN is not the low-power default. The raw implementation
  owns the Wi-Fi-on window and explicitly powers Wi-Fi down between windows.

## Radio roles and transport direction

The device mesh is deliberately multi-radio. Discovery, synchronization,
payload transport, and companion attachment are separate jobs; a successful
discovery callback is not proof that every subsequent radio path is reliable.

| Radio/path | Current role | Operating constraint |
| --- | --- | --- |
| Raw NAN SDF and beacons | Discovery and common DW/time synchronization. NAN TSF is preferred; channel-6 AP beacons are a powered fallback. | Battery ESPs wake only in their selected DW slots. SDF and raw NAN TX must be scheduled inside those windows. |
| Raw NAN follow-up/action | ESP-to-ESP control/data bearer and observer evidence. It is the first target for the shared short-packet/CBOR connection model. | Use the NAN discovery/multicast destination, not an application-selected peer MAC. The 802.11 source remains useful only for bootstrap context. |
| Android Wi-Fi Aware follow-up | Android-to-Android messages, and bounded Android-to-ESP diagnostics immediately after a fresh matching discovery callback. | Public Android APIs send to a short-lived `PeerHandle`; they cannot request arbitrary raw NAN BSSID/multicast destination frames. Do not retain a stale peer handle or claim delivery from framework queue acceptance alone. |
| BLE CoC | Preferred Android companion payload path after ESP discovery/publish. An unsolicited ESP publish can cause Android to open a short-lived CoC connection. | CoC must be assessed with the ESP wake policy; a retained connection may prevent the intended sleep behavior. |
| BLE GATT | Diagnostic and compatibility companion path, not the selected low-power bearer. | Validate pairing/read/write independently; keeping BLE active or a GATT link alive has not met the battery goal. |
| AP/STA or higher-rate links | Optional control-plane-selected bulk path between capable hosts/Android devices. | They are not the normal battery ESP payload transport. |

The shared model is therefore: NAN synchronizes and discovers; a suitable
transport carries the same compact-CBOR JSON-RPC payload. Raw NAN will use the
reviewed short-packet connection bearer first. CoC can carry the same payload
after Android rendezvous. GATT is retained only where its power and lifecycle
trade-offs are acceptable. A later encrypted form can derive connection IDs
from Ed25519/DH state; plaintext MAC-derived bootstrap IDs are only the current
reviewed direction.

### Reliability boundary

The lower radio bearer may use packet numbers, selective ACK ranges, and
retransmission timers. That is distinct from a command result: CBOR's reserved
`id=1` identifies a JSON-RPC request and its response, and each caller times
out or retries a command according to the active radio cadence. Do not restore
the retired custom `DMESH_NAN_ACK` payload message as a substitute for either
layer.

For current Android evidence, prefer the app's bounded NAN history/status and
`dumpsys wifiaware` only for framework diagnostics. A Pixel has accepted the
spec-derived ESP SDF and immediate callback-armed follow-up delivery; Samsung
raw-ESP acceptance and delayed follow-up behavior remain platform-specific
open evidence, not a general interoperability claim.

## Normal Battery Profile

The saved infra defaults are:

| Setting | Default | Rationale |
| --- | --- | --- |
| `wifi.mode` | `nan` | Starts raw/custom NAN duty operation. |
| `nan.boot` | `true` | Re-enters the saved raw-NAN duty profile after reset. |
| `nan.channel` | `6` | All active radios share one 2.4 GHz channel. |
| `nan.wake_ms` | `4000` ms | Battery wake cadence; compatible with a bounded discovery delay. |
| `nan.active_ms` | `250` ms | Wi-Fi/action receive and queue-drain window. |
| `nan.light_sleep` | `true` | Explicit light sleep while Wi-Fi is off. |
| `nan.early_ms` | `5` ms | Initial return margin before the selected DW0/DW-stride window. Runtime adapts this between 1 and 100 ms from beacon misses/successes without changing the selected slot. |
| `nan.dw_tu` / `nan.dw_off_tu` | `512` / `0` TU | Raw NAN cadence and phase. |
| `power.profile` | `auto` | DFS plus automatic idle light sleep outside explicit radio work. |
| `uart.hb_every` | `1` | Emits one empty framed UART heartbeat on every Wi-Fi wake so lmesh can flush queued CBOR. |

When a recent NAN beacon exists, its TSF aligns the next active window. In the
absence of a source the device uses its local duty timer. The current lab
measurements are board-specific: `lora2` settles around 18 mA and `lora4`
around 12 mA between raw-NAN wake spikes. Do not treat those as a release
power specification.

The scheduler sleeps until the current runtime wake margin before the selected
DW0/DW-stride slot, then stays awake only for `nan.active_ms`. After a beacon is
received the margin is reduced by 1 ms; after a missed beacon it is increased by
5 ms (bounded to 1..100 ms). The slot phase is unchanged. `mode status=true`
reports `nan_wake_early_ms`, `nan_last_wake_to_beacon_us`, and
`nan_last_beacon_to_sleep_us` for tuning and loss detection.

For a timing-only power experiment, set `uart.hb_every=4` on a stride-8 node;
that permits one UART activation about every 16 seconds while leaving the NAN
DW0/DW8 schedule unchanged. Restore `1` before interactive command or
reliability tests.

## Sync Source Selection

`nan.sync_source` selects the source used to align battery-node wake slots:

| Value | Behavior |
| --- | --- |
| `auto` | Prefer fresh NAN TSF immediately; otherwise use a channel-6 AP beacon TSF. |
| `nan_only` | Ignore AP beacons. |
| `ap_only` | Ignore NAN timing; deterministic AP fallback test mode. |

A battery node samples beacons during its normal raw-NAN receive interval. If
it has no usable source, it runs a bounded management-beacon recovery listen:

| Setting | Default | Rationale |
| --- | --- | --- |
| `nan.ap_recovery_ms` | 32000 ms | Avoid keeping Wi-Fi on after each missed timing source. |
| `nan.ap_recovery_listen_ms` | 1200 ms | Acquires AP/NAN timing without sustained Wi-Fi load. |

Counters in `mode status=true`, `nan stats=true`, and `xstatus` show NAN DW
activity, source choice, AP recovery runs, beacon freshness, misses, and
timing drift. Verify counters rather than assuming a source is present.

## Powered AP Fallback

Set `nan.ap_owner=true` only on a powered gateway, normally `lora1`. It keeps
Wi-Fi on and watches for NAN. If NAN has been absent for `nan.ap_loss_ms`, it
starts an open AP:

```text
SSID: DIRECT-DMESH-<last4MAChex>
channel: 6
beacon interval: nan.ap_beacon_tu (500 TU / 512 ms by default)
```

The AP is a timing source, not an IP service. The powered owner starts AP+STA
on the same channel: AP emits the timing beacon while the unassociated STA
interface is reserved for raw NAN management/action injection and the raw
receiver remains armed. While AP is active the board must not turn Wi-Fi off
or enter the raw NAN duty sleep path. In `auto`, a fresh NAN beacon stops the
fallback AP and returns the owner to NAN watch mode. `ap_only` starts the AP
immediately and is intended for repeatable laboratory tests.

An AP owner has no raw-NAN sleep callback, so it emits the same bounded UART
heartbeat on the saved `nan.wake_ms` cadence. This keeps the lmesh CBOR modem
forward usable while the owner is powered and hosting the AP.

| Setting | Default | Meaning |
| --- | --- | --- |
| `nan.ap_owner` | `false` | Enables powered gateway timing-source behavior. |
| `nan.ap_loss_ms` | 5000 ms | NAN absence before starting the fallback AP. |
| `nan.ap_beacon_tu` | 500 TU | AP beacon interval. ESP-IDF requires a multiple of 100 TU. In AP fallback, `TSF / beacon_interval mod nan.dw_stride` defines AP-DW0 and subsequent selected slots; a fresh NAN beacon replaces this with the 512-TU NAN grid. |
| `nan.dw_stride` | 8 | Use DW0 and every eighth source slot: NAN-DW0/NAN-DW0+8 or AP-DW0/AP-DW0+8 (about 4.19 seconds at 512 TU). |

### 512-TU cadence probe

`nan.dw_stride` is the firmware wake-scheduler contract.  With a 512-TU base,
`nan.dw_stride=8` selects one 4.194304-second slot per cycle.  `xstatus`
reports both `nan_selected_stride` and the absolute
`nan_expected_slot_index`; the latter must be divisible by the selected stride.

To verify reception without using a physical UART, start the Android NAN
service, publish the ESP descriptor, then have Android send one follow-up per
512-ms interval:

```bash
# Android app-dmesh shell command (after a PeerReady event)
adb -s <serial> shell "content call \
  --uri content://com.github.costinm.dmesh.lm.shell --method command \
  --arg 'wifi.nan.probe text=BITMAP count=16 interval_ms=512'"

# Managed lmesh forward only
mesh lmesh esp.serial.command port=<radio> command='nan action_dump=true'
mesh lmesh esp.serial.command port=<radio> command='xstatus'
```

For an ESP-to-Android discovery failure, inspect the exact bounded descriptor
that the firmware handed to raw Wi-Fi TX before changing timing or UART:

```bash
mesh lmesh esp.serial.command port=<radio> command='nan publish_dump=true'
```

The required Service Descriptor, Device Capability, Availability, and optional
SDEA fields are specified in [nan-sdf-fields.md](nan-sdf-fields.md). Generate
the ESP descriptor from those fields; never copy an Android capture into the
production encoder.

`publish_dump` is diagnostic only; it does not transmit or retain an
unbounded packet history.

`nan publish=true` requires `sync=true` and only queues SDFs. The mode task
releases at most one descriptor immediately after each observed NAN beacon.
For hardware evidence, require `publish_dw_tx` to advance and
`publish_dw_last_offset_us` to remain inside the post-beacon dwell reported by
`nan stats=true`; a queued publish acknowledgement alone is not TX evidence.

On 2026-07-30, lora3 with `nan.dw_stride=8` received `BITMAP#5` at
`dw512_index=37408`, which is `0 mod 8`; its current status independently
reported `nan_selected_stride=8` and `nan_expected_slot_index=37568`
(`0 mod 8`). Android recorded one `FollowupProbe sent=1` and a successful
`FollowupTxOk` for every bitmap position.

This validates the ESP receive scheduler, not the SDF Availability attribute.
The firmware now generates its NAN Availability attribute from `nan.dw_tu`,
`nan.dw_off_tu`, `nan.dw_stride`, and `nan.active_ms`: one committed 2.4-GHz
entry, 16-TU bitmap bits, and a standard 128..8192-TU repeat period. A 512-TU
base with stride 8 uses a 4096-TU repeat and a 16-bit (250-ms rounded) awake
bitmap at DW0.

Changing that ESP schedule also requires checking Android's
`awake_dw_interval`/discovery-window setting. Android's 2.4-GHz framework/HAL
supports values 1..5, representing every 1, 2, 4, 8, or 16 DWs; stride 8 maps
to Android value 4. `ConfigRequest` is hidden from ordinary apps, and the
current app attaches with the interval unset. On the Pixel, `dumpsys wifiaware`
reports `mDiscoveryWindowInterval=[-1,-1,-1]`; it therefore does not request a
matching Android cadence today. Recheck that output and repeat the bitmap probe
whenever `nan.dw_tu` or `nan.dw_stride` changes.

Ordinary channel-6 AP beacons can supply timing in `auto`, but
`DIRECT-DMESH-*` signals that the AP also accepts DMesh action frames. Identity
is not a security boundary; authentication/encryption is a higher-layer task.

## Control and Verification

Use lmesh logical forwards, never a raw physical TTY, for normal testing:

```bash
source env.sh
export LMESH_CONTROL_SOCKET=/run/mesh/lmesh/mesh.sock
export PYTHONPATH="${SSH_MESH_PYTHON:?set SSH_MESH_PYTHON to the ssh-mesh Python directory}"

# Persist the powered fallback role on lora1, then reinitialize infra radios.
# `reset` is not a firmware CBOR command; do not use DTR as a substitute.
mesh lmesh esp.serial.command port=lora1 command='nvs op=set nan.ap_owner=true nan.sync_source=auto'
mesh lmesh esp.serial.command port=lora1 command='mode infra=true'

# Lab observer: retain the AP (512 TU) and raw NAN management/action receiver
# even when NAN beacons are present. This is a powered-gateway test role, not
# the normal `auto` fallback policy.
mesh lmesh esp.serial.command port=lora1 \
  command='nvs op=set nan.ap_owner=true nan.sync_source=ap_only nan.ap_beacon_tu=512'
mesh lmesh esp.serial.command port=lora1 command='mode infra=true'

# Deterministic AP fallback validation. The runner restores normal auto policy.
python fw/esp32/rust/tools/presubmit.py \
  --topology fw/esp32/rust/tools/lab.example.json --profile full --case ap_sync \
  --timeout 12
```

The AP-sync scenario makes the powered owner use `ap_only`, makes battery
participants use `ap_only`, verifies owner AP activation and each participant's
AP timing counters, then restores all participants to `auto`; it leaves the
owner configured as `nan.ap_owner=true`, `nan.sync_source=auto`.

The standard lab topology also declares `power1` as a raw serial forward. The
runner records its 10 Hz samples in `power/power1.jsonl` and summarizes each
test phase in `power/summary.json`. A missing optional meter does not fail
transport tests; set `power_meters.<name>.required=true` when power capture is
part of the gate.

## Historical Results and Rejected Paths

- AP/STA normal data delivery needs association state. Synthetic AP station
  entries can make a test frame reach an AP netdev, but it is not the
  unassociated long-range mesh transport.
- Broadcast, multicast, and unicast data frames received through promiscuous
  mode overload the ESP with ambient traffic. Normal operation therefore uses
  filtered management/action frames.
- An ESP AP beacon works as a common timing source because its TSF is exposed
  to the raw beacon callback; 500 TU is close enough to the 512-TU NAN base.
  A normal channel-6 AP can also be sampled, but an allow-list may be added
  later if ambient AP density makes that unsafe.
- A powered AP does not sleep. It is an explicit infrastructure role; battery
  devices remain duty-cycled and only use it for synchronization.
