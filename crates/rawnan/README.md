# dmesh-rawnan

Raw NAN is a common implementation of a subset of Wifi Aware/NAN
for Linux and ESP32 (and others if they have the monitor/transmit action frame
capability).

It also include a subset/extensions for ESP-NOW and a subset of P2P/Wifi Direct.

The purpose is to have a minimal set of primitives over 'action frames' and beacons
that allow time synchronization and service discovery for devices that are not
connected to each other, and allow them to negotiate a connection.

## NAN - Wifi Aware

NAN is ONLY used to sync on the beacon and maintain a discovery window in sleepy
devices. This is an old technique - real NAN in Android/iPhone sends beacons

Linux host will send discovery in the DW for ESP32 devices in light sleep,
and activate them for a communication session. They go back to a 4 sec light sleep
duty cycle after the session is completed.

## P2P - Wifi Direct

P2P and NAN service disccovery are only implemented to interoperate with Android,
allowing the negotiation of a P2P group or AP/STA pairing.

The passive host/ESP P2P responder exposes DNS-SD instance `dmesh`, service
type `_dmesh._tcp`, and the small TXT marker `dmesh=<radio-id>` where the
radio ID is its local MAC encoded as lower-case hex. It deliberately does not
advertise a host/ESP transport command or credentials. Once Android is the
negotiated Group Owner, Android's platform DNS-SD service advertises the
actionable STA SSID/passphrase as the common `cbor=<unpadded-url-safe-base64>`
record.
Raw CBOR is unsuitable there because Android's public API exposes TXT values
as Java strings; base64url can be considered later as a coordinated change.

Current passive-P2P radio policy is deliberately AP-bound: a DMesh AP beacon
and its probe responses advertise the full P2P Device Info/Listen Channel IE,
and a received DMesh probe or GAS request is answered in worker context. An
AP-off NAN+NOW radio does **not** yet advertise or answer P2P probes. Extending
that response path to the persistent unassociated radio epoch is a separate
radio-lifecycle change, since it needs an on-channel management TX policy
without silently starting an AP.

Linux and ESP32 do not participate in cluster master election or data path - they
lack the ability, and AP/STA (and P2P group) are providing the same capability when
needed.

If Androids are not involved - ESP-NOW in disconnected state and a similar sync
on a regular AP beacon ( with 500 ms beacon interval instead of 512 for NAN).

The concept is the same: light sleep as much as possible when idle, to reduce
power use. Activate when needed - with Android interop.

This crate contains portable, allocation-friendly NAN wire parsing, service/follow-up
framing, and cluster-state logic shared by ESP32 Main and host services.
It has no ESP-IDF, sockets, FreeRTOS, or Linux interface-control code. It is
kept dependency-light for firmware, but is not currently advertised as a
strict `no_std` crate: `anyhow`, `Vec`, and atomics are deliberate shared-core
dependencies.

The shared core is intentionally below WPA and IP policy - close to L2.

It supports the NAN-derived open medium used by DMesh: discovery beacons, cluster BSSID
selection, A3 filtering decisions, service descriptors, follow-ups, and wake
flags. CBOR belongs to the firmware/host command transport, not this wire
crate. QUIC remains responsible for acknowledgements, loss recovery, ordering,
privacy, and duplicate suppression.

Raw NAN does not add software retransmission or duplicate caches - the
SD is indempotent and may be repeated over multiple DW.

Firmware owns radio lifecycle, queues, timing, interrupts, permissive mode and
ESP-IDF callbacks.  `lmesh-wifi` owns the Linux monitor/injection adapter and feeds
bounded RX metadata into the same `NanState`. Both adapters must
retain exclusive ownership of their interface while active and release filters
and queues on stop.

The current scope is raw NAN and associated discovery and related protocols.

Open AP/STA, LLC/SNAP IPv6/UDP, Neighbor Discovery, and physical-card capability
probing remain adapter work in `lmesh-wifi`; they do not belong in this wire
core. The core is covered by host tests and is the source of truth for frame
markers and cluster transitions.

NAN Availability and Device Capability attribute encoding is shared here;
ESP32 and Linux adapters should provide only timing/channel policy and radio
TX/RX ownership.

The end to end tests and probe run against pairs of Android, Linux and ESP32
devices and start with NAN discovery - to wake up sleepy ESP32 devices and
validate Android-Linux-ESP32 SD interop. The discovery is used to trigger the
active state and Wifi modes that are used for the rest of the probes.

## Additional rawnan notes

# dmesh-rawnan API

`dmesh-rawnan` owns the shared DMesh low-power radio protocol and raw-NAN
frame state machine. It contains no Linux interface or control-daemon
control; those responsibilities belong to `lmesh-wifi`. The core intentionally
uses only its small shared dependency set (`anyhow`, allocation, and atomics);
it does not contain CBOR or JSON wire framing.

## Shared protocol

Host JSON/debug conversion and legacy BLE service-data compatibility live in
`lmesh_wifi::radio_protocol`; they are intentionally outside this crate. This
crate exposes only byte-level NAN/ESP-NOW framing, validation, state, and
metrics, so no `serde_json` or BLE dependency is linked by ESP32.

## Raw frame state

`NanState` tracks discovery versus selected-cluster mode and returns actions
for accepted, foreign, stale, or re-discovery frames. `Action`, `FilterMode`,
`RxFrame`, and `MacAddr` are transport-neutral and can be used by Linux,
firmware, or Android adapters.

Timing helpers `beacon_seen_since`, `beacon_slot`, and `beacon_dwell_open`
contain the shared event/eligibility policy. They intentionally do not sleep:
the host and firmware adapters supply their own event primitive and clock
sample, then use these predicates before scheduling a frame.

Soft-NAN synchronization is shared as well. Adapters report a
`SoftNanSyncBeacon` for the selected NAN cluster and, when NAN is absent, the
nearest AP anchor (`DirectAp` or `InfrastructureAp`).
`select_soft_nan_sync` chooses a fresh NAN beacon first and falls back to a
fresh AP beacon. The resulting timing source is then passed to the adapter's
sleep/wake mechanism; the selection policy itself is not ESP32-specific.

## Ownership boundary

`lmesh-wifi` uses this crate to provide NAN together with open AP and STA
operations on an owned Linux interface. Its separate
`lmesh_wifi::radio_protocol` host module owns JSON/BLE compatibility and is
re-exported by `lmesh` for existing JNI callers.
