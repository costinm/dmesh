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
