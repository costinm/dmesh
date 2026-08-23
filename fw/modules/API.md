# Module tagged-CBOR API

`fw/modules` supplies optional flash-module handlers for any application that
links the ESP module loader. The handler transport is a normal QUIC-lite
stream or a direct bearer record; the stream payload begins with one complete
tagged-CBOR envelope. There is no stream service byte.

The common envelope fields are defined by `dmesh-server::tagged`:

```text
{ 1: component, 2: method, 3: request_id?, 10: binary_payload? }
```

Responses preserve `component`, `method`, and `request_id`, and put the result
in field `6` as `{1: ok, 2: loader_result_abs}`.

## Components

| Component | Handler | Method | Meaning |
|---:|---|---:|---|
| 1000 | module | 1 | Refresh and return loader header/status. |
| 1000 | module | 2 | Initialize the native module loader. |
| 1000 | module | 3 | Request a bounded loader stop before flash work. |
| 1001 | hello | 4 | Start module service tag 46. |
| 1002 | lora | 4 | Start module service tag 43. |
| 1003 | hardware | 4 | Start module service tag 45. |

For `RUN` (method 4), field `10` is passed unchanged as the bounded module
payload. The loader derives flash placement from its service tag and validates
the DMOD header; callers never supply a flash offset.

## Ownership and limits

`dmesh-server` owns a fixed 16-entry, no-allocation component registry. Each
component has a separate function registration, and a component may serve any
number of concurrent QUIC streams. The bearer only owns stream ordering and
flow control; it does not interpret a module ID.

This first extraction includes the loader control/start path. Module-originated
settings reads/writes, emitted events, and nested service calls currently fail
with loader ABI result `-2`; they are intentionally not routed through the
deleted Main string-command dispatcher. They will be connected to the common
`dmesh-server` settings/event/direct-record handlers in the next migration.

## Frozen Recovery build option

Recovery is currently frozen and its build entry point is deliberately
disabled. Do not use the historical commands below; Main is the active
firmware lane. They are retained only as migration notes:

The last C6 measurement (2026-08-21) produced 911,360 bytes without modules
and 949,136 bytes with modules: +37,776 bytes. The one-MiB recovery partition
therefore retains 99,440 bytes of headroom with module support.
