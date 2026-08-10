# Module services

Modules are replaceable `no_std` service images. Main supplies a small host
ABI and creates a FreeRTOS task for each service. The device never discovers
modules by scanning flash and does not use a module name in the DMOD header or
runtime dispatch - the gateway does the translations and maintains the numeric
IDs as CBOR tags (similar to protobuf services).

This will likely change when more modules are implemented, if the idea works,
with a more flexible system - but no point to do it too early.

## Identity and placement

The service namespace is numeric CBOR tags 43 through 100. A service's first
64-KiB slot is:

```text
slot = service_tag - 43
flash_offset = slot * 0x10000
```

`slot_count` in the DMOD v4 header permits adjacent slots for larger images.
The loader rejects mismatched tags, offsets, spans, sizes, VMAs, or ABI
versions before mapping code. Human names and operation names live only in
`services.toml` and the lmesh schema.

Current allocation:

| Tag | Controller name | Slot | Span |
|---:|---|---:|---:|
| 43 | lora | 0 | 2 |
| 45 | hw | 2 | 1 |
| 46 | hello | 3 | 1 |

Tag 44 is intentionally left available; future allocations must avoid an
existing service's adjacent span.

## Runtime model

Radio and hardware services have independent runtime occupancy. They may run
concurrently if the CPU has more cores. The host serializes shared peripheral transactions and owns GPIO/IRQ registration. 

The current Main-owned memory map is deliberately small and explicit:

| Region | Lifetime | Size/ownership |
|---|---|---|
| DMOD image | mapped while the service runs | flash-backed, 64-KiB slot alignment |
| module task stack | until the service task exits | requested by the header, clamped by Main (64 KiB for `mod_lora`) |
| transient arena | one invocation/task lifetime | 32 KiB Main-RAM bump arena, exposed as `alloc(size, align)` |
| command copy | one queued invocation | Main heap, bounded by the loader's argument limit |

The transient arena has no `free` operation and is reset when the invocation
returns. Modules must not retain arena pointers across a stop/reload. This
gives allocation a bounded execution time without allowing a module to take
ownership of Main's heap.

Upgrades requests all active services to stop and waits with a finite timeout
before erasing their slots.

Service callbacks use numeric tags and bounded CBOR payloads. Calls must be
non-blocking from an interrupt path; the initial Main bridge queues a bounded
number of calls for dispatch on the Main loop. A later synchronous call path
must enforce a 250-ms caller timeout and report calls over 50 ms as slow; it
must never forcibly delete a task that ignored its timeout.

## Build and deployment

Use the module build scripts. They generate fixed-VMA Xtensa images with the
service tag and slot span in the header, and PIC RISC-V images when supported:

```sh
bash fw/mod_lora/build.sh xtensa-esp32-espidf
bash fw/mod_hw/build.sh xtensa-esp32-espidf
bash fw/mod_hello/build.sh xtensa-esp32-espidf
```

The flash server may continue accepting human module names as a controller
compatibility interface; it maps them to the numeric allocation before
choosing the partition offset. Recovery itself remains module-agnostic.
