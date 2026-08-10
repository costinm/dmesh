# ESP32 modules

The main app ('mesh sidecar' in this project) is written in Rust using the ESP APIs.

It was getting large, complicated, hard to test and some of the functionality seems
pretty useful outside of ESP32. Flashing was also pretty slow and frequent.

With a bit of LLM help and few days of iterations, it appears quite reliable to
deploy 'micro services' (a great match for a mesh), with a serverless-like model,
and keep the sidecar focused on providing core services and anything that actually
require real-time or ESP specific code.

## Module API

Modules expose a CBOR service interface - as commands that can be tested and run
over the network or internally.

The sidecar also exposes a CBOR service interface, so all components can be treated
as services and used (or tested) from a host.

A function table and C structures are also available for faster calls.

## Module runtime environment

For ESP32 with Xtensa - Rust doesn't support PIC, so each module must have a specific
'slot ID', based on their CBOR tag number, and based on that it gets a specific 64k slot in flash and fixed base address in XIP. Large modules can take multiple slots. With RiscV - PIC works so location is flexible, but for now keeping the same model.


