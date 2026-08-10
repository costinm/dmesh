# mod_lora

The module-owned ABI is documented in [API.md](API.md); this file provides
implementation and hardware notes.

Service tag `43`, starting at slot `0`, spanning two adjacent 64-KiB slots.
The DMOD v4 header contains numeric identity and placement metadata; `lora`
is a controller/schema name, not a device-side module identifier.

Static-VMA or host-window-mapped, `no_std` LoRa module. Xtensa Rust does not
currently provide a safe generic PIC image; the fixed-VMA loader mode maps the
image into Main's reserved instruction window. The SX127x/SX126x radio drivers,
LoRa packet policy, and the chip's FSK mode are module-owned. Main supplies
only the ESP-IDF SPI/GPIO/IRQ host table and service bridge. The shared
configuration includes the SPI host and SCK/MISO/MOSI/CS/reset/IRQ pins; these
come from Main's persisted `lora.*` settings rather than being baked into the
module image.
The module also receives the persisted LoRa coding rate, preamble, and CRC
settings. Meshtastic framing policy and its codec now live in
`src/frames.rs` beside the radio implementation. The established defaults
remain US MediumFast `913125000` Hz, 250 kHz bandwidth, SF10/CR5 profile
selection, sync word `0x2b`, and test channel hash `0x1d` with port number
`256`; Main passes radio payloads opaquely and does not parse this format.
For SX1262, Main also supplies reset/BUSY pins; the host SPI primitive waits
for BUSY to clear with a bounded timeout before each command. Board power
(`lora.pwrpin`/`lora.pwrlvl`) and SX1262 TCXO, DIO2 RF-switch, PA, and sync-word
settings are part of the module configuration, so the deployed module owns
the complete radio setup rather than relying on a hidden Main LoRa driver.
The common module context also provides validated settings get/set callbacks
and a typed event callback (`event_id`, value type, bytes). Main can encode
those records as CBOR for lmesh without linking a CBOR library into the
module.

The Main-side wire representation is a four-item CBOR array
`[event_id, value_type, flags, value]`; integer values are encoded as CBOR
integers, text as a CBOR string, and byte values as a CBOR byte string. This
keeps the module ABI independent of the eventual wire encoding while still
allowing lmesh to render structured events directly.

The current event IDs are `1=rx_started`, `2=rx_stopped`, `3=tx_done` (bytes),
`4=reconfigured`, `5=stats` (two little-endian `u32` counters: RX then TX),
and `6=tx_error` (a little-endian `i32` result).  Queued TX is asynchronous,
so the error event preserves the radio result even though the command itself
has already been acknowledged as queued.

The first hardware target is `lora3` (SX127x), followed by `lora4` (SX1262).
The `probe` command selects the correct chip probe from the persisted chip
setting; the explicit `probe127`/`probe126` forms remain available for
diagnostics.

When the module image is named `lora`, Main passes its persisted radio
configuration and starts the module task. On SX127x and SX1262 the task
configures continuous LoRa RX, waits on the host GPIO/DIO interrupt
notification, samples the FIFO/IRQ registers, emits packets through the host
event callback, and accepts queued `stop` and `tx` commands. The host also
arms the DIO GPIO as an automatic light-sleep wake source while the receiver
is active.
The module also carries the chip-specific FSK packet path. `radio` selects
the common 100 kbit/s FSK/GFSK profile; its frequency, FIFO packet length,
carrier parameters, and TX/RX interrupts are configured in the module. A
selected module is authoritative; Main does not fall back to its old radio
backend.

Module discovery and `module op=status` are deliberately side-effect-free:
Main only reads the module header and cached loader counters. SPI/GPIO setup is
deferred until a concrete LoRa operation (`rx`, `tx`, `probe`, or `fsk`) is
requested, so a stale or incompatible image cannot hang a status query or
change radio ownership during boot.

The module service callback delivers received packets as `module op=lora_rx`
with the packet bytes in the payload and bounded `rssi`/`snr` arguments. Main
then reuses its existing mesh, NAN, Wi-Fi, BLE, and telemetry forwarding path.

`stop` ends the module task and powers down a configured board rail, so deep
sleep does not retain a polling task or leave the SX1262 rail on. The next
wake/infra transition starts a new `rx` task; a queued `tx` after a stop uses
the module's short-lived standalone TX entry path.
For SX1262, a queued TX from an active RX task temporarily disables DIO1,
resets and reconfigures the radio, performs TX, and exits that task; Main then
starts the next RX task. This keeps the asynchronous TX path equivalent to
the known-good standalone TX path.

Module status exposes current/last/maximum task runtime and invocation count.
The module header declares its FreeRTOS stack requirement (`16384` words for
this RX implementation). Main clamps that request to the loader's supported
range and reports the observed minimum remaining stack words in module status.
The module ABI is intentionally not based on Tokio or another executor. The
flat image has no linked heap allocator and runs as a host-created FreeRTOS
task. Main exposes an optional `alloc(size, align)` callback backed by a
32-KiB bump arena in Main RAM. Allocation is monotonic and there is no
`free`; the arena is reset before and after a module invocation. A module may
use the returned memory only for the lifetime of that invocation (a persistent
radio task holds it until that task stops). Host callbacks are bounded; only
the radio task's finite IRQ wait may sleep.

Build the Xtensa image with `bash fw/mod_lora/build.sh
xtensa-esp32s3-espidf`. Xtensa flat images default to the reserved fixed
window (`0x43000040` on ESP32-S3, `0x40300040` on classic ESP32); the script
sets the fixed DMOD flag automatically. `DMESH_MODULE_VMA` is accepted only
when it names that exact canonical window; a different slot requires a
coordinated Main loader change and is rejected for now. Do not deploy an
Xtensa image without the fixed flag: it is statically linked and cannot use
dynamic mapping.

For upcoming RISC-V boards, build the same module with the Espressif RISC-V
target:

```sh
bash fw/mod_lora/build.sh riscv32imac-esp-espidf
```

This lane uses Rust's PIC relocation model and the dynamic flash mapping path;
the build refuses relocations, exported symbols, and writable sections before
writing the DMOD artifact.

For a clean module-store experiment, Main's existing recovery command can
erase the complete raw data range with `recovery op=erase target=data`.
The loader does not scan the module region. An explicit numeric service request
selects slot `service_tag - 43`; the image header's slot span is validated
before mapping. Explicit byte offsets remain a host/debug compatibility form,
but must equal the service's fixed slot base.

There is no compiled Main-radio fallback when a `lora` module is selected;
module failure is reported through module status/logs and is repaired by a
module deployment. Deploy through the verified local flasher:
`scripts/flash-device.py lora4 module --module lora`.
The helper chooses the CPU-specific DMOD and fixed service slot; do not copy
the classic image to an S3 board.

For a managed-device smoke test (no physical UART, flash, or reset), run
`python3 fw/esp32/rust/tools/mod_lora_test.py --port lora3.lmesh`; use
`lora4.lmesh` for the SX1262 board.

FSK validation uses a common channel and short fixed payloads; rendezvous/
hopping is intentionally not part of this initial experiment. SX127x packet
exchange, GPIO interrupt notification, light-sleep wake compatibility, and
clean stop have been exercised on lora1/lora3. Variable-length framing and
CRC remain a follow-up after this fixed-frame carrier test.
