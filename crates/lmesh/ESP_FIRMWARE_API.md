# ESP32 Rust Firmware API

This is the canonical low-level firmware ABI reference. `crates/lmesh/API.md`
is the product API; lmesh adapts these commands over serial, BLE, and raw Wi-Fi.

> This file retains low-level diagnostic commands and dated hardware findings.
> The supported production control path is the compact-CBOR ABI, raw-NAN duty
> cycle, and lmesh high-level methods. Treat explicit `official`, `raw_ap`,
> `raw_sta`, plaintext `resp`/`notify`, and deep-sleep-loop examples below as
> retained experiment history unless the current firmware command registry and
> handoff explicitly say otherwise.

> ESP firmware is raw-NAN only. ESP-IDF official NAN was removed from supported
> firmware modes and tests because it cannot meet the sleep budget. Any later
> mentions of official NAN in historical measurement notes are not supported API.

Runtime UART diagnostics use the managed lmesh service (`esp.serial.command`)
and never open a raw tty or toggle modem-control lines. UART recovery is
reserved for `esptool` while flashing the bootloader, second-stage, or recovery
image; older DTR wake notes below are historical only.

## Compact CBOR command IDs

The outer CBOR envelope uses the IDs documented in `API.md`; command arguments
are the nested `payload` map. Firmware command IDs are scoped to the firmware
adapter and use two-byte CBOR integers, leaving `16..23` free for compact
service-local fields. Until a command is assigned below, it is sent as its text
name for forward compatibility.

| ID | Command |
| ---: | --- |
| 32 | Reserved; firmware help moved to the client-local tools catalog. |
| 33 | `status` |
| 34 | `xstatus` |
| 35 | `stats` |
| 36 | `logs` |
| 37 | `messages` |
| 38 | `local_messages` |
| 39 | `test` |
| 40 | `wifi` |
| 41 | `nan` |
| 42 | `ble` |
| 43 | `lora` |
| 44 | `lorasend` |
| 45 | `loralisten` |
| 46 | `loradump` |
| 47 | `loraprobe` |
| 48 | `sleep` |
| 49 | `mode` |
| 50 | `power` |
| 51 | `battery` |
| 52 | `adcprobe` |
| 53 | `namespace` |
| 54 | `set` |
| 55 | `get` |
| 56 | `list` |
| 57 | `rgbled` |
| 58 | `gpio` |
| 59 | `i2cconfig` |
| 60 | `i2cprobe` |
| 61 | `i2cdetect` |
| 62 | `i2cget` |
| 63 | `i2cset` |
| 64 | `i2cdump` |
| 65 | `button` |
| 66 | `nvs` |
| 67 | `radio` |

The ESP32 Rust firmware is binary-only. lmesh/mesh-cli may accept a convenient
text or JSON command at their local API boundary, but translate it to compact
CBOR before it reaches UART. BLE GATT, raw/custom NAN, LoRa, and UART all
dispatch the same CBOR bytes into the command registry.

The firmware does not serve MCP JSONL or command help. The client-local
`resources/firmware-tools.json` describes direct ESP modem commands, while
`resources/tools.json` describes the product-facing lmesh API. `mesh FQDN
help` reads the former without waking or contacting the device.

`lmesh` is the product-facing API boundary. Its high-level methods such as
`send`, `ping`, `radios.list`, `links.list`, and `messages.history` should be
able to use Linux radios, Android JNI radios, local ESP serial/BLE adapters, or
SSH-forwarded remote lmesh adapters. ESP-specific methods are diagnostics and
direct firmware controls unless there is no high-level method yet.

## Wire Shape

The lmesh UDS endpoint uses the common mesh stream envelope:

```text
u32-be body_length | 00 cb 00 00 | compact-CBOR payload
```

The physical UART link is separate and UART-only:

```text
0x7e | escaped compact-CBOR payload | 0x7e
```

Escape `0x7e` and `0x7d` as `0x7d, byte ^ 0x20`; decoded payloads are limited
to 4,000 bytes. UART carries no mesh metadata, length, FCS, raw boot marker,
or text output. lmesh converts between the UDS envelope and this physical
codec. A diagnostic is a CBOR notification with `status="event"` and its text
stored as payload data; applications should treat it as structured event data,
not console output.

Parsing guidance:

- parse command prefix, optional positional debug tokens, and `key=value`
  fields;
- tolerate extra fields;
- use `hex:...` for binary inputs;
- use bounded `max_bytes` on `logs`, `messages`, and `local_messages`;
- prefer counters/log events over exact full-line matching.

Structured CBOR/JSON callers should avoid positional debug tokens. Use explicit
fields instead, for example `method=nvs payload={op:set, uart.active_ms:2000}`
or `method=nvs payload={op:get, key:uart.active_ms}`.

## Host Workflow

Use repo-local dependencies only:

```bash
cd "$(git rev-parse --show-toplevel)"
scripts/esp32-deps.sh
. env.sh
cd fw/esp32/rust
```

`env.sh` is responsible for all ESP firmware paths: repo-local Nix
profile binaries, ESP-IDF tools, ESP Python environment, Cargo home, rustup
home, and the Xtensa Rust toolchain. Do not hand-edit `PATH`, `IDF_PATH`,
`CARGO_HOME`, or `RUSTUP_HOME` in test scripts; source `env.sh` instead.

Normal host/CI testing should access firmware through `crates/lmesh` USB
forwarding. Deployed updates use Main/Recovery Wi-Fi DRS2 while the managed
forward remains active for evidence. Physical USB-UART is only initial
provisioning or P0 stage-2/Recovery repair; it is not an RFC2217 transport.

Local recovery flash for classic ESP32:

```bash
cargo espflash flash --release --port /dev/ttyUSBX \
  --chip esp32 --flash-size 4mb --non-interactive
```

Flash an 8 MB ESP32-S3 board such as `lora4`:

```bash
ESP_IDF_SDKCONFIG_DEFAULTS=sdkconfig.heltec_v3.defaults \
  cargo espflash flash --release --target xtensa-esp32s3-espidf \
  --port /dev/serial/by-id/<s3-bridge> --chip esp32s3 --flash-size 8mb --non-interactive
```

The ESP32-S3 partition profile keeps the first 4 MB layout compatible with the
classic ESP32 image and adds `dmesh_store` at `0x400000`. Larger S3 flash parts
may reserve remaining capacity for future logs, message payloads, and radio-store
experiments; do not assume every lab S3 has 16 MB.

Fleet flash helper:

```bash
LMESH_CONTROL_SOCKET=/run/mesh/lmesh/mesh.sock \
  python tools/flash_test_fleet.py --lmesh-mode=local-release \
    --port lora1 --port lora2 --port lora3 --port lora4 --port e5
```

The helper resolves logical lmesh roles, keeps their UDS forwards active,
sparse-flashes and verifies through the stable physical USB-UART paths, and
retains forward evidence. Use logical role names or `DMESH_FLASH_PORTS` when
device selection matters. This is initial provisioning/P0 repair only; normal
Main and Recovery updates use Wi-Fi DRS2 because deployed boards may not have
USB.

Flashing must preserve NVS. Do not write the padded merged image at `0x0`: the
merged image contains `0xff` bytes across NVS (`0x9000..0xefff`) and erases
saved settings. The fleet helper sparse-flashes bootloader, partition-table,
and app chunks while skipping NVS/PHY. It uses the esptool RAM stub for writes;
ROM `--no-stub` is only for an initial chip probe.

The helper configures every flashed ESP for the current default: infra mode,
DFS, raw-NAN duty cycle, Wi-Fi off between active windows, and LoRa receive on
expected TLORA boards. By default `USB0`, `USB1`, and `USB2` are expected
TLORA/SX127x boards; configure overrides with
`DMESH_EXPECTED_LORA_PORTS=USB0,USB1` or repeated `--expected-lora-port`.
Expected LoRa ports are probed/saved with the TLORA V2.1-1.6 SX127x pin map
(`spi_host=2 sck=5 miso=19 mosi=27 cs=18 rst=23 dio0=26`) and the feature test
fails if any expected LoRa port is missing. Test-specific modes, such as
`wifi.mode=nan_sleep` or `sleep test=...`, belong in serial commands or
dedicated test scripts. See `docs/lmesh-firmware-handoff.md` for the current
lmesh-first workflow.

Run direct firmware commands through the lmesh control service:

```bash
mesh lmesh esp.serial.command port=USB0 command=status
```

NAN/LoRa command payloads should include explicit mesh addressing:
`to=<last4>` and `from=<last4>`, where each value is the last four bytes of the
device Wi-Fi STA MAC as lowercase hex without separators. The same value is the
planned LoRa short address. Current firmware still accepts payloads without
`to=` for manual debugging. If `to=` is present and does not match the local
suffix, the command is dropped, except broadcast discovery targets
`to=ffffffff`, `to=0xffffffff`, `to=broadcast`, or `to=all`, which every awake
device accepts.

Run multiple checks through lmesh:

```bash
mesh lmesh esp.serial.command port=USB0 command='lora status=true'
mesh lmesh esp.serial.command port=USB0 command='nan stats=true'
mesh lmesh esp.serial.command port=USB0 command=stats
```

## Core Commands

| Command | Purpose |
| --- | --- |
| `status` | Compact golden health line intended to fit in one small packet: uptime, CPU/PM, heap, idle/top task, packet counters, queue depth, and battery. |
| `xstatus` | Extended debug status: compact status plus wake/UART loop counters, sleep summary, runtime stats, and radio summaries. `reset=true` clears counters. |
| `stats` | Legacy/full packet, loop, wake, runtime, and battery counters. `reset=true` clears counters. |
| `test` | Non-blocking radio test state. `test cnt=NN` sends two discovery pings followed by `NN` broadcast status pings over raw/custom NAN as active windows permit. |
| `logs` | Recent structured event lines. Supports `count`, `depth`, `max_bytes`, `clear=true`. |
| `messages` | Recent packet buffer. Supports `transport`, `direction`, bounded output, pull/ACK fields. |
| `local_messages` | Local-address packet buffer. |
| `button` | `gpio=N` and `enabled=true|false` configure the physical PRG debug button. `pin=N slots=N [min_us=N|min_ms=N]` starts a separate any-edge GPIO interval capture; it never reconfigures the debug button and rejects its GPIO. `button get` (or `get=true`) returns chronological `low:DELTA_US,high:DELTA_US` samples and resets the ring. `button stop` disables the capture. `slots` is 1-128; `min_us` drops shorter edge intervals and reports the drop count. |
| `nvs` | Settings namespace and key/value operations: `op=ns|get|set|list`, direct `KEY=VALUE` updates, and `stats=true`. Debug text also accepts `nvs ns`, `nvs get KEY`, `nvs set KEY=VALUE...`, and `nvs list`. |
| `namespace`, `set`, `get`, `list` | Debug compatibility aliases for the grouped `nvs` command. |

## Settings

Settings live in the firmware `dmesh` namespace. `nvs list` returns only values
that are actually set, not every known key with empty defaults. `nvs list
stats=true` returns ESP-IDF NVS partition usage. Debug text examples:

```text
nvs ns
nvs get uart.active_ms
nvs set uart.active_ms=2000 nan.wake_ms=4000 lora.enabled=true
nvs list
```

Structured callers should use the grouped command and explicit fields:

```json
{"method":"nvs","payload":{"op":"set","uart.active_ms":"2000","nan.wake_ms":"4000"}}
{"method":"nvs","payload":{"op":"get","key":"uart.active_ms"}}
```

ESP-IDF NVS keys are limited to 15 bytes. Several historical firmware setting
names are longer; those names are recognized by the current settings registry
but need compact persisted aliases or numeric CBOR tags before they can be
reliably stored in NVS on all targets.

| Setting | Help |
| --- | --- |
| `mode` | Persisted operating mode: `infra` is powered/always-on; `companion` is the battery/duty-cycled role. |
| `power.profile` | Boot PM profile: `dfs`, `perf`, `low`, or `auto`. |
| `uart.active_ms` | UART debug input/output window after boot, PRG/button, or UART input. Minimum/default: 2000 ms. |
| `uart.hb_every` | UART heartbeat cadence for non-infrastructure raw-NAN duty wakes. `0` (default) disables periodic and LoRa/FSK-triggered UART output. `N>0` opens UART only for `nan.active_ms` and emits one empty `0x7e 0x7e` frame on every Nth raw-NAN wake; LoRa/FSK receive uses a 250 ms event window. Infrastructure mode keeps UART continuously active and does not use this cadence. |
| `wifi.mode` | Boot Wi-Fi policy; battery nodes use raw/custom NAN duty cycle, while `mode=infra` remains continuously powered. |
| `wifi.ssid` | Saved Wi-Fi SSID for explicit STA/AP experiments. |
| `nan.enabled` | Enable raw/custom NAN at boot; `mode=infra` keeps it continuously active, while battery nodes use the duty cycle. |
| `nan.backend` | `raw` for custom low-power NAN-like action frames, `official` for Espressif NAN tests. |
| `nan.role` | NAN role: publisher, publisher_solicited, subscriber, or both. |
| `nan.service` | NAN service name, normally `dmesh`. |
| `nan.channel` | NAN/raw-NAN channel, default 6. |
| `nan.wake_ms` | Raw-NAN duty period. Default: `4000` ms. |
| `nan.active_ms` | Raw-NAN active Wi-Fi/SDF dwell. Default: `64` ms; the adaptive pre-wake margin is scheduled separately. |
| Runtime `mode active` | Non-persistent powered/transfer override. `mode active=true` keeps raw-NAN Wi-Fi, NAN beacon/action receive, and configured LoRa RX active until `mode active=false`. `mode active_ms=N` keeps the same radios active for `1000..300000` ms, then resumes the configured duty cycle. UART/PRG input opens its configured console window and temporarily holds the same radio path active; it does not persist across reset. |
| `nan.light_sleep` | Use explicit light sleep while raw-NAN Wi-Fi is off between windows. Default: `true`; set `false` for timing/debug comparison. |
| `nan.early_ms` | Return from light sleep this many milliseconds before the expected window. Default: `5` ms. |
| `nan.dw_tu` | Raw-NAN Discovery Window period in TUs, used with the received beacon TSF to schedule the next radio wake. Default: `512` (524.288 ms). |
| `nan.dw_off_tu` | Raw-NAN Discovery Window phase offset in TUs. Default: `0`. |
| `nan.sync_source` | Timing-source policy: `auto` (default), `nan_only`, or `ap_only`. `ap_only` ignores NAN and is the deterministic AP-sync test mode. |
| `nan.ap_owner` | Powered timing-AP owner. When true, Wi-Fi stays on; after NAN is absent for `nan.ap_loss_ms`, firmware starts `DIRECT-DMESH-<last4MAChex>` and raw action receive. |
| `nan.ap_loss_ms` | NAN-loss interval before a powered AP owner starts its fallback AP. Default: `5000` ms. |
| `nan.ap_recovery_ms` / `nan.ap_recovery_listen_ms` | Battery-node AP/NAN recovery cadence and bounded management-beacon listen duration. Defaults: `32000` / `1200` ms. |
| `nan.ap_slot_tu` / `nan.ap_beacon_tu` | AP-derived common wake slot and owner SoftAP beacon interval. Defaults: `4000` TU (4.096 s) and `500` TU (512 ms). |
| `lora.enabled` | Enable LoRa receive at infra boot when pins/radio are configured. |
| `lora.chip` | Radio chip: `sx127x` or `sx1262`. |
| `lora.mode` | LoRa preset mode: `meshtastic` or `meshcore`. |
| `lora.freq` | Frequency in Hz. |
| `lora.bw` | Bandwidth in Hz. |
| `lora.sf` | Spreading factor. |
| `lora.cr` | Coding rate denominator/firmware value. |
| `lora.crc` | Enable packet CRC. |
| `lora.preamble` | Preamble symbols. |
| `lora.sync_word` | LoRa sync word. |
| `lora.sx_sync` | SX126x sync-word override. |
| `lora.tx_power` | TX power in dBm. |
| `lora.hop_limit` | Default LoRa hop limit. |
| `lora.portnum` | Meshtastic port number for encoded sends. |
| `lora.beacon` | LoRa beacon/announce behavior. |

The firmware rationale, raw-frame constraints, AP fallback state machine, and
E2E verification are maintained in
[`fw/esp32/rust/docs/wifi.md`](../../fw/esp32/rust/docs/wifi.md). This API file
remains the canonical ABI for the setting names and CBOR tags.
| `lora.channel_hash` | Meshtastic channel hash override. |
| `lora.rx_timeout` | Receive timeout/window setting. |
| `lora.spi_host` | ESP SPI host index for the radio. |
| `lora.sck` | LoRa SPI SCK GPIO. |
| `lora.miso` | LoRa SPI MISO GPIO. |
| `lora.mosi` | LoRa SPI MOSI GPIO. |
| `lora.cs` | LoRa SPI CS/NSS GPIO. |
| `lora.rst` | LoRa reset GPIO. |
| `lora.dio0` | SX127x DIO0/IRQ GPIO. |
| `lora.busy` | SX126x BUSY GPIO. |
| `lora.pwrpin` | Optional LoRa power-control GPIO. |
| `lora.pwrlvl` | Output level for `lora.pwrpin`. |
| `lora.dio2rf` | SX126x DIO2 RF switch setting. |
| `lora.tcxo_mv` | SX126x TCXO voltage in mV. |
| `lora.pa_duty` | SX126x PA duty-cycle setting. |
| `lora.pa_hp` | SX126x PA high-power setting. |
| `lora.pa_dev` | SX126x PA device selection. |
| `lora.pa_lut` | SX126x PA lookup-table setting. |
| `fsk.network_id` | 16-bit GFSK hardware sync/network ID. |
| `fsk.hop_seed` | Seed combined with the network ID to select the rendezvous channel. |
| `fsk.bitrate` | GFSK bit rate in bits/sec; default 100000. |
| `fsk.deviation` | GFSK frequency deviation in Hz; default 25000. |
| `fsk.rx_bw` | Requested GFSK receive bandwidth in Hz; default 250000. |
| `fsk.preamble` | GFSK preamble bytes; default 16. |
| `fsk.slot_ms` | Discovery-slot duration; default 80 ms. |
| `battery.enabled` | Enable battery voltage reporting. |
| `battery.pin` | ADC GPIO for battery voltage. |
| `battery.divider` | Voltage divider ratio/multiplier. |
| `battery.mult` | Additional calibration multiplier. |
| `battery.ctrl` | Optional GPIO that enables the battery divider. |
| `battery.ctl_lvl` | GPIO level that enables `battery.ctrl`. |
| `battery.ref_mv` | ADC reference voltage in mV. |
| `battery.min_mv` | Empty-battery voltage threshold. |
| `battery.max_mv` | Full-battery voltage threshold. |
| `button.enabled` | Enable PRG/button handling. |
| `button.gpio` | PRG/button GPIO. |
| `i2c.port` | I2C controller index. |
| `i2c.sda` | I2C SDA GPIO. |
| `i2c.scl` | I2C SCL GPIO. |
| `i2c.freq` | I2C bus frequency in Hz. |
| `identity.node` | Local node identity string. |
| `identity.pubkey` | Local public key/identity hint. |
| `identity.raw` | Raw identity bytes or debug identity marker. |
| `identity.meshtastic` | Meshtastic identity/channel metadata. |
| `identity.meshcore` | MeshCore identity/channel metadata. |
| `log.depth` | Structured console/log ring depth. |
| `msg.depth` | Packet/message ring depth. |
| `local_msg.depth` | Local-address packet/message ring depth. |
| `ble.comp` | Companion-mode BLE flag. |
| `ble.comp.ble` | Enable BLE in companion policy. |
| `ble.comp.adv_period_ms` | Companion advertising period. |
| `ble.comp.adv_window_ms` | Companion advertising window. |
| `ble.comp.active_ms` | Companion active window. |
| `ble.comp.ble_scan` | Companion BLE scan/listen flag. |
| `bc.scan_ms` | Bounded ESP scan duration for Android `wake_request` advertisements (50-2000 ms). |
| `bc.adv_ms` | Bounded connectable GATT response advertisement after a matched wake (100-10000 ms). |

The live (non-persisted) equivalents are `ble rendezvous_scan_ms=<50..2000>`
and `rendezvous_adv_ms=<100..10000>`; include `save=true` to persist them as
`bc.scan_ms` and `bc.adv_ms`.
| `ble.comp.channel` | Companion Wi-Fi channel. |
| `ble.comp.nan` | Companion NAN flag. |
| `ble.comp.ps` | Companion Wi-Fi power-save setting. |
| `ble.comp.raw` | Companion raw-Wi-Fi flag. |
| `ble.comp.serial` | Companion serial debug flag. |
| `ble.comp.wifi` | Companion Wi-Fi flag. |
| `ble.fixed_pin` | BLE fixed pairing PIN. |
| `ble.peer` | Saved BLE peer address/identity. |
| `bc.wake_ms` | Boot/companion wake cadence setting. |
| `bc.active_ms` | Boot/companion active duration. |
| `bc.win_ms` | Boot/companion window duration. |
| `bc.phase_ms` | Boot/companion phase offset. |
| `cm.adv_ms` | Companion advertising interval. |
| `cm.win_ms` | Companion advertising/check window. |
| `cm.boot_ms` | Companion boot active window. |
| `cm.active_ms` | Companion active duration after wake/input. |
| `cm.pending_ms` | Pending-data companion window. |
| `cm.pending_adv_ms` | Pending-data advertising interval. |
| `cm.wake_ms` | Companion deep-sleep timer period. |
| `cm.lora` | Companion LoRa listen during sleep/wake policy. |

## LoRa

| Command | Params | Result |
| --- | --- | --- |
| `lora` | `status=true` | Chip, mode, pins, modulation, RX state, CAD settings, and LoRa task interrupt-wake counters (`irq_wakes`). |
| `lora` | `rx=true\|false` | Start/stop background receive. |
| `lora` | `mode=meshtastic\|meshcore` | Set boot preset mode (persisted in NVS). Background RX applies this preset at startup. |
| `lora` | `preset=medium_fast\|medium_slow\|meshcore`, `freq`, `bw`, `sf`, `cr`, `sync_word`, `preamble`, `apply=true` | Update modulation settings. |
| `lora` | `chip=sx127x\|sx1262`, `board=heltec_v3`, pin/PA/TCXO args | Update hardware mapping. |
| `lora` | `cad=true`, `cad_timeout=<ms>` | One channel-activity probe. |
| `lora` | `cad_rx=true\|false`, `cad_tx=true\|false`, `cad_interval_ms`, `cad_rx_ms`, `cad_tx_tries` | Update CAD policy. |
| `radio` | `status=true` | Report the host-activated GFSK discovery profile and its rendezvous channel. |
| `radio` | `op=send data=hex:... channel=0..49` | Send one bounded GFSK packet on a selected channel. |
| `radio` | `op=sweep target=<last4> sequence=<n>` | Send one 50-slot, 4-second US915 discovery sweep. `target` is the destination MAC's final four bytes in network order; omit for broadcast. |
| `radio` | `op=listen ms=<n> [channel=<n>]` | Dwell on the deterministic rendezvous channel and return the first GFSK packet received. |
| `lorasend` | `text=...` or `data=hex:...`, `format=meshtastic\|raw`, `hop=0..7`, `portnum`, `timeout` | Send one LoRa packet. |
| `loralisten` | `ms`, `count`, `local_only=true` | Synchronous receive window. |
| `loradump` | none | Radio register/status dump. |
| `loraprobe` | pin lists, `chip`, `save=true` | Probe LoRa wiring candidates. |

### FSK discovery profile

`radio` is deliberately a bounded modem session: it stops the background
Meshtastic LoRa receiver, configures the requested radio as GFSK, runs the
operation, sleeps the radio, then restores background LoRa receive. It does
not alter the boot mode or the low-power LoRa CAD policy.

The initial profile is `us915_fhss_100k`: 100 kbps GFSK, 25 kHz deviation,
250 kHz receive bandwidth, 16-byte preamble, CCITT CRC with no whitening, a 16-bit
`network_id` hardware sync word, and packets capped at 128 bytes. Its 50
500-kHz channels are `902.250..912.750`, `913.750..915.250`, and
`916.250..927.750` MHz. This is an engineering test profile, not a statement
of regulatory approval. Current Meshtastic Medium Fast (913.125 MHz) and
MeshCore (910.525 MHz) are documented coexistence references, not guaranteed
quiet channels.

The rendezvous channel is `(network_id ^ hop_seed) % 50`. A sender repeats the
compact `DMSF` sync packet in all 50 slots; a target can dwell on its fixed
channel for one sweep plus guard instead of scanning. FSK is implemented for
both SX127x and SX126x. The SX126x path uses its distinct GFSK packet type,
sync-word register range, packet-status interpretation, and DIO1 IRQ mapping;
it was validated against a real SX127x on 2026-07-26. The fixed-channel smoke
matrix passed `lora1 -> lora2`, `lora2 -> lora1`, `lora1 -> lora4`, and
`lora4 -> lora1`. This does not yet qualify the 50-slot sweep, long-run loss,
or power behavior.

### Presets

| Preset | Frequency | BW | SF | CR | Sync Word | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `medium_fast` | (unchanged) | 250 kHz | 9 | 5 | `0x2b` | Meshtastic default channel. |
| `medium_slow` | (unchanged) | 250 kHz | 10 | 5 | `0x2b` | Meshtastic slow channel. |
| `meshcore` | 910.525 MHz | 62.5 kHz | 7 | 5 | `0x34` | MeshCore (US ISM 902–928 MHz). |

Current behavior:

- Background RX reads `lora.mode` from NVS at startup and applies the
  corresponding preset. Default mode is `meshtastic` (MEDIUM_FAST).
- SX127x CAD RX leaves the radio in standby between scans and uses the DIO0
  CAD_DONE interrupt. At SF9/BW250/preamble 16 with a 5 ms interval, a short
  regression received 4/4 packets. The canonical power matrix measured
  44.067 mA for CAD versus 43.14 mA for auto/light plus continuous RX, with
  0 percent CPU light sleep for both. Keep CAD optional until longer delivery
  tests establish reliability and power benefit.
- SX1262 uses hardware duty-cycle RX (`SetRxDutyCycle`) when `cad_rx=true`.
- Default firmware-originated Meshtastic hop limit is `0`.

## Wi-Fi Raw

| Command | Params | Result |
| --- | --- | --- |
| `wifi` | `mode=off` | Stop Wi-Fi/raw modes. |
| `wifi` | `mode=raw` | MGMT/action DMesh raw receive, channel 6 by default. |
| `wifi` | `mode=raw_data` | Explicit promiscuous MGMT+DATA test mode. |
| `wifi` | `mode=sta_idle`, `channel` | STA mode on a fixed channel without association, promiscuous receive, or connect attempts. |
| `wifi` | `mode=sta_idle`, `bssid`, `channel` | STA-idle with a configured target BSSID but no connect attempt. |
| `wifi` | `mode=ap_idle`, `ssid`, `psk`, `channel`, `beacon_ms` | SoftAP without promiscuous receive or mesh IP services. |
| `wifi` | `mode=raw_sta`, `ssid`, `psk`, `channel`, `timeout` | STA plus raw action mode. |
| `wifi` | `mode=raw_ap`, `ssid`, `psk`, `channel` | SoftAP plus raw action mode. |
| `wifi` | `mode=raw_ap_sta` | AP+STA plus raw action mode. |
| `wifi` | `wake_interval_ms=7000` | Set ESP-IDF connectionless-module wake interval before starting raw/NAN Wi-Fi tests. `0` restores ESP-IDF default mode. |
| `wifi` | `raw_action=TEXT` | Send one custom DMesh raw vendor-action payload (up to 1200 bytes). This is the ESP-NOW-like bulk transport, not a NAN SDF follow-up. NAN SDF remains the synchronization and wake-window control path. |
| `wifi` | `raw_action_hex=hex:...`, `dst`, `channel` | Send arbitrary binary CBOR/application bytes in the same custom raw action frame. This is used by gateway tests because raw-NAN/action command dispatch consumes binary firmware records rather than console text. |
| `wifi` | `raw=hex:...` | Send raw 802.11 frame bytes. |
| `wifi` | `raw_data=TEXT`, `dst`, `bssid`, `ds=none\|to_ap\|from_ap` | Inject one experimental data-frame payload for tests. |
| `wifi` | `raw_stats=true` | Raw RX/TX counters and last-frame summary. |
| `wifi` | `netif_stats=true` | Reports disabled counters; the old esp-netif probe is removed from the normal firmware profile. |
| `wifi` | `scan=true` | Scan visible Wi-Fi networks. |

Default raw mode must stay management/action-frame only. Promiscuous data-frame
receive can flood the ESP32 and belongs only in explicit test modes:
`raw_data`, `raw_sta_data`, `raw_ap_data`, and `raw_ap_sta_data`.

ESP32 product Wi-Fi should use DMesh MGMT/action frames for long-distance
no-association communication. Use normal AP+STA association chains when the
network needs infrastructure forwarding or IP-style connectivity. ESP32 Wi-Fi
modes used for mesh operation should keep MGMT/action receive enabled; data
frame receive remains debug/test-only unless the device is normally associated.
Raw mesh modes do not create default `esp_netif` STA/AP objects, run DHCP, start
SNTP, or assign IPv4/IPv6 addresses. lwIP/IPv6 remains enabled in the ESP-IDF
build because official Wi-Fi NAN selects it in Kconfig, but DMesh Wi-Fi comms
must not depend on IP services.

DMesh uses two action-frame paths:

```text
NAN SDF action + service_descriptor(dmesh service id, short timing/control payload)
custom vendor action + 7f:18:fe:34:ff:ff:ff:ff:04 + binary bulk payload (<=1200 bytes)
```

NAN SDF is the low-rate, discovery-window-synchronized "poor-man NDP" path:
it carries discovery, clock/window control, directed follow-ups, and bounded
datagrams while no standards-based NDP is available. The custom vendor-action
path is the ESP-NOW-like, unassociated bulk supplement used during those
windows. It deliberately does not use the ESP-NOW API or its 250-byte
compatibility limit. Firmware receives broad MGMT/action frames and uses a
fast software marker check for both paths.

Data-frame payloads are experimental and are not the supported sleepy-node
path. Earlier experiments used an IPv4/UDP shim so Linux/lmesh could reuse
packet tooling while the ESP parsed only the DMesh payload:

```text
802.11 data + LLC/SNAP IPv4 + UDP src/dst port 15009
  + 7f 18 fe 34 <mesh-dst4> 04 <payload>
```

The synthetic IPv4 source is `10.<last three source-MAC bytes>` and the
destination is the lmesh announce multicast address `224.0.0.250`. The UDP
payload used the debug-only DMesh data marker shown above followed by an
experiment payload. New firmware command traffic is compact CBOR, not text.

For data-frame injection, `bssid=...` defaults to a no-DS data frame with
`addr1=dst`, `addr2=sender`, and `addr3=bssid`. Use `ds=to_ap` for STA-to-AP
frames (`addr1=bssid`, `addr3=dst`) or `ds=from_ap` for AP-to-STA frames
(`addr1=dst`, `addr2/addr3=bssid`).

Current raw Wi-Fi command routing:

- valid compact-CBOR command records are dispatched through the common registry;
- action-frame commands receive action-frame responses to the sender MAC;
- data-frame commands receive unicast data-frame responses to the source MAC;
- firmware responses and notifications are compact-CBOR records over the
  selected response path;
- text `resp`/`notify` terminal-prefix handling is retired protocol history.

`wifi raw_stats=true` includes the last response path (`action` or `data`) and
the last command peer. `mode ping=true` sends a ping on all enabled transports:
LoRa, raw Wi-Fi action broadcast (`ff:ff:ff:ff:ff:ff`), and NAN when running.
Ping responses are directed: action response for action-frame RX and unicast
data response for data-frame RX.

Action-frame sizing:

- ESP-IDF TX accepts raw 802.11 frames up to 1500 bytes in this path;
- NAN SDF follow-ups currently cap their service payload at 255 bytes; the
  separate custom action-frame bulk path accepts up to 1200 bytes;
- official NAN and its text follow-up experiments are removed from the active
  firmware path;
- raw/custom NAN follow-ups carry compact CBOR command or response records;
  lmesh may translate local debug text before enqueueing them;
- raw/custom NAN command tests must use the envelope `to` and `from` fields.
  `nan stats=true` exposes `raw_cmd_rx`, `raw_resp_rx`, and `raw_resp_tx` for
  deterministic validation;
- larger payloads need chunking above this command path.

Follow-up versus session transport: raw-NAN follow-ups are intentionally for
short control or SMS-like messages (sync notification, status, and similarly
small records).  lmesh automatically requests a bounded “I want to talk”
window when a command exceeds its short payload budget; that window is where
the eventual QUIC-like/ESP-NOW-style bulk bearer belongs.  The current firmware
only establishes the active window and still carries the command over the
bounded raw-NAN command path.  It must not grow the command or radio queues:
each raw command and outgoing queue is capped at eight entries, oldest entries
are dropped on saturation, and `nan stats=true` reports `raw_cmd_drop` and
`raw_outgoing_drop` for sender-side retry/NACK policy.

DW continuation metadata uses reserved argument key `332`, encoded as one
byte: bit 0 means `MORE`, bit 1 means `DONE`, and bits 2..7 request additional
512-TU awake units. Exactly one NAN follow-up is sent in each selected DW. The
infrastructure gateway adds this hint from its bounded queue. A sleepy target
extends its awake window only for `MORE`/unit hints; `DONE` permits it to return
to the normal scheduler after the current command. The subsequent burst uses
the session bearer (CoC for Android, ESP-NOW-style frames for ESP peers).

## Sleep / Power

| Command | Params | Result |
| --- | --- | --- |
| `sleep` | `status=true` | RTC deep-sleep state and light-sleep test counters. |
| `sleep` | `mode=nan_raw wake_ms=7000 active_ms=1000 channel=6 serial=false` | Deep-sleep loop with Wi-Fi fully stopped during sleep, then a raw-NAN SDF receive/transmit window after timer or PRG wake. |
| `sleep` | `mode=deep wake_ms=5000 active_ms=1000 lora=true` | Deep-sleep loop with optional LoRa DIO0 wake. |
| `nan` | `cycle=true wake_ms=2000 active_ms=500 count=5 sync=true dw_tu=512 offset_tu=0 filter=nan` | Non-deep-sleep raw NAN timing test: turn Wi-Fi off between windows, start raw NAN, sync to beacon TSF phase, and log radio start/beacon/window timing. |

For the current S3 raw-NAN experiment, use:

```text
sleep mode=nan_raw wake_ms=7000 active_ms=1000 channel=6 serial=false
```

This is the intended measurement path for "Wi-Fi off for about 7 seconds,
awake for about 1 second". PRG/BOOT remains configured as a deep-sleep wake
source. Any command that promotes the device out of the loop should be followed
by `wifi mode=off` if the test window left Wi-Fi enabled unexpectedly.

### Historical Measurements and Retired Experiments

The rest of this Wi-Fi/sleep section preserves dated measurement notes and
retired official-NAN/AP/data-frame experiments. It is not current configuration
guidance; follow `docs/lmesh-firmware-handoff.md` for the supported raw-NAN
duty-cycle default.

Short-loop lab result: USB1 with `wake_ms=2000 active_ms=500` repeatedly woke by
timer and averaged about 37 mA, with about 10 mA during the sleep portion and
about 83 mA during the active raw-NAN Wi-Fi window. Directed commands did not
reliably land in the 500 ms window; use a longer active window for command
latency tests.

Raw-NAN's Wi-Fi-off interval uses explicit timer/GPIO light sleep, not automatic
PM. `sleep status=true` reports this separately as `raw_nan_light_runs`,
`raw_nan_light_ok`, and `raw_nan_light_last_ms`; `power status=true`'s `ls_*`
fields only cover automatic light sleep. `power quiet=true` returns its response
then disables UART RX and releases its PM locks until a PRG wake. This is
required for a valid battery measurement.

Raw NAN timing instrumentation:

- `nan stats=true` includes `last_beacon_local_us`, `last_beacon_tsf_us`, and
  `beacon_age_ms` when the raw NAN sniffer has seen NAN beacons;
- `nan beacon_history=true` returns the bounded sequence/TSF/local timestamp
  history plus the 802.11 source MAC used to compare a powered observer with a
  sleepy node. The source is diagnostic attribution; all beacons from the
  selected NAN cluster remain eligible for timing.
- `nan beacon_stats=reset` starts a beacon-only measurement and
  `nan beacon_stats=true` reports the selected BSSID, interval/stride,
  accepted beacons, selected slots seen/missed, duplicates, TSF regressions,
  phase range/span, and TSF/local receive deltas. Service descriptors, follow-ups,
  generic management frames, and foreign clusters are excluded. AP fallback
  uses the same counters with `source=ap` and the advertised AP interval.
- `nan cycle=true ... sync=true` uses that beacon TSF estimate to align active
  windows to `TSF % (dw_tu * 1024) == offset_tu * 1024`;
- USB1 measured raw-NAN radio startup at about 10.5 ms in the no-deep-sleep
  off/on test. With official NAN beacons from USB0/USB2 on channel 6, the first
  beacon after raw radio start was usually seen within about 60-160 ms.

ESP-IDF 5.5 official NAN exposes `op_channel`, `master_pref`, `scan_time`, and
`warm_up_sec` in the public `wifi_nan_config_t`. It does not expose a public
awake Discovery Window interval or an 8 second NAN radio-off schedule knob in
the headers we build against. Official NAN power behavior must therefore be
measured with modem sleep enabled rather than assumed from configuration.

ESP-IDF does expose `esp_wifi_connectionless_module_set_wake_interval()` for
connectionless modules. Firmware exposes it as `wifi wake_interval_ms=<ms>`;
call it before starting the raw/NAN Wi-Fi mode under test, then use
`sleep mode=light ...` or a manual power profile to measure whether the radio
actually idles between wake intervals. This is separate from `esp_now` wake
window APIs and does not enable ESP-NOW.

Verification status:

- raw action command/response works between ESP32 boards;
- verified on USB0/USB1 after flashing: USB0 sent
  `wifi raw_action="wifi raw_stats=true" dst=<USB1 STA MAC> channel=6`, USB1
  dispatched it as a command, and USB0 received a `resp raw_monitor=...`
  action-frame response;
- received ESP-IDF action frames include a four-byte trailer in the promiscuous
  buffer; firmware strips that trailer before command dispatch;
- official NAN start on USB0 with `nan start=true backend=official ... channel=6`
  kept the reported Wi-Fi channel at `ch=6 second=none`; action-frame commands
  from USB1 to USB0 still reached the raw command path while official NAN was
  running;
- AP+STA plus raw action works as a control path: USB1 `raw_ap` open AP on
  channel 6 and USB0 `raw_ap_sta` associated to it while retaining
  `raw_monitor=true filter=dmesh`; action-frame commands from USB0 reached USB1;
- raw promiscuous data command/response works between ESP32 boards with the
  IPv4/UDP shim above;
- unassociated `sta_idle` netif receive did not deliver injected unicast or
  multicast data frames (`netif_rx=0`) in the old esp-netif probe experiment.
  That probe has been removed; efficient non-promiscuous data RX still needs an
  associated AP/STA test path or a lower-level Wi-Fi driver callback that does
  not create IP services.
- `ap_idle` and `sta_idle bssid=...` are the non-promiscuous data-frame test
  modes. `wifi netif_stats=true` now reports disabled counters because the old
  esp-netif callback path was removed.
- Tested no-association data-frame delivery with receiver promiscuous disabled:
  AP receiver `ap_idle` did not receive unicast-to-AP, broadcast, no-DS+BSSID,
  or ToDS frames from an unassociated sender; STA receiver `sta_idle bssid=...`
  did not receive unicast-to-STA, broadcast, no-DS+BSSID, or FromDS frames.
  Both stayed at `netif_rx=0`.
- Repeating the STA fake-BSSID test with the well-known NAN BSSID
  `50:6f:9a:01:05:01` also stayed at `netif_rx=0`. Starting official NAN on
  the receiver and injecting data frames from a non-NAN sender with the NAN
  BSSID did not produce a DMesh data command; observed NAN `match`/`followup`
  counters came from proper NAN service traffic from another peer.
- AP/AP+STA chaining test: USB0 in `raw_ap` and USB1 in `raw_ap_sta` both kept
  `raw_monitor=true filter=dmesh`. An earlier build used default esp-netifs and
  briefly showed `sta_ip=192.168.4.2`; this was an unwanted lwIP/DHCP side
  effect and raw mesh modes now avoid creating those default netifs. Directed
  DMesh MGMT/action pings worked both directions between USB0 and USB1, with
  action-frame responses received on the sender.

Infra boot radio settings:

- `wifi.mode=nan` is the default infra Wi-Fi mode and now means raw/custom NAN
  duty cycle on all ESP targets;
- raw-NAN duty cycle starts a short raw-NAN SDF active window, drains queued
  messages, sends a reboot discovery ping with `from=<last4>`, then turns Wi-Fi
  off and explicitly enters light sleep until shortly before a Discovery Window
  calculated from the most recent NAN beacon TSF. If no recent beacon is
  available, it uses the configured duty interval as a conservative fallback.
  Defaults: `nan.wake_ms=4000`, `nan.active_ms=64`,
  `nan.light_sleep=true`, `nan.early_ms=5`, `nan.channel=6`;
- AP fallback is available for a powered infra owner. Set `nan.ap_owner=true`
  on `lora1`; after five seconds without NAN it starts open
  `DIRECT-DMESH-<last4MAChex>` on the raw-NAN channel at 500 TU. AP mode is
  always powered: it never enters the duty-sleep Wi-Fi-off path. Battery nodes
  prefer NAN, then a `DIRECT-DMESH-*` or ordinary channel beacon; use
  `nan.sync_source=ap_only` to validate AP synchronization while NAN exists.
- `xstatus` and `mode status=true` include raw-NAN per-window beacon telemetry:
  `nan_beacon_seen`, `nan_beacon_missed`, `nan_beacon_late`,
  `nan_beacon_late_next_dw`, and `nan_beacon_drift`. A missed beacon adds a
  one-second backoff before the next scheduled window. Late beacons are
  classified as approximately one Discovery Window late (`next_dw`) or timing
  phase drift (`drift`).
- The older `wifi.mode=nan_sleep`/infra deep-sleep experiment is historical and
  must not be used as the infrastructure default. Current `mode=infra` is
  always-on; only non-infrastructure battery nodes use the raw-NAN sleep loop.
- `wifi.mode=official_nan` starts Espressif official NAN explicitly on classic
  ESP32 boards for comparison tests;
- `wifi.mode=sta_idle` starts unassociated STA-idle mode;
- `wifi.mode=off` disables infra Wi-Fi startup;
- `wifi.mode=raw` starts the older raw monitor test mode explicitly;
- `wifi.ssid` is used by STA-oriented tests;
- `lora.enabled=true` is the default and starts LoRa background RX when a radio
  is detected; `lora.enabled=false` disables infra LoRa RX startup.

## BLE

`ble coc=true psm=0x80` enables the lab-only LE CoC echo server after NimBLE is
ready. It accepts only dynamic application PSMs `0x80..0xff`; it is not an
IPSP/6LoWPAN implementation. Android's `ble.coc addr=<BLE-address> psm=0x80`
probe writes a ping and records `BLE.COC state=echo_ok` on success.

| Command | Params | Result |
| --- | --- | --- |
| `ble` | `start=true\|stop=true` | Start/stop BLE runtime. |
| `ble` | `mode=gatt\|connectable` | Start local GATT/connectable mode. |
| `ble` | `companion=true save=true` | Persist companion mode and start companion runtime. |
| `ble` | `pairing=request`, `timeout_ms`, `confirm_ms` | Open pairing request/confirm windows. |
| `ble` | `pairing_recovery=true` | Clear bonds and advertise for recovery. |
| `ble` | `reset_pairing=true` | Clear pairing state and saved companion flags. |
| `ble` | `advertise=true`, `event=...`, `payload=hex:...` | Advertise DMesh event payload. |
| `ble` | `send=hex:...` | Notify a connected client. |
| `ble` | `stats=true`, `bonds=true` | BLE state, counters, and bond summary. |

BLE is for nearby companion-phone control. Infra mode should not depend on BLE
unless explicitly started for testing.

## Mode and Sleep

| Command | Params | Result |
| --- | --- | --- |
| `mode` | `status=true` | Current companion/infra state and radio policy. |
| `mode` | `companion=true\|infra=true save=true` | Switch persisted operating mode. |
| `mode` | `advertise=true window_ms=... adv_ms=...` | Open companion advertising window. |
| `mode` | `active=true ms=...` | Keep active for a bounded window. |
| `active` | none | Runtime-only persistent infra transfer mode. Keeps raw-NAN Wi-Fi, NAN receive, and configured LoRa RX active until `idle` or reset. |
| `idle` | none | End the runtime-only persistent `active` override and resume the configured raw-NAN duty cycle. |
| `mode` | `raw_wifi=true channel=6` | Enable raw Wi-Fi under mode policy. |
| `mode` | `raw_nan=true lora=false channel=6` | Start non-persistent raw-NAN duty cycling. `lora=false` isolates Wi-Fi sleep measurement. |
| `mode` | `lora_sleep_listen=true save=true` | Persist companion LoRa sleep-listen preference. |
| `mode` | `ping=true` | Send ping across enabled transports. |
| `power` | `status=true` | Current CPU frequency, XTAL, PM min/max, automatic light-sleep permission, and tick counter. Heap/PSRAM/task stats are in `status`/`xstatus`, not `power`. |
| `power` | `locks=true` | Print the active ESP-IDF power-management lock table to the debug UART. |
| `power` | `quiet=true` | Send the response, then enter UART idle: output is suppressed and PM locks are released, but RX/light-sleep wake stays armed. A PRG edge or UART wake preamble followed by a command reopens the active window. Intended for power tests. |
| `power` | `uart_status=true` | Report driver, active-window, RX-wake, ingress error/drop, `uart_frame_drop`, `uart_escape_err`, idle-TX-drop, and `uart_hb_*` heartbeat counters including the last heartbeat window. The physical UART decoder drops malformed frames at the next delimiter; it emits no recovery stream. |
| `power` | `uart_probe_ms=N` | Debug verification only: schedule one UART output attempt after `N` ms (1..60000). After a PRG/UART wake, `uart_status=true` must report `uart_probe_dropped` when the probe ran outside the active window; it must not emit the probe line. |
| `power` | `uart_probe_reset=true` | Clear the debug output-gate probe counters before a bounded test. |
| `power` | `uart_uninstall=true` | One-boot power-test operation: acknowledge first, then remove UART0's driver. Reset is required to restore the console. It is never part of normal boot or radio profiles. |
| `power` | `profile=dfs\|perf\|low\|auto save=true min_mhz=... max_mhz=... light=true\|false` | Configure ESP-IDF PM. Default boot profile is `dfs`: dynamic frequency scaling enabled, automatic light sleep disabled. `light=true` permits automatic light sleep; it does not force immediate sleep if UART, Wi-Fi, BLE, LoRa, timers, or tasks hold the chip active. |
| `nvs` | `op=set uart.active_ms=2000` | Configure the debug UART input/output window in milliseconds (minimum/default: 2000 ms). A scheduled UART/radio rendezvous or UART RX opens/extends the window. RX wake remains armed while idle; firmware output is dropped while idle. Modem-line control is reserved for direct esptool recovery flashing. |
| `nvs` | `op=set uart.hb_every=N` | Configure the disabled-by-default periodic UART heartbeat. `0` suppresses raw-NAN wake and LoRa/FSK-triggered UART output; `N>0` writes an empty UART frame and opens the bounded console window on every Nth raw-NAN wake. lmesh flushes queued command frames after receiving any firmware UART frame. |
| `sleep` | `status=true` | Sleep/PM/radio state and counters. |
| `sleep` | `test=ble\|raw\|raw_data\|sta\|ap\|nan ms=... restore=true` | Bounded light-sleep experiment with timer recovery. |
| `sleep` | `mode=deep wake_ms=... active_ms=... lora=true|false start=true` | Enter deep sleep with timer and button wake. LoRa deep-sleep listen is opt-in with `lora=true`. |
| `sleep` | `mode=light start=true\|stop=true ...` | Manual light-sleep/PM controls. |

Never use sleep paths without a timer or button recovery path. Infra mode should
not deep sleep.

`power status=true` also reports measured automatic light-sleep residency:
`ls_attempts`, `ls_entries`, `ls_skipped`, `ls_expected_us`, `ls_us`,
`ls_max_us`, `ls_tracked_us`, `ls_awake_us`, and `ls_pct`. Reset these with
`stats reset=true` before a bounded experiment.

`event type=uart.pm_lock ok=true state=released` means the firmware released
the APB frequency lock for the debug UART after the active window expired. It
does not uninstall the UART driver. A scheduled UART/radio rendezvous or RX
input opens a closed console window; when waking from light sleep, send
a complete delimiter-framed CBOR command; partial or corrupt UART bytes are
discarded at the next delimiter. Output while closed is intentionally dropped.
Each active console window holds both the UART APB lock and an
`ESP_PM_NO_LIGHT_SLEEP` lock for at least two seconds. lmesh UDS forwards are
passive; modem-control lines are reserved for direct esptool recovery flashing.

## Hardware and Probe

| Command | Params | Result |
| --- | --- | --- |
| `battery` | `status=true`, `pin`, `divider`, `ctrl_pin`, `ctrl_level`, `save=true` | Battery ADC reading and saved config. |
| `adcprobe` | `pins=32,33,34,35,36,39 interval_ms=... count=...` | ADC sample table. |
| `button` | `status=true`, `gpio=0`, `enabled=true`, `save=true` | Button config and press count. |
| `gpio` | `pin`, `mode=input\|output`, `level=0\|1` | GPIO diagnostics. |
| `rgbled` | `pin=N off=true`, or `pin=N r=0..255 g=0..255 b=0..255` | Sends one WS2812/SK6812-style GRB LED frame using RMT. Useful for generic ESP32-S3 boards whose addressable status LED is often on GPIO48 or GPIO38. |
| `i2cconfig` | `sda`, `scl`, `freq`, `save=true` | I2C config. |
| `i2cprobe`, `i2cdetect`, `i2cget`, `i2cset`, `i2cdump` | I2C diagnostics. |

On classic ESP32, avoid ADC2 pins while Wi-Fi is active. Use ADC1 pins
`32,33,34,35,36,39` for battery probing.

## NAN

| Command | Params | Result |
| --- | --- | --- |
| `nan` | `start=true\|stop=true`, `backend=raw`, `role=publish\|publisher_solicited\|subscribe\|both`, `service=dmesh`, `channel=6` | Start/stop raw NAN-like mode. `publisher_solicited` queues a standards-generated Publish only after a matching Subscribe and binds the received subscriber instance as the Publish Requestor Instance ID. |
| `nan` | `publish=true sync=true count=N sdea=true\|false sdea_update=0..255 availability_map=0..15` | Queue `N` raw-NAN unsolicited Publish SDFs in Discovery Windows. `sdea=false` omits only the optional Service Descriptor Extension Attribute; `sdea_update` changes only its Service Update Indicator (default `2`); `availability_map` changes only the Availability Attribute Map ID (default `1`). All are non-persistent interoperability probes, not saved radio settings. |
| `nan` | `uart_wake=*\|<last8> sync=true duration_ms=...` | Queue a targeted infrastructure wake Publish SDF. `*` targets every sleepy node; an 8-hex suffix targets one device. A match keeps raw Wi-Fi active for the bounded interval, opens UART, and permits raw action/ESP-NOW-like exchange. The advertisement is released only in the selected DW. |
| `nan` | `ble_wake=*\|<last8> sync=true duration_ms=...` | Queue a targeted BLE wake Publish SDF. A match starts the connectable NimBLE CoC server (PSM `0x80`) for the bounded interval without holding raw Wi-Fi or opening UART. This is intentionally separate from `uart_wake`; a frame carrying both flags requests both bearers. |
| `nan` | `queue=<CBOR command> dst=MAC` | Queue a compact CBOR command for the next raw-NAN active window; use it for sleepy peers. Raw-NAN command responses use the same queue while duty cycling. |
| `nan` | `stats=true` | NAN support, counters, role/backend state, beacon timing, queued raw-NAN work, and raw command/response counters. `rx_prefilter_drop` counts unrelated management frames rejected in the Wi-Fi callback before they can fill the raw-NAN queue. |
| `nan` | `service_dump=true\|clear` | Show or clear the bounded last received DMesh service descriptor. Clear before a one-peer observer test; it neither transmits nor changes radio configuration. |
| `nan` | `service_history=true\|clear` | Show or clear the bounded source/device/instance history of received DMesh service descriptors. Use it when nearby Android devices make a single last-frame capture ambiguous. |

Use `role=both` when testing ESP-to-ESP discovery without a host/phone active
subscriber. Use `role=publisher_solicited` when lmesh or Android owns active
subscribe and the ESP should only respond to matching subscribers instead of
broadcasting unsolicited publish frames every discovery window.

Raw/custom NAN command/response is the current reliable ESP-to-ESP validation
path. Example:

The raw-NAN payload budget is 231 bytes for compact-CBOR command/response
records. Verbose `status` and `ping` responses are returned as valid CBOR
`status=partial` records containing a bounded message prefix; they are not
truncated byte streams and must not be treated as transport errors.

```bash
python tools/nan_pair_test.py --backend raw \
  --a uds:///run/mesh/lmesh/USB1.sock \
  --a-mac 84:0d:8e:07:41:70 \
  --b uds:///run/mesh/lmesh/USB3.sock \
  --b-mac fc:f5:c4:0e:f1:e8 \
  --iterations 5
python tools/nan_stress_test.py --backend raw \
  --a uds:///run/mesh/lmesh/USB1.sock \
  --a-mac 84:0d:8e:07:41:70 \
  --b uds:///run/mesh/lmesh/USB3.sock \
  --b-mac fc:f5:c4:0e:f1:e8 \
  --iterations 100 --batch 10
```

The pair/stress helpers keep both serial consoles open, include `to=`/`from=`
tokens in each command payload, and validate `raw_cmd_rx`, `raw_resp_tx`, and
`raw_resp_rx`.

For fleet discovery, send a broadcast command such as
`dmesh.ping type=status to=ffffffff from=<host-last4>`. Each awake firmware node
should respond directly to the sender with its compact status/pong. Host
`lmesh` currently exposes `ping`, `send`, `wifi.nan.default`,
`wifi.nan.status`, `wifi.nan.events`, `wifi.nan.transmit`, and
`wifi.nan.ping`; the host queue that holds follow-up traffic for sleepy ESPs
for the next 8 second wake cycle is a host-side TODO, not firmware behavior yet.

Firmware send-test helper:

```text
test cnt=50 wake_ms=4000 active_ms=500 discovery=2
sleep mode=nan_raw channel=6 start=true
```

`test cnt=NN` returns immediately and stores its state in RTC memory. Each
raw-NAN active window sends at most one broadcast `dmesh.ping` with
`to=ffffffff` and this device's `from=<last4>`. The first `discovery` pings are
`type=discover`; the remaining `NN` are `type=status`. `test status=true`
reports `remaining`, `sent`, and received raw-NAN responses seen by the sender.
When a send test is active, `sleep mode=nan_raw start=true` defaults to the
test's `wake_ms` and `active_ms` values, so the short test cadence can be set on
the `test` command.

Official NAN command-delivery observations are retired with the official NAN
backend. Do not re-enable that path without a new power and interoperability
decision.

Companion mode should not depend on ESP NAN. Android can own NAN in companion
scenarios; ESP raw action frames are an ESP-side Wi-Fi experiment.

## lmesh Proxying

`lmesh` should treat this firmware as a radio adapter:

- list serial/BLE/raw-Wi-Fi firmware adapters in `radios.list`;
- expose the appropriate curated tools from `resources/tools.json`;
- translate tool calls into firmware commands;
- normalize responses into `lmesh` neighbor/link/message records;
- keep encryption/auth at the mesh layer, not in a text command ABI.

Production callers should prefer `lmesh send radio=...` over direct firmware
commands. For example, `send radio=lora payload=...` may use a local ESP over
UART, a companion ESP reached through Android BLE/JNI, or a remote ESP exposed
by an SSH-forwarded `lmesh` socket.
