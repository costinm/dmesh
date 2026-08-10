# ESP32 Build

The active fleet firmware is the Rust ESP-IDF application under
`fw/esp32/rust`. The older C application and Rust translation scaffold below
remain development material; the canonical current provisioning and remote
flashing procedure is [rust/docs/flashing.md](rust/docs/flashing.md).

Install dependencies:

```bash
scripts/esp32-deps.sh
```

Build the legacy C application:

```bash
. env.sh
(cd fw/esp32 && idf.py build)
```

The build uses the flake package in `fw/esp32` for host tools and keeps SDKs
under `target/esp32-6.0`, not `$HOME`.

Successful build outputs:

- `fw/esp32/build/dmesh.bin`
- `fw/esp32/build/bootloader/bootloader.bin`
- `fw/esp32/build/partition_table/partition-table.bin`

The legacy C build is retained for reference and does not own a flashing
workflow. Do not use `idf.py flash`, Cargo flash subcommands, or `espflash`.
Use the repository scripts below. Main images are never written over USB.

Build the current Rust fleet images from the repository root:

```bash
. env.sh
scripts/build-fw.sh e5          # classic ESP32 Main
scripts/build-fw.sh recovery-s3 # ESP32-S3 Main, common 4 MiB image
scripts/build-recovery-fleet.sh all
```

Artifacts are kept under `target/flash/` and `target/recovery-fleet/`.
USB flashing is limited to initial provisioning or emergency repair of the
stage-2 and Recovery partitions. Never use USB or esptool to replace Main on a
provisioned board. Once stage-2/Recovery are installed, the supported Main update is:

```bash
# mesh-init should run docs/lab/recovery-tcp-server.toml continuously.
# For a manual development start:
fw/recovery/tools/flash-server.py

# Then use the common local development flasher.
python3 scripts/flash-device.py e5 main
# server, port, saved SSID, and MAC-derived IP use defaults
```

Optional network values are saved in
`target/flash-devices/network.json`; pass `--ssid` or `--board-ip` once and
subsequent commands reuse them. An example is in
`docs/lab/flash-network.json.example`.

The helper sends only the recovery-start command through managed lmesh; the
Main image is transferred over Wi-Fi by Recovery. It reuses port 3336 for
successive boards. Do not invoke `idf.py flash`, `flash-fw.sh`, or an esptool
Main-image command for routine updates. The older
`update-main-wifi-fleet.py` remains a per-board/temporary-listener test helper,
not the canonical persistent-server procedure.

Main-update logs are available in:

- `target/recovery-server/all-3336.log` when using
  `fw/recovery/tools/start-server.sh` (or the compatibility wrapper
  `scripts/start-recovery-server.sh`);
- `target/flash-devices/<mac-without-colons>/`, especially `device.json`,
  `flashes/*.json`, `current.sha256`, and `flash-history.jsonl`;
- `target/evidence/flash/` and the active managed serial capture at
  `target/lmesh-radio-build/log/serial.log`.

For exceptional Stage2/Recovery provisioning, the fleet script archives the
existing partition table and NVS before writing. If a board's flash chip can
be identified but cannot be read, use one bounded attempt with the checked-in
SDK6 artifacts and the known partition table:

```sh
python3 scripts/flash-recovery-fleet.py --stage-only --skip-build \
  --skip-archive --flash-baud 115200 --flash-freq 20m lora2
```

`--skip-archive` does not bypass esptool flash verification; it only omits the
pre-write reads. Stop if the write still reports flash-chip communication
failure. Do not use this path for Main images.

The same persistent Recovery flash server can serve a module in the raw data
region. New Main clients select the requested resource in HELLO, so this does
not require a second port or a server restart. The module build outputs under
`target/modules/` are discovered automatically (CPU-specific copies under
`target/flash/esp32/modules/` or `target/flash/esp32s3/modules/` take
precedence); inspect them with:

```sh
python3 fw/recovery/tools/flash-server.py --list-modules
python3 fw/recovery/tools/flash-server.py --module lora
```

`--module NAME` sets the fallback target to `module` for older clients. New
clients request `module` plus its name directly, while the server keeps the
normal sparse/hash or unsigned-fast transfer protocol. The server remains
persistent and can serve Main, Recovery, stage2, data, or a module on the same
listener.
Build output under `target/modules/<rust-target>/` is discovered automatically
as well.

The target resolves both legacy `data` and current Rust `dmesh_store` partition
labels. On larger flash parts the module region begins at the selected
partition address and extends to the physical flash end; module images are
placed at 64 KiB-aligned offsets within that region.

The Main module command may target any aligned slot with `offset=...`. When
`size` is omitted, the loader reads and validates that slot's header and uses
the remaining raw region as its bounds, allowing independently deployed
modules larger than one 64 KiB slot.

Before a module transfer, Main must be running an image that quiesces the
module task and waits for it to stop before the raw data region is erased. The
module executes from that same flash mapping; flashing it while its task is
still running can disable the cache underneath the instruction fetch and
reset the board before the protocol's final `DONE` frame. If a module session
ends as `started`/`timed out`, verify the board is running the current Main
image before retrying the module transfer.

For Rust ESP development, source the same environment. `env.sh` owns
the repo-local Nix profile, ESP-IDF tools, ESP Python environment, Cargo home,
rustup home, and Xtensa Rust toolchain paths under `target/esp32-6.0`; do not
set those paths manually in scripts.

Build and module deployment timing
----------------------------------

The canonical S3 Main output is `target/flash/esp32s3/main-app.bin`. Main uses
the same `fw/boot/partitions.csv` image layout on every chip; only the
second-stage boot build uses the larger physical-flash profile.

The build scripts record JSONL timing under `target/evidence/` and print a
single elapsed value. Main and module commands therefore stay short:

```bash
. env.sh
scripts/build-fw.sh esp32s3       # prints MAIN_BUILD_MS=...
fw/mod_lora/build.sh              # prints MODULE_BUILD_MS=...
scripts/flash-module.sh lora4 lora # prints MODULE_PUSH_REQUEST_MS=...
```

The last command uses the direct managed lmesh USB path to Main; it does not
use DTR/RTS or Recovery. The negotiated transfer duration is appended by the
flash server to `target/recovery-server/all-${DMESH_FLASH_PORT}.log`. AP,
server, device IP, and mesh binary defaults are supplied by `env.sh` and can
be overridden with `DMESH_FLASH_*` variables.

Build the Rust translation scaffold:

```bash
. env.sh
(cd fw/esp32/rust && cargo build)
```

The Rust scaffold targets `xtensa-esp32-espidf`. It now includes:

- `components::l3dmesh`: C `onMessage`/transport forwarding boundary.
- `components::ble_bt`, `lora`, and `nan`: L2 transport shells.
- `components::wifi`: STA/AP command shell translated from `wifi_sta_ap.c`.
- `components::console`: native-console command shell translated from
  `console.c`.
- `components::gpio`, `i2c`, and `nvs`: command shells for the existing ESP
  helper components.
- `commands` and `transports`: transport-neutral command registry plus text
  and binary envelopes for native console, future USB, BLE, and Wi-Fi command
  paths.

The UI code (`ui.c`, `ssd1306`) is intentionally not part of the Rust scaffold
yet.

Device-test command examples after flashing the Rust scaffold:

```text
list
nvs list
nvs get i2c.sda
nvs set i2c.sda=21 i2c.scl=22
i2cconfig sda=21 scl=22 freq=100000
i2cprobe sda=21,4 scl=22,15 addr=0x3c save=true
lora freq=915000000 sck=5 miso=19 mosi=27 cs=18 rst=14 dio0=26 sf=7 cr=5 sync_word=0x34
loraprobe sck=5,18 miso=19 mosi=27 cs=18,5 rst=14 dio0=26 save=true
```

The settings are stored in the `dmesh` NVS namespace. Probe commands already
accept candidate pin lists and validate/save settings, but the low-level I2C
transaction and SX127x register-read hooks are still marked `pending-driver` in
the Rust scaffold.
