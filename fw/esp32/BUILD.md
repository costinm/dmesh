# ESP32 Build

The active Main firmware is the Rust ESP-IDF application under
`fw/esp32/rust`. Stage2 is under `fw/boot`; Rust Recovery is under
`fw/recovery-rust`. The retired C Recovery must not be restored. The canonical
build/provisioning procedure is [../../BUILD.md](../../BUILD.md), and the
active shared-transport cleanup is
[../../notes/plans/main-recovery-transport-reuse.md](../../notes/plans/main-recovery-transport-reuse.md).

Install dependencies:

```bash
scripts/esp32-deps.sh
```

The build uses the flake package in `fw/esp32` for host tools and keeps SDKs
under `target/esp32-6.0`, not `$HOME`. Do not use `idf.py flash`, Cargo flash
subcommands, or `espflash`; use the repository scripts below. The obsolete
"no USB Main" rule no longer applies: every write, including Main, must go
through `scripts/flash-device.py`.

Build the current Rust fleet images from the repository root:

```bash
scripts/build-fw.sh --help
scripts/build-stage2.sh --help
scripts/build-recovery-rust.sh --help
scripts/build-fw.sh e5          # classic ESP32 Main
scripts/build-fw.sh recovery-s3 # ESP32-S3 Main, common 4 MiB image
scripts/build-stage2.sh all
scripts/build-recovery-rust.sh esp32c6
```

The scripts source `env.sh` themselves. Main and Stage2 default to `all` when
no target is supplied; Recovery defaults to classic ESP32. Prefer an explicit
CPU target during iteration.

Artifacts are kept under `target/flash/`, `target/stage2/`, and
`target/recovery-rust/`.
Use `scripts/flash-device.py` for every firmware target, including Main. It is
the sole supported flashing entry point and currently provisions images through
its direct USB/esptool implementation. Do not call `esptool`, `idf.py flash`,
or `flash-fw.sh` directly. Wi-Fi Recovery remains the intended production
Main-update path and will be owned by `lmesh-wifi` when it is complete; it is
not the current default in this checkout.

```bash
# Use the common local development flasher. Production Recovery will be
# served by lmesh-wifi once that path is complete.
python3 scripts/flash-device.py e5
# server, port, saved SSID, and MAC-derived IP use defaults
```

The omitted target means `main`. Select `stage`, `recovery`, `main`, or `nvs`
explicitly when needed. Use the `nvs` target and its Stage2-selector option for
reliable boot selection; do not use modem-line scripts for that purpose.

Optional network values are saved in
`target/flash-devices/network.json`; pass `--ssid` or `--board-ip` once and
subsequent commands reuse them. An example is in
`notes/lab/flash-network.json.example`.

Today the helper writes through esptool and verifies the result. Future
production updates will have `lmesh-wifi` own the Recovery UDP server; separate
UDP Recovery servers may use different ports. Do not invoke `idf.py flash`,
`flash-fw.sh`, or an esptool command outside this helper.

Main no longer links the retired C flash ABI or TCP flash worker. Flash policy
is target-specific: Main never writes its active Main partition and Recovery
never writes its active Recovery partition. Both use the shared Rust transport
and protocol path as it is extracted.

Main and Recovery default to `wifi-raw-udp6` and `wifi-espnow`, using the same
common transport code. There is no DMesh lwIP socket-transport feature;
residual SDK linkage is acceptable. Diagnostic device-to-device clients remain
lab-only so normal Main does not reserve their state:

```bash
DMESH_FW_FEATURES=e6-raw-udp6-iperf-lab scripts/build-fw.sh e6
DMESH_FW_FEATURES=e6-espnow-iperf-lab scripts/build-fw.sh e6
```

Build the selected lab immediately before `scripts/flash-device.py e7 main`.
The build wrapper tracks feature composition and invalidates incompatible
stale Cargo output. Exact identities, commands, rates, size deltas, and the
remaining receive-filter limitation are in
[../../notes/2026-08-18-c6-raw-udp6-espnow-results.md](../../notes/2026-08-18-c6-raw-udp6-espnow-results.md).

Main-update logs are available in:

- `target/flash-devices/<mac-without-colons>/`, especially `device.json`,
  `flashes/*.json`, `current.sha256`, and `flash-history.jsonl`;
- `target/evidence/flash/` and the active managed serial capture at
  `target/lmesh-radio-build/log/serial.log`.

For exceptional Stage2/Recovery provisioning, the fleet script archives the
existing partition table and NVS before writing. If a board's flash chip can
be identified but cannot be read, use one bounded attempt with the checked-in
SDK6 artifacts and the known partition table:

```sh
scripts/flash-device.py lora2 stage
```

`--skip-archive` does not bypass esptool flash verification; it only omits the
pre-write reads. Stop if the write still reports flash-chip communication
failure. Do not use this path for Main images.

The managed object service discovers module outputs under `target/modules/`.
Use `scripts/flash-device.py <role> module --module NAME` for local
provisioning.

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
