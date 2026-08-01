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
under `target/esp32-5.5`, not `$HOME`.

Successful build outputs:

- `fw/esp32/build/dmesh.bin`
- `fw/esp32/build/bootloader/bootloader.bin`
- `fw/esp32/build/partition_table/partition-table.bin`

Legacy direct flash command from ESP-IDF after a successful build:

```bash
cd fw/esp32
idf.py -p PORT flash
```

Build the current Rust fleet images from the repository root:

```bash
. env.sh
scripts/build-fw.sh e5          # classic ESP32 Main
scripts/build-fw.sh recovery-s3 # 8 MB ESP32-S3 Main
scripts/build-recovery-fleet.sh all
```

Artifacts are kept under `target/flash/` and `target/recovery-fleet/`.
Direct USB flashing is only for initial provisioning or emergency repair. Once
Main is installed, use `scripts/flash-main-command.py` through managed lmesh;
CBOR starts the session and the image travels as a raw `DRS1` TCP stream.

For Rust ESP development, source the same environment. `env.sh` owns
the repo-local Nix profile, ESP-IDF tools, ESP Python environment, Cargo home,
rustup home, and Xtensa Rust toolchain paths under `target/esp32-5.5`; do not
set those paths manually in scripts.

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
