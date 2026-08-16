# Rust Recovery

This target is the Rust Recovery target for the classic ESP32 and ESP32-C6
(RISC-V) boards. It owns the packetized USB/UART control loop and the RTC-only
Main handoff. The C6 build is selected with `scripts/build-recovery-rust.sh
esp32c6`.
It uses the same bearer-neutral `dmesh-transport` framing and embedded
`dmesh-object-store::protocol` receiver that Main is adopting. Its UDP object
worker performs the version-0 short-header bootstrap (`DCID=0`, stream 0),
installs independent client/server receive CIDs, then sends the object GET.
The build probe is still dry-run only: it exercises construction and framing
without claiming a live NAN/BLE bearer or a successful device exchange.

Build it with:

```sh
scripts/build-recovery-rust.sh esp32c6
```

The result is written below `target/recovery-rust/`; this script never flashes
a board. The checked-in `scripts/flash-device.py e7 stage` wrapper performs
the actual verified provisioning.

Recovery accepts PPP/CBOR method 68 packets on USB. `op=main` or
`op=reboot_main` sets the RTC handoff to Main and reboots immediately. A
transport packet may carry `ssid`, `server`, `ip`, `gateway`/`gw`, `mask`,
`port`, `dry_run`, and `log_level`; these are retained as runtime parameters
for the network worker and are never written to NVS.
