# Rust Recovery

This is a retained, standalone Rust implementation of the canonical bootstrap
Recovery application. It intentionally does not depend on the larger Rust
Main firmware crate. It is not the Recovery implementation currently used
for E5; the C Recovery remains active while the bootstrap transport and
partition layout are being validated.

This version is bootstrap-only. It does not yet parse or verify signed
records, and must not be treated as an authenticated updater.

The current implementation matches the tested C bootstrap path:

- read `recovery` NVS settings and the `RECOVER IMG_IP:port IP SSID [PASSWORD]`
  UART override;
- use STA when an SSID is configured, otherwise use an open AP;
- receive the `DRS1` length-delimited TCP image stream;
- collect each requested byte range completely before writing it;
- erase and write the `main` application partition in 4096-byte chunks; and
- reject unsigned bootstrap when `trust_key` exists in NVS.

The Rust transport currently accepts a numeric IPv4 server address. It uses
direct POSIX/lwIP socket calls rather than `std::net` to keep the image small.

The C and Rust prototypes currently provide the unsigned bring-up transport;
signature verification is still pending. The size benefit of building an
AP-only or STA-only Recovery has also not yet been measured.

## Build

From the repository root:

```sh
bash scripts/build-recovery-rust.sh
```

The build uses the repository-local ESP-IDF/Rust toolchain and writes generated
artifacts under `target/recovery-rust/`. It does not flash a device.

The Rust project uses `esp-idf-sys` and the ESP-IDF Wi-Fi/netif/lwIP,
partition, NVS, event, and UART components directly. It does not use
`esp-idf-svc`, `embedded-svc`, HTTP, or the existing Main application graph.

## Canonical layout and size

The build uses the same canonical partition table as the C Recovery:

```text
Recovery: 0x10000, 0xd0000
Main:     0xe0000, 0x2e0000
Data:     0x3c0000, 0x40000
```

Measured optimized application images:

| implementation | image size | Recovery headroom |
| --- | ---: | ---: |
| C Recovery STA build | 652,816 bytes (`0x9f610`) | 199,152 bytes |
| Rust Recovery | 849,424 bytes (`0xcf610`) | 2,544 bytes |

The Rust bootstrap image is therefore 196,608 bytes, or approximately 30.1%,
larger than the C image. It still fits the current `0xd0000` partition, but
with little margin. Authenticated CBOR records or additional transport
features should not be added to this Rust image without revisiting the
partition size.

This comparison uses the same ESP-IDF 5.5.4 Wi-Fi stack and equivalent
size-oriented release settings. The difference is primarily the Rust runtime
and application code; the existing Main crate is not part of the Rust Recovery
image.
