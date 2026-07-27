# Building DMesh

This repository owns device-specific mesh code: `lmesh`, `dmesh-store`,
`mesh-tun`, and `fw/esp32`. It consumes upstream `mesh` for common telemetry
and protocol support, and `ssh-mesh` for SSH, HTTPS, SFTP, and forwarding.

## Local build environment

Source `env.sh` before Cargo, Nix, Android, or firmware commands. It keeps all
mutable state under `target/`: Cargo, Rustup, Gradle, Nix profiles, Android
SDK/NDK, ESP-IDF, and the Rust ESP toolchain. It does not use a host home
directory or host-installed build tools.

```sh
cd "$(git rev-parse --show-toplevel)"
. ./env.sh
```

## Linux MUSL binaries

Install the repo-local Nix profile, then build every DMesh binary for static
MUSL:

```sh
scripts/build.sh deps
scripts/build.sh musl
```

The profile is `target/nix/profile`; binaries are written to
`target/x86_64-unknown-linux-musl/release/`. `scripts/build.sh check` runs the
workspace Cargo check using the same local ssh-mesh override when that checkout
is present.

## Android

Install the Android SDK, NDK, JDK, Rust/NDK helpers, and other host tools into
the same repo-local profile, then build the Android apps:

```sh
scripts/build-android.sh deps
scripts/build-android.sh build debug
```

Android SDK/NDK contents are installed under `target/android-sdk`; generated
native libraries and APKs remain under `target/`.

## ESP32 firmware

Install ESP32 host tools into their dedicated profile and ESP-IDF/Rust ESP
toolchains under `target/`:

```sh
scripts/esp32-deps.sh
. fw/esp32/env.sh
(cd fw/esp32/rust && cargo build)
```

ESP-IDF and Rust ESP state live under `target/esp32-5.5`; its Nix host profile
is `target/nix/esp32-profile`. See [fw/esp32/BUILD.md](fw/esp32/BUILD.md) for
firmware-specific build and flash details.
