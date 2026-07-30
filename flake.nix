{
  description = "DMesh device-mesh, Android, MUSL, and ESP32 build dependencies";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            config = {
              android_sdk.accept_license = true;
              allowUnfree = true;
            };
          };

          android = pkgs.androidenv.composeAndroidPackages {
            platformVersions = [ ];
            buildToolsVersions = [ ];
            includeNDK = false;
            includeEmulator = false;
            includeSources = false;
            includeSystemImages = false;
          };

          androidSdk = android.androidsdk;
          androidHome = "${androidSdk}/libexec/android-sdk";

          dmeshSetenv = pkgs.writeShellScriptBin "dmesh-setenv" ''
            _dmesh_repo="''${DMESH_REPO:-$PWD}"
            _dmesh_sdk="''${DMESH_ANDROID_SDK:-$_dmesh_repo/target/android-sdk}"

            if [ -d "$_dmesh_sdk/platforms" ]; then
              export ANDROID_HOME="$_dmesh_sdk"
            else
              export ANDROID_HOME="${androidHome}"
            fi
            export ANDROID_SDK_ROOT="$ANDROID_HOME"
            export JAVA_HOME="${pkgs.jdk17.home}"
            _dmesh_sdkmanager="$(find "${androidHome}/cmdline-tools" -path '*/bin/sdkmanager' -type f | sort -V | tail -n 1)"
            _dmesh_cmdline_bin="$(dirname "$_dmesh_sdkmanager")"
            if [ -d "$ANDROID_HOME/ndk" ]; then
              export ANDROID_NDK_HOME="$(find "$ANDROID_HOME/ndk" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -n 1)"
            fi

            if [ -n "''${BASH_SOURCE:-}" ]; then
              _dmesh_profile_bin="$(cd "$(dirname "''${BASH_SOURCE[0]}")" && pwd)"
            else
              _dmesh_profile_bin="$(cd "$(dirname "$0")" && pwd)"
            fi

            export PATH="$_dmesh_profile_bin:$JAVA_HOME/bin:$_dmesh_sdk/platform-tools:$_dmesh_sdk/emulator:$_dmesh_cmdline_bin:${androidHome}/platform-tools:$PATH"
          '';

          dmeshAndroidSdk = pkgs.writeShellScriptBin "dmesh-android-sdk" ''
            set -euo pipefail

            sdk_root="''${DMESH_ANDROID_SDK:-$PWD/target/android-sdk}"
            mkdir -p "$sdk_root"

            sdkmanager="$(find "${androidHome}/cmdline-tools" -path '*/bin/sdkmanager' -type f | sort -V | tail -n 1)"
            packages=(
              "platform-tools"
              "platforms;android-36"
              "build-tools;36.0.0"
              "ndk;29.0.14206865"
              "emulator"
            )

            yes | "$sdkmanager" --sdk_root="$sdk_root" --licenses >/dev/null || true
            "$sdkmanager" --sdk_root="$sdk_root" "''${packages[@]}"

            rustup target add \
              aarch64-linux-android \
              armv7-linux-androideabi \
              i686-linux-android \
              x86_64-linux-android

            echo "Installed Android SDK components in $sdk_root"
            echo "Load with: . target/nix/profile/bin/dmesh-setenv"
          '';

          deps = pkgs.symlinkJoin {
            name = "dmesh-deps";
            paths = [
              androidSdk
              dmeshAndroidSdk
              dmeshSetenv
              pkgs.bashInteractive
              pkgs.bluez
              pkgs.cargo-ndk
              pkgs.coreutils
              pkgs.findutils
              pkgs.gawk
              pkgs.git
              pkgs.gnugrep
              pkgs.gnused
              pkgs.gradle
              pkgs.jdk17
              pkgs.openssh
              pkgs.python3
              pkgs.ripgrep
              pkgs.rustc
              pkgs.socat
              pkgs.rustup
              pkgs.unzip
              pkgs.which
              pkgs.zip
              musl-toolchain
            ];
            meta.priority = 10;
          };

          musl-toolchain = pkgs.runCommand "dmesh-musl-toolchain" { } ''
            mkdir -p "$out/bin"
            for tool in ${pkgs.pkgsCross.musl64.stdenv.cc}/bin/*; do
              ln -s "$tool" "$out/bin/$(basename "$tool")"
            done
            for tool in gcc g++ cc c++ cpp ar as ld ld.bfd ld.gold nm objcopy objdump ranlib readelf size strings strip; do
              if [ -e "$out/bin/x86_64-unknown-linux-musl-$tool" ] &&
                 [ ! -e "$out/bin/x86_64-linux-musl-$tool" ]; then
                ln -s "x86_64-unknown-linux-musl-$tool" "$out/bin/x86_64-linux-musl-$tool"
              fi
            done
          '';
        in
        {
          inherit deps musl-toolchain;
          default = deps;
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            config = {
              android_sdk.accept_license = true;
              allowUnfree = true;
            };
          };
          deps = self.packages.${system}.deps;
        in
        {
          default = pkgs.mkShell {
            packages = [ deps ];
            shellHook = ''
              if [ -f target/nix/profile/bin/dmesh-setenv ]; then
                . target/nix/profile/bin/dmesh-setenv
              fi
              export CARGO_HOME="''${CARGO_HOME:-$PWD/target/.cargo}"
              export GRADLE_USER_HOME="''${GRADLE_USER_HOME:-$PWD/target/.gradle}"
            '';
          };
        }
      );
    };
}
